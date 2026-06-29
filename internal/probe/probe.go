// Package probe captura el estado bruto del host para un check (parte IMPURA acotada).
// El motor (paquete engine) no ejecuta nada: recibe el RawRead ya capturado y lo evalua.
package probe

import (
	"os"
	"strings"

	"github.com/Shotafry/talos/internal/catalog"
)

// RawRead es el resultado bruto de leer el estado de un check.
type RawRead struct {
	Stdout  string      // exec: salida estandar
	Stderr  string      // exec: salida de error
	Exit    int         // exec: codigo de salida
	Content string      // file/sysctl: contenido leido
	Exists  bool        // file/stat/sysctl: existe el recurso
	Mode    os.FileMode // file/stat: permisos
	Value   string      // sysctl: valor normalizado simple
	Err     error       // error de lectura (probe): el motor lo traduce a NA
}

// AllowedBinaries es la lista blanca de binarios que el probe exec puede ejecutar.
// Un read.cmd cuyo argv[0] no este aqui se rechaza: un catalogo manipulado no puede
// ejecutar binarios arbitrarios.
var AllowedBinaries = map[string]bool{
	"ss": true, "sshd": true, "systemctl": true, "getenforce": true,
	"apparmor_status": true, "aa-status": true, "apt-get": true, "apt": true,
	"dnf": true, "yum": true, "apk": true, "auditctl": true, "sysctl": true,
	"mount": true, "findmnt": true, "passwd": true, "timedatectl": true,
	"ufw": true, "firewall-cmd": true, "nft": true, "dpkg-query": true,
	"rpm": true, "uname": true,
	// Windows (0.20.1): lectura de registro, PowerShell (escalar) y politica de cuentas.
	"reg": true, "powershell": true, "net": true,
}

// Capture obtiene el RawRead segun read.Type. timeoutMs es el tope por probe exec (0 = 5000).
func Capture(read catalog.Read, allow map[string]bool, timeoutMs int) RawRead {
	switch read.Type {
	case "exec", "sshd_t", "ss", "systemd", "pkgmgr", "cmdlet", "netaccounts":
		// Estos tipos se materializan como un comando concreto (mapCommand);
		// el valor fino lo extrae el motor con el evaluador tipado correspondiente.
		return runExec(mapCommand(read), allow, timeoutMs)
	case "registry":
		return regQuery(read, allow, timeoutMs)
	case "pkgver":
		return pkgVersion(read.Key, allow, timeoutMs)
	case "file":
		return readFile(read.Path)
	case "shadow":
		return readFile(orDefault(read.Path, "/etc/shadow"))
	case "passwd":
		return readFile(orDefault(read.Path, "/etc/passwd"))
	case "stat":
		return statPath(read.Path)
	case "sysctl":
		return readSysctl(read.Key)
	default:
		return RawRead{Err: &unsupportedTypeError{read.Type}}
	}
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

type unsupportedTypeError struct{ t string }

func (e *unsupportedTypeError) Error() string { return "tipo de read no soportado: " + e.t }

// mapCommand traduce un read de alto nivel a su argv concreto (sin shell).
func mapCommand(read catalog.Read) []string {
	switch read.Type {
	case "sshd_t":
		return []string{"sshd", "-T"}
	case "ss":
		return []string{"ss", "-H", "-tlnup"}
	case "systemd":
		return []string{"systemctl", "is-active", read.Unit}
	case "netaccounts":
		return []string{"net", "accounts"}
	case "cmdlet":
		// PowerShell evalua una expresion del catalogo (confiable, embebida) y emite un escalar.
		// -Command recibe la expresion como un unico argumento (sin shell): no hay inyeccion externa.
		return []string{"powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", strings.Join(read.Cmd, " ")}
	default: // exec, pkgmgr
		return read.Cmd
	}
}

// regQuery lee un valor del registro con reg.exe. Clave/valor ausente (exit != 0) ->
// Exists=false SIN Err: no es un error de lectura, es una senal ("absent") que cada ficha
// interpreta (para muchos valores, ausente = inseguro; para otros, ausente = default seguro).
func regQuery(read catalog.Read, allow map[string]bool, timeoutMs int) RawRead {
	r := runExec([]string{"reg", "query", read.Path, "/v", read.Name}, allow, timeoutMs)
	if r.Err != nil {
		return r // no se pudo ejecutar reg.exe (no es Windows, falta el binario): el motor -> NA
	}
	if r.Exit != 0 || strings.TrimSpace(r.Stdout) == "" {
		return RawRead{Exists: false, Stdout: r.Stdout}
	}
	return RawRead{Exists: true, Stdout: r.Stdout}
}

func readSysctl(key string) RawRead {
	path := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
	b, err := os.ReadFile(path)
	if err != nil {
		return RawRead{Exists: false, Err: err}
	}
	content := string(b)
	// Normaliza aqui: algunos sysctl (p.ej. rp_filter agregado) traen varios valores
	// separados por tab/espacio; tomamos el primero. Asi el valor ya viene limpio.
	val := ""
	if f := strings.Fields(content); len(f) > 0 {
		val = f[0]
	}
	return RawRead{Exists: true, Value: val, Content: content}
}
