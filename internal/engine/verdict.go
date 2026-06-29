package engine

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Shotafry/talos/internal/catalog"
	"github.com/Shotafry/talos/internal/engine/typed"
	"github.com/Shotafry/talos/internal/probe"
)

// Facts son los hechos del host que el motor consulta para la aplicabilidad.
// Lo recolecta el paquete facts (impuro, T9); aqui es solo dato (PURO).
// Bloque ampliable: anadir campos no rompe a los consumidores.
type Facts struct {
	OS            string          // id de SO del host (debian, ubuntu, rhel, alpine, windows...)
	DistroRelease string          // VERSION_ID de /etc/os-release ("11", "22.04") - para el pack por version
	KernelRelease string          // p.ej. 5.15.0-89-generic
	Services      map[string]bool // unidades systemd instaladas
	Packages      map[string]bool // paquetes instalados
	Files         map[string]bool // ficheros/directorios presentes
}

// Env es el contexto barato ya resuelto que el motor necesita para evaluar.
type Env struct {
	OS     string // SO del host (para el filtro check.os)
	IsRoot bool
	Facts  Facts
}

// Verdict es el resultado de evaluar un check. ValueRead + Status bastan para re-puntuar en Argos.
type Verdict struct {
	CheckID     string
	Status      string // PASS | WARN | FAIL | NA
	ValueRead   string
	Band        string // good|medium|weak|""
	Reason      string // motivo legible ES (sobre todo en NA)
	Points      int
	Earned      int // PASS=points, WARN=ceil(points/2), FAIL/NA=0
	Severity    string
	Criticality string
	Category    string
	ENS         []string
}

// Evaluate aplica el orden exacto: applicability -> privilegio -> error de probe ->
// extraccion de valor -> banda -> estado. NA nunca penaliza (Earned=0, fuera del score).
func Evaluate(check catalog.Check, raw probe.RawRead, env Env) Verdict {
	v := Verdict{
		CheckID:     check.ID,
		Severity:    check.Severity,
		Criticality: check.Criticality,
		Category:    check.Category,
		ENS:         check.ENSControls,
		Points:      check.Points,
	}

	if ok, reason := applicabilityHolds(check.Applicability, env.Facts); !ok {
		v.Status, v.Reason = "NA", reason
		return v
	}
	if check.RequiresPrivilege && !env.IsRoot {
		v.Status, v.Reason = "NA", "requiere privilegios de root (ejecuta con sudo)"
		return v
	}
	if raw.Err != nil {
		v.Status, v.Reason = "NA", "no se pudo leer: "+raw.Err.Error()
		return v
	}
	// Un comando que fallo (exit != 0) y no dejo salida usable -> no pudimos leer el estado: NA.
	// (systemd is-active inactivo SI deja salida "inactive", asi que ese caso si se evalua.)
	if isCommandRead(check.Read.Type) && raw.Exit != 0 && strings.TrimSpace(raw.Stdout) == "" {
		v.Status, v.Reason = "NA", fmt.Sprintf("no se pudo leer (salida vacia, codigo %d)", raw.Exit)
		return v
	}
	// Un cmdlet de PowerShell que devuelve $null/vacio SALE con exit 0 (la propiedad no
	// existe en ese Defender/Windows, o el cmdlet no esta disponible). Eso es "no se pudo
	// leer" -> NA, no FAIL: un valor vacio no debe penalizar el indice (invariante: NA no
	// penaliza). No afecta a ss/systemd (dejan salida util como "inactive"/sockets).
	if check.Read.Type == "cmdlet" && strings.TrimSpace(raw.Stdout) == "" {
		v.Status, v.Reason = "NA", "no se pudo leer (cmdlet sin salida)"
		return v
	}

	value := extractValue(check, raw)
	band := matchBand(check.Comparator, check.Expected, value)
	v.ValueRead = truncateValue(value) // se compara con el valor completo, pero se guarda recortado
	v.Band = band
	switch band {
	case "good":
		v.Status, v.Earned = "PASS", check.Points
	case "medium":
		v.Status, v.Earned = "WARN", (check.Points+1)/2 // ceil(points/2)
	default:
		v.Status, v.Earned = "FAIL", 0
	}
	return v
}

// isCommandRead indica si el read ejecuta un comando (su salida/exit importan).
// registry NO entra: su ausencia es senal ("absent"), no un error de lectura.
func isCommandRead(t string) bool {
	switch t {
	case "exec", "sshd_t", "ss", "systemd", "pkgmgr", "cmdlet", "netaccounts":
		return true
	default:
		return false
	}
}

// extractValue normaliza el valor a comparar usando el evaluador tipado de cada tipo de read.
func extractValue(check catalog.Check, raw probe.RawRead) string {
	if raw.Value != "" {
		return raw.Value // pre-extraido (tests o cache del runner)
	}
	switch check.Read.Type {
	case "sshd_t":
		return typed.ParseSSHD(raw.Stdout)[check.Read.Key]
	// sysctl: el probe ya devuelve el valor normalizado en raw.Value (atendido arriba).
	case "registry":
		if !raw.Exists {
			return "absent" // clave/valor ausente: cada ficha decide si es seguro o no
		}
		return typed.RegistryValue(raw.Stdout, check.Read.Name)
	case "netaccounts":
		return typed.NetAccountsField(raw.Stdout, check.Read.Key)
	case "cmdlet":
		return strings.TrimSpace(raw.Stdout)
	case "ss":
		return ssValue(check.Read, raw.Stdout)
	case "shadow":
		return shadowValue(check.Read, raw.Content)
	case "passwd":
		return strconv.Itoa(typed.UID0Count(raw.Content))
	case "pkgmgr":
		if check.Read.Op == "security" {
			return strconv.Itoa(typed.CountSecurityUpgradable(raw.Stdout))
		}
		return strconv.Itoa(typed.CountUpgradable(raw.Stdout))
	case "file":
		if check.Comparator == "exists" {
			return boolStr(raw.Exists)
		}
		return strings.TrimSpace(raw.Content)
	case "stat":
		return boolStr(raw.Exists)
	default:
		if check.Comparator == "exists" {
			return boolStr(raw.Exists)
		}
		return strings.TrimSpace(raw.Stdout)
	}
}

// truncateValue colapsa espacios/saltos y limita la longitud del valor que se guarda y muestra
// (evita persistir ficheros enteros leidos por regex/nregex).
func truncateValue(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 120 {
		return s[:120] + "..."
	}
	return s
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// ssValue: con read.Key = puerto, devuelve si hay un socket a la escucha en ese puerto
// ("true"/"false"); sin Key, "exposed" si algun servicio sensible escucha en wildcard, si no "none".
func ssValue(read catalog.Read, stdout string) string {
	socks := typed.ParseSS(stdout)
	if read.Key != "" {
		for _, s := range socks {
			if strconv.Itoa(s.Port) == read.Key {
				return "true"
			}
		}
		return "false"
	}
	for _, s := range socks {
		if s.Wildcard && sensitivePorts[s.Port] {
			return "exposed"
		}
	}
	return "none"
}

// sensitivePorts: servicios que no deberian escuchar en 0.0.0.0/[::] (bases de datos, admin).
var sensitivePorts = map[int]bool{
	2375: true, 2376: true, 3306: true, 5432: true, 6379: true, 9200: true,
	11211: true, 27017: true, 5984: true, 9000: true, 9090: true, 8086: true,
}

// shadowValue: User="*" -> "true" si alguna cuenta tiene contrasena vacia;
// User=<nombre> -> estado de esa cuenta (LOCKED|NOLOGIN|PASSWORD|EMPTY).
func shadowValue(read catalog.Read, content string) string {
	if read.User == "*" {
		return boolStr(typed.HasEmptyPassword(content))
	}
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, read.User+":") {
			return typed.ShadowState(line)
		}
	}
	return ""
}

func applicabilityHolds(a *catalog.Applicability, f Facts) (bool, string) {
	if a == nil {
		return true, ""
	}
	if len(a.AnyOf) > 0 {
		ok := false
		for _, p := range a.AnyOf {
			if predHolds(p, f) {
				ok = true
				break
			}
		}
		if !ok {
			return false, "no aplica: " + describeOne(a.AnyOf[0])
		}
	}
	for _, p := range a.AllOf {
		if !predHolds(p, f) {
			return false, "no aplica: " + describeOne(p)
		}
	}
	if a.Not != nil && predHolds(*a.Not, f) {
		return false, "no aplica: condicion excluyente presente"
	}
	return true, ""
}

func predHolds(p catalog.Predicate, f Facts) bool {
	switch {
	case p.Service != "":
		return f.Services[p.Service]
	case p.Package != "":
		return f.Packages[p.Package]
	case p.File != "":
		return f.Files[p.File]
	case p.OS != "":
		return p.OS == f.OS || p.OS == "linux" // family linux
	case p.Release != "":
		return p.Release == f.DistroRelease // version del SO (pack por version)
	case p.KernelRange != "":
		return true // evaluado por typed/semver en T8; por defecto aplica
	default:
		return true
	}
}

func describeOne(p catalog.Predicate) string {
	switch {
	case p.Service != "":
		return "servicio " + p.Service + " no instalado"
	case p.Package != "":
		return "paquete " + p.Package + " no instalado"
	case p.File != "":
		return "fichero " + p.File + " ausente"
	case p.OS != "":
		return "SO distinto de " + p.OS
	case p.Release != "":
		return "version del SO distinta de " + p.Release
	case p.KernelRange != "":
		return "kernel fuera del rango " + p.KernelRange
	default:
		return "condicion no cumplida"
	}
}
