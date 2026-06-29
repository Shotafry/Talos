//go:build windows

package facts

import (
	"os/exec"

	"github.com/Shotafry/talos/internal/engine"
)

// Collect en Windows: el SO basta para la aplicabilidad (las fichas Windows usan os: windows;
// servicios/paquetes/ficheros los resuelven sus propias lecturas registry/cmdlet). El inventario
// fino de Windows ya lo cubren Atera/Intune; el valor de Talos aqui es el bastionado.
func Collect() engine.Facts {
	return engine.Facts{
		OS:       "windows",
		Services: map[string]bool{},
		Packages: map[string]bool{},
		Files:    map[string]bool{},
	}
}

// IsPrivileged detecta si el proceso esta elevado (administrador). `net session` solo lo permite
// un proceso elevado: exit 0 => admin. os.Geteuid() no sirve en Windows (devuelve -1 siempre).
func IsPrivileged() bool {
	cmd := exec.Command("net", "session")
	cmd.Stdout, cmd.Stderr = nil, nil
	return cmd.Run() == nil
}
