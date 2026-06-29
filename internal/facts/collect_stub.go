//go:build !linux && !windows

package facts

import "github.com/Shotafry/talos/internal/engine"

// Collect en plataformas sin colector propio (macOS para desarrollo): facts minimos para que el
// modulo compile y los tests del resto corran. La recoleccion real es linux/windows.
func Collect() engine.Facts {
	return engine.Facts{
		OS:       "unknown",
		Services: map[string]bool{},
		Packages: map[string]bool{},
		Files:    map[string]bool{},
	}
}

// IsPrivileged: sin colector propio no podemos saberlo; asumimos sin privilegios.
func IsPrivileged() bool { return false }
