//go:build linux

package facts

import "testing"

func TestCollectLinux(t *testing.T) {
	f := Collect()
	if f.OS == "" || f.OS == "unknown" {
		t.Errorf("OS no detectado: %q", f.OS)
	}
	if f.KernelRelease == "" {
		t.Error("kernel no detectado")
	}
	// En WSL/cualquier linux deberia haber al menos algun paquete listado.
	if len(f.Packages) == 0 {
		t.Log("aviso: 0 paquetes (gestor no detectado en este host)")
	}
}
