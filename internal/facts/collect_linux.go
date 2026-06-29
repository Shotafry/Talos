//go:build linux

// Package facts recolecta los hechos del host (parte IMPURA, acotada al SO).
// Produce un engine.Facts que el motor consulta para la aplicabilidad. La recoleccion
// real corre en el binario linux del argonauta; en otras plataformas hay un stub.
package facts

import (
	"os"
	"os/exec"
	"strings"

	"github.com/Shotafry/talos/internal/engine"
)

// Collect reune OS, version del SO, kernel, servicios instalados y paquetes instalados.
// Los predicados de fichero (applicability file:) los resuelve el runner (CLI) con stat.
func Collect() engine.Facts {
	f := engine.Facts{
		Services: map[string]bool{},
		Packages: map[string]bool{},
		Files:    map[string]bool{},
	}
	id, release := osRelease()
	f.OS = id
	f.DistroRelease = release
	f.KernelRelease = readTrim("/proc/sys/kernel/osrelease")
	collectServices(f.Services)
	collectPackages(f.Packages)
	return f
}

// IsPrivileged indica si el proceso corre como root (cobertura completa de checks privilegiados).
func IsPrivileged() bool { return os.Geteuid() == 0 }

// osRelease devuelve (ID, VERSION_ID) de /etc/os-release. VERSION_ID ("11", "22.04") lo usa el
// pack de vulns por version para elegir la version corregida por distro+release.
func osRelease() (id, versionID string) {
	id = "linux"
	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return id, ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		switch {
		case strings.HasPrefix(line, "ID="):
			id = strings.Trim(strings.TrimPrefix(line, "ID="), "\"")
		case strings.HasPrefix(line, "VERSION_ID="):
			versionID = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), "\"")
		}
	}
	return id, versionID
}

func readTrim(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func collectServices(m map[string]bool) {
	out, err := exec.Command("systemctl", "list-unit-files", "--type=service", "--no-legend", "--no-pager").Output()
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		m[strings.TrimSuffix(fields[0], ".service")] = true
	}
}

func collectPackages(m map[string]bool) {
	if out, err := exec.Command("dpkg-query", "-W", "-f", "${Package}\n").Output(); err == nil {
		addLines(m, out)
		return
	}
	if out, err := exec.Command("rpm", "-qa", "--qf", "%{NAME}\n").Output(); err == nil {
		addLines(m, out)
	}
}

func addLines(m map[string]bool, out []byte) {
	for _, line := range strings.Split(string(out), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			m[line] = true
		}
	}
}
