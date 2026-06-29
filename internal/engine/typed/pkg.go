package typed

import "strings"

// CountUpgradable cuenta paquetes actualizables en la salida de `apt list --upgradable`
// (ignora la cabecera "Listing..." y lineas vacias).
func CountUpgradable(out string) int {
	count := 0
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Listing") {
			continue
		}
		count++
	}
	return count
}

// CountSecurityUpgradable cuenta los actualizables cuyo repositorio es de seguridad
// (el primer campo "pkg/repo" contiene "security").
func CountSecurityUpgradable(out string) int {
	count := 0
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Listing") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 && strings.Contains(fields[0], "security") {
			count++
		}
	}
	return count
}
