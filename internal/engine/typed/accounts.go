package typed

import (
	"strconv"
	"strings"
)

// ShadowState clasifica el estado de la contrasena de una linea de /etc/shadow por el campo 2:
// "" -> EMPTY (sin contrasena, peligroso), "*" -> NOLOGIN (cuenta de sistema),
// empieza por "!" -> LOCKED, empieza por "$" u otro hash -> PASSWORD (contrasena establecida).
func ShadowState(line string) string {
	parts := strings.Split(line, ":")
	if len(parts) < 2 {
		return ""
	}
	h := parts[1]
	switch {
	case h == "":
		return "EMPTY"
	case h == "*":
		return "NOLOGIN"
	case strings.HasPrefix(h, "!"):
		return "LOCKED"
	default:
		return "PASSWORD"
	}
}

// HasEmptyPassword indica si alguna cuenta del contenido de /etc/shadow tiene contrasena vacia.
func HasEmptyPassword(shadow string) bool {
	for _, line := range strings.Split(shadow, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if ShadowState(line) == "EMPTY" {
			return true
		}
	}
	return false
}

// UID0Count cuenta las cuentas con UID 0 en /etc/passwd (debe ser exactamente 1: root).
func UID0Count(passwd string) int {
	count := 0
	for _, line := range strings.Split(passwd, "\n") {
		fields := strings.Split(strings.TrimSpace(line), ":")
		if len(fields) < 3 {
			continue
		}
		if uid, err := strconv.Atoi(fields[2]); err == nil && uid == 0 {
			count++
		}
	}
	return count
}
