package typed

import "strings"

// NormalizeSysctl normaliza el valor crudo de un sysctl: recorta y, si vienen varios
// valores por interfaz (p.ej. rp_filter "1\t1"), devuelve el primer token.
func NormalizeSysctl(raw string) string {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}
