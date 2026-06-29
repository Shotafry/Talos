// Package typed contiene evaluadores/parsers PUROS por dominio (sshd -T, ss, /etc/shadow,
// versiones, paquetes). Cada uno se valida contra OUTPUT REAL (fixtures en testdata/).
package typed

import "strings"

// ParseSSHD parsea el volcado de `sshd -T` (config efectiva: una directiva por linea,
// clave en minuscula, valor tal cual; las multivaluadas -ciphers/macs/kex- como CSV).
func ParseSSHD(stdout string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, val, found := strings.Cut(line, " ")
		key = strings.ToLower(key)
		if !found {
			m[key] = ""
			continue
		}
		m[key] = strings.TrimSpace(val)
	}
	return m
}
