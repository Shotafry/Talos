package typed

import (
	"strconv"
	"strings"
)

// Socket es un socket a la escucha parseado de `ss -H -tlnup`.
type Socket struct {
	Proto    string // tcp | udp
	Addr     string // direccion local (0.0.0.0, [::], 127.0.0.1, ...)
	Port     int
	Wildcard bool   // escucha en 0.0.0.0 / [::] / * (exposicion potencial)
	Process  string // nombre del proceso si esta disponible (root); "" si no
}

// ParseSS parsea `ss -H -tlnup`. Tolera la columna de proceso ausente (sin root).
// Columnas: Netid State Recv-Q Send-Q Local:Port Peer:Port [Process].
func ParseSS(out string) []Socket {
	var socks []Socket
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		addr, port := splitHostPort(fields[4])
		if port < 0 {
			continue
		}
		s := Socket{
			Proto:    fields[0],
			Addr:     addr,
			Port:     port,
			Wildcard: addr == "0.0.0.0" || addr == "[::]" || addr == "*",
		}
		if len(fields) >= 7 {
			s.Process = extractProcessName(strings.Join(fields[6:], " "))
		}
		socks = append(socks, s)
	}
	return socks
}

func splitHostPort(s string) (string, int) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return s, -1
	}
	port, err := strconv.Atoi(s[i+1:])
	if err != nil {
		return s[:i], -1
	}
	return s[:i], port
}

// extractProcessName saca "sshd" de users:(("sshd",pid=1233,fd=3)).
func extractProcessName(proc string) string {
	i := strings.Index(proc, "((\"")
	if i < 0 {
		return ""
	}
	rest := proc[i+3:]
	j := strings.Index(rest, "\"")
	if j < 0 {
		return ""
	}
	return rest[:j]
}
