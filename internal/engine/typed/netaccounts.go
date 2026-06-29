package typed

import (
	"regexp"
	"strconv"
	"strings"
)

// colGap separa la etiqueta del valor en `net accounts` (columna alineada con 2+ espacios).
var colGap = regexp.MustCompile(`\s{2,}`)

// netAccountsFields mapea el nombre logico de campo al INDICE de fila en `net accounts`.
// El ORDEN de filas de `net accounts` es estable entre idiomas (la salida esta localizada,
// pero la secuencia no), asi que parseamos por posicion y NO por la etiqueta acentuada -que
// ademas llega en codepage OEM, no UTF-8, al ejecutar el comando-. Los valores (numeros)
// son ASCII, inmunes al codepage.
var netAccountsFields = map[string]int{
	"minPwAge":         1,
	"maxPwAge":         2,
	"minPwLen":         3,
	"lockoutThreshold": 5,
}

// ParseNetAccounts devuelve la columna de valores de `net accounts`, una por fila de datos,
// en orden. Una fila de datos es la que tiene el patron "etiqueta<gap>valor"; la linea final
// ("Se ha completado...") no tiene ese hueco de columna y se descarta.
func ParseNetAccounts(stdout string) []string {
	var out []string
	for _, raw := range strings.Split(stdout, "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if line == "" {
			continue
		}
		parts := colGap.Split(line, 2)
		if len(parts) < 2 {
			continue
		}
		out = append(out, strings.TrimSpace(parts[1]))
	}
	return out
}

// NetAccountsField extrae un campo numerico normalizado de `net accounts`. Un valor no numerico
// ("Nunca"/"Never"/"Ninguna") se traduce por su semantica: para maxPwAge significa "no caduca"
// (peor que cualquier umbral -> 99999); para el resto, "sin minimo/sin bloqueo" -> 0.
func NetAccountsField(stdout, field string) string {
	vals := ParseNetAccounts(stdout)
	idx, ok := netAccountsFields[field]
	if !ok || idx >= len(vals) {
		return ""
	}
	tok := strings.TrimSpace(vals[idx])
	if _, err := strconv.Atoi(tok); err == nil {
		return tok
	}
	if field == "maxPwAge" {
		return "99999"
	}
	return "0"
}
