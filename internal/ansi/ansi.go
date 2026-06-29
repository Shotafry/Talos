// Package ansi son codigos de color de terminal minimos, sin dependencias. Se usan solo
// en la salida de consola del modo standalone (nunca en el contrato JSON que consume Argos).
package ansi

const (
	Reset  = "\x1b[0m"
	Bold   = "\x1b[1m"
	Dim    = "\x1b[2m"
	Red    = "\x1b[31m"
	Green  = "\x1b[32m"
	Yellow = "\x1b[33m"
	Cyan   = "\x1b[36m"
	Bronze = "\x1b[38;5;179m" // dorado/bronce (256 colores), guino a la marca
)

// P pinta s con code si on es true; si no, devuelve s tal cual (sin codigos).
func P(on bool, code, s string) string {
	if !on {
		return s
	}
	return code + s + Reset
}
