package cli

import "testing"

// El formato de salida: --format explicito manda; si no, se infiere de la extension del fichero
// de -o (.html/.htm -> html, .json -> json); en cualquier otro caso, texto.
func TestEffectiveFormat(t *testing.T) {
	cases := []struct{ format, output, want string }{
		{"", "", "text"},
		{"", "informe.html", "html"},
		{"", "informe.HTM", "html"},
		{"", "datos.json", "json"},
		{"", "informe.txt", "text"},
		{"", "INFORME.HTML", "html"},
		{"html", "", "html"},
		{"text", "informe.html", "text"}, // --format explicito manda sobre la extension
		{"json", "x.html", "json"},
	}
	for _, c := range cases {
		if got := effectiveFormat(c.format, c.output); got != c.want {
			t.Errorf("effectiveFormat(%q,%q) = %q, esperaba %q", c.format, c.output, got, c.want)
		}
	}
}
