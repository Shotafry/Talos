package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/Shotafry/talos/internal/ansi"
)

// WriteConsole escribe un informe de texto legible (modo standalone/TTY). color activa los
// codigos ANSI; el contrato JSON que consume Argos no pasa por aqui (ver report/json.go).
func WriteConsole(w io.Writer, r Report, verbose, color bool) {
	bc := bandColor(r.Band)

	// --- Indice + medidor ---
	fmt.Fprintln(w, ansi.P(color, ansi.Bold, "Índice de bastionado"))
	fmt.Fprintf(w, "  %s  %s  %s\n",
		gauge(r.Index, r.Band, color),
		ansi.P(color, ansi.Bold+bc, fmt.Sprintf("%d/100", r.Index)),
		ansi.P(color, bc, r.Band))

	// --- Recuento ---
	fmt.Fprintf(w, "  %s   %s   %s   %s\n",
		ansi.P(color, ansi.Green, "✓ "+plural(r.Counts.Pass, "correcto", "correctos")),
		ansi.P(color, ansi.Yellow, "⚠ "+plural(r.Counts.Warn, "aviso", "avisos")),
		ansi.P(color, ansi.Red, "✗ "+plural(r.Counts.Fail, "fallo", "fallos")),
		ansi.P(color, ansi.Dim, "· "+plural(r.Counts.NA, "no aplica", "no aplican")))
	if r.Excluded.NoPrivilege > 0 {
		fmt.Fprintf(w, "  %s\n", ansi.P(color, ansi.Dim,
			fmt.Sprintf("(%d comprobaciones omitidas por falta de privilegios; ejecuta con sudo para cobertura total)", r.Excluded.NoPrivilege)))
	}
	fmt.Fprintln(w)

	// --- Hallazgos criticos (explicados: que pasa / detectado / solucion) ---
	if len(r.CriticalVulns) > 0 {
		fmt.Fprintln(w, ansi.P(color, ansi.Bold+ansi.Red, "Fallos críticos (arréglalos ya):"))
		for _, c := range r.CriticalVulns {
			fmt.Fprintf(w, "  %s %s  %s\n",
				ansi.P(color, ansi.Red, "✗"),
				ansi.P(color, ansi.Bold, c.CheckID),
				ansi.P(color, ansi.Dim, c.Category+" · severidad "+sevLabel(c.Severity)))
			if c.Title != "" {
				fmt.Fprintf(w, "      %s\n", c.Title)
			}
			if v := cleanValue(c.ValueRead); v != "" {
				fmt.Fprintf(w, "      %s %s\n", ansi.P(color, ansi.Dim, "detectado:"), v)
			}
			if c.Remediation != "" {
				fmt.Fprintf(w, "      %s %s\n", ansi.P(color, ansi.Cyan+ansi.Bold, "solución: "), c.Remediation)
			}
		}
		fmt.Fprintln(w)
	}

	// --- Por categoria (mini-barra) ---
	fmt.Fprintln(w, ansi.P(color, ansi.Bold, "Por categoría:"))
	for _, c := range r.Categories {
		cbc := bandColor(c.Band)
		fmt.Fprintf(w, "  %-10s %s %s  %s\n",
			c.Category,
			gauge(c.Index, c.Band, color),
			ansi.P(color, cbc, fmt.Sprintf("%3d", c.Index)),
			ansi.P(color, ansi.Dim, fmt.Sprintf("✓%d ⚠%d ✗%d ·%d", c.Counts.Pass, c.Counts.Warn, c.Counts.Fail, c.Counts.NA)))
	}

	// --- Detalle (-v): glifo + id + descripcion legible + valor/razon ---
	if verbose {
		fmt.Fprintf(w, "\n%s\n", ansi.P(color, ansi.Bold, "Detalle:"))
		for _, res := range r.Results {
			desc := truncate(res.Description, 52)
			detail := cleanValue(res.ValueRead)
			if res.Status == "NA" && res.Reason != "" {
				detail = res.Reason
			}
			fmt.Fprintf(w, "  %s  %-24s %s",
				statusGlyph(res.Status, color),
				res.CheckID,
				padRunes(desc, 52))
			if detail != "" {
				fmt.Fprintf(w, "  %s", ansi.P(color, ansi.Dim, truncate(detail, 60)))
			}
			fmt.Fprintln(w)
		}
	}

	// --- Sugerencia de cobertura ---
	if r.Profile == "core" {
		fmt.Fprintf(w, "\n%s\n", ansi.P(color, ansi.Cyan,
			"Sugerencia: has corrido el perfil 'core' (rápido). Para el análisis completo, incluido el pack de vulnerabilidades por versión: talos audit --profile full"))
	}
}

// bandColor mapea la banda (verde|amarillo|rojo|n/d) a su color ANSI.
func bandColor(band string) string {
	switch band {
	case "verde":
		return ansi.Green
	case "amarillo":
		return ansi.Yellow
	case "rojo":
		return ansi.Red
	default:
		return ansi.Dim
	}
}

// gauge dibuja una barra 0-100 coloreada por banda (relleno) + atenuada (resto).
func gauge(index int, band string, on bool) string {
	const width = 24
	filled := index * width / 100
	if filled < 0 {
		filled = 0
	}
	if filled > width {
		filled = width
	}
	return ansi.P(on, bandColor(band), strings.Repeat("█", filled)) +
		ansi.P(on, ansi.Dim, strings.Repeat("░", width-filled))
}

// statusGlyph devuelve el estado con icono y color, ancho visible fijo (6) para alinear.
func statusGlyph(status string, on bool) string {
	switch status {
	case "PASS":
		return ansi.P(on, ansi.Green, "✓ PASS")
	case "WARN":
		return ansi.P(on, ansi.Yellow, "⚠ WARN")
	case "FAIL":
		return ansi.P(on, ansi.Red, "✗ FAIL")
	default:
		return ansi.P(on, ansi.Dim, "· NA  ")
	}
}

func sevLabel(s string) string {
	switch s {
	case "critical":
		return "crítica"
	case "high":
		return "alta"
	case "medium":
		return "media"
	case "low":
		return "baja"
	default:
		return s
	}
}

// cleanValue normaliza un valor leido a una sola linea acotada (evita volcar ficheros).
func cleanValue(s string) string {
	return truncate(strings.Join(strings.Fields(s), " "), 60)
}

// truncate corta por runas (no por bytes) para no partir caracteres UTF-8.
func truncate(s string, max int) string {
	s = strings.TrimSpace(s)
	r := []rune(s)
	if len(r) > max {
		return string(r[:max-1]) + "…"
	}
	return s
}

// padRunes rellena con espacios hasta n runas (alinea aunque haya tildes/UTF-8, que
// fmt %-Ns no maneja porque cuenta bytes).
func padRunes(s string, n int) string {
	if d := n - len([]rune(s)); d > 0 {
		return s + strings.Repeat(" ", d)
	}
	return s
}

// plural devuelve "N palabra" usando el singular si N==1.
func plural(n int, sing, plur string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, sing)
	}
	return fmt.Sprintf("%d %s", n, plur)
}
