package report

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Shotafry/talos/internal/ansi"
	"github.com/Shotafry/talos/internal/score"
)

// Glifos de estado, fuente unica para las tres zonas que los pintan (recuento, desglose por
// categoria y detalle -v). Solo runas de ancho SIMPLE y presentacion de texto, para que las
// columnas cuadren en cualquier terminal. NO usar ⚠ (U+26A0): Windows Terminal y muchos
// terminales Linux lo pintan como emoji de DOBLE ancho y descuadra cada fila (se come el digito
// siguiente). ▲ (U+25B2) es el triangulo de aviso en su forma de texto, mismo ancho que ✓/✗/·.
const (
	glyphPass = "✓"
	glyphWarn = "▲"
	glyphFail = "✗"
	glyphNA   = "·"
)

// WriteConsole escribe un informe de texto legible (modo standalone/TTY). color activa los
// codigos ANSI; el contrato JSON que consume Argos no pasa por aqui (ver report/json.go).
func WriteConsole(w io.Writer, r Report, verbose, color bool) {
	bc := bandColor(r.Band)

	// --- Cabecera: que host, cuando y con que perfil (identifica el artefacto, tambien al -o) ---
	if h := reportHeader(r); h != "" {
		fmt.Fprintln(w, ansi.P(color, ansi.Dim, h))
		fmt.Fprintln(w)
	}

	// --- Indice + medidor ---
	fmt.Fprintln(w, ansi.P(color, ansi.Bold, "Índice de bastionado"))
	fmt.Fprintf(w, "  %s  %s  %s\n",
		gauge(r.Index, r.Band, color),
		ansi.P(color, ansi.Bold+bc, fmt.Sprintf("%d/100", r.Index)),
		ansi.P(color, bc, r.Band))

	// --- Recuento ---
	fmt.Fprintf(w, "  %s   %s   %s   %s\n",
		ansi.P(color, ansi.Green, glyphPass+" "+plural(r.Counts.Pass, "correcto", "correctos")),
		ansi.P(color, ansi.Yellow, glyphWarn+" "+plural(r.Counts.Warn, "aviso", "avisos")),
		ansi.P(color, ansi.Red, glyphFail+" "+plural(r.Counts.Fail, "fallo", "fallos")),
		ansi.P(color, ansi.Dim, glyphNA+" "+plural(r.Counts.NA, "no aplica", "no aplican")))
	if r.Excluded.NoPrivilege > 0 {
		fmt.Fprintf(w, "  %s\n", ansi.P(color, ansi.Dim,
			fmt.Sprintf("(%d comprobaciones omitidas por falta de privilegios; ejecuta con sudo para cobertura total)", r.Excluded.NoPrivilege)))
	}
	fmt.Fprintln(w)

	// --- Hallazgos criticos (severidad alta/critica): que pasa / detectado / solucion ---
	// El conteo "N de M" deja claro que es un SUBCONJUNTO de los fallos totales (lo demas va
	// en "Otros hallazgos"), no todos los fallos.
	if len(r.CriticalVulns) > 0 {
		fmt.Fprintln(w, ansi.P(color, ansi.Bold+ansi.Red,
			fmt.Sprintf("Fallos críticos (severidad alta/crítica) - %d de %d - arréglalos ya:",
				len(r.CriticalVulns), r.Counts.Fail)))
		for _, c := range r.CriticalVulns {
			writeFinding(w, color, "FAIL", c.CheckID, c.Category, c.Severity, c.Title, c.ValueRead, c.Remediation)
		}
		fmt.Fprintln(w)
	}

	// --- Otros hallazgos (fallos medios/bajos + avisos): mismo formato que los criticos (que
	// pasa / detectado / solucion), solo cambia el titulo. Sale SIEMPRE, sin -v: el standalone
	// debe bastarse solo, y sin la explicacion no se sabe que se esta corrigiendo. ---
	others := otherFindings(r.Results)
	if len(others) > 0 {
		fmt.Fprintln(w, ansi.P(color, ansi.Bold+ansi.Yellow, "Otros hallazgos a corregir:"))
		for _, res := range others {
			writeFinding(w, color, res.Status, res.CheckID, res.Category, res.Severity, res.Description, res.ValueRead, res.Remediation)
		}
		fmt.Fprintln(w)
	}

	// --- Todo en orden: ni fallos ni avisos pendientes (y hubo checks que aplicaron) ---
	if len(r.CriticalVulns) == 0 && len(others) == 0 && r.Counts.Pass > 0 {
		fmt.Fprintln(w, ansi.P(color, ansi.Green, glyphPass+" Sin hallazgos que corregir."))
		fmt.Fprintln(w)
	}

	// --- Por categoria (mini-barra) ---
	fmt.Fprintln(w, ansi.P(color, ansi.Bold, "Por categoría:"))
	cw := countWidth(r.Categories)
	for _, c := range r.Categories {
		idxCell := fmt.Sprintf("%3d", c.Index)
		if c.Band == "n/d" { // sin checks aplicables: no es un 0, es que la categoria no aplica
			idxCell = "n/d"
		}
		fmt.Fprintf(w, "  %-10s %s %s  %s\n",
			c.Category,
			gauge(c.Index, c.Band, color),
			ansi.P(color, bandColor(c.Band), idxCell),
			categoryCounts(c.Counts, cw, color))
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

	// --- Pie: como ver mas / exportar (siempre, para que sepas que existe) ---
	writeFooter(w, r, verbose, color)
}

// reportHeader resume a quien y cuando audita esta corrida: "host · SO kernel · fecha · perfil".
func reportHeader(r Report) string {
	parts := make([]string, 0, 4)
	if r.Host.Hostname != "" {
		parts = append(parts, r.Host.Hostname)
	}
	if osk := strings.TrimSpace(r.Host.OS + " " + r.Host.Kernel); osk != "" {
		parts = append(parts, osk)
	}
	if d := humanDate(r.GeneratedAt); d != "" {
		parts = append(parts, d)
	}
	if r.Profile != "" {
		parts = append(parts, "perfil "+r.Profile)
	}
	return strings.Join(parts, " · ")
}

// humanDate convierte el RFC3339 UTC del informe en "AAAA-MM-DD HH:MM UTC"; si no parsea, crudo.
func humanDate(s string) string {
	if s == "" {
		return ""
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return s
	}
	return t.UTC().Format("2006-01-02 15:04") + " UTC"
}

// otherFindings son los hallazgos accionables que NO van al bloque de criticos: fallos de
// severidad media/baja y TODOS los avisos. Orden: fallos antes que avisos y, dentro, severidad
// descendente, para que lo mas grave quede arriba.
func otherFindings(results []Result) []Result {
	out := make([]Result, 0)
	for _, res := range results {
		if (res.Status == "FAIL" && !isHighSeverity(res.Severity)) || res.Status == "WARN" {
			out = append(out, res)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if a, b := statusOrder(out[i].Status), statusOrder(out[j].Status); a != b {
			return a < b
		}
		return severityOrder(out[i].Severity) < severityOrder(out[j].Severity)
	})
	return out
}

func isHighSeverity(s string) bool { return s == "high" || s == "critical" }

func statusOrder(s string) int {
	if s == "FAIL" {
		return 0
	}
	return 1 // WARN
}

func severityOrder(s string) int {
	switch s {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

// writeFooter imprime, atenuado, como obtener mas (detalle -v, informe HTML imprimible). Lo que
// no encaja en consola (lista completa con remediaciones) vive en el HTML; aqui se senala.
func writeFooter(w io.Writer, r Report, verbose, color bool) {
	type hint struct{ label, cmd string }
	hints := []hint{{"Informe imprimible (HTML/PDF):", "talos audit -o informe.html"}}
	if !verbose {
		hints = append(hints, hint{"Detalle por comprobación:", "talos audit -v"})
	}
	if r.Profile == "core" {
		hints = append(hints, hint{"Análisis completo:", "talos audit --profile full"})
	}
	lw := 0
	for _, h := range hints {
		if n := len([]rune(h.label)); n > lw {
			lw = n
		}
	}
	fmt.Fprintln(w)
	for _, h := range hints {
		fmt.Fprintf(w, "  %s  %s\n",
			ansi.P(color, ansi.Dim, padRunes(h.label, lw)),
			ansi.P(color, ansi.Cyan, h.cmd))
	}
}

// writeFinding pinta un hallazgo accionable con todo el contexto: cabecera (glifo + id +
// categoria/severidad), que pasa (descripcion), valor detectado y como arreglarlo. Lo comparten
// el bloque de criticos y el de "otros hallazgos" para que AMBOS expliquen igual el problema:
// sin la descripcion solo sabrias como arreglarlo, no que estas arreglando.
func writeFinding(w io.Writer, color bool, status, checkID, category, severity, description, valueRead, remediation string) {
	fmt.Fprintf(w, "  %s %s  %s\n",
		statusMark(status, color),
		ansi.P(color, ansi.Bold, checkID),
		ansi.P(color, ansi.Dim, category+" · severidad "+sevLabel(severity)))
	if description != "" {
		fmt.Fprintf(w, "      %s\n", description)
	}
	if v := cleanValue(valueRead); v != "" {
		fmt.Fprintf(w, "      %s %s\n", ansi.P(color, ansi.Dim, "detectado:"), v)
	}
	if remediation != "" {
		fmt.Fprintf(w, "      %s %s\n", ansi.P(color, ansi.Cyan+ansi.Bold, "solución:"), remediation)
	}
}

// statusMark devuelve solo el glifo de estado, coloreado (sin la palabra). Para encabezados de
// hallazgo donde el id y la severidad ya dan el contexto.
func statusMark(status string, on bool) string {
	switch status {
	case "PASS":
		return ansi.P(on, ansi.Green, glyphPass)
	case "WARN":
		return ansi.P(on, ansi.Yellow, glyphWarn)
	case "FAIL":
		return ansi.P(on, ansi.Red, glyphFail)
	default:
		return ansi.P(on, ansi.Dim, glyphNA)
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

// statusGlyph devuelve el estado con icono y color, ancho visible fijo (6 runas) para alinear
// la columna de descripcion. Todos los glifos son de ancho simple (ver constantes arriba).
func statusGlyph(status string, on bool) string {
	switch status {
	case "PASS":
		return ansi.P(on, ansi.Green, glyphPass+" PASS")
	case "WARN":
		return ansi.P(on, ansi.Yellow, glyphWarn+" WARN")
	case "FAIL":
		return ansi.P(on, ansi.Red, glyphFail+" FAIL")
	default:
		return ansi.P(on, ansi.Dim, glyphNA+" NA  ")
	}
}

// categoryCounts arma el desglose por categoria (✓ ▲ ✗ ·) con cada contador a ancho fijo w
// (alineado a la derecha) y separacion uniforme, para que las columnas cuadren entre filas.
func categoryCounts(c score.Counts, w int, on bool) string {
	return ansi.P(on, ansi.Dim, fmt.Sprintf("%s%*d  %s%*d  %s%*d  %s%*d",
		glyphPass, w, c.Pass,
		glyphWarn, w, c.Warn,
		glyphFail, w, c.Fail,
		glyphNA, w, c.NA))
}

// countWidth es el numero de digitos del contador mas grande de todas las categorias; con el
// se alinean las columnas del desglose sin cablear un ancho a ojo.
func countWidth(cats []score.CategoryScore) int {
	w := 1
	for _, c := range cats {
		for _, n := range [4]int{c.Counts.Pass, c.Counts.Warn, c.Counts.Fail, c.Counts.NA} {
			if d := len(strconv.Itoa(n)); d > w {
				w = d
			}
		}
	}
	return w
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
