package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Shotafry/talos/internal/ansi"
	"github.com/Shotafry/talos/internal/score"
)

// consoleSampleReport mezcla contadores de uno y dos digitos a proposito: asi el padding de
// columnas del desglose queda ejercitado (el host de CI puede no tener categorias con >9).
func consoleSampleReport() Report {
	return Report{
		Index: 64, Band: "amarillo", Profile: "full",
		Counts: score.Counts{Pass: 14, Warn: 2, Fail: 10, NA: 3},
		Categories: []score.CategoryScore{
			{Category: "KERNEL", Index: 64, Band: "amarillo", Counts: score.Counts{Pass: 14, Warn: 2, Fail: 10, NA: 0}},
			{Category: "SSH", Index: 100, Band: "verde", Counts: score.Counts{Pass: 1, Warn: 0, Fail: 0, NA: 4}},
			{Category: "FIREWALL", Index: 0, Band: "rojo", Counts: score.Counts{Pass: 0, Warn: 0, Fail: 1, NA: 2}},
		},
		Results: []Result{
			{CheckID: "SSH-02", Status: "FAIL", Category: "SSH", Description: "Autenticación por contraseña activa", ValueRead: "yes"},
			{CheckID: "KRN-01", Status: "WARN", Category: "KERNEL", Description: "ASLR parcial", ValueRead: "1"},
			{CheckID: "FW-01", Status: "PASS", Category: "FIREWALL", Description: "Cortafuegos activo", ValueRead: "active"},
		},
	}
}

// El bug original: ⚠ (U+26A0) se pinta como emoji de doble ancho y descuadra la tabla. La
// salida de consola NUNCA debe contenerlo (usa glyphWarn = ▲, de ancho simple).
func TestConsoleNoWideEmoji(t *testing.T) {
	var buf bytes.Buffer
	WriteConsole(&buf, consoleSampleReport(), true, false)
	if strings.ContainsRune(buf.String(), '⚠') {
		t.Error("la salida contiene ⚠ (U+26A0): emoji de doble ancho que descuadra la tabla; usa glyphWarn (▲)")
	}
}

// Las cuatro columnas del desglose por categoria (✓ ▲ ✗ ·) deben empezar en la misma columna
// en todas las filas, aunque los contadores tengan distinto numero de digitos.
func TestConsoleCategoryColumnsAligned(t *testing.T) {
	var buf bytes.Buffer
	WriteConsole(&buf, consoleSampleReport(), false, false)
	lines := categoryLines(buf.String())
	if len(lines) != 3 {
		t.Fatalf("esperaba 3 líneas de categoría, hay %d", len(lines))
	}
	for _, g := range []string{glyphPass, glyphWarn, glyphFail, glyphNA} {
		col := -1
		for _, ln := range lines {
			c := runeIndex(ln, g)
			if c < 0 {
				t.Fatalf("glifo %q no encontrado en %q", g, ln)
			}
			if col == -1 {
				col = c
			} else if c != col {
				t.Errorf("glifo %q desalineado: columna %d vs %d en %q", g, c, col, ln)
			}
		}
	}
}

// El ancho de contador es el del numero mas grande, y los contadores van alineados a la derecha.
func TestCategoryCountsPadding(t *testing.T) {
	if w := countWidth(consoleSampleReport().Categories); w != 2 {
		t.Fatalf("countWidth = %d, esperaba 2 (máximo es 14)", w)
	}
	s := categoryCounts(score.Counts{Pass: 14, Warn: 2, Fail: 10, NA: 0}, 2, false)
	if !strings.Contains(s, "✓14") || !strings.Contains(s, "▲ 2") || !strings.Contains(s, "✗10") {
		t.Errorf("contadores sin alinear a la derecha: %q", s)
	}
}

// Cada glifo de estado del detalle (-v) ocupa exactamente 6 runas visibles para que la columna
// de descripcion cuadre. Solo es cierto si todos los glifos son de ancho simple.
func TestStatusGlyphWidth(t *testing.T) {
	for _, st := range []string{"PASS", "WARN", "FAIL", "NA"} {
		if n := len([]rune(statusGlyph(st, false))); n != 6 {
			t.Errorf("statusGlyph(%q) tiene %d runas, esperaba 6", st, n)
		}
	}
}

// categoryLines extrae las filas del bloque "Por categoría:" (hasta la primera línea en blanco).
func categoryLines(out string) []string {
	var res []string
	in := false
	for _, ln := range strings.Split(out, "\n") {
		if strings.Contains(ln, "Por categoría:") {
			in = true
			continue
		}
		if in {
			if strings.TrimSpace(ln) == "" {
				break
			}
			res = append(res, ln)
		}
	}
	return res
}

// runeIndex devuelve la posicion (en runas, = columna en pantalla con glifos de ancho simple)
// de la primera aparicion de sub, o -1.
func runeIndex(s, sub string) int {
	b := strings.Index(s, sub)
	if b < 0 {
		return -1
	}
	return len([]rune(s[:b]))
}

// findingsReport cubre todos los carriles del informe: un fallo crítico (alta), fallos medio/bajo
// y un aviso (van a "Otros hallazgos"), un PASS y un NA (no van), y una categoría todo-N/A (n/d).
func findingsReport() Report {
	return Report{
		Index: 50, Band: "amarillo", Profile: "full",
		Host:        Host{Hostname: "srv-1", OS: "debian", Kernel: "6.1.0"},
		GeneratedAt: "2026-06-30T08:00:00Z",
		Counts:      score.Counts{Pass: 2, Warn: 1, Fail: 3, NA: 1},
		Categories: []score.CategoryScore{
			{Category: "SSH", Index: 0, Band: "rojo", Counts: score.Counts{Fail: 1}},
			{Category: "AUDIT", Index: 0, Band: "n/d", Counts: score.Counts{NA: 1}},
		},
		CriticalVulns: []CriticalVuln{
			{CheckID: "SSH-02", Title: "Auth por contraseña", Severity: "high", Category: "SSH", Remediation: "PasswordAuthentication no"},
		},
		Results: []Result{
			{CheckID: "SSH-02", Status: "FAIL", Severity: "high", Category: "SSH", Description: "Auth por contraseña", Remediation: "PasswordAuthentication no"},
			{CheckID: "FS-03", Status: "FAIL", Severity: "medium", Category: "FS", Description: "umask laxo", ValueRead: "077", Remediation: "Pon umask 027"},
			{CheckID: "KRN-09", Status: "FAIL", Severity: "low", Category: "KERNEL", Description: "dmesg abierto", Remediation: "kernel.dmesg_restrict=1"},
			{CheckID: "TIME-01", Status: "WARN", Severity: "medium", Category: "TIME", Description: "NTP sin fijar", Remediation: "Activa NTP"},
			{CheckID: "OK-01", Status: "PASS", Severity: "low", Category: "SSH", Description: "todo bien"},
			{CheckID: "NA-01", Status: "NA", Severity: "low", Category: "AUDIT", Description: "no medible", Reason: "no aplica"},
		},
	}
}

// "Otros hallazgos" lista los fallos medio/bajo y los avisos (no los críticos, ni PASS, ni NA),
// con los fallos antes que los avisos.
func TestOtherFindingsSection(t *testing.T) {
	var buf bytes.Buffer
	WriteConsole(&buf, findingsReport(), false, false)
	out := buf.String()
	if !strings.Contains(out, "Otros hallazgos a corregir:") {
		t.Fatal("falta la sección 'Otros hallazgos a corregir'")
	}
	others := section(out, "Otros hallazgos a corregir:")
	for _, want := range []string{"FS-03", "KRN-09", "TIME-01"} {
		if !strings.Contains(others, want) {
			t.Errorf("'Otros hallazgos' debería incluir %s", want)
		}
	}
	if strings.Contains(others, "SSH-02") {
		t.Error("SSH-02 (severidad alta) va en críticos, no en 'Otros hallazgos'")
	}
	if strings.Contains(others, "OK-01") || strings.Contains(others, "NA-01") {
		t.Error("PASS/NA no son hallazgos a corregir")
	}
	if idxFail, idxWarn := strings.Index(others, "KRN-09"), strings.Index(others, "TIME-01"); idxFail > idxWarn {
		t.Error("los fallos deben listarse antes que los avisos")
	}
	// Igual que los críticos: cada hallazgo explica el qué (descripción) y el valor detectado,
	// no solo la solución (sin eso no se sabe qué se está corrigiendo).
	if !strings.Contains(others, "umask laxo") {
		t.Error("'Otros hallazgos' debe incluir la descripción (el qué pasa)")
	}
	if !strings.Contains(others, "detectado:") || !strings.Contains(others, "077") {
		t.Error("'Otros hallazgos' debe incluir el valor detectado, como los críticos")
	}
}

// El título de "Otros hallazgos" va coloreado (amarillo) para marcar jerarquía frente al rojo
// de los críticos y al neutro de las secciones informativas.
func TestOtherFindingsTitleColored(t *testing.T) {
	var buf bytes.Buffer
	WriteConsole(&buf, findingsReport(), false, true) // color ON
	if !strings.Contains(buf.String(), ansi.Bold+ansi.Yellow+"Otros hallazgos a corregir:") {
		t.Error("el título de 'Otros hallazgos' debería ir en amarillo (Bold+Yellow)")
	}
}

// Una categoría sin checks aplicables (banda n/d) muestra "n/d", no un "0" que parece catástrofe.
func TestCategoryNdShown(t *testing.T) {
	var buf bytes.Buffer
	WriteConsole(&buf, findingsReport(), false, false)
	var audit string
	for _, ln := range categoryLines(buf.String()) {
		if strings.Contains(ln, "AUDIT") {
			audit = ln
		}
	}
	if audit == "" {
		t.Fatal("no encontré la fila de AUDIT")
	}
	if !strings.Contains(audit, "n/d") {
		t.Errorf("la categoría todo-N/A debe mostrar 'n/d', no '0': %q", audit)
	}
}

// El pie con cómo exportar/ver más sale siempre; el de -v solo si no estás ya en verbose; el de
// --profile full solo en perfil core.
func TestFooterHints(t *testing.T) {
	var buf bytes.Buffer
	WriteConsole(&buf, findingsReport(), false, false)
	out := buf.String()
	if !strings.Contains(out, "talos audit -o informe.html") {
		t.Error("falta la pista de exportar a HTML (comando corto)")
	}
	if !strings.Contains(out, "talos audit -v") {
		t.Error("sin -v activo, debería sugerir el detalle")
	}

	var bufV bytes.Buffer
	WriteConsole(&bufV, findingsReport(), true, false)
	if strings.Contains(bufV.String(), "Detalle por comprobación:") {
		t.Error("con -v ya activo no debe sugerir el detalle")
	}

	core := findingsReport()
	core.Profile = "core"
	var bufC bytes.Buffer
	WriteConsole(&bufC, core, false, false)
	if !strings.Contains(bufC.String(), "talos audit --profile full") {
		t.Error("en perfil core debe sugerir --profile full")
	}
}

// La cabecera identifica el artefacto: host, SO y perfil en la primera línea.
func TestReportHeaderShown(t *testing.T) {
	var buf bytes.Buffer
	WriteConsole(&buf, findingsReport(), false, false)
	first := strings.SplitN(buf.String(), "\n", 2)[0]
	for _, want := range []string{"srv-1", "debian", "2026-06-30", "perfil full"} {
		if !strings.Contains(first, want) {
			t.Errorf("la cabecera debería contener %q: %q", want, first)
		}
	}
}

// Sin fallos ni avisos (y con checks que aplicaron), el informe lo confirma en vez de quedar mudo.
func TestAllClearLine(t *testing.T) {
	r := findingsReport()
	r.CriticalVulns = nil
	r.Counts = score.Counts{Pass: 5}
	r.Results = []Result{{CheckID: "OK-1", Status: "PASS", Category: "SSH"}}
	var buf bytes.Buffer
	WriteConsole(&buf, r, false, false)
	if !strings.Contains(buf.String(), "Sin hallazgos que corregir") {
		t.Error("sin fallos ni avisos debería confirmar 'Sin hallazgos que corregir'")
	}
}

func TestHumanDate(t *testing.T) {
	if got := humanDate("2026-06-30T08:00:00Z"); got != "2026-06-30 08:00 UTC" {
		t.Errorf("humanDate = %q, esperaba '2026-06-30 08:00 UTC'", got)
	}
	if got := humanDate(""); got != "" {
		t.Errorf("humanDate(\"\") = %q, esperaba vacío", got)
	}
	if got := humanDate("no-es-fecha"); got != "no-es-fecha" {
		t.Errorf("humanDate sin parsear debe devolver crudo, dio %q", got)
	}
}

// section devuelve las líneas de un bloque (desde su encabezado hasta la primera línea en blanco).
func section(out, header string) string {
	var b strings.Builder
	in := false
	for _, ln := range strings.Split(out, "\n") {
		if strings.Contains(ln, header) {
			in = true
			continue
		}
		if in {
			if strings.TrimSpace(ln) == "" {
				break
			}
			b.WriteString(ln + "\n")
		}
	}
	return b.String()
}
