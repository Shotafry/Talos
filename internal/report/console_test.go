package report

import (
	"bytes"
	"strings"
	"testing"

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
