package catalog

import (
	"os"
	"testing"
)

func mustParseMetaForTest(t *testing.T) Meta {
	t.Helper()
	b, err := os.ReadFile("checks/_meta.yaml")
	if err != nil {
		t.Fatalf("leer _meta.yaml: %v", err)
	}
	m, err := parseMeta(b)
	if err != nil {
		t.Fatalf("parse meta: %v", err)
	}
	return m
}

func TestMetaParses(t *testing.T) {
	m := mustParseMetaForTest(t)
	if m.Version != "2026.09.1" {
		t.Fatalf("version: %q", m.Version)
	}
	if m.SchemaVersion != 1 {
		t.Fatalf("schemaVersion: %d", m.SchemaVersion)
	}
	if m.Compat.MinEngine != "0.20.0" {
		t.Fatalf("compat.minEngine: %q", m.Compat.MinEngine)
	}
	if len(m.Categories) < 12 {
		t.Fatalf("categorias: %d (esperaba >=12)", len(m.Categories))
	}
}
