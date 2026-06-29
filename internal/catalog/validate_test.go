package catalog

import "testing"

func TestValidateRejectsBadCatalog(t *testing.T) {
	c := &Catalog{
		Meta: Meta{SchemaVersion: 1, Version: "x", Categories: []Category{{ID: "SSH", Label: "ssh"}}},
		Checks: []Check{
			{ID: "A", Category: "SSH", OS: "linux", Tier: "core", Comparator: "eq", Points: 1, Severity: "low", Criticality: "BAJA", Expected: Expected{Good: "x"}},
			// id duplicado (A), categoria desconocida (NOPE), points=0
			{ID: "A", Category: "NOPE", OS: "linux", Tier: "core", Comparator: "eq", Points: 0, Severity: "low", Criticality: "BAJA", Expected: Expected{Good: "x"}},
		},
	}
	errs := Validate(c)
	if len(errs) < 3 {
		t.Fatalf("esperaba >=3 errores (id dup, categoria, points), hubo %d: %v", len(errs), errs)
	}
}

func TestLoadEmbeddedIsValid(t *testing.T) {
	cat, err := Load()
	if err != nil {
		t.Fatalf("Load() del catalogo embebido fallo: %v", err)
	}
	if cat.Meta.Version == "" {
		t.Fatal("meta sin version")
	}
	if len(cat.Checks) == 0 {
		t.Fatal("catalogo sin checks")
	}
}
