package catalog

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"sort"
)

//go:embed checks/_meta.yaml checks/linux/*.yaml checks/windows/*.yaml
var embedded embed.FS

// Load carga el catalogo embebido (fuente de verdad, go:embed), lo valida y lo devuelve.
func Load() (*Catalog, error) { return loadFS(embedded) }

// LoadDir carga un catalogo desde un directorio externo (flag --catalog, desarrollo/override).
// Espera la misma estructura: checks/_meta.yaml + checks/<so>/*.yaml.
func LoadDir(dir string) (*Catalog, error) { return loadFS(os.DirFS(dir)) }

func loadFS(fsys fs.FS) (*Catalog, error) {
	mb, err := fs.ReadFile(fsys, "checks/_meta.yaml")
	if err != nil {
		return nil, fmt.Errorf("leer _meta.yaml: %w", err)
	}
	meta, err := parseMeta(mb)
	if err != nil {
		return nil, fmt.Errorf("parse _meta.yaml: %w", err)
	}
	cat := &Catalog{Meta: meta}

	entries, err := fs.Glob(fsys, "checks/*/*.yaml")
	if err != nil {
		return nil, err
	}
	sort.Strings(entries) // orden determinista
	for _, e := range entries {
		b, err := fs.ReadFile(fsys, e)
		if err != nil {
			return nil, fmt.Errorf("leer %s: %w", e, err)
		}
		checks, err := parseChecks(b)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", e, err)
		}
		cat.Checks = append(cat.Checks, checks...)
	}

	if errs := Validate(cat); len(errs) > 0 {
		return nil, fmt.Errorf("catalogo invalido: %d error(es): %v", len(errs), errs)
	}
	return cat, nil
}
