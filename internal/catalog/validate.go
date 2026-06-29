package catalog

import (
	"fmt"
	"regexp"
)

const supportedSchemaVersion = 1

var (
	validSeverity    = map[string]bool{"info": true, "low": true, "medium": true, "high": true, "critical": true}
	validCriticality = map[string]bool{"BAJA": true, "MEDIA": true, "ALTA": true, "CRITICA": true}
	validTier        = map[Tier]bool{TierCore: true, TierDeep: true}
	validOS          = map[string]bool{"linux": true, "windows": true}
	validComparator  = map[string]bool{
		"eq": true, "ne": true, "lt": true, "gt": true, "le": true, "ge": true,
		"in": true, "regex": true, "nregex": true, "exists": true, "range": true,
		"vge": true, "vgt": true, "vle": true, "vlt": true, // comparacion de version (Debian/RPM)
	}
)

// Validate acumula TODOS los errores fatales del catalogo (no para en el primero):
// schemaVersion soportado, ids unicos y no vacios, good presente, points>0,
// enums validos (severity/criticality/tier/os/comparator) y categoria conocida.
// Devuelve nil/[] si el catalogo es valido.
func Validate(c *Catalog) []error {
	var errs []error
	if c.Meta.SchemaVersion != supportedSchemaVersion {
		errs = append(errs, fmt.Errorf("schemaVersion %d no soportado (este motor soporta %d)", c.Meta.SchemaVersion, supportedSchemaVersion))
	}
	cats := map[string]bool{}
	for _, cat := range c.Meta.Categories {
		cats[cat.ID] = true
	}
	seen := map[string]bool{}
	for _, ch := range c.Checks {
		where := ch.ID
		if where == "" {
			where = "(check sin id)"
			errs = append(errs, fmt.Errorf("%s: id vacio", where))
		} else if seen[ch.ID] {
			errs = append(errs, fmt.Errorf("%s: id duplicado", ch.ID))
		}
		seen[ch.ID] = true
		if ch.Expected.Good == nil {
			errs = append(errs, fmt.Errorf("%s: falta expected.good", where))
		}
		if ch.Points <= 0 {
			errs = append(errs, fmt.Errorf("%s: points debe ser > 0 (es %d)", where, ch.Points))
		}
		if !validSeverity[ch.Severity] {
			errs = append(errs, fmt.Errorf("%s: severity invalida %q", where, ch.Severity))
		}
		if !validCriticality[ch.Criticality] {
			errs = append(errs, fmt.Errorf("%s: criticality invalida %q", where, ch.Criticality))
		}
		if !validTier[ch.Tier] {
			errs = append(errs, fmt.Errorf("%s: tier invalido %q", where, ch.Tier))
		}
		if !validOS[ch.OS] {
			errs = append(errs, fmt.Errorf("%s: os invalido %q", where, ch.OS))
		}
		if !validComparator[ch.Comparator] {
			errs = append(errs, fmt.Errorf("%s: comparator invalido %q", where, ch.Comparator))
		}
		if !cats[ch.Category] {
			errs = append(errs, fmt.Errorf("%s: categoria desconocida %q", where, ch.Category))
		}
		if ch.Comparator == "regex" || ch.Comparator == "nregex" {
			if s, ok := ch.Expected.Good.(string); ok {
				if _, err := regexp.Compile(s); err != nil {
					errs = append(errs, fmt.Errorf("%s: patron regex invalido %q: %v", where, s, err))
				}
			}
		}
	}
	return errs
}
