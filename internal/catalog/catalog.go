// Package catalog define los tipos del catalogo declarativo de Talos (los checks
// son datos) y su carga/validacion. Es PURO: no ejecuta nada en el host ni toca red.
package catalog

import "gopkg.in/yaml.v3"

// Tier separa los checks curados (core) de la auditoria a fondo (deep).
type Tier string

const (
	TierCore Tier = "core"
	TierDeep Tier = "deep"
)

// Read describe COMO obtener el estado bruto de un check. El motor no ejecuta nada:
// recibe el RawRead ya capturado por el probe (paquete probe) y lo evalua.
type Read struct {
	Type string   `yaml:"type"`           // linux: exec|file|stat|sysctl|sshd_t|ss|shadow|passwd|systemd|pkgmgr|pkgver -- windows: registry|cmdlet|netaccounts
	Key  string   `yaml:"key,omitempty"`  // sysctl/sshd_t: clave/directiva. netaccounts: campo (minPwLen|maxPwAge|lockoutThreshold). pkgver: paquete
	Path string   `yaml:"path,omitempty"` // file/stat: ruta. registry: clave HKLM completa
	Cmd  []string `yaml:"cmd,omitempty"`  // exec: argv (SIN shell). cmdlet: expresion PowerShell (un escalar)
	User string   `yaml:"user,omitempty"` // shadow: usuario ("*" = todos)
	Unit string   `yaml:"unit,omitempty"` // systemd: unidad
	Op   string   `yaml:"op,omitempty"`   // pkgmgr: upgradable|installed|security
	Name string   `yaml:"name,omitempty"` // registry: nombre del valor dentro de la clave
}

// Expected son los umbrales por banda. good es obligatorio; medium/weak opcionales.
// Cada campo es string o []string (lista -> se evalua como pertenencia).
type Expected struct {
	Good   any `yaml:"good"`
	Medium any `yaml:"medium,omitempty"`
	Weak   any `yaml:"weak,omitempty"`
}

// Predicate es un predicado atomico de aplicabilidad, resuelto contra los facts del host.
type Predicate struct {
	Service     string `yaml:"service,omitempty"`     // unidad systemd instalada
	Package     string `yaml:"package,omitempty"`     // paquete instalado
	File        string `yaml:"file,omitempty"`        // fichero/directorio existe
	OS          string `yaml:"os,omitempty"`          // id de SO (debian, ubuntu, rhel, alpine, linux)
	Release     string `yaml:"release,omitempty"`     // version del SO (VERSION_ID: "11", "22.04") - para el pack por version
	KernelRange string `yaml:"kernelRange,omitempty"` // rango semver del kernel
}

// Applicability es un arbol booleano de predicados. Omitida -> el check siempre aplica.
type Applicability struct {
	AllOf []Predicate `yaml:"allOf,omitempty"`
	AnyOf []Predicate `yaml:"anyOf,omitempty"`
	Not   *Predicate  `yaml:"not,omitempty"`
}

// Check es una ficha del catalogo: una comprobacion de hardening como dato.
type Check struct {
	ID                string         `yaml:"id"`       // estable, unico; NUNCA se reusa ni renombra
	Category          string         `yaml:"category"` // debe existir en Meta.Categories
	OS                string         `yaml:"os"`       // linux | windows
	Tier              Tier           `yaml:"tier"`
	Description       string         `yaml:"description"`
	Read              Read           `yaml:"read"`
	Comparator        string         `yaml:"comparator"` // eq|ne|lt|gt|le|ge|in|regex|exists|range
	Expected          Expected       `yaml:"expected"`
	Points            int            `yaml:"points"`      // peso (>0)
	Severity          string         `yaml:"severity"`    // info|low|medium|high|critical
	Criticality       string         `yaml:"criticality"` // BAJA|MEDIA|ALTA|CRITICA (SLA del backlog)
	Applicability     *Applicability `yaml:"applicability,omitempty"`
	RequiresPrivilege bool           `yaml:"requiresPrivilege"`
	Remediation       string         `yaml:"remediation"` // ES, consejo; NO se auto-aplica
	ENSControls       []string       `yaml:"ensControls,omitempty"`
	SyntaxConfidence  string         `yaml:"syntaxConfidence,omitempty"` // high|review
}

// Category es una categoria del catalogo (id estable + etiqueta en ES para la UI).
type Category struct {
	ID    string `yaml:"id"`
	Label string `yaml:"label"`
}

// Compat es la politica de compatibilidad del catalogo (motor/Argos minimos).
type Compat struct {
	MinEngine string `yaml:"minEngine"`
	MinArgos  string `yaml:"minArgos"`
}

// Meta son los metadatos del catalogo (checks/_meta.yaml, bajo la clave raiz "catalog").
type Meta struct {
	Version       string     `yaml:"version"` // CalVer AAAA.MM.parche
	SchemaVersion int        `yaml:"schemaVersion"`
	GeneratedAt   string     `yaml:"generatedAt"`
	Compat        Compat     `yaml:"compat"`
	Categories    []Category `yaml:"categories"`
}

// Catalog es el catalogo cargado y validado: metadatos + todas las fichas.
type Catalog struct {
	Meta   Meta
	Checks []Check
}

type metaDoc struct {
	Catalog Meta `yaml:"catalog"`
}

type checksDoc struct {
	Checks []Check `yaml:"checks"`
}

// parseMeta parsea checks/_meta.yaml (clave raiz "catalog"). Puro.
func parseMeta(b []byte) (Meta, error) {
	var d metaDoc
	if err := yaml.Unmarshal(b, &d); err != nil {
		return Meta{}, err
	}
	return d.Catalog, nil
}

// parseChecks parsea un fichero de categoria (clave raiz "checks"). Puro.
func parseChecks(b []byte) ([]Check, error) {
	var d checksDoc
	if err := yaml.Unmarshal(b, &d); err != nil {
		return nil, err
	}
	return d.Checks, nil
}
