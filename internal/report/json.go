// Package report serializa el resultado de una auditoria al contrato JSON (que se empuja a
// Argos o se escribe en local) y a un informe de consola legible.
package report

import (
	"encoding/json"
	"io"

	"github.com/Shotafry/talos/internal/catalog"
	"github.com/Shotafry/talos/internal/engine"
	"github.com/Shotafry/talos/internal/score"
)

// Host son los datos del host. facts es un objeto abierto (extensible): Argos lo guarda
// crudo para enriquecer la CMDB en el futuro sin re-migrar.
type Host struct {
	Hostname string         `json:"hostname"`
	OS       string         `json:"os"`
	Kernel   string         `json:"kernel"`
	IsRoot   bool           `json:"isRoot"`
	Facts    map[string]any `json:"facts,omitempty"`
}

type Result struct {
	CheckID     string   `json:"checkId"`
	Status      string   `json:"status"`
	ValueRead   string   `json:"valueRead"`
	Band        string   `json:"band,omitempty"`
	Severity    string   `json:"severity"`
	Criticality string   `json:"criticality"`
	Category    string   `json:"category"`
	Points      int      `json:"points"`
	Earned      int      `json:"earned"`
	ENS         []string `json:"ensControls,omitempty"`
	Reason      string   `json:"reason,omitempty"`
	Description string   `json:"description,omitempty"` // del catalogo: que comprueba (para la UI de Argos)
	Remediation string   `json:"remediation,omitempty"` // del catalogo: como arreglarlo (backlog de Argos)
}

type CriticalVuln struct {
	CheckID     string   `json:"checkId"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Category    string   `json:"category"`
	ValueRead   string   `json:"valueRead"`
	Remediation string   `json:"remediation"`
	ENS         []string `json:"ensControls,omitempty"`
}

// Report es el contrato unico de salida (validable con Zod en Argos).
type Report struct {
	TalosVersion   string                `json:"talosVersion"`
	CatalogVersion string                `json:"catalogVersion"`
	SchemaVersion  int                   `json:"schemaVersion"`
	GeneratedAt    string                `json:"generatedAt"`
	Profile        string                `json:"profile"`
	ElapsedMs      int64                 `json:"elapsedMs"`
	Host           Host                  `json:"host"`
	Results        []Result              `json:"results"`
	CriticalVulns  []CriticalVuln        `json:"criticalVulns"`
	Index          int                   `json:"index"`
	Band           string                `json:"band"`
	Categories     []score.CategoryScore `json:"categories"`
	Counts         score.Counts          `json:"counts"`
	Excluded       score.Excluded        `json:"excluded"`
}

// Meta son los metadatos de cabecera que el runner conoce (no salen de los veredictos).
type Meta struct {
	TalosVersion   string
	CatalogVersion string
	SchemaVersion  int
	GeneratedAt    string
	Profile        string
	ElapsedMs      int64
	Host           Host
}

// Build ensambla el contrato desde los veredictos, el catalogo (para remediacion/titulo de
// los criticalVulns) y el score ya calculado.
func Build(m Meta, verdicts []engine.Verdict, checks map[string]catalog.Check, sc score.Score) Report {
	r := Report{
		TalosVersion: m.TalosVersion, CatalogVersion: m.CatalogVersion, SchemaVersion: m.SchemaVersion,
		GeneratedAt: m.GeneratedAt, Profile: m.Profile, ElapsedMs: m.ElapsedMs, Host: m.Host,
		Index: sc.Index, Band: sc.Band, Categories: sc.Categories, Counts: sc.Counts, Excluded: sc.Excluded,
		Results:       []Result{},
		CriticalVulns: []CriticalVuln{},
	}
	for _, v := range verdicts {
		ch := checks[v.CheckID]
		r.Results = append(r.Results, Result{
			CheckID: v.CheckID, Status: v.Status, ValueRead: v.ValueRead, Band: v.Band,
			Severity: v.Severity, Criticality: v.Criticality, Category: v.Category,
			Points: v.Points, Earned: v.Earned, ENS: v.ENS, Reason: v.Reason,
			Description: ch.Description, Remediation: ch.Remediation,
		})
		if v.Status == "FAIL" && (v.Severity == "high" || v.Severity == "critical") {
			ch := checks[v.CheckID]
			r.CriticalVulns = append(r.CriticalVulns, CriticalVuln{
				CheckID: v.CheckID, Title: ch.Description, Severity: v.Severity, Category: v.Category,
				ValueRead: v.ValueRead, Remediation: ch.Remediation, ENS: v.ENS,
			})
		}
	}
	return r
}

// WriteJSON escribe el contrato indentado.
func WriteJSON(w io.Writer, r Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
