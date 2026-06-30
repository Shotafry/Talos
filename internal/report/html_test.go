package report

import (
	"strings"
	"testing"

	"github.com/Shotafry/talos/internal/score"
)

func sampleReport() Report {
	return Report{
		TalosVersion: "0.20.1", CatalogVersion: "2026.06.1", SchemaVersion: 1,
		GeneratedAt: "2026-06-25T10:00:00Z", Profile: "core",
		Host:  Host{Hostname: "srv-test", OS: "windows"},
		Index: 64, Band: "amarillo",
		Counts:   score.Counts{Pass: 2, Warn: 1, Fail: 1, NA: 0},
		Excluded: score.Excluded{},
		Categories: []score.CategoryScore{
			{Category: "SMB", Index: 50, Band: "amarillo"},
		},
		Results: []Result{
			{CheckID: "WIN-SMB-01", Status: "PASS", Category: "SMB", Severity: "critical", ValueRead: "absent", Description: "SMBv1 off"},
			{CheckID: "WIN-SMB-02", Status: "FAIL", Category: "SMB", Severity: "high", ValueRead: "0", Description: "Firma SMB", Remediation: "Activa la firma SMB."},
		},
		CriticalVulns: []CriticalVuln{
			{CheckID: "WIN-SMB-02", Title: "Firma SMB", Severity: "high", Category: "SMB", ValueRead: "0", Remediation: "Activa la firma SMB."},
		},
	}
}

func TestWriteHTML(t *testing.T) {
	var b strings.Builder
	if err := WriteHTML(&b, sampleReport()); err != nil {
		t.Fatalf("WriteHTML error: %v", err)
	}
	out := b.String()
	for _, want := range []string{
		"<!doctype html>", "srv-test", "TALOS", "Informe de bastionado",
		"WIN-SMB-02", "Activa la firma SMB.", "Todas las comprobaciones",
		"Severidad", "data-sev=", "--bronze", "Moderado",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("el HTML no contiene %q", want)
		}
	}
	if strings.Contains(out, "guardian de bronce") {
		t.Error("el informe ya no debe llevar el lema 'guardian de bronce'")
	}
}

// buildHTMLView ordena lo accionable primero (FAIL antes que PASS) para el explorador.
func TestBuildHTMLView_OrdenAccionable(t *testing.T) {
	v := buildHTMLView(sampleReport())
	if len(v.Findings) != 2 {
		t.Fatalf("esperaba 2 findings, hay %d", len(v.Findings))
	}
	if v.Findings[0].Status != "FAIL" {
		t.Errorf("primero debe ir el FAIL, no %q", v.Findings[0].Status)
	}
	if v.Summary == "" {
		t.Error("la vista debe traer un resumen ejecutivo")
	}
}
