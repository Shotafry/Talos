package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Shotafry/talos/internal/catalog"
	"github.com/Shotafry/talos/internal/engine"
	"github.com/Shotafry/talos/internal/score"
)

func TestBuildAndJSON(t *testing.T) {
	verdicts := []engine.Verdict{
		{CheckID: "SSH-01", Status: "FAIL", ValueRead: "yes", Severity: "high", Category: "SSH", Points: 8, Earned: 0, ENS: []string{"op.exp.2"}},
		{CheckID: "KRNL-01", Status: "PASS", ValueRead: "2", Band: "good", Severity: "high", Category: "KERNEL", Points: 4, Earned: 4},
	}
	checks := map[string]catalog.Check{
		"SSH-01": {ID: "SSH-01", Description: "Login de root por SSH prohibido", Remediation: "PermitRootLogin no"},
	}
	sc := score.Compute(verdicts)
	r := Build(Meta{
		TalosVersion: "0.20.0", CatalogVersion: "2026.06.0", SchemaVersion: 1,
		GeneratedAt: "2026-06-25T00:00:00Z", Profile: "core",
		Host: Host{Hostname: "h", OS: "debian", Facts: map[string]any{"kernel": "6.6"}},
	}, verdicts, checks, sc)

	if len(r.CriticalVulns) != 1 {
		t.Fatalf("criticalVulns = %d, want 1", len(r.CriticalVulns))
	}
	if r.CriticalVulns[0].Remediation == "" || r.CriticalVulns[0].Title == "" {
		t.Error("criticalVuln sin remediacion/titulo")
	}

	var buf bytes.Buffer
	if err := WriteJSON(&buf, r); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"\"talosVersion\"", "\"facts\"", "\"criticalVulns\"", "SSH-01", "\"index\""} {
		if !strings.Contains(out, want) {
			t.Errorf("falta %q en el JSON", want)
		}
	}
}
