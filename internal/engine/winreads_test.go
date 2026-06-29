package engine

import (
	"testing"

	"github.com/Shotafry/talos/internal/catalog"
	"github.com/Shotafry/talos/internal/probe"
)

func TestEvaluateWindowsReads(t *testing.T) {
	env := Env{OS: "windows", IsRoot: true}

	// cmdlet con salida -> evalua (True casa con good "true")
	fw := catalog.Check{ID: "WIN-FW-01", OS: "windows", Comparator: "eq", Points: 8, Severity: "high", Category: "FIREWALL",
		Expected: catalog.Expected{Good: "true"}, Read: catalog.Read{Type: "cmdlet", Cmd: []string{"(Get-NetFirewallProfile).Enabled"}}}
	if v := Evaluate(fw, probe.RawRead{Stdout: "True\r\n"}, env); v.Status != "PASS" {
		t.Fatalf("cmdlet True debe PASS, fue %s", v.Status)
	}
	// cmdlet con salida VACIA y exit 0 -> NA (no penaliza), no FAIL
	if v := Evaluate(fw, probe.RawRead{Stdout: "", Exit: 0}, env); v.Status != "NA" {
		t.Fatalf("cmdlet sin salida debe ser NA, fue %s (val %q)", v.Status, v.ValueRead)
	}

	// registry ausente -> "absent"; con good [absent,1] PASS, con good [1] FAIL
	ppl := catalog.Check{ID: "WIN-CRED-01", OS: "windows", Comparator: "in", Points: 8, Severity: "high", Category: "CREDS",
		Expected: catalog.Expected{Good: []any{"absent", "0"}}, Read: catalog.Read{Type: "registry", Path: `HKLM\X`, Name: "WDigest"}}
	if v := Evaluate(ppl, probe.RawRead{Exists: false}, env); v.Status != "PASS" || v.ValueRead != "absent" {
		t.Fatalf("registry ausente con good[absent] debe PASS/absent, fue %s/%q", v.Status, v.ValueRead)
	}
	ppl.Expected = catalog.Expected{Good: []any{"1"}}
	if v := Evaluate(ppl, probe.RawRead{Exists: false}, env); v.Status != "FAIL" {
		t.Fatalf("registry ausente con good[1] debe FAIL, fue %s", v.Status)
	}
	// registry presente DWORD normalizado
	ppl.Expected = catalog.Expected{Good: []any{"1", "2"}}
	rr := probe.RawRead{Exists: true, Stdout: "\nHKEY_LOCAL_MACHINE\\X\n    WDigest    REG_DWORD    0x2\n"}
	if v := Evaluate(ppl, rr, env); v.Status != "PASS" || v.ValueRead != "2" {
		t.Fatalf("registry 0x2 con good[1,2] debe PASS/2, fue %s/%q", v.Status, v.ValueRead)
	}

	// gating por release: ficha para release 12 evaluada en host release 11 -> NA
	rel := catalog.Check{ID: "VULNPKG-X", OS: "linux", Comparator: "vge", Points: 5, Severity: "critical", Category: "VULN",
		Expected: catalog.Expected{Good: "2.0"}, Read: catalog.Read{Type: "pkgver", Key: "p"},
		Applicability: &catalog.Applicability{AllOf: []catalog.Predicate{{OS: "debian"}, {Release: "12"}}}}
	envDeb11 := Env{OS: "debian", IsRoot: true, Facts: Facts{OS: "debian", DistroRelease: "11"}}
	if v := Evaluate(rel, probe.RawRead{Value: "1.0", Exists: true}, envDeb11); v.Status != "NA" {
		t.Fatalf("ficha release 12 en host release 11 debe NA, fue %s", v.Status)
	}
}
