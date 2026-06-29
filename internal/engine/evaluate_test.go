package engine

import (
	"testing"

	"github.com/Shotafry/talos/internal/catalog"
	"github.com/Shotafry/talos/internal/probe"
)

func TestComparators(t *testing.T) {
	cases := []struct {
		name string
		cmp  string
		good any
		val  string
		want string
	}{
		{"eq match", "eq", "no", "no", "good"},
		{"eq no match", "eq", "no", "yes", ""},
		{"eq bool synonym", "eq", "no", "0", "good"},
		{"ne match", "ne", "22", "2222", "good"},
		{"le equal", "le", "3", "3", "good"},
		{"le over", "le", "3", "5", ""},
		{"ge under", "ge", "2", "1", ""},
		{"in list", "in", []any{"1", "2"}, "1", "good"},
		{"regex match", "regex", "^Status: active", "Status: active", "good"},
		{"nregex sin debil", "nregex", "(cbc|3des)", "aes256-ctr,chacha20-poly1305", "good"},
		{"nregex con debil", "nregex", "(cbc|3des)", "aes128-cbc,aes256-ctr", ""},
		{"exists false absent", "exists", "false", "false", "good"},
		{"exists false present", "exists", "false", "true", ""},
	}
	for _, c := range cases {
		got := matchBand(c.cmp, catalog.Expected{Good: c.good}, c.val)
		if got != c.want {
			t.Errorf("%s: matchBand(%s, good=%v, %q) = %q, want %q", c.name, c.cmp, c.good, c.val, got, c.want)
		}
	}
}

func TestNumericNonNumberIsNoMatch(t *testing.T) {
	if matchBand("le", catalog.Expected{Good: "3"}, "abc") != "" {
		t.Fatal("valor no numerico debe no casar (-> FAIL), no panic")
	}
}

func TestBandResolution(t *testing.T) {
	exp := catalog.Expected{Good: "no", Medium: []any{"prohibit-password", "forced-commands-only"}}
	if got := matchBand("eq", exp, "no"); got != "good" {
		t.Errorf("good esperado, fue %q", got)
	}
	if got := matchBand("eq", exp, "prohibit-password"); got != "medium" {
		t.Errorf("medium esperado, fue %q", got)
	}
	if got := matchBand("eq", exp, "yes"); got != "" {
		t.Errorf("ninguna banda esperada (-> FAIL), fue %q", got)
	}
}

func TestEvaluateOrder(t *testing.T) {
	ssh := catalog.Check{
		ID: "SSH-01", OS: "linux", Comparator: "eq", Points: 8, Severity: "high", Category: "SSH",
		Expected:      catalog.Expected{Good: "no"},
		Applicability: &catalog.Applicability{AnyOf: []catalog.Predicate{{Service: "sshd"}}},
	}

	// applicability no se cumple (sin sshd) -> NA
	v := Evaluate(ssh, probe.RawRead{Value: "no"}, Env{OS: "linux", IsRoot: true, Facts: Facts{}})
	if v.Status != "NA" {
		t.Fatalf("sin sshd debe ser NA, fue %s", v.Status)
	}

	// con sshd presente y valor good -> PASS, earned = points
	env := Env{OS: "linux", IsRoot: true, Facts: Facts{Services: map[string]bool{"sshd": true}}}
	v = Evaluate(ssh, probe.RawRead{Value: "no"}, env)
	if v.Status != "PASS" || v.Earned != 8 {
		t.Fatalf("PASS/8 esperado, fue %s/%d", v.Status, v.Earned)
	}

	// requiresPrivilege sin root -> NA con motivo
	ssh.RequiresPrivilege = true
	v = Evaluate(ssh, probe.RawRead{Value: "no"}, Env{OS: "linux", IsRoot: false, Facts: env.Facts})
	if v.Status != "NA" || v.Reason == "" {
		t.Fatalf("sin root debe ser NA con motivo, fue %s", v.Status)
	}

	// WARN con banda medium -> earned = ceil(points/2)
	ssh.RequiresPrivilege = false
	ssh.Expected = catalog.Expected{Good: "no", Medium: []any{"prohibit-password"}}
	v = Evaluate(ssh, probe.RawRead{Value: "prohibit-password"}, env)
	if v.Status != "WARN" || v.Earned != 4 {
		t.Fatalf("WARN/4 esperado, fue %s/%d", v.Status, v.Earned)
	}
}

func TestEvaluateTypedReads(t *testing.T) {
	env := Env{OS: "linux", IsRoot: true}

	// PORTS: telnet (23) a la escucha -> FAIL (exists good:false)
	telnet := catalog.Check{ID: "PORTS-23", OS: "linux", Comparator: "exists", Points: 5, Severity: "critical", Category: "PORTS",
		Expected: catalog.Expected{Good: false}, Read: catalog.Read{Type: "ss", Key: "23"}}
	v := Evaluate(telnet, probe.RawRead{Stdout: "tcp LISTEN 0 128 0.0.0.0:23 0.0.0.0:*"}, env)
	if v.Status != "FAIL" {
		t.Fatalf("telnet a la escucha debe FAIL, fue %s (val %q)", v.Status, v.ValueRead)
	}
	v = Evaluate(telnet, probe.RawRead{Stdout: "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*"}, env)
	if v.Status != "PASS" {
		t.Fatalf("sin telnet debe PASS, fue %s (val %q)", v.Status, v.ValueRead)
	}

	// USERS: root con cuenta bloqueada -> PASS (in [LOCKED,NOLOGIN])
	rootLocked := catalog.Check{ID: "USERS-01", OS: "linux", Comparator: "in", Points: 4, Severity: "high", Category: "USERS",
		Expected: catalog.Expected{Good: []any{"LOCKED", "NOLOGIN"}}, Read: catalog.Read{Type: "shadow", User: "root"}}
	v = Evaluate(rootLocked, probe.RawRead{Content: "root:*:20627:0:99999:7:::"}, env)
	if v.Status != "PASS" || v.ValueRead != "NOLOGIN" {
		t.Fatalf("root '*' debe PASS/NOLOGIN, fue %s/%q", v.Status, v.ValueRead)
	}

	// USERS: un solo UID 0 -> PASS (eq "1")
	uid0 := catalog.Check{ID: "USERS-05", OS: "linux", Comparator: "eq", Points: 4, Severity: "critical", Category: "USERS",
		Expected: catalog.Expected{Good: "1"}, Read: catalog.Read{Type: "passwd"}}
	v = Evaluate(uid0, probe.RawRead{Content: "root:x:0:0::/root:/bin/bash\nbin:x:2:2::/bin:/usr/sbin/nologin"}, env)
	if v.Status != "PASS" || v.ValueRead != "1" {
		t.Fatalf("un UID 0 debe PASS/1, fue %s/%q", v.Status, v.ValueRead)
	}
}

func TestEvaluateCommandFailEmptyIsNA(t *testing.T) {
	// Un comando que falla (exit != 0) sin salida usable -> NA, no FAIL.
	ch := catalog.Check{
		ID: "X-01", OS: "linux", Comparator: "eq", Points: 5, Severity: "high", Category: "SSH",
		Expected: catalog.Expected{Good: "no"},
		Read:     catalog.Read{Type: "sshd_t", Key: "permitrootlogin"},
	}
	v := Evaluate(ch, probe.RawRead{Exit: 255, Stdout: ""}, Env{OS: "linux", IsRoot: true})
	if v.Status != "NA" {
		t.Fatalf("comando fallido sin salida debe ser NA, fue %s", v.Status)
	}
}
