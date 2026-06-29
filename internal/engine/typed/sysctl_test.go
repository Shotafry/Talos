package typed

import "testing"

func TestNormalizeSysctl(t *testing.T) {
	if got := NormalizeSysctl("2\n"); got != "2" {
		t.Errorf("trim: %q", got)
	}
	if got := NormalizeSysctl(" 1\t1 "); got != "1" {
		t.Errorf("multi-iface (primer token): %q", got)
	}
	if got := NormalizeSysctl(""); got != "" {
		t.Errorf("vacio: %q", got)
	}
}
