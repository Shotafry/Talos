package typed

import "testing"

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"5.15.0-89-generic", "5.15.0", 0}, // sufijo de build de distro ignorado
		{"5.10", "5.15", -1},
		{"6.1", "5.15", 1},
		{"1.1.1w", "1.1.1", 0}, // sufijo de letra ignorado
		{"6.6.114", "6.6.0", 1},
	}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestKernelInRange(t *testing.T) {
	if in, err := KernelInRange("5.15.0-89-generic", ">=5.10 <6.1"); err != nil || !in {
		t.Errorf("5.15 en [5.10,6.1): in=%v err=%v", in, err)
	}
	if in, _ := KernelInRange("6.6.114", ">=5.10 <6.1"); in {
		t.Error("6.6 no deberia estar en <6.1")
	}
	if in, _ := KernelInRange("5.10", "[5.4,5.15]"); !in {
		t.Error("5.10 en [5.4,5.15]")
	}
	if _, err := KernelInRange("5.10", "??"); err == nil {
		t.Error("rango invalido deberia dar error")
	}
}
