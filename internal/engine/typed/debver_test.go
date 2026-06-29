package typed

import "testing"

func TestDebianVersionCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"2.31-13+deb11u7", "2.31-13+deb11u11", -1}, // sufijo de seguridad: u7 < u11
		{"1.9.5p2", "1.9.5p1", 1},                   // p2 > p1
		{"1.9.5p1", "1.9.5p2", -1},
		{"1.9.5p2", "1.9.5p2", 0},
		{"1.0~rc1", "1.0", -1}, // ~ ordena antes que el lanzamiento final
		{"1:1.0", "2.0", 1},    // el epoch manda
		{"0.105-31", "0.105-31", 0},
		{"1.8.27-1", "1.9.5p2-3", -1}, // sudo vulnerable < parcheado
		{"5.4.0", "5.4.0-89-generic", -1},
	}
	for _, c := range cases {
		if got := DebianVersionCompare(c.a, c.b); got != c.want {
			t.Errorf("DebianVersionCompare(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}
