package typed

import (
	"os"
	"testing"
)

func TestCountUpgradableEmpty(t *testing.T) {
	b, _ := os.ReadFile("testdata/apt-upgradable-empty.txt")
	if n := CountUpgradable(string(b)); n != 0 {
		t.Fatalf("vacio deberia ser 0, fue %d", n)
	}
}

func TestCountUpgradableSample(t *testing.T) {
	b, _ := os.ReadFile("testdata/apt-upgradable-sample.txt")
	if n := CountUpgradable(string(b)); n != 4 {
		t.Fatalf("sample tiene 4 actualizables, fue %d", n)
	}
	if n := CountSecurityUpgradable(string(b)); n != 2 {
		t.Fatalf("sample tiene 2 de seguridad, fue %d", n)
	}
}
