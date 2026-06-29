package typed

import (
	"os"
	"path/filepath"
	"testing"
)

func readFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("no se pudo leer el fixture %s: %v", name, err)
	}
	return string(b)
}

// Validado contra la salida REAL de `net accounts` en Windows 11 es-ES (codepage OEM):
// la posicion de cada campo es estable aunque la etiqueta este localizada.
func TestNetAccountsField_RealEsES(t *testing.T) {
	out := readFixture(t, "net-accounts-es.txt")
	cases := map[string]string{
		"minPwLen":         "0",
		"maxPwAge":         "42",
		"lockoutThreshold": "10",
		"minPwAge":         "0",
	}
	for field, want := range cases {
		if got := NetAccountsField(out, field); got != want {
			t.Errorf("NetAccountsField(%q) = %q, quiero %q", field, got, want)
		}
	}
}

func TestNetAccountsField_NoNumerico(t *testing.T) {
	// "Nunca" en la fila de caducidad maxima = la contrasena no caduca = peor que cualquier umbral.
	out := "Tiempo:                  Nunca\n" +
		"Edad min:                0\n" +
		"Edad max:                Nunca\n" +
		"Longitud min:            14\n" +
		"Historial:               Ninguna\n" +
		"Umbral bloqueo:          Nunca\n"
	if got := NetAccountsField(out, "maxPwAge"); got != "99999" {
		t.Errorf("maxPwAge no caduca = %q, quiero 99999", got)
	}
	if got := NetAccountsField(out, "lockoutThreshold"); got != "0" {
		t.Errorf("lockoutThreshold Nunca = %q, quiero 0", got)
	}
	if got := NetAccountsField(out, "minPwLen"); got != "14" {
		t.Errorf("minPwLen = %q, quiero 14", got)
	}
}

func TestNetAccountsField_Ausente(t *testing.T) {
	if got := NetAccountsField("", "minPwLen"); got != "" {
		t.Errorf("entrada vacia = %q, quiero cadena vacia", got)
	}
}

// Validado contra la salida REAL de `reg query` en Windows 11.
func TestRegistryValue_DwordReal(t *testing.T) {
	out := readFixture(t, "reg-runasppl.txt")
	if got := RegistryValue(out, "RunAsPPL"); got != "2" {
		t.Errorf("RunAsPPL = %q, quiero 2 (0x2 normalizado a decimal)", got)
	}
}

func TestRegistryValue_Sz(t *testing.T) {
	out := "\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\n" +
		"    EnableSmartScreen    REG_SZ    RequireAdmin\n"
	if got := RegistryValue(out, "EnableSmartScreen"); got != "RequireAdmin" {
		t.Errorf("EnableSmartScreen = %q, quiero RequireAdmin", got)
	}
}

func TestRegistryValue_NoEncontrado(t *testing.T) {
	out := "\nHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\n    RunAsPPL    REG_DWORD    0x2\n"
	if got := RegistryValue(out, "OtroValor"); got != "" {
		t.Errorf("valor inexistente = %q, quiero cadena vacia", got)
	}
}

func TestRegistryValue_DwordCero(t *testing.T) {
	out := "    RequireSecuritySignature    REG_DWORD    0x0\n"
	if got := RegistryValue(out, "RequireSecuritySignature"); got != "0" {
		t.Errorf("0x0 = %q, quiero 0", got)
	}
}
