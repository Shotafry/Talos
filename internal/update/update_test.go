package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

const metaYAML = `catalog:
  version: "9999.01.0"
  schemaVersion: 1
  categories:
    - { id: TEST, label: "Prueba" }
`

const checkYAML = `checks:
  - id: TST-01
    category: TEST
    os: linux
    tier: core
    description: "x"
    read: { type: sysctl, key: "kernel.x" }
    comparator: eq
    expected: { good: "1" }
    points: 1
    severity: low
    criticality: BAJA
    requiresPrivilege: false
    remediation: "x"
`

func makeTarGz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func sha256hex(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }

// serveCatalog sirve el tar.gz en /c.tar.gz y su checksum en /c.tar.gz.sha256 (con el sha dado,
// que puede ser distinto del real para probar el rechazo).
func serveCatalog(tgz []byte, sha string) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/c.tar.gz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(tgz) })
	mux.HandleFunc("/c.tar.gz.sha256", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(sha + "  c.tar.gz\n"))
	})
	return httptest.NewServer(mux)
}

func TestRun_InstalaYValida(t *testing.T) {
	tgz := makeTarGz(t, map[string]string{
		"checks/_meta.yaml":      metaYAML,
		"checks/linux/test.yaml": checkYAML,
	})
	srv := serveCatalog(tgz, sha256hex(tgz))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "catalog")
	msg, err := Run(srv.Client(), srv.URL+"/c.tar.gz", "", dest)
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if !bytes.Contains([]byte(msg), []byte("9999.01.0")) {
		t.Errorf("mensaje sin version: %q", msg)
	}
	if _, err := os.Stat(filepath.Join(dest, "checks", "_meta.yaml")); err != nil {
		t.Errorf("no se instalo el _meta.yaml: %v", err)
	}
}

func TestRun_RechazaChecksumIncorrecto(t *testing.T) {
	tgz := makeTarGz(t, map[string]string{"checks/_meta.yaml": metaYAML})
	srv := serveCatalog(tgz, "deadbeef"+sha256hex(tgz)[8:]) // sha alterado
	defer srv.Close()
	dest := filepath.Join(t.TempDir(), "catalog")
	if _, err := Run(srv.Client(), srv.URL+"/c.tar.gz", "", dest); err == nil {
		t.Fatal("se esperaba error por checksum incorrecto")
	}
	if _, err := os.Stat(dest); err == nil {
		t.Error("no debe instalar nada si el checksum no casa")
	}
}

func TestRun_RechazaCatalogoInvalido(t *testing.T) {
	// tar.gz con checksum correcto pero sin _meta.yaml -> LoadDir falla -> no se instala.
	tgz := makeTarGz(t, map[string]string{"checks/linux/x.yaml": checkYAML})
	srv := serveCatalog(tgz, sha256hex(tgz))
	defer srv.Close()
	dest := filepath.Join(t.TempDir(), "catalog")
	if _, err := Run(srv.Client(), srv.URL+"/c.tar.gz", "", dest); err == nil {
		t.Fatal("se esperaba error por catalogo invalido")
	}
	if _, err := os.Stat(dest); err == nil {
		t.Error("no debe quedar dest instalado tras un catalogo invalido")
	}
}

func TestRun_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(404)
	}))
	defer srv.Close()
	dest := filepath.Join(t.TempDir(), "catalog")
	if _, err := Run(srv.Client(), srv.URL+"/c.tar.gz", "", dest); err == nil {
		t.Fatal("se esperaba error por HTTP 404")
	}
}

func TestExtractTarGz_NeutralizaTraversal(t *testing.T) {
	tgz := makeTarGz(t, map[string]string{"../pwned.txt": "x", "checks/_meta.yaml": metaYAML})
	dest := t.TempDir()
	sub := filepath.Join(dest, "out")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := extractTarGz(bytes.NewReader(tgz), sub); err != nil {
		t.Fatalf("extract error: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "pwned.txt")); err == nil {
		t.Fatal("traversal: se escribio fuera del destino")
	}
}

func TestExtractTarGz_AbortaFicheroGrande(t *testing.T) {
	big := bytes.Repeat([]byte("A"), maxFileBytes+10)
	tgz := makeTarGz(t, map[string]string{"checks/huge.yaml": string(big)})
	if err := extractTarGz(bytes.NewReader(tgz), t.TempDir()); err == nil {
		t.Fatal("se esperaba error por fichero que excede el tope (no truncado silencioso)")
	}
}
