package probe

import (
	"testing"

	"github.com/Shotafry/talos/internal/catalog"
)

func TestExecRejectsUnlistedBinary(t *testing.T) {
	r := Capture(catalog.Read{Type: "exec", Cmd: []string{"rm", "-rf", "/"}}, AllowedBinaries, 1000)
	if r.Err == nil {
		t.Fatal("esperaba rechazo de binario no permitido (no en la lista blanca)")
	}
}

func TestFileReadsContent(t *testing.T) {
	r := Capture(catalog.Read{Type: "file", Path: "testdata/sample.txt"}, AllowedBinaries, 1000)
	if !r.Exists || r.Content == "" {
		t.Fatalf("no leyo el fichero: %+v", r)
	}
}

func TestFileMissingIsNotExist(t *testing.T) {
	r := Capture(catalog.Read{Type: "file", Path: "testdata/nope.txt"}, AllowedBinaries, 1000)
	if r.Exists {
		t.Fatal("fichero inexistente deberia dar Exists=false")
	}
	if r.Err != nil {
		t.Fatalf("fichero inexistente no es un error de probe: %v", r.Err)
	}
}
