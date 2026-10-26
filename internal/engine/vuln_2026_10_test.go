package engine

import (
	"strings"
	"testing"

	"github.com/Shotafry/talos/internal/catalog"
	"github.com/Shotafry/talos/internal/probe"
)

// Las fichas de octubre de 2026 comparan versiones con expresiones por rama y buscan certificados
// por una linea de su base64. Una expresion que se equivoca por un digito da por corregido lo que
// no lo esta, y eso no lo ve la validacion del catalogo: se prueban aqui con los valores frontera.
func fichaDelCatalogo(t *testing.T, id string) catalog.Check {
	t.Helper()
	cat, err := catalog.Load()
	if err != nil {
		t.Fatalf("cargar el catalogo: %v", err)
	}
	for _, c := range cat.Checks {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("no existe la ficha %s", id)
	return catalog.Check{}
}

func estadoCon(t *testing.T, c catalog.Check, valor string) string {
	t.Helper()
	env := Env{OS: "linux", IsRoot: true, Facts: Facts{OS: "debian", Files: map[string]bool{"/usr/local/include/php/main/php_version.h": true, "/usr/local/include/node/node_version.h": true, "/etc/ssl/certs/ca-certificates.crt": true, "/etc/pki/tls/certs/ca-bundle.crt": true}}}
	return Evaluate(c, probe.RawRead{Value: valor, Exists: true}, env).Status
}

// Lo que traen las cabeceras de una instalacion de PHP y de Node, con la version dentro.
func cabeceraDePHP(v string) string {
	return "#ifndef PHP_VERSION_H\n#define PHP_MAJOR_VERSION 8\n#define PHP_VERSION \"" + v + "\"\n#define PHP_VERSION_ID 80424\n"
}

func cabeceraDeNode(v string) string {
	p := strings.SplitN(strings.TrimPrefix(v, "v"), ".", 3)
	return "#ifndef SRC_NODE_VERSION_H_\n#define NODE_MAJOR_VERSION " + p[0] + "\n#define NODE_MINOR_VERSION " + p[1] + "\n#define NODE_PATCH_VERSION " + p[2] + "\n\n#define NODE_VERSION_IS_LTS 1\n"
}

func TestPHP2ShellPorRama(t *testing.T) {
	c := fichaDelCatalogo(t, "VULNPKG-PHP2SHELL-FUENTES")
	casos := map[string]string{
		"8.2.34": "FAIL", "8.2.35": "PASS", "8.2.40": "PASS", "8.2.100": "PASS",
		"8.3.35": "FAIL", "8.3.36": "PASS",
		"8.4.26": "FAIL", "8.4.27": "PASS", "8.4.30": "PASS",
		"8.5.11": "FAIL", "8.5.12": "PASS", "8.5.12-dev": "PASS", "8.5.2": "FAIL", "8.5.20": "PASS",
		"8.1.33": "FAIL", "7.4.33": "FAIL", "8.6.0": "PASS", "9.0.0": "PASS",
	}
	for v, want := range casos {
		if got := estadoCon(t, c, cabeceraDePHP(v)); got != want {
			t.Errorf("PHP %s: %s, se esperaba %s", v, got, want)
		}
	}
}

func TestNodeOctubre2026PorRama(t *testing.T) {
	c := fichaDelCatalogo(t, "VULNPKG-NODE-2026-10-FUENTES")
	casos := map[string]string{
		"v22.23.3": "FAIL", "v22.23.4": "PASS", "v22.24.0": "PASS", "v22.3.0": "FAIL",
		"v24.22.0": "FAIL", "v24.22.1": "PASS", "v24.22.10": "PASS", "v24.23.0": "PASS", "v24.2.9": "FAIL",
		"v26.12.0": "FAIL", "v26.12.1": "PASS", "v26.13.0": "PASS", "v26.2.5": "FAIL",
		"v25.9.0": "FAIL", "v23.11.1": "FAIL", "v20.19.5": "FAIL", "v27.0.0": "PASS",
	}
	for v, want := range casos {
		if got := estadoCon(t, c, cabeceraDeNode(v)); got != want {
			t.Errorf("Node %s: %s, se esperaba %s", v, got, want)
		}
	}
}

func TestEmudhraEnElAlmacen(t *testing.T) {
	emsign := "-----BEGIN CERTIFICATE-----\nMIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG\nEwJJTjET\n-----END CERTIFICATE-----\n"
	aaa := "-----BEGIN CERTIFICATE-----\nMIIEMjCCAxqgAwIBAgIBATANBgkqhkiG9w0BAQUFADB7MQswCQYDVQQGEwJHQjEb\nMBkGA1UECAwSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHDAdTYWxmb3JkMRow\nGAYDVQQKDBFDb21vZG8gQ0EgTGltaXRlZDEhMB8GA1UEAwwYQUFBIENlcnRpZmlj\n-----END CERTIFICATE-----\n"
	// Otra raiz de Comodo con la misma organizacion: no puede casar (comparte la segunda linea).
	otra := "-----BEGIN CERTIFICATE-----\nMIIF2DCCA8CgAwIBAgIQTKr5yttjb+Af907YWwOGnTANBgkqhkiG9w0BAQwFADCB\nhTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G\n-----END CERTIFICATE-----\n"
	for _, id := range []string{"VULN-EMUDHRA-ALMACEN", "VULN-EMUDHRA-ALMACEN-RHEL"} {
		c := fichaDelCatalogo(t, id)
		if got := estadoCon(t, c, otra); got != "PASS" {
			t.Errorf("%s sin las raices: %s, se esperaba PASS", id, got)
		}
		if got := estadoCon(t, c, otra+emsign); got != "FAIL" {
			t.Errorf("%s con emSign ECC G3: %s, se esperaba FAIL", id, got)
		}
		if got := estadoCon(t, c, otra+aaa); got != "FAIL" {
			t.Errorf("%s con AAA Certificate Services: %s, se esperaba FAIL", id, got)
		}
	}
}
