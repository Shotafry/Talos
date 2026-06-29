// Package update refresca el catalogo embebido tirando del repo PUBLICO `talos` de GitHub
// (release con catalog.tar.gz), NUNCA de una Argos: si Talos es open-source, nadie ataca una
// Argos para envenenar una actualizacion. Es musculo del modo standalone; en nativo el catalogo
// llega por query-pack desde la propia Argos. token opcional (Bearer) para la fase de repo privado.
package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/Shotafry/talos/internal/catalog"
)

// DefaultURL: asset de la ultima release del repo publico. Cuando el repo es publico funciona
// sin token; en la fase privada se pasa un token (Bearer) con permiso de lectura.
const DefaultURL = "https://github.com/Shotafry/Talos/releases/latest/download/catalog.tar.gz"

const (
	maxFileBytes = 5 << 20  // 5 MB por fichero del catalogo (anti zip-bomb); un yaml real son KBs
	maxDownload  = 25 << 20 // 25 MB el tar.gz entero (anti DoS)
	maxEntries   = 500      // nº maximo de entradas del tar (anti agotamiento)
)

// Run descarga el catalogo (tar.gz con checks/...) de url, VERIFICA su SHA256 contra <url>.sha256,
// lo valida estructuralmente y lo instala en destDir de forma atomica (escribe en un hermano y hace
// swap). El catalogo es codigo-como-datos que el binario ejecuta (cmdlet/registry); por eso se
// verifica por hash, igual que el propio binario (CLAUDE 8.8). token Bearer opcional (repo privado).
func Run(client *http.Client, url, token, destDir string) (string, error) {
	if url == "" {
		url = DefaultURL
	}
	body, err := fetch(client, url, token, maxDownload)
	if err != nil {
		return "", err
	}
	// Verificacion de integridad: el .sha256 acompana al asset. Fail-closed: si no se puede
	// obtener o no casa, NO se instala (no degradar a "solo TLS").
	sumText, err := fetch(client, url+".sha256", token, 1024)
	if err != nil {
		return "", fmt.Errorf("no se pudo obtener el checksum (%s.sha256): %w", url, err)
	}
	expected := firstHexToken(string(sumText))
	actual := fmt.Sprintf("%x", sha256.Sum256(body))
	if expected == "" || !strings.EqualFold(expected, actual) {
		return "", fmt.Errorf("checksum del catalogo no coincide (esperado %q, obtenido %s); no se instala", expected, actual)
	}

	// Extraer en un hermano de destDir (misma particion -> rename atomico, sin EXDEV).
	newDir := destDir + ".new"
	_ = os.RemoveAll(newDir)
	if err := os.MkdirAll(newDir, 0o755); err != nil {
		return "", err
	}
	defer os.RemoveAll(newDir)
	if err := extractTarGz(bytes.NewReader(body), newDir); err != nil {
		return "", err
	}

	cat, err := catalog.LoadDir(newDir)
	if err != nil {
		return "", fmt.Errorf("catalogo descargado invalido (no se instala): %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(destDir), 0o755); err != nil {
		return "", err
	}
	back := destDir + ".bak"
	_ = os.RemoveAll(back)
	if _, err := os.Stat(destDir); err == nil {
		if err := os.Rename(destDir, back); err != nil {
			return "", err
		}
	}
	if err := os.Rename(newDir, destDir); err != nil {
		_ = os.Rename(back, destDir) // rollback
		return "", err
	}
	_ = os.RemoveAll(back)
	return fmt.Sprintf("catalogo actualizado a %s (%d checks) en %s", cat.Meta.Version, len(cat.Checks), destDir), nil
}

// fetch hace un GET con token Bearer opcional y devuelve el cuerpo, acotado a maxBytes.
func fetch(client *http.Client, url, token string, maxBytes int64) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Accept", "application/octet-stream")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("descarga fallida: HTTP %d (%s)", resp.StatusCode, url)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil {
		return nil, err
	}
	return b, nil
}

// firstHexToken extrae el primer token hex de un fichero estilo sha256sum ("<hash>  fichero").
func firstHexToken(s string) string {
	for _, f := range strings.Fields(s) {
		ok := len(f) >= 32
		for _, c := range f {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				ok = false
				break
			}
		}
		if ok {
			return f
		}
	}
	return ""
}

// extractTarGz extrae un tar.gz a dest, con guardas anti path-traversal (zip-slip), tope POR
// fichero (aborta si se excede, no trunca) y tope de NUMERO de entradas. Solo procesa directorios
// y ficheros regulares (ignora symlinks y demas).
func extractTarGz(r io.Reader, dest string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	root := filepath.Clean(dest)
	entries := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if entries++; entries > maxEntries {
			return fmt.Errorf("el catalogo tiene demasiadas entradas (> %d)", maxEntries)
		}
		target := filepath.Join(root, filepath.Clean("/"+hdr.Name)) // ancla a / y junta: neutraliza ../
		if target != root && !strings.HasPrefix(target, root+string(os.PathSeparator)) {
			return fmt.Errorf("entrada de tar fuera del destino: %s", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
			if err != nil {
				return err
			}
			// CopyN con maxFileBytes+1: si copia mas que el tope, el fichero excede -> abortar
			// (no truncar silenciosamente, que dejaria un yaml a medias pasando como valido).
			n, err := io.CopyN(f, tr, maxFileBytes+1)
			cerr := f.Close()
			if err != nil && err != io.EOF {
				return err
			}
			if n > maxFileBytes {
				return fmt.Errorf("entrada de tar excede el tope (%d bytes): %s", maxFileBytes, hdr.Name)
			}
			if cerr != nil {
				return cerr
			}
		}
	}
	return nil
}
