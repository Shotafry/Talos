// Package push envia el informe de Talos a Argos (modo nativo). Impuro (red).
// Anti-C2: Talos EMPUJA; Argos nunca abre conexion ni ordena. El token de agente
// (argosagt_...) autentica el push contra POST /api/agents/hardening.
package push

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Send envia el contrato JSON a POST <server>/api/agents/hardening con el token de agente.
func Send(server, token string, payload []byte) error {
	if server == "" || token == "" {
		return fmt.Errorf("push requiere --server y --token (o env TALOS_SERVER/TALOS_TOKEN)")
	}
	url := strings.TrimRight(server, "/") + "/api/agents/hardening"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2000))
		return fmt.Errorf("Argos respondio %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}
