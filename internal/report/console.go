package report

import (
	"fmt"
	"io"
	"strings"
)

// WriteConsole escribe un informe de texto legible (modo standalone/TTY).
func WriteConsole(w io.Writer, r Report, verbose bool) {
	fmt.Fprintf(w, "Indice de bastionado: %d/100 (%s)\n", r.Index, r.Band)
	fmt.Fprintf(w, "PASS %d  WARN %d  FAIL %d  NA %d\n",
		r.Counts.Pass, r.Counts.Warn, r.Counts.Fail, r.Counts.NA)
	if r.Excluded.NoPrivilege > 0 {
		fmt.Fprintf(w, "(%d checks omitidos por falta de privilegios; ejecuta con sudo para cobertura completa)\n", r.Excluded.NoPrivilege)
	}
	fmt.Fprintln(w)

	if len(r.CriticalVulns) > 0 {
		fmt.Fprintln(w, "Fallos criticos (arreglar ya):")
		for _, c := range r.CriticalVulns {
			fmt.Fprintf(w, "  [%s] %s - %s\n", strings.ToUpper(c.Severity), c.CheckID, c.Title)
			if c.Remediation != "" {
				fmt.Fprintf(w, "      remediacion: %s\n", c.Remediation)
			}
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, "Por categoria:")
	for _, c := range r.Categories {
		fmt.Fprintf(w, "  %-10s %3d/100 (%-8s) P%d W%d F%d NA%d\n",
			c.Category, c.Index, c.Band, c.Counts.Pass, c.Counts.Warn, c.Counts.Fail, c.Counts.NA)
	}

	if verbose {
		fmt.Fprintln(w, "\nDetalle:")
		for _, res := range r.Results {
			line := fmt.Sprintf("  %-14s %-4s %s", res.CheckID, res.Status, res.ValueRead)
			if res.Reason != "" {
				line += " (" + res.Reason + ")"
			}
			fmt.Fprintln(w, line)
		}
	}
}
