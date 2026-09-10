// Package cli orquesta la herramienta Talos: carga el catalogo, recolecta los facts del
// host, evalua los checks, puntua y emite el informe (texto/JSON). No modifica el sistema.
package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/Shotafry/talos/internal/ansi"
	"github.com/Shotafry/talos/internal/catalog"
	"github.com/Shotafry/talos/internal/engine"
	"github.com/Shotafry/talos/internal/facts"
	"github.com/Shotafry/talos/internal/probe"
	"github.com/Shotafry/talos/internal/push"
	"github.com/Shotafry/talos/internal/report"
	"github.com/Shotafry/talos/internal/score"
	"github.com/Shotafry/talos/internal/update"
)

// version se inyecta al compilar via -ldflags "-X .../internal/cli.version=<tag>". El valor de
// aqui es el que sale cuando nadie la inyecta, y es la version PUBLICADA de Talos.
//
// No es la version de Argos, y hasta la 1.5.1 lo era: `scripts/build.sh` la sacaba de
// `git describe --tags`, que dentro del monorepo devuelve el tag de ARGOS. Los binarios que
// Argos sirve a sus agentes se identificaban como "talos 0.42.2" en la cabecera de cada informe
// y en el campo talosVersion que se ingiere. `talos-publish/publish.sh` no publica si esta
// constante no coincide con la version que se esta publicando.
var version = "1.5.2"

// Run es el entry de la CLI. Devuelve el exit code: 0 ok, 1 hay FAIL high/critical,
// 2 error de uso, 3 error de catalogo.
func Run(args []string) int {
	cmd := "audit"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "audit", "push":
		return runAudit(cmd, args)
	case "version":
		printVersion()
		return 0
	case "catalog":
		return runCatalog(args)
	case "update":
		return runUpdate(args)
	case "help":
		printHelp()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "comando desconocido: %s (usa 'talos help')\n", cmd)
		return 2
	}
}

func runAudit(cmd string, args []string) int {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	profile := fs.String("profile", "core", "core|deep|full|critical")
	format := fs.String("format", "", "json|html|text (default text)")
	only := fs.String("only", "", "categorias separadas por coma")
	output := fs.String("output", "", "fichero de salida (default stdout)")
	quiet := fs.Bool("quiet", false, "sin banner")
	verbose := fs.Bool("verbose", false, "muestra cada check")
	catDir := fs.String("catalog", "", "directorio de catalogo externo")
	timeout := fs.Int("timeout", 5000, "timeout por probe (ms)")
	colorMode := fs.String("color", "auto", "color de salida: auto|always|never")
	server := fs.String("server", os.Getenv("TALOS_SERVER"), "(push) URL base de Argos")
	token := fs.String("token", os.Getenv("TALOS_TOKEN"), "(push) token de agente")
	verFlag := fs.Bool("version", false, "imprime version y sale")
	fs.BoolVar(quiet, "q", false, "alias de --quiet")
	fs.BoolVar(verbose, "v", false, "alias de --verbose")
	fs.StringVar(output, "o", "", "alias de --output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *verFlag {
		printVersion()
		return 0
	}

	cat, err := loadCatalog(*catDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error de catalogo: %v\n", err)
		return 3
	}

	hostFacts := facts.Collect()
	isRoot := facts.IsPrivileged()
	resolveFilePredicates(cat.Checks, hostFacts.Files)
	env := engine.Env{OS: hostFacts.OS, IsRoot: isRoot, Facts: hostFacts}

	checks := selectChecks(cat.Checks, hostFacts.OS, *profile, parseCSVSet(*only))

	outFormat := effectiveFormat(*format, *output)
	useColor := wantColor(*colorMode, *output)
	if !*quiet && outFormat == "text" && *output == "" {
		printBanner(cat.Meta.Version, osFamily(hostFacts.OS), useColor)
	}

	start := time.Now()
	cache := probe.NewCache()
	verdicts := make([]engine.Verdict, 0, len(checks))
	checksByID := make(map[string]catalog.Check, len(checks))
	for _, ch := range checks {
		checksByID[ch.ID] = ch
		raw := cache.Capture(ch.Read, probe.AllowedBinaries, *timeout)
		verdicts = append(verdicts, engine.Evaluate(ch, raw, env))
	}
	elapsed := time.Since(start).Milliseconds()

	sc := score.Compute(verdicts)
	rep := report.Build(report.Meta{
		TalosVersion: version, CatalogVersion: cat.Meta.Version, SchemaVersion: cat.Meta.SchemaVersion,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339), Profile: *profile, ElapsedMs: elapsed,
		Host: report.Host{
			Hostname: hostname(), OS: hostFacts.OS, Kernel: hostFacts.KernelRelease, IsRoot: isRoot,
			Facts: map[string]any{
				"servicesCount": len(hostFacts.Services),
				"packagesCount": len(hostFacts.Packages),
			},
		},
	}, verdicts, checksByID, sc)

	// Modo push (nativo): empuja el contrato JSON a Argos en vez de escribir informe local.
	if cmd == "push" {
		payload, err := json.Marshal(rep)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error serializando el informe: %v\n", err)
			return 10
		}
		if err := push.Send(*server, *token, payload); err != nil {
			fmt.Fprintf(os.Stderr, "error al empujar a Argos: %v\n", err)
			return 4
		}
		if !*quiet {
			fmt.Printf("Auditoria de bastionado enviada a Argos. Indice %d/100 (%s).\n", rep.Index, rep.Band)
		}
		return exitCode(verdicts)
	}

	// Modo audit (standalone): escribe el informe local.
	w := os.Stdout
	if *output != "" {
		f, ferr := os.Create(*output)
		if ferr != nil {
			fmt.Fprintf(os.Stderr, "no se pudo crear %s: %v\n", *output, ferr)
			return 2
		}
		defer f.Close()
		w = f
	}
	switch outFormat {
	case "json":
		_ = report.WriteJSON(w, rep)
	case "html":
		_ = report.WriteHTML(w, rep)
	default:
		report.WriteConsole(w, rep, *verbose, useColor)
	}
	return exitCode(verdicts)
}

// exitCode: 1 si hay algun FAIL de severidad high/critical (gate util para scripts/CI).
func exitCode(verdicts []engine.Verdict) int {
	for _, v := range verdicts {
		if v.Status == "FAIL" && (v.Severity == "high" || v.Severity == "critical") {
			return 1
		}
	}
	return 0
}

func runCatalog(args []string) int {
	sub := "list"
	if len(args) > 0 {
		sub = args[0]
	}
	cat, err := catalog.Load()
	switch sub {
	case "lint":
		if err != nil {
			fmt.Fprintf(os.Stderr, "catalogo invalido: %v\n", err)
			return 3
		}
		fmt.Printf("catalogo OK: %d checks, version %s\n", len(cat.Checks), cat.Meta.Version)
		return 0
	case "list":
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 3
		}
		sort.Slice(cat.Checks, func(i, j int) bool { return cat.Checks[i].ID < cat.Checks[j].ID })
		for _, ch := range cat.Checks {
			fmt.Printf("%-14s %-9s %-5s %-9s %s\n", ch.ID, ch.Category, ch.Tier, ch.Severity, ch.Description)
		}
		return 0
	default:
		fmt.Fprintf(os.Stderr, "subcomando de catalog desconocido: %s (list|lint)\n", sub)
		return 2
	}
}

func loadCatalog(dir string) (*catalog.Catalog, error) {
	if dir != "" {
		return catalog.LoadDir(dir)
	}
	// Preferir el catalogo externo actualizado por `talos update` si existe y carga valido;
	// ante cualquier problema, caer al catalogo embebido (nunca romper la auditoria).
	ext := externalCatalogDir()
	if _, err := os.Stat(filepath.Join(ext, "checks", "_meta.yaml")); err == nil {
		if cat, err := catalog.LoadDir(ext); err == nil {
			return cat, nil
		}
	}
	return catalog.Load()
}

// dataDir es el directorio de datos de Talos (catalogo actualizado, etc.), por SO. Se puede
// forzar con TALOS_DATA_DIR (util en standalone sin privilegios).
func dataDir() string {
	if d := os.Getenv("TALOS_DATA_DIR"); d != "" {
		return d
	}
	if runtime.GOOS == "windows" {
		if pd := os.Getenv("ProgramData"); pd != "" {
			return filepath.Join(pd, "Talos")
		}
		return filepath.Join(os.TempDir(), "Talos")
	}
	return "/var/lib/talos"
}

func externalCatalogDir() string { return filepath.Join(dataDir(), "catalog") }

func runUpdate(args []string) int {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	url := fs.String("url", os.Getenv("TALOS_UPDATE_URL"), "URL del catalog.tar.gz (default: release publica del repo talos)")
	token := fs.String("token", os.Getenv("TALOS_UPDATE_TOKEN"), "token Bearer (solo si el repo aun es privado)")
	dir := fs.String("dir", externalCatalogDir(), "directorio destino del catalogo")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	client := &http.Client{Timeout: 60 * time.Second}
	msg, err := update.Run(client, *url, *token, *dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error al actualizar el catalogo: %v\n", err)
		return 4
	}
	fmt.Println(msg)
	return 0
}

func selectChecks(all []catalog.Check, hostOS, profile string, only map[string]bool) []catalog.Check {
	family := osFamily(hostOS)
	out := make([]catalog.Check, 0, len(all))
	for _, ch := range all {
		if ch.OS != family { // solo los checks del SO del host (linux en Linux, windows en Windows)
			continue
		}
		if len(only) > 0 && !only[ch.Category] {
			continue
		}
		if !profileIncludes(profile, ch) {
			continue
		}
		out = append(out, ch)
	}
	return out
}

// osFamily mapea el id de SO del host (debian, ubuntu, rhel, windows...) a la familia que usa
// el campo os de las fichas del catalogo (linux | windows).
func osFamily(hostOS string) string {
	if hostOS == "windows" {
		return "windows"
	}
	return "linux"
}

func profileIncludes(profile string, ch catalog.Check) bool {
	switch profile {
	case "deep", "full":
		return true
	case "critical":
		return ch.Severity == "high" || ch.Severity == "critical"
	default: // core
		return ch.Tier == catalog.TierCore
	}
}

func resolveFilePredicates(checks []catalog.Check, files map[string]bool) {
	for _, ch := range checks {
		if ch.Applicability == nil {
			continue
		}
		for _, p := range allPreds(ch.Applicability) {
			if p.File != "" {
				if _, seen := files[p.File]; !seen {
					_, err := os.Stat(p.File)
					files[p.File] = err == nil
				}
			}
		}
	}
}

func allPreds(a *catalog.Applicability) []catalog.Predicate {
	ps := append([]catalog.Predicate{}, a.AllOf...)
	ps = append(ps, a.AnyOf...)
	if a.Not != nil {
		ps = append(ps, *a.Not)
	}
	return ps
}

func parseCSVSet(s string) map[string]bool {
	m := map[string]bool{}
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			m[p] = true
		}
	}
	return m
}

func resolvedFormat(f string) string {
	switch f {
	case "json":
		return "json"
	case "html":
		return "html"
	default:
		return "text"
	}
}

// effectiveFormat resuelve el formato de salida: si se pasa --format explicito manda; si no, se
// infiere de la extension del fichero de salida (-o informe.html -> html, .json -> json) para
// que guardar un .html no acabe siendo texto plano con extension equivocada. Sin -o, texto.
func effectiveFormat(format, output string) string {
	switch format {
	case "json", "html", "text":
		return format
	}
	switch lower := strings.ToLower(output); {
	case strings.HasSuffix(lower, ".html"), strings.HasSuffix(lower, ".htm"):
		return "html"
	case strings.HasSuffix(lower, ".json"):
		return "json"
	default:
		return "text"
	}
}

func printBanner(catVersion, osFam string, color bool) {
	fmt.Print(ansi.P(color, ansi.Bronze, asciiBadge))
	fmt.Printf("  %s   %s\n",
		ansi.P(color, ansi.Cyan+ansi.Bold, "BY ARGOS"),
		ansi.P(color, ansi.Bold, "Hardening y vigilancia de sistemas"))
	fmt.Printf("  %s\n\n", ansi.P(color, ansi.Dim,
		fmt.Sprintf("auditoría de bastionado · solo lectura · v%s · catálogo %s · %s", version, catVersion, osFam)))
}

// wantColor decide si emitir color: never/always lo fuerzan; auto = a stdout, TTY y sin NO_COLOR.
func wantColor(mode, output string) bool {
	switch mode {
	case "always":
		return true
	case "never":
		return false
	default:
		if output != "" || os.Getenv("NO_COLOR") != "" {
			return false
		}
		return isCharDevice(os.Stdout)
	}
}

func isCharDevice(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func printVersion() { fmt.Printf("talos %s\n", version) }

func printHelp() {
	fmt.Print(`TALOS by Argos - auditoría de bastionado (solo lectura)

Uso:
  talos audit [flags]     audita el host y muestra el informe (por defecto)
  talos catalog list      lista las comprobaciones del catálogo
  talos catalog lint      valida el catálogo
  talos update            actualiza el catálogo desde el repo público (standalone)
  talos version           versión del binario

Perfiles (--profile, por defecto 'core'):
  core       rápido: las comprobaciones esenciales
  full       completo: TODO el catálogo, incluido el pack de vulnerabilidades por versión
  deep       como 'full'
  critical   solo las comprobaciones de severidad alta/crítica

Flags de audit:
  --only <cat,cat>      limita a categorías (p.ej. SSH,KERNEL)
  --output, -o <file>   escribe el informe a un fichero; la EXTENSIÓN elige el formato
                        (.html = informe imprimible/interactivo, .json = datos)
  --format json|html|text  fuerza el formato (por defecto: el de la extensión de -o, o texto)
  --color auto|always|never  (por defecto auto: color solo si la salida es un terminal)
  --quiet, -q           sin banner
  --verbose, -v         detalle por comprobación
  --catalog <dir>       catálogo externo
  --timeout <ms>        timeout por probe (por defecto 5000)

Ejemplos:
  talos audit                     auditoría rápida en pantalla
  talos audit --profile full      análisis completo (incluye vulnerabilidades por versión)
  talos audit -o informe.html     informe imprimible y interactivo (ábrelo en el navegador)
  sudo talos audit                cobertura total (algunas comprobaciones piden privilegios)
`)
}

func hostname() string {
	h, _ := os.Hostname()
	return h
}
