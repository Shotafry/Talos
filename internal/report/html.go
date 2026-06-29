package report

import (
	"html/template"
	"io"
	"sort"
	"strings"
)

// WriteHTML escribe un informe HTML autocontenido (sin recursos externos: abre offline en
// cualquier navegador y es "imprimir a PDF" directo). Identidad visual de Talos (bronce).
func WriteHTML(w io.Writer, r Report) error {
	return htmlTemplate.Execute(w, buildHTMLView(r))
}

type htmlGroup struct {
	Category string
	Index    int
	Band     string
	Results  []Result
}

type htmlView struct {
	R      Report
	Groups []htmlGroup
}

func buildHTMLView(r Report) htmlView {
	idx := map[string]int{}
	for i, c := range r.Categories {
		idx[c.Category] = i
	}
	byCat := map[string][]Result{}
	for _, res := range r.Results {
		byCat[res.Category] = append(byCat[res.Category], res)
	}
	groups := make([]htmlGroup, 0, len(r.Categories))
	for _, c := range r.Categories {
		rs := byCat[c.Category]
		sort.SliceStable(rs, func(i, j int) bool { return statusRank(rs[i].Status) < statusRank(rs[j].Status) })
		groups = append(groups, htmlGroup{Category: c.Category, Index: c.Index, Band: c.Band, Results: rs})
	}
	return htmlView{R: r, Groups: groups}
}

// statusRank ordena los resultados poniendo primero lo accionable (FAIL > WARN > NA > PASS).
func statusRank(s string) int {
	switch s {
	case "FAIL":
		return 0
	case "WARN":
		return 1
	case "NA":
		return 2
	default:
		return 3
	}
}

var htmlFuncs = template.FuncMap{
	"upper": strings.ToUpper,
	"bandColor": func(band string) string {
		switch band {
		case "verde":
			return "#3fb950"
		case "amarillo":
			return "#d29922"
		case "rojo":
			return "#f85149"
		default:
			return "#8b949e"
		}
	},
	"statusClass": func(s string) string { return strings.ToLower(s) },
	"pct":         func(n int) template.CSS { return template.CSS(itoa(n) + "%") },
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

var htmlTemplate = template.Must(template.New("talos").Funcs(htmlFuncs).Parse(htmlDoc))

const htmlDoc = `<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Talos - Informe de bastionado - {{.R.Host.Hostname}}</title>
<style>
  :root { --bg:#0d1117; --panel:#161b22; --border:#30363d; --fg:#e6edf3; --muted:#8b949e; --bronze:#c9893f; }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--fg); font-family:system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif; font-size:14px; line-height:1.5; }
  .wrap { max-width:980px; margin:0 auto; padding:32px 20px 64px; }
  header { display:flex; align-items:center; gap:20px; border-bottom:2px solid var(--bronze); padding-bottom:20px; margin-bottom:24px; }
  .brand { font-weight:800; letter-spacing:3px; font-size:22px; color:var(--bronze); }
  .brand small { display:block; font-weight:500; letter-spacing:1px; font-size:11px; color:var(--muted); }
  .meta { margin-left:auto; text-align:right; font-size:12px; color:var(--muted); }
  .meta b { color:var(--fg); }
  .top { display:flex; gap:24px; align-items:center; flex-wrap:wrap; margin-bottom:28px; }
  .ring { width:140px; height:140px; border-radius:50%; display:grid; place-items:center; flex-shrink:0;
          background:conic-gradient(var(--ring) var(--p), #21262d 0); }
  .ring .inner { width:108px; height:108px; border-radius:50%; background:var(--panel); display:grid; place-items:center; text-align:center; }
  .ring .num { font-size:34px; font-weight:800; }
  .ring .band { font-size:11px; text-transform:uppercase; letter-spacing:1px; color:var(--muted); }
  .counts { display:flex; gap:10px; flex-wrap:wrap; }
  .pill { padding:6px 14px; border-radius:999px; border:1px solid var(--border); background:var(--panel); font-size:13px; }
  .pill b { font-size:16px; }
  .pass b{color:#3fb950}.warn b{color:#d29922}.fail b{color:#f85149}.na b{color:#8b949e}
  h2 { font-size:15px; border-left:3px solid var(--bronze); padding-left:10px; margin:32px 0 12px; }
  table { width:100%; border-collapse:collapse; background:var(--panel); border:1px solid var(--border); border-radius:8px; overflow:hidden; }
  th,td { text-align:left; padding:9px 12px; border-bottom:1px solid var(--border); vertical-align:top; }
  th { font-size:11px; text-transform:uppercase; letter-spacing:.5px; color:var(--muted); }
  tr:last-child td { border-bottom:none; }
  .st { font-weight:700; font-size:11px; padding:2px 8px; border-radius:6px; display:inline-block; }
  .st.pass{background:rgba(63,185,80,.15);color:#3fb950}.st.warn{background:rgba(210,153,34,.15);color:#d29922}
  .st.fail{background:rgba(248,81,73,.15);color:#f85149}.st.na{background:rgba(139,148,158,.15);color:#8b949e}
  .crit { background:rgba(248,81,73,.08); border:1px solid rgba(248,81,73,.3); border-radius:8px; padding:14px 16px; margin-bottom:6px; }
  .crit h3 { margin:0 0 4px; font-size:14px; }
  .crit p { margin:4px 0 0; color:var(--muted); font-size:13px; }
  .catbar { display:flex; align-items:center; gap:12px; margin:6px 0; }
  .catbar .name { width:120px; font-size:13px; }
  .catbar .track { flex:1; height:8px; background:#21262d; border-radius:999px; overflow:hidden; }
  .catbar .fill { height:100%; }
  .catbar .val { width:48px; text-align:right; font-size:12px; color:var(--muted); }
  .rem { color:var(--muted); font-size:12.5px; }
  .check { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12px; color:var(--bronze); }
  footer { margin-top:40px; padding-top:16px; border-top:1px solid var(--border); font-size:12px; color:var(--muted); }
  @media print { body{background:#fff;color:#111} .wrap{max-width:none} header{border-color:var(--bronze)}
    .panel,.pill,table,.crit{background:#fff!important} .ring .inner{background:#fff} td,th{border-color:#ddd}
    :root{--fg:#111;--muted:#555;--panel:#fff;--border:#ddd} }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="brand">TALOS<small>by argos . guardian de bronce</small></div>
    <div class="meta">
      <div><b>{{.R.Host.Hostname}}</b> . {{.R.Host.OS}}</div>
      <div>{{.R.GeneratedAt}} . perfil {{.R.Profile}}</div>
      <div>Talos {{.R.TalosVersion}} . catalogo {{.R.CatalogVersion}}</div>
    </div>
  </header>

  <div class="top">
    <div class="ring" style="--ring:{{bandColor .R.Band}}; --p:{{pct .R.Index}}">
      <div class="inner"><div><div class="num">{{.R.Index}}</div><div class="band">{{.R.Band}}</div></div></div>
    </div>
    <div class="counts">
      <div class="pill pass"><b>{{.R.Counts.Pass}}</b> correctos</div>
      <div class="pill warn"><b>{{.R.Counts.Warn}}</b> avisos</div>
      <div class="pill fail"><b>{{.R.Counts.Fail}}</b> fallos</div>
      <div class="pill na"><b>{{.R.Counts.NA}}</b> no aplican</div>
    </div>
  </div>

  {{if .R.CriticalVulns}}
  <h2>Fallos criticos - arreglar ya</h2>
  {{range .R.CriticalVulns}}
  <div class="crit">
    <h3>{{.Title}}</h3>
    <div><span class="st fail">{{upper .Severity}}</span> <span class="check">{{.CheckID}}</span> . valor leido: {{.ValueRead}}</div>
    {{if .Remediation}}<p>{{.Remediation}}</p>{{end}}
  </div>
  {{end}}
  {{end}}

  <h2>Indice por categoria</h2>
  {{range .Groups}}
  <div class="catbar">
    <div class="name">{{.Category}}</div>
    <div class="track"><div class="fill" style="width:{{pct .Index}};background:{{bandColor .Band}}"></div></div>
    <div class="val">{{.Index}}/100</div>
  </div>
  {{end}}

  {{range .Groups}}
  <h2>{{.Category}} . {{.Index}}/100</h2>
  <table>
    <thead><tr><th>Estado</th><th>Comprobacion</th><th>Valor</th><th>Remediacion</th></tr></thead>
    <tbody>
    {{range .Results}}
      <tr>
        <td><span class="st {{statusClass .Status}}">{{.Status}}</span></td>
        <td><div>{{.Description}}</div><div class="check">{{.CheckID}}</div></td>
        <td>{{.ValueRead}}{{if .Reason}}<div class="rem">{{.Reason}}</div>{{end}}</td>
        <td class="rem">{{if ne .Status "PASS"}}{{.Remediation}}{{end}}</td>
      </tr>
    {{end}}
    </tbody>
  </table>
  {{end}}

  <footer>
    Talos by argos - auditoria de bastionado de solo lectura (no modifica el sistema).
    Generado el {{.R.GeneratedAt}} para {{.R.Host.Hostname}}.
  </footer>
</div>
</body>
</html>`
