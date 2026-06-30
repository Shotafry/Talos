package report

import (
	"fmt"
	"html/template"
	"io"
	"sort"
	"strings"
)

// WriteHTML escribe un informe HTML autocontenido (sin recursos externos: abre offline en
// cualquier navegador, es "imprimir a PDF" directo y permite filtrar/buscar y cambiar de tema en
// local). Es una vista de presentacion mas: no toca el contrato JSON.
func WriteHTML(w io.Writer, r Report) error {
	return htmlTemplate.Execute(w, buildHTMLView(r))
}

type htmlView struct {
	R        Report
	Summary  string
	Findings []Result // todos los checks, ordenados (accionable primero) para el explorador
}

func buildHTMLView(r Report) htmlView {
	findings := append([]Result{}, r.Results...)
	sort.SliceStable(findings, func(i, j int) bool {
		if a, b := statusRank(findings[i].Status), statusRank(findings[j].Status); a != b {
			return a < b
		}
		if a, b := severityOrder(findings[i].Severity), severityOrder(findings[j].Severity); a != b {
			return a < b
		}
		return findings[i].CheckID < findings[j].CheckID
	})
	return htmlView{R: r, Summary: execSummary(r), Findings: findings}
}

// statusRank ordena lo accionable primero (FAIL > WARN > NA > PASS).
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

// execSummary es el veredicto en una frase, en lenguaje llano.
func execSummary(r Report) string {
	switch crit := len(r.CriticalVulns); {
	case crit > 0:
		return fmt.Sprintf("%d de %d fallos son de severidad alta o crítica y exigen acción inmediata. %d avisos por revisar.",
			crit, r.Counts.Fail, r.Counts.Warn)
	case r.Counts.Fail > 0:
		return fmt.Sprintf("%d fallos y %d avisos por corregir; ninguno de severidad alta o crítica.", r.Counts.Fail, r.Counts.Warn)
	case r.Counts.Warn > 0:
		return fmt.Sprintf("Sin fallos. %d avisos por revisar.", r.Counts.Warn)
	default:
		return "Sin hallazgos pendientes: la configuración cumple todas las comprobaciones aplicables."
	}
}

var htmlFuncs = template.FuncMap{
	"sevLabel":     sevLabel,
	"postureLabel": postureLabel,
	"lower":        strings.ToLower,
	"bandKey": func(b string) string {
		switch b {
		case "verde":
			return "green"
		case "amarillo":
			return "amber"
		case "rojo":
			return "red"
		default:
			return "na"
		}
	},
	"statusKey": func(s string) string { return strings.ToLower(s) },
	"sevTone": func(s string) string {
		switch s {
		case "critical":
			return "crit"
		case "high":
			return "high"
		case "medium":
			return "med"
		default:
			return "low"
		}
	},
	"statusLabel": func(s string) string {
		switch s {
		case "PASS":
			return "Correcto"
		case "WARN":
			return "Aviso"
		case "FAIL":
			return "Fallo"
		default:
			return "N/A"
		}
	},
}

var htmlTemplate = template.Must(template.New("talos").Funcs(htmlFuncs).Parse(htmlDoc))

const htmlDoc = `<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Talos · Informe de bastionado · {{.R.Host.Hostname}}</title>
<style>
  /* Tema CLARO (por defecto). --bronze = color de marca (chrome), aparte de la escala de
     severidad rojo/ambar/verde, que es solo para datos. */
  .page{
    --paper:#FCFBF9; --surface:#FFFFFF; --ink:#1A1D23; --muted:#5F6670; --line:#E6E4DF; --line-soft:#EEEDE8;
    --bronze:#9A6B2F; --code-bg:rgba(0,0,0,.05);
    --red:#C13B32; --red-fill:#FCEBE8; --red-line:#F2CEC8;
    --amber:#9A6B12; --amber-fill:#FBF1DA; --amber-line:#EEDFB6;
    --green:#2E7D4A; --green-fill:#E9F4ED; --green-line:#CDE6D6;
    --slate:#5A6472; --slate-fill:#EFF1F5; --slate-line:#DDE1E8;
  }
  /* Tema OSCURO. Superficies y bordes con paso claro respecto al fondo para que todo se
     distinga; severidad y bronce subidos de luz para contrastar sobre el oscuro. */
  .page[data-theme="dark"]{
    --paper:#0F141B; --surface:#1A2230; --ink:#F3F6FA; --muted:#AEB8C6; --line:#333F50; --line-soft:#26303F;
    --bronze:#D8A862; --code-bg:rgba(255,255,255,.09);
    --red:#F4847C; --red-fill:#2E1714; --red-line:#6B332B;
    --amber:#E6B05A; --amber-fill:#2B2113; --amber-line:#5E4827;
    --green:#6CC68C; --green-fill:#15281C; --green-line:#2F523C;
    --slate:#9FAAB9; --slate-fill:#1E2733; --slate-line:#3A4555;
  }
  :root{
    --mono:ui-monospace,"Cascadia Code","SF Mono",Menlo,Consolas,monospace;
    --sans:system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  }
  *{box-sizing:border-box}
  body{margin:0;font-family:var(--sans);font-size:15px;line-height:1.55;-webkit-font-smoothing:antialiased}
  .page{min-height:100vh;background:var(--paper);color:var(--ink);transition:background .2s,color .2s}
  .wrap{max-width:1040px;margin:0 auto;padding:40px 28px 80px;color:var(--ink)}

  /* Masthead */
  .mast{display:flex;justify-content:space-between;align-items:flex-end;gap:24px;padding-bottom:18px;border-bottom:2px solid var(--bronze)}
  .word{font-family:var(--mono);font-size:30px;font-weight:700;letter-spacing:.34em;margin:0 0 2px;color:var(--bronze)}
  .tagline{font-size:13px;color:var(--muted);letter-spacing:.02em}
  .mast-right{display:flex;flex-direction:column;align-items:flex-end;gap:10px}
  .meta{font-family:var(--mono);font-size:12px;color:var(--muted);text-align:right;line-height:1.7;white-space:nowrap}
  .meta b{color:var(--ink);font-weight:600}
  .theme-toggle{display:inline-flex;align-items:center;justify-content:center;width:34px;height:34px;border:1px solid var(--line);border-radius:9px;background:var(--surface);color:var(--muted);cursor:pointer;padding:0}
  .theme-toggle:hover{border-color:var(--ink);color:var(--ink)}
  .theme-toggle svg{width:17px;height:17px}
  .theme-toggle .i-sun{display:none}
  .theme-toggle .i-moon{display:block}
  .page[data-theme="dark"] .theme-toggle .i-moon{display:none}
  .page[data-theme="dark"] .theme-toggle .i-sun{display:block}

  /* Hero / posture */
  .hero{display:grid;grid-template-columns:minmax(280px,1fr) minmax(280px,1.1fr);gap:40px;align-items:center;margin:36px 0 8px}
  .score-num{font-family:var(--mono);font-size:72px;line-height:.9;font-weight:700;letter-spacing:-.02em}
  .score-slash{font-size:24px;color:var(--muted)}
  .score-band{font-family:var(--mono);font-size:13px;letter-spacing:.22em;text-transform:uppercase;margin-top:8px}
  .band-red{color:var(--red)} .band-amber{color:var(--amber)} .band-green{color:var(--green)} .band-na{color:var(--slate)}
  .meter{margin-top:22px}
  .meter-track{position:relative;height:10px;border-radius:6px;overflow:hidden;display:flex}
  .meter-track .z{height:100%}
  .z-red{width:50%;background:var(--red-line)} .z-amber{width:30%;background:var(--amber-line)} .z-green{width:20%;background:var(--green-line)}
  .marker{position:absolute;top:-4px;width:3px;height:18px;border-radius:2px;background:var(--ink);transform:translateX(-1.5px)}
  .meter-scale{position:relative;height:16px;margin-top:4px;font-family:var(--mono);font-size:10px;color:var(--muted)}
  .meter-scale span{position:absolute;transform:translateX(-50%)}
  .summary{font-size:15px;color:var(--ink);margin:0 0 18px;max-width:46ch}
  .counts{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}
  .tile{display:flex;align-items:baseline;gap:8px;border:1px solid var(--line);background:var(--surface);border-radius:10px;padding:12px 14px;cursor:pointer;font:inherit;text-align:left;transition:border-color .12s}
  .tile:hover{border-color:var(--ink)}
  .tile b{font-family:var(--mono);font-size:22px;font-weight:700}
  .tile span{font-size:13px;color:var(--muted)}
  .tile.pass b{color:var(--green)} .tile.warn b{color:var(--amber)} .tile.fail b{color:var(--red)} .tile.na b{color:var(--slate)}

  /* Section headers */
  h2{font-size:12px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;color:var(--muted);margin:48px 0 16px;display:flex;align-items:center;gap:10px}
  h2::before{content:"";width:18px;height:2px;background:var(--bronze);border-radius:2px}
  h2.crit{color:var(--red)} h2.crit::before{background:var(--red)}

  /* Finding cards (pastel, sin borde neon) */
  .card{border-radius:14px;padding:18px 20px;margin-bottom:12px;background:var(--red-fill);border:1px solid var(--red-line);color:var(--ink)}
  .card .what{font-size:15px;font-weight:600;margin:0 0 12px;line-height:1.5}
  .card .ref{display:flex;align-items:center;gap:10px;flex-wrap:wrap;font-family:var(--mono);font-size:12.5px;color:var(--muted);margin-bottom:10px}
  .card .id{color:var(--ink);font-weight:600}
  .card .fix{font-size:14px;color:var(--ink);line-height:1.55}
  .card .fix b{font-weight:600}
  code{font-family:var(--mono);font-size:.92em;background:var(--code-bg);padding:1px 5px;border-radius:5px}

  .chip{display:inline-block;font-family:var(--mono);font-size:11px;font-weight:700;letter-spacing:.04em;padding:2px 8px;border-radius:999px;text-transform:uppercase}
  .s-fail{background:var(--red-fill);color:var(--red)} .s-warn{background:var(--amber-fill);color:var(--amber)}
  .s-pass{background:var(--green-fill);color:var(--green)} .s-na{background:var(--slate-fill);color:var(--slate)}

  /* Severidad: cuatro niveles, del más grave (sólido) al más leve (apagado) */
  .sv{display:inline-block;font-family:var(--mono);font-size:10.5px;font-weight:700;letter-spacing:.04em;padding:2px 7px;border-radius:6px;text-transform:uppercase;white-space:nowrap}
  .sv-crit{background:var(--red);color:var(--paper)}
  .sv-high{background:var(--red-fill);color:var(--red);border:1px solid var(--red-line)}
  .sv-med{background:var(--amber-fill);color:var(--amber)}
  .sv-low{background:var(--slate-fill);color:var(--slate)}

  /* Category bars */
  .cat{display:grid;grid-template-columns:120px 1fr auto;align-items:center;gap:14px;padding:7px 0;cursor:pointer}
  .cat:hover .cat-name{color:var(--ink)}
  .cat-name{font-family:var(--mono);font-size:13px;color:var(--muted)}
  .cat-track{height:8px;border-radius:6px;background:var(--line-soft);overflow:hidden}
  .cat-fill{display:block;height:100%;border-radius:6px;min-width:2px}
  .fill-red{background:var(--red)} .fill-amber{background:var(--amber)} .fill-green{background:var(--green)} .fill-na{background:var(--slate-line)}
  .cat-val{font-family:var(--mono);font-size:12px;color:var(--muted);min-width:54px;text-align:right}

  /* Toolbar + explorer */
  .toolbar{display:flex;flex-wrap:wrap;gap:12px;align-items:center;margin-bottom:14px}
  .seg{display:inline-flex;border:1px solid var(--line);border-radius:10px;overflow:hidden}
  .seg button{font:inherit;font-size:13px;border:0;background:var(--surface);color:var(--muted);padding:7px 13px;cursor:pointer;border-right:1px solid var(--line)}
  .seg button:last-child{border-right:0}
  .seg button.on{background:var(--ink);color:var(--paper)}
  select,.search{font:inherit;font-size:13px;border:1px solid var(--line);border-radius:10px;padding:7px 12px;background:var(--surface);color:var(--ink)}
  .search{min-width:200px;flex:1}
  .shown{font-family:var(--mono);font-size:12px;color:var(--muted);margin-left:auto}
  table{width:100%;border-collapse:collapse;font-size:14px;table-layout:fixed}
  /* Columnas cortas a la izquierda; las dos de texto (comprobación + remediación) anchas y
     juntas, para que el texto no se parta en una tira vertical que estira las filas. */
  .c-est{width:8%} .c-sev{width:9%} .c-cat{width:10%} .c-det{width:11%} .c-comp{width:31%} .c-rem{width:31%}
  th{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);font-weight:600;padding:8px 12px;border-bottom:1px solid var(--line)}
  td{padding:11px 12px;border-bottom:1px solid var(--line-soft);vertical-align:top;overflow-wrap:break-word;color:var(--ink)}
  td .id{font-family:var(--mono);font-size:12px;color:var(--muted);display:block;margin-top:3px}
  .fix-cell{font-size:13.5px}
  .reason{color:var(--muted);font-size:12px;margin-top:4px}
  .empty{display:none;padding:28px;text-align:center;color:var(--muted)}

  footer{margin-top:56px;padding-top:18px;border-top:1px solid var(--line);font-family:var(--mono);font-size:11.5px;color:var(--muted);line-height:1.8}

  @media (max-width:720px){
    .hero{grid-template-columns:1fr;gap:24px}
    .mast{flex-direction:column;align-items:flex-start}
    .mast-right{align-items:flex-start}
    .meta{text-align:left}
    .cat{grid-template-columns:96px 1fr auto}
    .table-scroll{overflow-x:auto}
  }
  @media print{
    .page[data-theme="dark"]{--paper:#fff;--surface:#fff;--ink:#111;--muted:#555;--line:#ddd;--line-soft:#eee;--bronze:#9A6B2F;--code-bg:rgba(0,0,0,.05);
      --red:#C13B32;--red-fill:#FCEBE8;--red-line:#F2CEC8;--amber:#996B12;--amber-fill:#FBF1DA;--amber-line:#EEDFB6;
      --green:#2E7D4A;--green-fill:#E9F4ED;--green-line:#CDE6D6;--slate:#5A6472;--slate-fill:#EFF1F5;--slate-line:#DDE1E8;}
    .toolbar,.tile,.theme-toggle{display:none!important}
    .card{break-inside:avoid}
  }
</style>
</head>
<body>
<div class="page" id="page" data-theme="light">
<div class="wrap">

  <header class="mast">
    <div>
      <h1 class="word">TALOS</h1>
      <div class="tagline">Informe de bastionado</div>
    </div>
    <div class="mast-right">
      <button id="themeBtn" class="theme-toggle" type="button" aria-label="Cambiar entre tema claro y oscuro" title="Tema claro / oscuro">
        <svg class="i-moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>
        <svg class="i-sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M5 5l1.5 1.5M17.5 17.5L19 19M19 5l-1.5 1.5M6.5 17.5L5 19"/></svg>
      </button>
      <div class="meta">
        <div><b>{{.R.Host.Hostname}}</b> · {{.R.Host.OS}}{{if .R.Host.Kernel}} {{.R.Host.Kernel}}{{end}}</div>
        <div>{{.R.GeneratedAt}} · perfil {{.R.Profile}}</div>
        <div>Talos {{.R.TalosVersion}} · catálogo {{.R.CatalogVersion}}</div>
      </div>
    </div>
  </header>

  <section class="hero">
    <div>
      <div class="score-num band-{{bandKey .R.Band}}">{{.R.Index}}<span class="score-slash">/100</span></div>
      <div class="score-band band-{{bandKey .R.Band}}">{{postureLabel .R.Index}}</div>
      <div class="meter">
        <div class="meter-track">
          <span class="z z-red"></span><span class="z z-amber"></span><span class="z z-green"></span>
          <span class="marker" style="left:{{.R.Index}}%"></span>
        </div>
        <div class="meter-scale"><span style="left:0%">0</span><span style="left:50%">50</span><span style="left:80%">80</span><span style="left:100%">100</span></div>
      </div>
    </div>
    <div>
      <p class="summary">{{.Summary}}</p>
      <div class="counts">
        <button class="tile pass" data-status="PASS"><b>{{.R.Counts.Pass}}</b><span>correctos</span></button>
        <button class="tile warn" data-status="WARN"><b>{{.R.Counts.Warn}}</b><span>avisos</span></button>
        <button class="tile fail" data-status="FAIL"><b>{{.R.Counts.Fail}}</b><span>fallos</span></button>
        <button class="tile na" data-status="NA"><b>{{.R.Counts.NA}}</b><span>no aplican</span></button>
      </div>
    </div>
  </section>

  {{if .R.CriticalVulns}}
  <h2 class="crit">Fallos críticos · corregir de inmediato</h2>
  {{range .R.CriticalVulns}}
  <div class="card">
    <p class="what">{{.Title}}</p>
    <div class="ref"><span class="chip s-fail">{{sevLabel .Severity}}</span><span class="id">{{.CheckID}}</span>{{if .ValueRead}}<span>· detectado: <code>{{.ValueRead}}</code></span>{{end}}</div>
    {{if .Remediation}}<div class="fix"><b>Solución.</b> {{.Remediation}}</div>{{end}}
  </div>
  {{end}}
  {{end}}

  <h2>Índice por categoría</h2>
  {{range .R.Categories}}
  <div class="cat" data-catbar="{{.Category}}">
    <span class="cat-name">{{.Category}}</span>
    <span class="cat-track"><span class="cat-fill fill-{{bandKey .Band}}" style="width:{{.Index}}%"></span></span>
    <span class="cat-val">{{if eq .Band "n/d"}}n/d{{else}}{{.Index}}/100{{end}}</span>
  </div>
  {{end}}

  <h2 id="explorer">Todas las comprobaciones</h2>
  <div class="toolbar">
    <div class="seg" id="statusSeg">
      <button data-status="" class="on">Todas</button>
      <button data-status="FAIL">Fallos</button>
      <button data-status="WARN">Avisos</button>
      <button data-status="PASS">Correctos</button>
      <button data-status="NA">N/A</button>
    </div>
    <select id="sevSel" aria-label="Filtrar por severidad">
      <option value="">Toda severidad</option>
      <option value="critical">Crítica</option>
      <option value="high">Alta</option>
      <option value="medium">Media</option>
      <option value="low">Baja</option>
    </select>
    <select id="catSel" aria-label="Filtrar por categoría">
      <option value="">Todas las categorías</option>
      {{range .R.Categories}}<option value="{{.Category}}">{{.Category}}</option>{{end}}
    </select>
    <input class="search" id="search" type="search" placeholder="Buscar comprobación…" aria-label="Buscar">
    <span class="shown" id="shown"></span>
  </div>
  <div class="table-scroll">
  <table>
    <colgroup><col class="c-est"><col class="c-sev"><col class="c-cat"><col class="c-det"><col class="c-comp"><col class="c-rem"></colgroup>
    <thead><tr><th>Estado</th><th>Severidad</th><th>Categoría</th><th>Detectado</th><th>Comprobación</th><th>Remediación</th></tr></thead>
    <tbody id="rows">
    {{range .Findings}}
      <tr data-status="{{.Status}}" data-sev="{{.Severity}}" data-cat="{{.Category}}" data-text="{{lower .CheckID}} {{lower .Description}} {{lower .Category}}">
        <td><span class="chip s-{{statusKey .Status}}">{{statusLabel .Status}}</span></td>
        <td><span class="sv sv-{{sevTone .Severity}}">{{sevLabel .Severity}}</span></td>
        <td>{{.Category}}</td>
        <td>{{if .ValueRead}}<code>{{.ValueRead}}</code>{{end}}{{if .Reason}}<div class="reason">{{.Reason}}</div>{{end}}</td>
        <td>{{.Description}}<span class="id">{{.CheckID}}</span></td>
        <td class="fix-cell">{{if ne .Status "PASS"}}{{.Remediation}}{{end}}</td>
      </tr>
    {{end}}
    </tbody>
  </table>
  <div class="empty" id="empty">Ninguna comprobación coincide con el filtro.</div>
  </div>

  <footer>
    Talos {{.R.TalosVersion}} · catálogo {{.R.CatalogVersion}} · generado el {{.R.GeneratedAt}}<br>
    Auditoría de bastionado de solo lectura · no modifica el sistema.
  </footer>
</div>
</div>

<script>
(function(){
  var page=document.getElementById('page');
  var btn=document.getElementById('themeBtn');
  function setTheme(t){ page.setAttribute('data-theme',t); try{localStorage.setItem('talos-theme',t);}catch(e){} }
  var saved=null; try{saved=localStorage.getItem('talos-theme');}catch(e){}
  if(saved){ setTheme(saved); }
  else if(window.matchMedia && matchMedia('(prefers-color-scheme: dark)').matches){ setTheme('dark'); }
  btn.addEventListener('click',function(){ setTheme(page.getAttribute('data-theme')==='dark'?'light':'dark'); });

  var rows=[].slice.call(document.querySelectorAll('#rows tr'));
  var shown=document.getElementById('shown'), empty=document.getElementById('empty');
  var fStatus='', fSev='', fCat='', fSearch='';
  function apply(){
    var n=0;
    rows.forEach(function(r){
      var ok=(!fStatus||r.getAttribute('data-status')===fStatus)
          &&(!fSev||r.getAttribute('data-sev')===fSev)
          &&(!fCat||r.getAttribute('data-cat')===fCat)
          &&(!fSearch||r.getAttribute('data-text').indexOf(fSearch)>-1);
      r.style.display=ok?'':'none'; if(ok)n++;
    });
    shown.textContent='Mostrando '+n+' de '+rows.length;
    empty.style.display=n?'none':'block';
  }
  function setStatus(s){
    fStatus=s;
    [].forEach.call(document.querySelectorAll('#statusSeg button'),function(b){
      b.classList.toggle('on', b.getAttribute('data-status')===s);
    });
    apply();
  }
  [].forEach.call(document.querySelectorAll('#statusSeg button'),function(b){
    b.addEventListener('click',function(){ setStatus(b.getAttribute('data-status')); });
  });
  [].forEach.call(document.querySelectorAll('.tile'),function(t){
    t.addEventListener('click',function(){
      setStatus(t.getAttribute('data-status'));
      document.getElementById('explorer').scrollIntoView({behavior:'smooth'});
    });
  });
  [].forEach.call(document.querySelectorAll('[data-catbar]'),function(c){
    c.addEventListener('click',function(){
      fCat=c.getAttribute('data-catbar'); document.getElementById('catSel').value=fCat; apply();
      document.getElementById('explorer').scrollIntoView({behavior:'smooth'});
    });
  });
  document.getElementById('sevSel').addEventListener('change',function(e){ fSev=e.target.value; apply(); });
  document.getElementById('catSel').addEventListener('change',function(e){ fCat=e.target.value; apply(); });
  document.getElementById('search').addEventListener('input',function(e){ fSearch=e.target.value.toLowerCase().trim(); apply(); });
  apply();
})();
</script>
</body>
</html>`
