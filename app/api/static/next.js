// Dashboard prototipo "inminente" (/next). Script EXTERNO: la CSP de la app es
// script-src 'self', que bloquea scripts inline (por eso el dashboard actual usa
// app.js/pending_status.js externos). Consume los endpoints /api/* de solo lectura.
"use strict";
const $ = s => document.querySelector(s);
const fmtDate = s => s ? String(s).slice(0, 10) : "—";
const daysAgo = s => { if (!s) return null; const d = (Date.now() - new Date(s)) / 86400000; return Math.round(d); };
const esc = s => (s == null ? "" : String(s)).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
// Solo http(s) como enlace navegable (evita XSS por href javascript:/data:).
const safeUrl = u => { try { const p = new URL(u, location.origin); return (p.protocol === "http:" || p.protocol === "https:") ? p.href : null; } catch (e) { return null; } };
const _MESES = ["ene", "feb", "mar", "abr", "may", "jun", "jul", "ago", "sep", "oct", "nov", "dic"];
const monthYear = s => { if (!s) return "el arranque"; const d = new Date(s); return isNaN(d) ? String(s).slice(0, 7) : _MESES[d.getUTCMonth()] + " " + d.getUTCFullYear(); };
const fmtLongDate = s => { if (!s) return ""; const d = new Date(String(s).slice(0, 10) + "T00:00:00Z"); return isNaN(d) ? String(s) : d.getUTCDate() + " " + _MESES[d.getUTCMonth()] + " " + d.getUTCFullYear(); };

// tema
const tb = $("#themebtn");
tb.onclick = () => {
  const r = document.documentElement;
  const cur = r.getAttribute("data-theme") || (matchMedia("(prefers-color-scheme:dark)").matches ? "dark" : "light");
  r.setAttribute("data-theme", cur === "dark" ? "light" : "dark");
  try { localStorage.setItem("fs-theme", r.getAttribute("data-theme")); } catch (e) {}
};
try { const t = localStorage.getItem("fs-theme"); if (t) document.documentElement.setAttribute("data-theme", t); } catch (e) {}

async function jget(u) {
  const ctrl = new AbortController();
  const to = setTimeout(() => ctrl.abort(), 25000);
  try {
    const r = await fetch(u, { signal: ctrl.signal });
    if (!r.ok) throw new Error(u + " " + r.status);
    return await r.json();
  } finally { clearTimeout(to); }
}

function scoreColor(v) { return v >= 80 ? "var(--crit)" : v >= 60 ? "var(--warn)" : v >= 40 ? "var(--m2)" : "var(--muted)"; }
function dial(v) {
  const val = Math.round(v || 0), c = scoreColor(val), frac = Math.max(0, Math.min(1, val / 100));
  const r = 22, C = 2 * Math.PI * r, off = C * (1 - frac);
  return `<div class="dial"><svg viewBox="0 0 52 52" width="52" height="52">
    <circle cx="26" cy="26" r="${r}" fill="none" stroke="var(--surface2)" stroke-width="5"/>
    <circle cx="26" cy="26" r="${r}" fill="none" stroke="${c}" stroke-width="5" stroke-linecap="round"
      stroke-dasharray="${C.toFixed(1)}" stroke-dashoffset="${off.toFixed(1)}"
      transform="rotate(-90 26 26)"/></svg><span class="v" style="color:${c}">${val}</span></div>`;
}
const MAT = { pre_cve: "pre-CVE", cve_prereserved: "prereservado", cve_reserved: "reservado" };

// Desglose del Foreshock Score (misma fórmula que el servidor, _CRIT_SCORE_SQL):
// KEV +50 · PoC +20 · gravedad = CVSS×4 (0–40) o severity_hint · tier 1→15…4→3.
function sevPoints(row) {
  if (row.cvss != null) return Math.round(row.cvss * 4 * 10) / 10;
  const m = { critical: 40, high: 28, medium: 14, low: 4 };
  return m[(row.severity_hint || "").toLowerCase()] || 0;
}
function tierPoints(t) { return ({ 1: 15, 2: 10, 3: 6, 4: 3 })[t] != null ? ({ 1: 15, 2: 10, 3: 6, 4: 3 })[t] : 1; }
function scoreBreakdown(row) {
  if (!row) return "";
  const sev = sevPoints(row);
  const parts = [
    { l: "Explotación activa (KEV)", v: row.in_kev ? 50 : 0, on: !!row.in_kev },
    { l: "PoC público", v: row.has_public_poc ? 20 : 0, on: !!row.has_public_poc },
    { l: row.cvss != null ? ("Gravedad · CVSS " + esc(row.cvss) + " × 4") : ("Gravedad · " + esc(row.severity_hint || "sin dato")), v: sev, on: sev > 0 },
    { l: "Prontitud de la fuente (tier " + esc(row.min_tier != null ? row.min_tier : "?") + ")", v: tierPoints(row.min_tier), on: true },
  ];
  const items = parts.map(p => `<div class="sb-row ${p.on ? "" : "off"}"><span>${p.l}</span><b>+${p.v}</b></div>`).join("");
  return `<h3>De dónde sale el score</h3>
    <div class="sb-total">Foreshock Score <b>${esc(row.score)}</b> / 100</div>
    <div class="sbrk">${items}</div>
    <p class="sbnote">Suma de: KEV (+50) · PoC público (+20) · gravedad CVSS×4 o severidad (0–40) ·
      prontitud de la fuente por tier (1→15, 2→10, 3→6, 4→3). Más alto = más urgente actuar.</p>`;
}

function renderLag(el, headEl, lag) {
  const since = monthYear(lag.operational_start);
  headEl.innerHTML = `<div class="lead" style="margin:0 0 12px">La mitad se detectaron
    <b>≥ ${esc(lag.median)} día(s)</b> antes que NVD (mediana); el 10% más adelantado,
    <b>≥ ${esc(lag.p90)} días</b>. Sobre <b>${(lag.count || 0).toLocaleString()}</b> medidas desde ${esc(since)}
    (arranque de Foreshock).</div>`;
  barChart(el, (lag.bins || []).map(b => ({ label: b.label + " d", v: b.count })), {});
}

// "Cola de espera": cuánto llevan esperando las pendientes a que NVD publique,
// por antigüedad (days desde first_seen) y si ya tienen CVE o no. Fuente /api/queue/age.
function renderQueueAge(el, headEl, qa) {
  const un = (qa && qa.unassigned) || { bins: [] }, as = (qa && qa.assigned) || { bins: [] };
  const labels = (un.bins || []).map(b => b.label);
  const rows = labels.map((lab, i) => ({
    label: lab,
    sin: ((un.bins[i] || {}).count) || 0,
    con: ((as.bins && as.bins[i] || {}).count) || 0,
  }));
  headEl.innerHTML = `<div class="lead" style="margin:0 0 12px">Mediana de espera:
    <b>${esc(un.median_days)} d</b> sin CVE · <b>${esc(as.median_days)} d</b> con CVE.
    Cuanto más a la derecha, más lleva NVD sin publicarlas.</div>`;
  const keys = [["sin", "var(--m1)", "sin CVE"], ["con", "var(--m3)", "con CVE (reservado)"]];
  const W = 940, H = 200, padL = 34, padB = 30, padT = 8;
  const tot = rows.map(r => r.sin + r.con), max = Math.max(1, ...tot), n = rows.length, bw = (W - padL - 6) / n;
  const ticks = 4; let gl = "";
  for (let t = 0; t <= ticks; t++) {
    const v = Math.round(max * t / ticks), y = padT + (H - padT - padB) * (1 - t / ticks);
    gl += `<line x1="${padL}" y1="${y.toFixed(1)}" x2="${W}" y2="${y.toFixed(1)}" stroke="var(--grid)" stroke-width="1"/>`;
    gl += `<text x="${padL - 5}" y="${(y + 3).toFixed(1)}" font-size="9" text-anchor="end" fill="var(--muted)">${v}</text>`;
  }
  let bars = "";
  rows.forEach((r, i) => {
    let y = H - padB; const x = padL + i * bw;
    keys.forEach(([k, c]) => { const h = (r[k] || 0) / max * (H - padT - padB); y -= h;
      if (h > 0) bars += `<rect x="${(x + 2).toFixed(1)}" y="${y.toFixed(1)}" width="${(bw - 4).toFixed(1)}" height="${h.toFixed(1)}" fill="${c}"><title>${esc(r.label)} d: ${r.sin + r.con}</title></rect>`; });
  });
  const labs = rows.map((r, i) => `<text x="${(padL + i * bw + bw / 2).toFixed(1)}" y="${H - 12}" font-size="10" text-anchor="middle" fill="var(--muted)">${esc(r.label)} d</text>`).join("");
  el.innerHTML = `<svg class="evo-svg" viewBox="0 0 ${W} ${H}" width="100%" role="img" aria-label="Antigüedad de la cola de pendientes">${gl}${bars}${labs}</svg>
    <div class="lgd">${keys.map(([, c, lab]) => `<span><i style="background:${c}"></i>${lab}</span>`).join("")}</div>`;
}

let IMM = [];
function renderImm(filter) {
  const q = (filter || "").trim().toLowerCase();
  const rows = IMM.filter(r => !q || (r.product || "").toLowerCase().includes(q) || (r.cve_id || "").toLowerCase().includes(q));
  if (!rows.length) { $("#imm").innerHTML = '<div class="empty">sin resultados para «' + esc(q) + '»</div>'; return; }
  $("#imm").innerHTML = rows.slice(0, 60).map(r => {
    const isCvssHigh = r.cvss != null && r.cvss >= 9.0;
    const chips = [];
    if (r.in_kev) chips.push('<span class="chip kev">KEV</span>');
    if (r.has_public_poc) chips.push('<span class="chip poc">PoC público</span>');
    if (r.cvss != null) chips.push('<span class="chip ' + (isCvssHigh ? "cvss10" : "cvss") + '">CVSS ' + esc(r.cvss) + '</span>');
    if (r.min_tier != null) chips.push('<span class="chip">tier ' + esc(r.min_tier) + '</span>');
    const mat = MAT[r.maturity] || r.maturity || "";
    const age = daysAgo(r.first_seen_at);
    // Rojo: KEV (acento fuerte) o CVSS ≥ 9.0 (un escalón por debajo).
    const rowcls = r.in_kev ? "imm kev" : (isCvssHigh ? "imm red" : "imm");
    return `<div class="${rowcls}" data-id="${esc(r.id)}">
      ${dial(r.score)}
      <div class="body">
        <div class="prod">${esc(r.product || r.cve_id || "—")}</div>
        <div class="meta"><span class="mono">${esc(r.cve_id || "sin CVE")}</span>
          · <span class="badge-mat mat-${esc(r.maturity)}">${esc(mat)}</span>
          ${age != null ? " · visto hace " + age + " d" : ""}</div>
        <div class="chips">${chips.join("")}</div>
      </div></div>`;
  }).join("");
  document.querySelectorAll(".imm").forEach(el => el.onclick = () => openDrawer(el.dataset.id));
}

function barChart(el, items, opts) {
  const max = Math.max(1, ...items.map(i => i.v));
  el.innerHTML = items.map(i => {
    const w = (i.v / max * 100).toFixed(1), col = i.color || "var(--accent)";
    return `<div class="bar-row"><span class="lab" title="${esc(i.label)}">${esc(i.label)}</span>
      <div class="bar-track"><div class="bar-fill" style="width:${w}%;background:${col}"></div></div>
      <span class="val">${esc(opts && opts.fmt ? opts.fmt(i.v) : i.v)}</span></div>`;
  }).join("");
}

function renderTrend(el, series) {
  if (!series || !series.length) { el.innerHTML = '<div class="empty">sin datos</div>'; return; }
  const W = 340, H = 120, pad = 4;
  const keys = [["pre_cve", "var(--m1)"], ["cve_prereserved", "var(--m2)"], ["published", "var(--ctx)"]];
  const tot = series.map(s => keys.reduce((a, [k]) => a + (s[k] || 0), 0));
  const max = Math.max(1, ...tot), n = series.length, bw = (W - pad * 2) / n;
  let bars = "";
  series.forEach((s, i) => {
    let y = H - pad; const x = pad + i * bw;
    keys.forEach(([k, c]) => { const h = (s[k] || 0) / max * (H - pad * 2); y -= h;
      bars += `<rect x="${x + 1}" y="${y.toFixed(1)}" width="${(bw - 2).toFixed(1)}" height="${h.toFixed(1)}" fill="${c}"/>`; });
  });
  // Etiquetas rotadas para que no se solapen en columna estrecha.
  const labs = series.map((s, i) => { const cx = (pad + i * bw + bw / 2).toFixed(1);
    return `<text x="${cx}" y="${H + 2}" font-size="8" fill="var(--muted)" text-anchor="end"
      transform="rotate(-40 ${cx} ${H + 2})">${esc(String(s.period).slice(2))}</text>`; }).join("");
  el.innerHTML = `<svg viewBox="0 0 ${W} ${H + 26}" width="100%">${bars}${labs}</svg>
    <div class="lgd">
      <span><i style="background:var(--m1)"></i>pre-CVE</span>
      <span><i style="background:var(--m2)"></i>prereservado</span>
      <span><i style="background:var(--ctx)"></i>publicado</span></div>`;
}

// "Evolución": detecciones de las PENDIENTES actuales por mes, apiladas por madurez
// (solo los tres estados pendientes; el publicado no es pendiente). Fuente: /api/trend.
function renderEvolution(el, series) {
  if (!series || !series.length) { el.innerHTML = '<div class="empty">sin datos</div>'; return; }
  const keys = [["pre_cve", "var(--m1)", "pre-CVE"], ["cve_prereserved", "var(--m2)", "prereservado"], ["cve_reserved", "var(--m3)", "reservado"]];
  const W = 940, H = 240, padL = 34, padB = 22, padT = 8;
  const tot = series.map(s => keys.reduce((a, [k]) => a + (s[k] || 0), 0));
  const max = Math.max(1, ...tot), n = series.length, bw = (W - padL - 6) / n;
  const ticks = 4; let gl = "";
  for (let t = 0; t <= ticks; t++) {
    const v = Math.round(max * t / ticks), y = padT + (H - padT - padB) * (1 - t / ticks);
    gl += `<line x1="${padL}" y1="${y.toFixed(1)}" x2="${W}" y2="${y.toFixed(1)}" stroke="var(--grid)" stroke-width="1"/>`;
    gl += `<text x="${padL - 5}" y="${(y + 3).toFixed(1)}" font-size="9" text-anchor="end">${v}</text>`;
  }
  let bars = "";
  series.forEach((s, i) => {
    let y = H - padB; const x = padL + i * bw;
    keys.forEach(([k, c]) => {
      const h = (s[k] || 0) / max * (H - padT - padB); y -= h;
      if (h > 0) bars += `<rect x="${(x + 2).toFixed(1)}" y="${y.toFixed(1)}" width="${(bw - 4).toFixed(1)}" height="${h.toFixed(1)}" fill="${c}"><title>${esc(s.period)}: ${tot[i]} pendientes</title></rect>`;
    });
  });
  const labs = series.map((s, i) => { const cx = (padL + i * bw + bw / 2).toFixed(1);
    return `<text x="${cx}" y="${H - 6}" font-size="9" text-anchor="end"
      transform="rotate(-35 ${cx} ${H - 6})">${esc(String(s.period).slice(2))}</text>`; }).join("");
  el.innerHTML = `<svg class="evo-svg" viewBox="0 0 ${W} ${H}" width="100%" role="img" aria-label="Detecciones de pendientes por mes y madurez">${gl}${bars}${labs}</svg>
    <div class="lgd">${keys.map(([, c, lab]) => `<span><i style="background:${c}"></i>${lab}</span>`).join("")}</div>`;
}

// ---------- Velocidad de captura (gráfica al pie, carga diferida) ----------
function lineChart(el, series) {
  if (!series.length) { el.innerHTML = '<div class="empty">sin datos</div>'; return; }
  const W = 940, H = 180, padL = 34, padB = 22, padT = 10;
  const max = Math.max(1, ...series.map(s => s.count)), n = series.length;
  const px = i => padL + (i / Math.max(1, n - 1)) * (W - padL - 6);
  const py = v => H - padB - (v / max) * (H - padT - padB);
  let grid = "";
  for (let t = 0; t <= 4; t++) { const gy = padT + (H - padT - padB) * t / 4;
    grid += `<line x1="${padL}" y1="${gy.toFixed(1)}" x2="${W}" y2="${gy.toFixed(1)}" stroke="var(--grid)"/><text x="${padL - 5}" y="${(gy + 3).toFixed(1)}" font-size="9" text-anchor="end" fill="var(--muted)">${Math.round(max * (1 - t / 4))}</text>`; }
  const path = series.map((s, i) => `${i ? "L" : "M"}${px(i).toFixed(1)} ${py(s.count).toFixed(1)}`).join(" ");
  const area = `M${padL} ${H - padB} ` + series.map((s, i) => `L${px(i).toFixed(1)} ${py(s.count).toFixed(1)}`).join(" ") + ` L${px(n - 1).toFixed(1)} ${H - padB} Z`;
  const step = Math.max(1, Math.ceil(n / 8));
  const labs = series.map((s, i) => (i % step === 0) ? `<text x="${px(i).toFixed(1)}" y="${H - 7}" font-size="8" text-anchor="middle" fill="var(--muted)">${esc(String(s.day).slice(5))}</text>` : "").join("");
  el.innerHTML = `<svg class="scatter" viewBox="0 0 ${W} ${H}" width="100%"><title>señales/día</title>${grid}<path d="${area}" fill="var(--accent-wash)"/><path d="${path}" fill="none" stroke="var(--accent)" stroke-width="1.5"/>${labs}</svg>`;
}

function renderVelocity(el, data) { lineChart(el, data.series || []); }

async function openDrawer(id) {
  $("#scrim").classList.add("on"); $("#drawer").classList.add("on"); $("#drawer").setAttribute("aria-hidden", "false");
  $("#dbody").innerHTML = '<div class="empty">cargando…</div>';
  const row = IMM.find(x => String(x.id) === String(id));  // trae score + factores del listado
  try {
    const c = await jget("/api/candidate/" + encodeURIComponent(id));
    $("#dtitle").textContent = c.cve_id || ("cand " + String(id).slice(0, 8));
    const cv = (c.cvss && c.cvss[0]) || null;
    const aff = (c.affected || []).map(a => esc([a.vendor, a.product].filter(Boolean).join(" / ") + (a.ecosystem ? " (" + a.ecosystem + ")" : ""))).join("<br>") || "—";
    const tl = (c.timeline || []).slice().sort((a, b) => new Date(a.seen_at) - new Date(b.seen_at));
    const first = tl.length ? tl[0].seen_at : c.first_seen_at;
    let leadHtml = "";
    if (c.days_ahead_present != null) {
      leadHtml = `<div class="lead"><b>${esc(c.days_ahead_present)} días</b> de ventaja sobre la publicación en NVD
        (desde la primera señal del radar).</div>`;
    } else if (c.status !== "published") {
      const age = daysAgo(first);
      leadHtml = `<div class="lead">CVE aún <b>${esc(c.status)}</b> — NVD todavía no ha publicado datos.
        La señal lleva <b>${age != null ? age + " días" : "—"}</b> en el radar. Ventana abierta.</div>`;
    }
    const race = (tl.length ? tl : []).map(e => `<div class="ev"><span class="d">${fmtDate(e.seen_at)}</span>
      <span class="t"><span class="src">${esc(e.source)}</span> — ${esc(e.title || "")}</span></div>`).join("")
      + (c.status === "published"
        ? `<div class="ev fin"><span class="d">meta</span><span class="t">NVD publica el CVE (línea de meta)</span></div>` : "");
    const chips = [];
    if (c.in_kev) chips.push('<span class="chip kev">KEV ' + fmtDate(c.kev_date) + '</span>');
    if (c.has_public_poc) chips.push('<span class="chip poc">PoC público</span>');
    if (cv) chips.push('<span class="chip cvss">CVSS ' + esc(cv.base_score) + ' ' + esc(cv.base_severity || "") + '</span>');
    (c.cwe_ids || []).slice(0, 4).forEach(w => chips.push('<span class="chip">' + esc(w) + '</span>'));
    const refs = (c.reference_urls || []).slice(0, 8).map(u => {
      const s = safeUrl(u);
      return s ? '<a href="' + esc(s) + '" target="_blank" rel="noopener noreferrer">' + esc(u) + '</a>'
               : '<span class="mono">' + esc(u) + '</span>';
    }).join("") || "—";
    $("#dbody").innerHTML = `
      ${leadHtml}
      <div class="chips" style="margin:8px 0">${chips.join("")}</div>
      ${scoreBreakdown(row)}
      <h3>La carrera — señales por orden de llegada</h3>
      <div class="race">${race || '<div class="empty">sin señales</div>'}</div>
      <h3>Software afectado</h3><div class="kv">${aff}</div>
      <h3>CVSS</h3><div class="kv">${cv ? ('<b>' + esc(cv.base_score) + '</b> ' + esc(cv.base_severity || "") + ' · <span class="mono">' + esc(cv.vector || "") + '</span> · ' + esc(cv.provenance) + '/' + esc(cv.source)) : "—"}</div>
      <h3>Identificadores</h3><div class="kv mono">${(c.identifiers || []).map(i => esc(i.scheme + ":" + i.value)).join(" · ") || "—"}</div>
      <h3>Referencias</h3><div class="reflist">${refs}</div>`;
  } catch (e) { $("#dbody").innerHTML = '<div class="empty">error cargando el candidate</div>'; }
}
function closeDrawer() { $("#scrim").classList.remove("on"); $("#drawer").classList.remove("on"); $("#drawer").setAttribute("aria-hidden", "true"); }
$("#scrim").onclick = closeDrawer; $("#dclose").onclick = closeDrawer;
addEventListener("keydown", e => { if (e.key === "Escape") closeDrawer(); });
$("#surface").oninput = e => renderImm(e.target.value);

// Carga por secciones (allSettled): si un endpoint falla, el resto se pinta igual.
async function load() {
  const eps = ["/api/pending/critical?limit=60", "/api/lag/histogram", "/api/stats",
    "/api/trend?months=12", "/api/emerging?limit=100",
    "/api/queue/age", "/api/velocity?days=60", "/api/funnel"];
  const res = await Promise.allSettled(eps.map(jget));
  const val = i => res[i].status === "fulfilled" ? res[i].value : null;
  const [crit, lag, stats, trend, emerging, queue, vel, funnel] =
    [val(0), val(1), val(2), val(3), val(4), val(5), val(6), val(7)];
  const fail = i => `<div class="empty">no disponible</div>`;

  if (crit) { IMM = crit.rows || []; renderImm(""); } else { $("#imm").innerHTML = fail(); }

  const imminent = IMM.filter(r => (r.score || 0) >= 60).length;
  const today = new Date().toISOString().slice(0, 10);
  const newToday = ((emerging && emerging.rows) || []).filter(r => String(r.first_seen_at || "").slice(0, 10) === today).length;
  $("#kpis").innerHTML = [
    { n: crit ? imminent : "—", c: "crit", l: "Inminentes ahora", s: "score ≥ 60 · exploit/KEV/severidad" },
    { n: lag && lag.median != null ? lag.median : "—", c: "good", l: "Ventaja mediana (días)", s: "p90 = " + (lag && lag.p90 != null ? lag.p90 : "—") + " · n=" + (lag ? lag.count || 0 : "—") },
    { n: emerging ? newToday : "—", c: "", l: "Nuevos hoy en el radar", s: "primera detección = hoy" },
    { n: funnel ? (funnel.pre_cve + funnel.cve_prereserved + funnel.cve_reserved).toLocaleString() : "—", c: "", l: "Pendientes de NVD", s: "pre-CVE " + (funnel ? funnel.pre_cve.toLocaleString() : "—") + " · desde " + (funnel ? monthYear(funnel.operational_start) : "—") },
  ].map(k => `<div class="kpi"><div class="n ${k.c}">${k.n}</div><div class="l">${k.l}</div><div class="s">${k.s}</div></div>`).join("");

  // Pirámide: embudo COHERENTE desde el arranque real (misma población y ventana
  // en las 4 capas), de /api/funnel. Muestra la fecha de arranque para aclararlo.
  const f = funnel || {};
  const setk = (id, v) => { const e = document.getElementById(id); if (e) e.textContent = v == null ? "—" : Number(v).toLocaleString(); };
  setk("sk-pre_cve", f.pre_cve);
  setk("sk-cve_prereserved", f.cve_prereserved);
  setk("sk-cve_reserved", f.cve_reserved);
  setk("sk-published", f.published);
  const sinceEl = document.getElementById("pyr-since");
  if (sinceEl) sinceEl.textContent = f.operational_start
    ? "Todas las cifras: población detectada desde el " + fmtLongDate(f.operational_start) + " (arranque de Foreshock)"
    : "";

  if (lag) renderLag($("#lag"), $("#lag-head"), lag); else $("#lag").innerHTML = fail();
  if (stats) {
    const ss = (stats.sources || []).slice().sort((a, b) => parseFloat(b.avg_days) - parseFloat(a.avg_days)).slice(0, 12);
    barChart($("#srcs"), ss.map(s => ({ label: s.source, v: parseFloat(s.avg_days), color: "var(--m2)" })), { fmt: v => v.toFixed(1) + "d" });
  } else $("#srcs").innerHTML = fail();
  if (trend) {
    renderTrend($("#trend"), (trend.series || []).slice(-6));
    renderEvolution($("#evo"), trend.series || []);
  } else { $("#trend").innerHTML = fail(); $("#evo").innerHTML = fail(); }
  if (queue) renderQueueAge($("#queue"), $("#queue-head"), queue); else $("#queue").innerHTML = fail();
  if (vel) renderVelocity($("#x-vel"), vel); else $("#x-vel").innerHTML = fail();
}
load();
