"use strict";
const $ = s => document.querySelector(s);
const SVGNS = "http://www.w3.org/2000/svg";
const el = (n, a) => { const e = document.createElementNS(SVGNS, n); for (const k in a) e.setAttribute(k, a[k]); return e; };
const css = v => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
const fmtN = n => (n == null ? "—" : Number(n).toLocaleString());

// TODO dato externo (títulos, paquetes OSV, mensajes de commit…) pasa por esc()
// antes de interpolarse en innerHTML: cubre texto Y atributos (comillas incluidas).
function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
// Solo se enlazan URLs http(s); cualquier otro esquema (javascript:, data:…)
// se muestra como texto plano.
function safeUrl(u) { const s = String(u ?? ""); return /^https?:\/\//i.test(s) ? s : null; }

const state = { gran: "month", months: 12, kind: "product", tech: "", period: null };
let SERIES = [];

async function j(url) { const r = await fetch(url); if (!r.ok) throw new Error(r.status); return r.json(); }
function qs(obj) { return Object.entries(obj).filter(([, v]) => v != null && v !== "")
  .map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join("&"); }

async function loadAll() {
  const t = await j(`/api/trend?${qs({ granularity: state.gran, months: state.months, kind: state.kind, tech: state.tech })}`);
  SERIES = t.series;
  drawChart();
  await Promise.all([loadPending(), loadEmerging()]);
  $("#chartnote").textContent =
    "Publicados = CVEs oficiales (cvelist). Pre-publicados = CVEs identificados en otras fuentes " +
    "que NVD aún no ha publicado, por primera detección. " +
    (state.period ? `Filtrando por ${state.period}. ` : "") +
    "OSV/GitHub tienen ventana de captación: los periodos antiguos pueden estar sesgados.";
}

// ---------- chart ----------
const W = 960, H = 190, mL = 52, mR = 14, mT = 12, mB = 26;
const iw = W - mL - mR, ih = H - mT - mB;
const xAt = (i, n) => mL + (n <= 1 ? 0 : i * iw / (n - 1));
function ticks(max) { const raw = max / 4 || 1, p = Math.pow(10, Math.floor(Math.log10(raw)));
  const step = [1, 2, 2.5, 5, 10].map(s => s * p).find(s => s >= raw) || 10 * p;
  const top = Math.max(step, Math.ceil(max / step) * step), t = []; for (let v = 0; v <= top + 1e-9; v += step) t.push(v); return { t, top }; }

function panel(svgId, key, color, fillVar) {
  const svg = $(svgId); svg.innerHTML = "";
  const periods = SERIES.map(d => d.period), n = periods.length;
  const vals = SERIES.map(d => d[key]); const max = Math.max(1, ...vals);
  const { t, top } = ticks(max); const y = v => mT + ih - (v / top) * ih;
  const g = el("g", {});
  const grid = el("g", { class: "grid" }), axis = el("g", { class: "axis" });
  t.forEach(tv => { grid.appendChild(el("line", { x1: mL, y1: y(tv), x2: W - mR, y2: y(tv), "stroke-width": 1 }));
    const tx = el("text", { x: mL - 8, y: y(tv) + 3.5, "text-anchor": "end" }); tx.textContent = tv >= 1000 ? (tv / 1000) + "k" : tv; axis.appendChild(tx); });
  periods.forEach((p, i) => { if (n > 14 && i % 2 && i !== n - 1) return;
    const tx = el("text", { x: xAt(i, n), y: H - 8, "text-anchor": "middle" }); tx.textContent = p.length > 4 ? p.slice(2) : p; axis.appendChild(tx); });
  g.appendChild(grid);
  // area + line
  let dp = `M${xAt(0, n)} ${y(0)} `, dl = "";
  SERIES.forEach((d, i) => { const px = xAt(i, n), py = y(d[key]); dp += `L${px} ${py} `; dl += (i ? "L" : "M") + px + " " + py + " "; });
  dp += `L${xAt(n - 1, n)} ${y(0)} Z`;
  g.appendChild(el("path", { d: dp, fill: `var(${fillVar})` }));
  g.appendChild(el("path", { d: dl, fill: "none", stroke: color, "stroke-width": 2, "stroke-linejoin": "round" }));
  SERIES.forEach((d, i) => { const c = el("circle", { cx: xAt(i, n), cy: y(d[key]), r: state.period === d.period ? 4.5 : 2.6, fill: color }); g.appendChild(c); });
  g.appendChild(el("line", { x1: mL, y1: y(0), x2: W - mR, y2: y(0), stroke: css("--hair") }));
  const ch = el("line", { class: "crosshair", x1: 0, y1: mT, x2: 0, y2: mT + ih, "stroke-width": 1 }); g.appendChild(ch);
  svg.appendChild(g); svg._ch = ch; svg._y = y;
}
function drawChart() {
  panel("#s-pub", "published", css("--pub"), "--pub-fill");
  panel("#s-pre", "pre_published", css("--pre"), "--pre-fill");
}
const fig = $("#fig"), tt = $("#tt");
function nearest(clientX) { const r = $("#s-pub").getBoundingClientRect(); const px = (clientX - r.left) / r.width * W;
  let bi = 0, bd = 1e9; SERIES.forEach((d, i) => { const dd = Math.abs(px - xAt(i, SERIES.length)); if (dd < bd) { bd = dd; bi = i; } }); return bi; }
fig.addEventListener("mousemove", e => {
  if (!SERIES.length) return; const i = nearest(e.clientX), n = SERIES.length, x = xAt(i, n);
  ["#s-pub", "#s-pre"].forEach(id => { const s = $(id); s._ch.setAttribute("x1", x); s._ch.setAttribute("x2", x); s._ch.style.opacity = 1; });
  const r = $("#s-pub").getBoundingClientRect(), fr = fig.getBoundingClientRect();
  tt.style.left = (r.left - fr.left + x / W * r.width) + "px"; tt.style.top = (r.top - fr.top + 6) + "px"; tt.style.opacity = 1;
  const d = SERIES[i];
  tt.innerHTML = `<div class="m">${esc(d.period)}</div>
    <div class="row"><span>Publicados</span><b>${fmtN(d.published)}</b></div>
    <div class="row"><span>Pre-publicados</span><b>${fmtN(d.pre_published)}</b></div>`;
});
fig.addEventListener("mouseleave", () => { tt.style.opacity = 0; ["#s-pub", "#s-pre"].forEach(id => $(id)._ch.style.opacity = 0); });
fig.addEventListener("click", e => {
  if (!SERIES.length) return; const i = nearest(e.clientX); const p = SERIES[i].period;
  state.period = state.period === p ? null : p; drawChart();
  $("#hint").textContent = state.period ? `— filtrado por ${state.period} (clic de nuevo para quitar)` : "— clic en un periodo para filtrar las tablas";
  loadPending(); loadEmerging();
});

// ---------- tables ----------
// Sin handlers inline (los bloquea la CSP y obligarían a escapar contexto JS):
// las filas llevan data-* escapado y un listener delegado por tabla.
async function loadPending() {
  const d = await j(`/api/pending?${qs({ kind: state.kind, top: 25, tech: state.tech, period: state.period, granularity: state.gran })}`);
  $("#pcount").textContent = `· ${fmtN(d.total)} pendientes (product=${d.by_kind.product || 0} · malware=${d.by_kind.malware || 0} · distro=${d.by_kind.distro || 0})`;
  $("#ptbody").innerHTML = d.top.map(r =>
    `<tr data-software="${esc(r.software)}"><td>${esc(r.software)}</td><td class="num">${fmtN(r.pending)}</td></tr>`).join("")
    || `<tr><td colspan="2" class="muted">sin datos</td></tr>`;
}
async function loadEmerging() {
  const d = await j(`/api/emerging?${qs({ pending_only: true, tech: state.tech, kind: state.kind, period: state.period, granularity: state.gran, page_size: 60 })}`);
  $("#ecount").textContent = `· ${fmtN(d.total)}`;
  $("#etbody").innerHTML = d.rows.map(r => {
    const label = r.cve_id || (r.id.slice(0, 8) + "…");
    const kev = r.in_kev ? '<span class="pill kev">KEV</span>' : "";
    const sev = r.cvss != null ? r.cvss : (r.severity_hint || "");
    return `<tr data-key="${esc(r.cve_id || r.id)}"><td class="mono">${esc(label)} ${kev}</td>
      <td>${r.vuln_type ? esc(r.vuln_type) : '<span class="muted">—</span>'}</td><td class="num">${esc(sev)}</td>
      <td class="num">${fmtN(r.source_count)}</td><td class="muted">${esc((r.sources || "").split(",")[0] || "")}</td></tr>`;
  }).join("") || `<tr><td colspan="5" class="muted">sin datos</td></tr>`;
}
$("#ptbody").addEventListener("click", e => {
  const tr = e.target.closest("tr[data-software]");
  if (tr) openSoftware(tr.dataset.software);
});
$("#etbody").addEventListener("click", e => {
  const tr = e.target.closest("tr[data-key]");
  if (tr) openCandidate(tr.dataset.key);
});

// ---------- drawer (deepdive) ----------
const drawer = $("#drawer"), dbody = $("#dbody");
function closeDrawer() { drawer.classList.remove("open"); }
$("#dclose").addEventListener("click", closeDrawer);
// Las filas generadas dentro del drawer también navegan por delegación.
dbody.addEventListener("click", e => {
  const tr = e.target.closest("tr[data-key]");
  if (tr) openCandidate(tr.dataset.key);
});
async function openCandidate(key) {
  drawer.classList.add("open"); dbody.innerHTML = "<p class='muted'>cargando…</p>";
  const d = await j(`/api/candidate/${encodeURIComponent(key)}`);
  const cvss = d.cvss.map(c => `${esc(c.version)} <b>${esc(c.base_score ?? "?")}</b> ${esc(c.base_severity || "")} <span class="muted">(${esc(c.provenance)}/${esc(c.source)})</span>`).join("<br>") || "—";
  const aff = d.affected.map(a => `${a.ecosystem ? esc(a.ecosystem) + ":" : ""}${esc(a.product)} <span class="muted">${esc(a.kind || "")}</span>`).join("<br>") || "—";
  const tl = d.timeline.map(t => {
    const u = safeUrl(t.url);
    const link = u ? `<a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(u.slice(0, 60))}</a>`
      : (t.url ? `<span class="mono">${esc(String(t.url).slice(0, 60))}</span>` : "");
    return `<div class="ev"><div class="d">${esc((t.seen_at || "").slice(0, 16).replace("T", " "))} · ${esc(t.source)}</div>
    <div>${esc(t.title)}</div>${link}</div>`;
  }).join("");
  dbody.innerHTML = `<h3>${esc(d.cve_id || "(pre-CVE)")} ${d.in_kev ? '<span class="pill kev">KEV</span>' : ""}</h3>
    <div class="kv"><b>estado</b>${esc(d.status)}</div>
    <div class="kv"><b>tipo / vector</b>${esc(d.vuln_type || "—")} / ${esc(d.attack_vector || "—")}</div>
    <div class="kv"><b>PoC público</b>${d.has_public_poc ? "sí" : "—"}</div>
    <div class="kv"><b>días ventaja NVD</b>present=${esc(d.days_ahead_present ?? "—")} · analyzed=${esc(d.days_ahead_analyzed ?? "—")}</div>
    <div class="kv"><b>EPSS</b>${d.epss ? esc(d.epss.score + " (pct " + d.epss.percentile + ")") : "—"}</div>
    <div class="kv"><b>CWE</b>${esc((d.cwe_ids || []).join(", ") || "—")}</div>
    <div class="kv"><b>CVSS</b><div>${cvss}</div></div>
    <div class="kv"><b>afectados</b><div>${aff}</div></div>
    <div class="kv"><b>ids</b><div class="mono">${esc(d.identifiers.map(i => i.scheme + ":" + i.value).join(" · "))}</div></div>
    <h4>Timeline</h4><div class="tl">${tl || '<span class="muted">—</span>'}</div>`;
}
async function openSoftware(name) {
  drawer.classList.add("open"); dbody.innerHTML = "<p class='muted'>cargando…</p>";
  let eco = "", prod = name;
  if (name.includes(":")) { [eco, prod] = name.split(":", 2); }
  const d = await j(`/api/software?${qs({ name: prod, ecosystem: eco, granularity: state.gran, months: state.months })}`);
  const rows = d.candidates.slice(0, 60).map(c => `<tr data-key="${esc(c.cve_id || c.id)}">
    <td class="mono">${esc(c.cve_id || c.id.slice(0, 8))}</td><td>${c.pending ? '<span class="pill pre">pendiente</span>' : (c.cve_id ? "publicado" : "pre-CVE")}</td>
    <td>${c.in_kev ? '<span class="pill kev">KEV</span>' : ""}</td></tr>`).join("");
  dbody.innerHTML = `<h3>${esc(name)}</h3>
    <div class="kv"><b>total identificados</b>${fmtN(d.total)}</div>
    <div class="kv"><b>pendientes (NVD aún sin publicar)</b>${fmtN(d.pending)}</div>
    <h4>Vulnerabilidades</h4>
    <table><thead><tr><th>CVE/id</th><th>Estado</th><th></th></tr></thead><tbody>${rows}</tbody></table>`;
}

// ---------- controls ----------
$("#gran").addEventListener("click", e => { if (e.target.dataset.v) {
  [...$("#gran").children].forEach(b => b.classList.toggle("on", b === e.target));
  state.gran = e.target.dataset.v; } });
$("#apply").addEventListener("click", () => {
  state.months = +$("#months").value; state.kind = $("#kind").value; state.tech = $("#tech").value.trim();
  state.period = null; $("#hint").textContent = "— clic en un periodo para filtrar las tablas"; loadAll();
});
loadAll();
