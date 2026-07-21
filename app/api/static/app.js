"use strict";
/* Dashboard Foreshock — consume la API local de solo lectura.
 * TODO el texto dinámico (títulos, paquetes, mensajes de commit…) entra al DOM
 * con textContent/createElement, nunca por interpolación en innerHTML. */

const $ = s => document.querySelector(s);
const SVGNS = "http://www.w3.org/2000/svg";
const fmt = n => n == null ? "—" : Number(n).toLocaleString("es-ES");
const fmtD = iso => (iso || "").slice(0, 10);
/* Periodos legibles: "2026-07" -> "07/26", "2026-W29" -> "s29/26", "2026" -> "2026". */
function fmtP(p) {
  p = String(p || "");
  if (/^\d{4}-\d{2}$/.test(p)) return p.slice(5, 7) + "/" + p.slice(2, 4);
  if (/^\d{4}-W\d{2}$/.test(p)) return "s" + p.slice(6) + "/" + p.slice(2, 4);
  return p;
}
/* Semana ISO de una fecha ISO ("2026-07-15…") -> "2026-W29". */
function isoWeekKey(iso) {
  const d = new Date(iso.slice(0, 10) + "T00:00:00Z");
  d.setUTCDate(d.getUTCDate() - ((d.getUTCDay() + 6) % 7) + 3);   // jueves ISO
  const y = d.getUTCFullYear(), jan4 = new Date(Date.UTC(y, 0, 4));
  const week = 1 + Math.round(((d - jan4) / 86400000 - 3 + ((jan4.getUTCDay() + 6) % 7)) / 7);
  return y + "-W" + String(week).padStart(2, "0");
}

async function j(url) { const r = await fetch(url); if (!r.ok) throw new Error(url + " → " + r.status); return r.json(); }
function qs(obj) { return Object.entries(obj).filter(([, v]) => v != null && v !== "" && v !== false)
  .map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join("&"); }
// Solo se enlazan URLs http(s); cualquier otro esquema se muestra como texto.
function safeUrl(u) { const s = String(u ?? ""); return /^https?:\/\//i.test(s) ? s : null; }

/* ================= tema claro/oscuro ================= */
const THEME_KEY = "foreshock-theme";      // "dark" | "light" | ausente = auto (SO)
function applyTheme(v) {
  if (v === "dark" || v === "light") document.documentElement.setAttribute("data-theme", v);
  else document.documentElement.removeAttribute("data-theme");
  $("#themebtn").textContent = "Tema: " + (v === "dark" ? "oscuro" : v === "light" ? "claro" : "auto");
}
applyTheme(localStorage.getItem(THEME_KEY));
$("#themebtn").addEventListener("click", () => {
  const cur = localStorage.getItem(THEME_KEY);
  const next = cur === null ? "dark" : cur === "dark" ? "light" : null;   // auto → oscuro → claro → auto
  if (next) localStorage.setItem(THEME_KEY, next); else localStorage.removeItem(THEME_KEY);
  applyTheme(next);
});

/* ================= madurez ================= */
const MAT = {
  pre_cve:        { label: "pre-CVE",           cls: "f-m1", varn: "--m1" },
  cve_prereserved:{ label: "CVE pre-reservado", cls: "f-m2", varn: "--m2" },
  cve_reserved:   { label: "CVE reservado",     cls: "f-m3", varn: "--m3" },
};
const MK = Object.keys(MAT);
const SURGE_PERIOD = "2026-03";           // inflexión observada en publicaciones oficiales

/* ================= estado ================= */
const state = { win: "ytd", gran: "month", mat: "all", period: null,
                tech: "", kind: "all", source: "", kevOnly: false, cvssMin: 0,
                sgran: "week" };            // eje temporal de la inspección
const CAPS = { week: false, days: false };  // se sondea contra la API al arrancar
function winParams() {
  switch (state.win) {
    case "w1": return { days: 7 };
    case "m1": return { months: 1 };
    case "m6": return { months: 6 };
    case "12": return { months: 12 };
    case "24": return { months: 24 };
    default: {                              // "2026": meses transcurridos del año
      const now = new Date();
      return { months: Math.max(1, (now.getFullYear() - 2026) * 12 + now.getMonth() + 1) };
    }
  }
}

/* datos vivos */
let TREND = [];     // serie de la ventana (con desglose de madurez)
let CTXS = [];      // serie fija de 24 m para la gráfica de contexto
const ctx = { a: 0, b: 0 };
let ROWS = [];      // emerging de la selección

/* ================= helpers svg ================= */
function el(n, a, parent) {
  const e = document.createElementNS(SVGNS, n);
  for (const k in a) e.setAttribute(k, a[k]);
  if (parent) parent.appendChild(e);
  return e;
}
function txt(e, s) { e.textContent = s; return e; }
function ticks(max, k = 4) {
  const raw = max / k || 1, p = Math.pow(10, Math.floor(Math.log10(raw)));
  const step = [1, 2, 2.5, 5, 10].map(s => s * p).find(s => s >= raw) || 10 * p;
  const top = Math.max(step, Math.ceil(max / step) * step);
  const t = []; for (let v = 0; v <= top + 1e-9; v += step) t.push(v);
  return { t, top };
}
function roundTopRect(x, y, w, h, r) {
  if (h <= r) r = Math.max(0, h - .5);
  return r ? `M${x} ${y + h} V${y + r} Q${x} ${y} ${x + r} ${y} H${x + w - r} Q${x + w} ${y} ${x + w} ${y + r} V${y + h} Z`
           : `M${x} ${y} h${w} v${h} h${-w} Z`;
}
const tt = $("#tt");
function showTT(x, y, head, rows) {
  tt.replaceChildren();
  const h = document.createElement("div"); h.className = "h"; h.textContent = head; tt.appendChild(h);
  rows.forEach(([kcolor, label, value]) => {
    const r = document.createElement("div"); r.className = "r";
    const l = document.createElement("span");
    if (kcolor) { const k = document.createElement("span"); k.className = "key";
      k.style.background = `var(${kcolor})`; l.appendChild(k); l.appendChild(document.createTextNode(" ")); }
    l.appendChild(document.createTextNode(label));
    const v = document.createElement("b"); v.textContent = value;
    r.append(l, v); tt.appendChild(r);
  });
  tt.style.opacity = 1;
  const w = tt.offsetWidth;
  tt.style.left = Math.min(Math.max(8, x - w / 2), innerWidth - w - 8) + "px";
  tt.style.top = (y - tt.offsetHeight - 12) + "px";
}
function hideTT() { tt.style.opacity = 0; }

/* Franja de anotación «desde mar 2026» (solo granularidad mensual). */
function annotate(svg, periods, xAt, mT, ih, label) {
  const i = periods.indexOf(SURGE_PERIOD);
  if (i < 0) return;
  const x = xAt(i);
  el("rect", { x, y: mT, width: Math.max(0, xAt(periods.length - 1) - x), height: ih,
               class: "ann-band" }, svg);
  el("line", { x1: x, y1: mT, x2: x, y2: mT + ih, class: "ann-line" }, svg);
  if (label) txt(el("text", { x: x + 5, y: mT + 11, class: "ann-tag" }, svg), "▲ mar 2026");
}

/* ================= gráfica: columnas apiladas por madurez ================= */
function drawMat() {
  const svg = $("#c-mat"); svg.replaceChildren();
  const data = TREND;
  if (!data.length) return;
  const W = 940, H = 250, mL = 46, mR = 14, mT = 14, mB = 30;
  const iw = W - mL - mR, ih = H - mT - mB;
  const totals = data.map(d => d.pre_cve + d.cve_prereserved + d.cve_reserved);
  const { t, top } = ticks(Math.max(...totals, 1));
  const y = v => mT + ih - v / top * ih;
  t.forEach(v => {
    el("line", { x1: mL, y1: y(v), x2: W - mR, y2: y(v), class: v === 0 ? "baseline" : "gridline" }, svg);
    txt(el("text", { x: mL - 8, y: y(v) + 3.5, "text-anchor": "end", class: "axis" }, svg), fmt(v));
  });
  const band = iw / data.length, bw = Math.min(24, band * .55);
  annotate(svg, data.map(d => d.period), i => mL + band * i + (band - bw) / 2 - 3, mT, ih, true);
  data.forEach((d, i) => {
    const x = mL + band * i + (band - bw) / 2;
    const vals = [d.pre_cve, d.cve_prereserved, d.cve_reserved];
    const isSel = state.period === d.period;
    let acc = 0;
    const segs = [];
    MK.forEach((k, ki) => { if (vals[ki]) { segs.push({ k, v: vals[ki], y0: acc }); acc += vals[ki]; } });
    segs.forEach((s, si) => {
      const yTop = y(s.y0 + s.v), yBot = y(s.y0);
      const hpx = Math.max(1.5, yBot - yTop - (si < segs.length - 1 ? 2 : 0));  // hueco 2px
      const r = el("path", { class: MAT[s.k].cls,
        d: roundTopRect(x, yTop, bw, hpx, si === segs.length - 1 ? 4 : 0) }, svg);
      if (state.mat !== "all" && state.mat !== s.k) r.setAttribute("opacity", ".25");
    });
    if (isSel) el("rect", { x: x - 3, y: y(acc) - 3, width: bw + 6, height: y(0) - y(acc) + 3, rx: 5, class: "col-sel" }, svg);
    if (data.length <= 26 && (data.length <= 13 || i % 2 === (data.length - 1) % 2))
      txt(el("text", { x: x + bw / 2, y: H - 9, "text-anchor": "middle", class: "axis" }, svg), fmtP(d.period));
    if (i === data.length - 1)
      txt(el("text", { x: x + bw / 2, y: y(acc) - 7, "text-anchor": "middle", class: "dlabel" }, svg), fmt(acc));
    const hit = el("rect", { x: mL + band * i, y: mT, width: band, height: ih, class: "colhit",
      tabindex: 0, role: "button", "aria-label": d.period + ": " + fmt(acc) + " pendientes" }, svg);
    hit.addEventListener("pointermove", ev => showTT(ev.clientX, ev.clientY, fmtP(d.period),
      MK.map((k, ki) => [MAT[k].varn, MAT[k].label, fmt(vals[ki])]).concat([[null, "Total", fmt(acc)]])));
    hit.addEventListener("pointerleave", hideTT);
    const sel = () => { state.period = state.period === d.period ? null : d.period; applyAll(); };
    hit.addEventListener("click", sel);
    hit.addEventListener("keydown", ev => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); sel(); } });
  });
}

/* ================= paneles de línea (contexto, con zoom) ================= */
function drawLinePanel(id, data, get, lineCls, washCls, dotCls) {
  const svg = $(id); svg.replaceChildren();
  if (!data.length) return;
  const W = 940, H = 150, mL = 46, mR = 56, mT = 12, mB = 22;
  const iw = W - mL - mR, ih = H - mT - mB;
  const n = data.length;
  const xa = i => mL + (n <= 1 ? iw / 2 : i * iw / (n - 1));
  const { t, top } = ticks(Math.max(...data.map(get), 1), 3);
  const y = v => mT + ih - v / top * ih;
  annotate(svg, data.map(d => d.period), xa, mT, ih, false);
  t.forEach(v => {
    el("line", { x1: mL, y1: y(v), x2: W - mR, y2: y(v), class: v === 0 ? "baseline" : "gridline" }, svg);
    txt(el("text", { x: mL - 8, y: y(v) + 3.5, "text-anchor": "end", class: "axis" }, svg),
        v >= 1000 ? (v / 1000) + "k" : fmt(v));
  });
  data.forEach((d, i) => { if (n <= 13 || i % 2 === (n - 1) % 2)
    txt(el("text", { x: xa(i), y: H - 6, "text-anchor": "middle", class: "axis" }, svg), fmtP(d.period)); });
  let area = `M${xa(0)} ${y(0)}`, line = "";
  data.forEach((d, i) => { const px = xa(i), py = y(get(d)); area += ` L${px} ${py}`; line += (i ? " L" : "M") + px + " " + py; });
  area += ` L${xa(n - 1)} ${y(0)} Z`;
  el("path", { d: area, class: washCls }, svg);
  el("path", { d: line, class: lineCls }, svg);
  const last = get(data[n - 1]);
  el("circle", { cx: xa(n - 1), cy: y(last), r: 4.5, class: dotCls + " ring" }, svg);
  txt(el("text", { x: xa(n - 1) + 9, y: y(last) + 4, class: "dlabel" }, svg), fmt(last));
  svg._x = xa;
  svg._ch = el("line", { x1: 0, x2: 0, y1: mT, y2: mT + ih, class: "crossh" }, svg);
}
function ctxData() { return CTXS.slice(ctx.a, ctx.b); }
function renderCtx() {
  const data = ctxData();
  if (!data.length) return;
  drawLinePanel("#c-pub", data, d => d.published, "l-ctx", "wash-ctx", "f-ctx");
  drawLinePanel("#c-pre", data, d => d.pre_published, "l-acc", "wash-acc", "f-acc");
  $("#ctx-note").textContent = `Mostrando ${fmtP(data[0].period)} → ${fmtP(data[data.length - 1].period)}`;
  const n = ctx.b - ctx.a, isPreset = ctx.b === CTXS.length && [6, 12, 24].includes(n);
  [...$("#ctx-win").children].forEach(b => b.classList.toggle("on", isPreset && +b.dataset.v === n));
}
/* Indicadores del incremento: media mensual desde mar 2026 (meses completos)
 * frente a la media del semestre anterior. */
function renderSurge() {
  const complete = CTXS.slice(0, -1);            // el mes en curso está incompleto
  const i = complete.findIndex(d => d.period === SURGE_PERIOD);
  if (i < 3) { $("#surge-pub").hidden = true; $("#surge-pre").hidden = true; return; }
  const since = complete.slice(i), base = complete.slice(Math.max(0, i - 6), i);
  const mean = (arr, k) => arr.reduce((a, d) => a + d[k], 0) / arr.length;
  const mk = (id, label, k) => {
    const b = mean(base, k), s = mean(since, k);
    if (!b) { $(id).hidden = true; return; }
    const ratio = s / b, chip = $(id);
    chip.replaceChildren();
    chip.appendChild(document.createTextNode(label + " desde mar 2026: "));
    const bb = document.createElement("b");
    bb.textContent = ratio >= 2 ? "×" + ratio.toFixed(1) : (ratio >= 1 ? "+" : "") + Math.round((ratio - 1) * 100) + " %";
    chip.appendChild(bb);
    chip.hidden = false;
  };
  mk("#surge-pub", "Publicados", "published");
  mk("#surge-pre", "Pendientes", "pre_published");
}
function nearestCtxIndex(clientX, svg) {
  const data = ctxData(), r = svg.getBoundingClientRect();
  const px = (clientX - r.left) / r.width * 940;
  let bi = 0, bd = 1e9;
  data.forEach((d, i) => { const dd = Math.abs(px - svg._x(i)); if (dd < bd) { bd = dd; bi = i; } });
  return bi;
}
function bindCrosshair() {
  const wrapEl = $("#twopanel"), svgs = ["#c-pub", "#c-pre"].map(s => $(s));
  let drag = null;
  const band = document.createElement("div");
  band.style.cssText = "position:absolute;top:0;bottom:0;background:var(--accent-wash);" +
    "border-left:1px solid var(--accent);border-right:1px solid var(--accent);display:none;pointer-events:none";
  wrapEl.appendChild(band);
  wrapEl.addEventListener("pointerdown", ev => {
    if (ctxData().length < 3) return;
    drag = { x0: ev.clientX, i0: nearestCtxIndex(ev.clientX, svgs[0]), moved: false };
    wrapEl.setPointerCapture(ev.pointerId);
  });
  wrapEl.addEventListener("pointermove", ev => {
    const data = ctxData(); if (!data.length || !svgs[0]._x) return;
    if (drag) {
      if (Math.abs(ev.clientX - drag.x0) > 6) drag.moved = true;
      if (drag.moved) {
        const wr = wrapEl.getBoundingClientRect();
        band.style.left = (Math.min(drag.x0, ev.clientX) - wr.left) + "px";
        band.style.width = Math.abs(ev.clientX - drag.x0) + "px";
        band.style.display = "block";
        hideTT(); return;
      }
    }
    const bi = nearestCtxIndex(ev.clientX, svgs[0]);
    const x = svgs[0]._x(bi);
    svgs.forEach(s => { if (!s._ch) return; s._ch.setAttribute("x1", x); s._ch.setAttribute("x2", x); s._ch.style.opacity = 1; });
    const d = data[bi];
    showTT(ev.clientX, ev.clientY, fmtP(d.period), [
      ["--ctx", "Publicados NVD", fmt(d.published)],
      ["--accent", "Pendientes", fmt(d.pre_published)],
    ]);
  });
  wrapEl.addEventListener("pointerup", ev => {
    if (drag && drag.moved) {
      const i1 = nearestCtxIndex(ev.clientX, svgs[0]);
      const lo = Math.min(drag.i0, i1), hi = Math.max(drag.i0, i1);
      if (hi - lo >= 1) { const base = ctx.a; ctx.a = base + lo; ctx.b = base + hi + 1; renderCtx(); }
    }
    drag = null; band.style.display = "none";
  });
  wrapEl.addEventListener("dblclick", () => { ctx.a = Math.max(0, CTXS.length - 12); ctx.b = CTXS.length; renderCtx(); });
  wrapEl.addEventListener("pointerleave", () => { hideTT(); svgs.forEach(s => { if (s._ch) s._ch.style.opacity = 0; }); });
  $("#ctx-win").addEventListener("click", ev => {
    const b = ev.target.closest("button[data-v]"); if (!b) return;
    ctx.a = Math.max(0, CTXS.length - +b.dataset.v); ctx.b = CTXS.length; renderCtx();
  });
}

/* ================= histograma de ventaja + fuentes + cola ================= */
function drawHist(lag) {
  const svg = $("#c-hist"); svg.replaceChildren();
  const bins = lag.bins;
  const W = 520, H = 222, mL = 40, mR = 10, mT = 14, mB = 42;
  const iw = W - mL - mR, ih = H - mT - mB;
  const max = Math.max(...bins.map(d => d.count), 1);
  const { t, top } = ticks(max, 3);
  const y = v => mT + ih - v / top * ih;
  t.forEach(v => {
    el("line", { x1: mL, y1: y(v), x2: W - mR, y2: y(v), class: v === 0 ? "baseline" : "gridline" }, svg);
    txt(el("text", { x: mL - 7, y: y(v) + 3.5, "text-anchor": "end", class: "axis" }, svg), fmt(v));
  });
  const band = iw / bins.length, bw = Math.min(24, band * .5);
  bins.forEach((d, i) => {
    const x = mL + band * i + (band - bw) / 2;
    el("path", { d: roundTopRect(x, y(d.count), bw, y(0) - y(d.count), 4), class: "f-acc" }, svg);
    txt(el("text", { x: mL + band * i + band / 2, y: H - 26, "text-anchor": "middle", class: "axis" }, svg), d.label);
    if (d.count === max)
      txt(el("text", { x: x + bw / 2, y: y(d.count) - 6, "text-anchor": "middle", class: "dlabel" }, svg), fmt(d.count));
    const hit = el("rect", { x: mL + band * i, y: mT, width: band, height: ih, class: "colhit" }, svg);
    hit.addEventListener("pointermove", ev => showTT(ev.clientX, ev.clientY, d.label + " días", [[null, "CVEs", fmt(d.count)]]));
    hit.addEventListener("pointerleave", hideTT);
  });
  txt(el("text", { x: mL + iw / 2, y: H - 7, "text-anchor": "middle", class: "axis" }, svg),
      "días de antelación conseguidos →");
  const note = $("#lag-note"); note.replaceChildren();
  note.appendChild(document.createTextNode("Mediana "));
  let b = document.createElement("b"); b.textContent = fmt(lag.median) + " días"; note.appendChild(b);
  note.appendChild(document.createTextNode(": la mitad de los CVEs se conocieron aquí al menos esa antelación. p90 "));
  b = document.createElement("b"); b.textContent = fmt(lag.p90) + " días"; note.appendChild(b);
  note.appendChild(document.createTextNode(`. ${fmt(lag.count)} CVEs publicados en los últimos ${lag.months} meses; se excluyen fuentes con backfill histórico.`));
}
function drawQueue(qa) {
  const svg = $("#c-queue"); svg.replaceChildren();
  const bins = qa.unassigned.bins.map((d, i) => ({ b: d.label, sin: d.count, con: qa.assigned.bins[i]?.count ?? 0 }));
  const W = 940, H = 260, mL = 50, mR = 14, mT = 16, mB = 44;
  const iw = W - mL - mR, ih = H - mT - mB;
  const max = Math.max(...bins.flatMap(d => [d.sin, d.con]), 1);
  const { t, top } = ticks(max);
  const y = v => mT + ih - v / top * ih;
  t.forEach(v => {
    el("line", { x1: mL, y1: y(v), x2: W - mR, y2: y(v), class: v === 0 ? "baseline" : "gridline" }, svg);
    txt(el("text", { x: mL - 8, y: y(v) + 3.5, "text-anchor": "end", class: "axis" }, svg),
        v >= 1000 ? (v / 1000).toLocaleString("es-ES") + "k" : fmt(v));
  });
  const band = iw / bins.length, bw = Math.min(24, band * .18);
  bins.forEach((d, i) => {
    const cx = mL + band * i + band / 2;
    el("path", { d: roundTopRect(cx - bw - 1, y(d.sin), bw, y(0) - y(d.sin), 4), class: "f-m1" }, svg);
    el("path", { d: roundTopRect(cx + 1, y(d.con), bw, y(0) - y(d.con), 4), class: "f-m2" }, svg);
    txt(el("text", { x: cx, y: H - 26, "text-anchor": "middle", class: "axis" }, svg), d.b);
    if (d.sin === max)
      txt(el("text", { x: cx - bw / 2 - 1, y: y(d.sin) - 6, "text-anchor": "middle", class: "dlabel" }, svg), fmt(d.sin));
    const hit = el("rect", { x: mL + band * i, y: mT, width: band, height: ih, class: "colhit" }, svg);
    hit.addEventListener("pointermove", ev => showTT(ev.clientX, ev.clientY, d.b + " días esperando", [
      ["--m1", "Sin CVE asignado", fmt(d.sin)],
      ["--m2", "Con CVE, sin publicar", fmt(d.con)]]));
    hit.addEventListener("pointerleave", hideTT);
  });
  txt(el("text", { x: mL + iw / 2, y: H - 7, "text-anchor": "middle", class: "axis" }, svg),
      "días en la cola desde la primera detección →");
  $("#q-leg-sin").textContent = `Esperando asignación de CVE — ${fmt(qa.unassigned.total)} en cola · mediana ${fmt(qa.unassigned.median_days)} días`;
  $("#q-leg-con").textContent = `Esperando publicación en NVD (ya con CVE) — ${fmt(qa.assigned.total)} en cola · mediana ${fmt(qa.assigned.median_days)} días`;
}
function drawSrc(stats) {
  const svg = $("#c-src"); svg.replaceChildren();
  const rows = stats.slice(0, 12);              // la API ya ordena por ventaja media desc
  const rest = stats.length - rows.length;
  const W = 460, mL = 128, mR = 46, rh = 26, mT = 8;
  const H = mT + rows.length * rh + 10;
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  const iw = W - mL - mR;
  const max = Math.max(...rows.map(d => +d.avg_days), 1);
  rows.forEach((d, i) => {
    const yy = mT + i * rh, bh = 14;
    const w = Math.max(2, +d.avg_days / max * iw);
    txt(el("text", { x: mL - 8, y: yy + bh - 2.5, "text-anchor": "end", class: "axis" }, svg), d.source);
    el("path", { d: `M${mL} ${yy} h${Math.max(0, w - 4)} q4 0 4 4 v${bh - 8} q0 4 -4 4 H${mL} Z`, class: "f-acc" }, svg);
    txt(el("text", { x: mL + w + 7, y: yy + bh - 2.5, class: "dlabel" }, svg), Math.round(+d.avg_days) + " d");
    const hit = el("rect", { x: 0, y: yy - 3, width: W, height: rh, class: "colhit" }, svg);
    hit.addEventListener("pointermove", ev => showTT(ev.clientX, ev.clientY, d.source,
      [[null, "Ventaja media", (+d.avg_days).toFixed(1) + " días"], [null, "Vulnerabilidades", fmt(d.candidates)]]));
    hit.addEventListener("pointerleave", hideTT);
  });
  el("line", { x1: mL, y1: mT - 4, x2: mL, y2: H - 8, class: "baseline" }, svg);
  $("#src-note").textContent = "Barra larga con pocas vulnerabilidades = fuente nicho pero temprana; " +
    "media con miles = el grueso fiable de la señal." +
    (rest > 0 ? ` Se muestran ${rows.length} de ${rows.length + rest} fuentes.` : "");
  // el desplegable de fuente del drill se rellena con las fuentes reales
  const sel = $("#f-src");
  if (sel.options.length <= 1)
    stats.slice().sort((a, b) => b.candidates - a.candidates).forEach(d => {
      const o = document.createElement("option"); o.value = d.source; o.textContent = d.source; sel.appendChild(o);
    });
}

/* ================= hero + meter + glosario + KPIs ================= */
function renderPending(pall, pmats) {
  const bm = pall.by_maturity || { pre_cve: 0, cve_prereserved: 0, cve_reserved: 0 };
  $("#hero-n").textContent = fmt(state.mat === "all" ? pall.total : pmats[state.mat].total);
  if (!state.period) {           // el glosario habla del "hoy" global, sin filtros de periodo
    $("#g-c1").textContent = fmt(bm.pre_cve) + " hoy";
    $("#g-c2").textContent = fmt(bm.cve_prereserved) + " hoy";
    $("#g-c3").textContent = fmt(bm.cve_reserved) + " hoy";
  }
  const meter = $("#meter"); meter.replaceChildren();
  const sum = MK.reduce((a, k) => a + (bm[k] || 0), 0) || 1;
  MK.forEach((k, i) => {
    const d = document.createElement("div");
    d.className = "s" + (i + 1);
    d.style.flex = String(Math.max(bm[k] || 0, sum * .01));
    if (state.mat !== "all" && state.mat !== k) d.style.opacity = ".25";
    d.title = MAT[k].label + ": " + fmt(bm[k]);
    meter.appendChild(d);
  });
  [["#mleg", true], ["#mleg2", false]].forEach(([sel, counts]) => {
    const box = $(sel); box.replaceChildren();
    MK.forEach(k => {
      const b = document.createElement("button");
      b.className = "k" + (state.mat !== "all" && state.mat !== k ? " dim" : "");
      const sw = document.createElement("span"); sw.className = "sw"; sw.style.background = `var(${MAT[k].varn})`;
      b.appendChild(sw);
      b.appendChild(document.createTextNode(" " + MAT[k].label + (counts ? " " : "")));
      if (counts) { const bb = document.createElement("b"); bb.textContent = fmt(bm[k]); b.appendChild(bb); }
      b.addEventListener("click", () => setMat(state.mat === k ? "all" : k));
      box.appendChild(b);
    });
  });
}
function spark(vals, w = 120, h = 30) {
  const svg = el("svg", { viewBox: `0 0 ${w} ${h}`, width: w, height: h });
  svg.setAttribute("class", "chart");
  const max = Math.max(...vals, 1);
  const dx = vals.length > 1 ? (w - 14) / (vals.length - 1) : 0;
  const xa = i => 2 + i * dx, ya = v => h - 3 - v / max * (h - 8);
  let dline = "";
  vals.forEach((v, i) => dline += (i ? " L" : "M") + xa(i) + " " + ya(v));
  el("path", { d: dline, class: "l-ctx" }, svg);
  el("circle", { cx: xa(vals.length - 1), cy: ya(vals[vals.length - 1]), r: 4, class: "f-acc ring" }, svg);
  return svg;
}
function drawKpis(lag) {
  const box = $("#kpis"); box.replaceChildren();
  if (!TREND.length) return;
  const last = TREND[TREND.length - 1], prev = TREND[TREND.length - 2] || last;
  const pl = fmtP(last.period), pp = fmtP(prev.period);
  const items = [
    { lbl: `CVE pre-reservado — nuevas en ${pl}`, star: true, v: last.cve_prereserved,
      d: last.cve_prereserved - prev.cve_prereserved, dlbl: "vs " + pp,
      cap: "La señal estrella: CVE ya asignado pero sin ficha pública.",
      vals: TREND.map(d => d.cve_prereserved) },
    { lbl: `pre-CVE — nuevas en ${pl}`, v: last.pre_cve, d: last.pre_cve - prev.pre_cve, dlbl: "vs " + pp,
      cap: "Solo tienen el código de su fuente (GHSA, RUSTSEC, ZDI…), sin CVE aún.",
      vals: TREND.map(d => d.pre_cve) },
    { lbl: `CVE reservado — nuevas en ${pl}`, v: last.cve_reserved, d: last.cve_reserved - prev.cve_reserved,
      dlbl: "vs " + pp,
      cap: "Con ficha MITRE; NVD aún sin publicar. A un paso de ser oficial.",
      vals: TREND.map(d => d.cve_reserved) },
    lag ? { lbl: "Mediana días hasta CVE público", v: lag.median, unit: " d",
      fixed: `p90: ${fmt(lag.p90)} d — 1 de cada 10 se anticipó más`,
      cap: "La mitad de los CVEs publicados (últimos 12 m) se conocieron aquí con esa antelación o más.",
      vals: null } : null,
  ].filter(Boolean);
  items.forEach(it => {
    const c = document.createElement("div"); c.className = "card tile" + (it.star ? " star" : "");
    const l = document.createElement("div"); l.className = "lbl"; l.textContent = it.lbl;
    const v = document.createElement("div"); v.className = "val"; v.textContent = fmt(it.v) + (it.unit || "");
    const de = document.createElement("div"); de.className = "delta";
    if (it.fixed) de.textContent = it.fixed;
    else {
      const sp = document.createElement("span");
      if (it.d > 0 && it.star) sp.className = "up";
      sp.textContent = (it.d >= 0 ? "+" : "") + fmt(it.d);
      de.append(sp, document.createTextNode(" " + it.dlbl));
    }
    const cap = document.createElement("div"); cap.className = "tcap"; cap.textContent = it.cap;
    c.append(l, v, de);
    if (it.vals) c.append(spark(it.vals));
    c.append(cap);
    box.appendChild(c);
  });
}

/* ================= top software ================= */
function drawTopSw(pall, pmats) {
  const tb = $("#topsw"); tb.replaceChildren();
  const perMat = {};
  MK.forEach(k => { perMat[k] = new Map(pmats[k].top.map(r => [r.software, r.pending])); });
  const rows = pall.top.slice(0, 10);
  const max = rows.length ? rows[0].pending : 1;
  rows.forEach(r => {
    const tr = document.createElement("tr");
    tr.dataset.key = r.software; tr.tabIndex = 0;
    if (state.tech && r.software.toLowerCase().includes(state.tech.toLowerCase()))
      tr.style.background = "var(--accent-wash)";
    const td1 = document.createElement("td"); td1.className = "mono"; td1.textContent = r.software;
    const counts = MK.map(k => perMat[k].get(r.software) || 0);
    const tds = counts.map(v => { const td = document.createElement("td"); td.className = "num";
      td.textContent = v ? fmt(v) : "—"; return td; });
    const tdt = document.createElement("td"); tdt.className = "num";
    const bt = document.createElement("b"); bt.textContent = fmt(r.pending); tdt.appendChild(bt);
    const tdb = document.createElement("td");
    const bar = document.createElement("div"); bar.className = "minibar";
    bar.style.width = Math.round(r.pending / max * 100) + "%";
    counts.forEach((v, i) => { if (!v) return; const seg = document.createElement("div");
      seg.style.flex = String(v); seg.style.background = `var(${MAT[MK[i]].varn})`; bar.appendChild(seg); });
    tdb.appendChild(bar);
    tr.append(td1, ...tds, tdt, tdb);
    const sel = () => {
      const same = state.tech === r.software;
      state.tech = same ? "" : r.software; $("#f-tech").value = state.tech;
      applyAll();
      if (!same) $("#drill").scrollIntoView({ behavior: "smooth", block: "start" });
    };
    tr.addEventListener("click", sel);
    tr.addEventListener("keydown", ev => { if (ev.key === "Enter") sel(); });
    tb.appendChild(tr);
  });
  if (!rows.length) {
    const tr = document.createElement("tr"); const td = document.createElement("td");
    td.colSpan = 6; td.className = "muted"; td.textContent = "sin pendientes con los filtros actuales";
    tr.appendChild(td); tb.appendChild(tr);
  }
}

/* ================= drill-down ================= */
function drillRows() {
  return ROWS.filter(r => state.cvssMin === 0 || (r.cvss != null && r.cvss >= state.cvssMin));
}
function drawChips(total) {
  const box = $("#chips"); box.replaceChildren();
  const mk = (label, on, clear) => {
    const c = document.createElement("span"); c.className = "chip" + (on ? " on" : "");
    c.appendChild(document.createTextNode(label));
    if (on && clear) { const b = document.createElement("button"); b.textContent = "×";
      b.setAttribute("aria-label", "Quitar filtro"); b.addEventListener("click", clear); c.appendChild(b); }
    box.appendChild(c);
  };
  mk(state.period ? "periodo: " + fmtP(state.period) : "todos los periodos (clic en una columna de la evolución)",
     !!state.period, () => { state.period = null; applyAll(); });
  mk(state.mat === "all" ? "todas las madureces" : MAT[state.mat].label, state.mat !== "all", () => setMat("all"));
  if (state.tech) mk("tecnología: " + state.tech, true, () => { $("#f-tech").value = ""; state.tech = ""; applyAll(); });
  if (state.kind !== "all") mk("tipo: " + state.kind, true, () => { $("#f-kind").value = "all"; state.kind = "all"; applyAll(); });
  if (state.source) mk("fuente: " + state.source, true, () => { $("#f-src").value = ""; state.source = ""; applyAll(); });
  if (state.cvssMin > 0) mk("CVSS ≥ " + state.cvssMin, true, () => { $("#f-cvss").value = "0"; state.cvssMin = 0; renderDrill(); });
  if (state.kevOnly) mk("solo KEV", true, () => { $("#f-kev").checked = false; state.kevOnly = false; applyAll(); });
  mk(fmt(total) + " vulnerabilidades en la selección", false);
}
function drawScatter(rows) {
  const svg = $("#c-scatter"); svg.replaceChildren();
  const W = 520, H = 300, mL = 40, mR = 14, mT = 12, mB = 44, nullBand = 26;
  const iw = W - mL - mR, ih = H - mT - mB - nullBand;
  for (let v = 0; v <= 10; v += 2.5) {
    const yy = mT + ih - v / 10 * ih;
    el("line", { x1: mL, y1: yy, x2: W - mR, y2: yy, class: v === 0 ? "baseline" : "gridline" }, svg);
    txt(el("text", { x: mL - 7, y: yy + 3.5, "text-anchor": "end", class: "axis" }, svg), v);
  }
  const ybandNull = mT + ih + nullBand - 6;
  txt(el("text", { x: mL - 7, y: ybandNull + 3, "text-anchor": "end", class: "axis" }, svg), "s/CVSS");
  el("line", { x1: mL, y1: ybandNull, x2: W - mR, y2: ybandNull, class: "gridline" }, svg);
  const bucket = r => state.sgran === "week" ? isoWeekKey(r.first_seen_at) : r.first_seen_at.slice(0, 7);
  const frac = r => state.sgran === "week"
    ? ((new Date(r.first_seen_at.slice(0, 10) + "T00:00:00Z").getUTCDay() + 6) % 7) / 7
    : (+(r.first_seen_at.slice(8, 10) || 15) - 1) / 31;
  const periods = [...new Set(rows.map(bucket))].sort();
  const span = Math.max(periods.length, 1);
  if (periods.length) {
    const step = Math.ceil(periods.length / 6);
    periods.forEach((p, i) => { if (i % step === 0)
      txt(el("text", { x: mL + i / span * iw + iw / span / 2, y: H - 24, "text-anchor": "middle", class: "axis" }, svg),
          fmtP(p)); });
  }
  txt(el("text", { x: mL, y: H - 7, class: "axis" }, svg), "primera detección →");
  txt(el("text", { x: W - mR, y: H - 7, "text-anchor": "end", class: "axis" }, svg), "eje y: CVSS");
  rows.forEach(r => {
    const cy = r.cvss == null ? ybandNull : mT + ih - r.cvss / 10 * ih;
    const cx = mL + ((periods.indexOf(bucket(r)) + frac(r)) / span) * iw;
    if (r.in_kev) el("circle", { cx, cy, r: 8, class: "ring-kev" }, svg);
    el("circle", { cx, cy, r: 5, class: (MAT[r.maturity] || MAT.pre_cve).cls + " ring" }, svg);
    const hit = el("circle", { cx, cy, r: 13, class: "colhit", tabindex: 0, role: "button", "aria-label": r.key }, svg);
    hit.addEventListener("pointermove", ev => showTT(ev.clientX, ev.clientY, r.key, [
      [(MAT[r.maturity] || MAT.pre_cve).varn, (MAT[r.maturity] || MAT.pre_cve).label, ""],
      [null, "CVSS", r.cvss == null ? "—" : (+r.cvss).toFixed(1)],
      [null, "Tipo", r.vuln_type || "—"],
      [null, "Fuentes", (r.sources || "").split(",").slice(0, 3).join(", ")]]
      .concat(r.in_kev ? [[null, "⚠ KEV", "sí"]] : [])));
    hit.addEventListener("pointerleave", hideTT);
    hit.addEventListener("click", () => openCandidate(r.key));
    hit.addEventListener("keydown", ev => { if (ev.key === "Enter") openCandidate(r.key); });
  });
  const leg = $("#sleg"); leg.replaceChildren();
  MK.forEach(k => {
    const s = document.createElement("span"); s.className = "k";
    const sw = document.createElement("span"); sw.className = "sw"; sw.style.borderRadius = "50%";
    sw.style.background = `var(${MAT[k].varn})`;
    s.append(sw, document.createTextNode(" " + MAT[k].label));
    leg.appendChild(s);
  });
  const kv = document.createElement("span"); kv.className = "k";
  const ring = document.createElement("span"); ring.className = "sw"; ring.style.cssText =
    "border-radius:50%;background:none;border:2px solid var(--crit);width:9px;height:9px";
  kv.append(ring, document.createTextNode(" en KEV"));
  leg.appendChild(kv);
}
function drawTable(rows, total) {
  const tb = $("#tbody"); tb.replaceChildren();
  const shown = rows.slice(0, 14);
  shown.forEach(r => {
    const tr = document.createElement("tr");
    tr.dataset.key = r.key; tr.tabIndex = 0;
    const td1 = document.createElement("td"); td1.className = "mono"; td1.textContent = r.key;
    if (r.in_kev) { const p = document.createElement("span"); p.className = "pill kev"; p.textContent = "KEV";
      td1.appendChild(document.createTextNode(" ")); td1.appendChild(p); }
    const td2 = document.createElement("td");
    const m = MAT[r.maturity] || MAT.pre_cve;
    const pm = document.createElement("span"); pm.className = "pill";
    const dot = document.createElement("span"); dot.className = "dot"; dot.style.background = `var(${m.varn})`;
    pm.append(dot, document.createTextNode(m.label));
    td2.appendChild(pm);
    const td3 = document.createElement("td"); td3.className = "num";
    td3.textContent = r.cvss == null ? "—" : (+r.cvss).toFixed(1);
    const td4 = document.createElement("td"); td4.textContent = r.vuln_type || "—";
    const td5 = document.createElement("td"); td5.className = "mono"; td5.textContent = fmtD(r.first_seen_at);
    const td6 = document.createElement("td"); td6.className = "muted";
    td6.textContent = (r.sources || "").split(",").slice(0, 2).join(", ");
    tr.append(td1, td2, td3, td4, td5, td6);
    tr.addEventListener("click", () => openCandidate(r.key));
    tr.addEventListener("keydown", ev => { if (ev.key === "Enter") openCandidate(r.key); });
    tb.appendChild(tr);
  });
  if (!rows.length) {
    const tr = document.createElement("tr"); const td = document.createElement("td");
    td.colSpan = 6; td.className = "muted"; td.textContent = "sin resultados con esta selección";
    tr.appendChild(td); tb.appendChild(tr);
  }
  $("#tmore").textContent = total > shown.length
    ? `Mostrando ${shown.length} de ${fmt(total)} (las ${fmt(Math.min(total, 400))} más recientes alimentan la gráfica).` : "";
}
function renderDrill() {
  const rows = drillRows();
  drawChips(rows.length);
  drawScatter(rows);
  drawTable(rows, rows.length);
}

/* ================= drawer (ficha /api/candidate) ================= */
const drawer = $("#drawer"), ovl = $("#ovl");
function kvRow(parent, k, node) {
  const d = document.createElement("div"); d.className = "kv";
  const b = document.createElement("b"); b.textContent = k;
  d.append(b, node); parent.appendChild(d);
}
function spanText(s, mono) {
  const sp = document.createElement("span"); if (mono) sp.className = "mono";
  sp.textContent = s; return sp;
}
async function openCandidate(key) {
  drawer.classList.add("open"); ovl.classList.add("open");
  const body = $("#dbody"); body.replaceChildren();
  body.appendChild(spanText("cargando…"));
  let d;
  try { d = await j("/api/candidate/" + encodeURIComponent(key)); }
  catch { body.replaceChildren(spanText("No se pudo cargar la ficha.")); return; }
  body.replaceChildren();
  const h = document.createElement("h3"); h.className = "mono";
  h.textContent = d.cve_id || "(pre-CVE) " + d.id.slice(0, 8);
  body.appendChild(h);
  if (d.in_kev) { const kp = document.createElement("span"); kp.className = "pill kev";
    kp.textContent = "⚠ KEV — explotación activa"; body.appendChild(kp); }

  const g = document.createElement("div"); g.className = "gaugewrap";
  const gn = document.createElement("div"); gn.className = "gauge-n";
  const gc = document.createElement("div"); gc.className = "gauge-cap";
  if (d.days_ahead_present != null) {
    gn.textContent = fmt(d.days_ahead_present) + " días de ventaja";
    gc.textContent = "se conoció aquí antes de que NVD publicara sus datos";
  } else if (d.timeline.length) {
    const first = new Date(d.timeline[0].seen_at);
    const days = Math.max(0, Math.round((Date.now() - first.getTime()) / 86400000));
    gn.textContent = fmt(days) + " días en cola";
    gc.textContent = "desde la primera detección · NVD aún sin publicar (la ventaja se fija al publicarse)";
  } else { gn.textContent = "—"; gc.textContent = "sin menciones registradas"; }
  g.append(gn, gc); body.appendChild(g);

  kvRow(body, "estado", spanText(d.status));
  kvRow(body, "tipo / vector", spanText((d.vuln_type || "—") + " / " + (d.attack_vector || "—")));
  kvRow(body, "PoC público", spanText(d.has_public_poc ? "sí" : "—"));
  kvRow(body, "EPSS", spanText(d.epss ? `${d.epss.score} (percentil ${d.epss.percentile})` : "—"));
  kvRow(body, "CWE", spanText((d.cwe_ids || []).join(", ") || "—"));
  const cv = document.createElement("div");
  if (d.cvss.length) d.cvss.forEach(c => {
    const line = document.createElement("div");
    line.textContent = `${c.version} ${c.base_score ?? "?"} ${c.base_severity || ""} (${c.provenance}/${c.source})`;
    cv.appendChild(line);
  }); else cv.textContent = "—";
  kvRow(body, "CVSS", cv);
  const af = document.createElement("div");
  if (d.affected.length) d.affected.forEach(a => {
    const line = document.createElement("div");
    line.textContent = (a.ecosystem ? a.ecosystem + ":" : "") + a.product + (a.kind ? " · " + a.kind : "");
    af.appendChild(line);
  }); else af.textContent = "—";
  kvRow(body, "software afectado", af);
  kvRow(body, "identificadores", spanText(d.identifiers.map(i => i.scheme + ":" + i.value).join(" · ") || "—", true));

  const h4 = document.createElement("h4"); h4.textContent = "Línea temporal"; h4.style.margin = "16px 0 4px";
  body.appendChild(h4);
  const tl = document.createElement("div"); tl.className = "tl";
  d.timeline.forEach(t => {
    const ev = document.createElement("div"); ev.className = "ev";
    const dd = document.createElement("div"); dd.className = "d";
    dd.textContent = String(t.seen_at || "").slice(0, 16).replace("T", " ") + " · " + t.source;
    const ti = document.createElement("div"); ti.textContent = t.title || "";
    ev.append(dd, ti);
    const u = safeUrl(t.url);
    if (u) { const a = document.createElement("a"); a.href = u; a.target = "_blank";
      a.rel = "noopener noreferrer"; a.textContent = u.slice(0, 60); ev.appendChild(a); }
    tl.appendChild(ev);
  });
  if (!d.timeline.length) tl.appendChild(spanText("—"));
  body.appendChild(tl);
}
function closeDrawer() { drawer.classList.remove("open"); ovl.classList.remove("open"); }
$("#dclose").addEventListener("click", closeDrawer);
ovl.addEventListener("click", closeDrawer);
addEventListener("keydown", ev => { if (ev.key === "Escape") closeDrawer(); });

/* ================= carga de datos ================= */
async function loadStatic() {
  // sonda: ¿soporta la API granularidad semanal y ventana en días?
  try {
    const probe = await j("/api/trend?granularity=week&months=1&days=7");
    CAPS.week = true; CAPS.days = "days" in probe;
  } catch { /* API sin semana: los botones quedan ocultos */ }
  document.querySelectorAll('#f-gran [data-v="week"]').forEach(b => { b.hidden = !CAPS.week; });
  document.querySelectorAll('#f-win [data-v="w1"]').forEach(b => { b.hidden = !(CAPS.week && CAPS.days); });
  const months = 24;
  const [lagR, queueR, statsR, ctxR] = await Promise.allSettled([
    j("/api/lag/histogram?months=12"),
    j("/api/queue/age"),
    j("/api/stats"),
    j(`/api/trend?months=${months}&granularity=month`),
  ]);
  if (ctxR.status === "fulfilled") {
    CTXS = ctxR.value.series;
    ctx.a = Math.max(0, CTXS.length - 12); ctx.b = CTXS.length;
    renderCtx(); renderSurge();
  }
  if (queueR.status === "fulfilled") drawQueue(queueR.value);
  if (statsR.status === "fulfilled") drawSrc(statsR.value.sources);
  window._lag = lagR.status === "fulfilled" ? lagR.value : null;
  if (window._lag) drawHist(window._lag);
}
async function loadMain() {
  const base = { top: 100, kind: "all", period: state.period, granularity: state.gran };
  const [trend, pall, ...mats] = await Promise.all([
    j(`/api/trend?${qs({ ...winParams(), granularity: state.gran })}`),
    j(`/api/pending?${qs(base)}`),
    ...MK.map(k => j(`/api/pending?${qs({ ...base, maturity: k })}`)),
  ]);
  TREND = trend.series;
  const pmats = Object.fromEntries(MK.map((k, i) => [k, mats[i]]));
  renderPending(pall, pmats);
  drawKpis(window._lag);
  drawMat();
  drawTopSw(pall, pmats);
}
async function loadDrill() {
  const d = await j(`/api/emerging?${qs({
    pending_only: true, page_size: 400,
    maturity: state.mat === "all" ? null : state.mat,
    period: state.period, granularity: state.gran,
    kind: state.kind === "all" ? null : state.kind,
    tech: state.tech, source: state.source, in_kev: state.kevOnly || null,
  })}`);
  ROWS = d.rows.map(r => ({
    key: r.cve_id || r.id, cvss: r.cvss, maturity: r.maturity, in_kev: r.in_kev,
    vuln_type: r.vuln_type, sources: r.sources,
    first_seen_at: r.first_seen_at || r.last_seen_at || "",
  }));
  ROWS._total = d.total;
  renderDrill();
}
async function applyAll() {
  $("#stamp").textContent = "consultando API…";
  try {
    await Promise.all([loadMain(), loadDrill()]);
    $("#stamp").textContent = "datos en vivo · " + new Date().toLocaleString("es-ES",
      { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" });
  } catch (e) {
    console.error(e);
    $("#stamp").textContent = "error consultando la API";
  }
}

/* ================= controles ================= */
function bindSeg(id, key, after) {
  $(id).addEventListener("click", ev => {
    const b = ev.target.closest("button[data-v]"); if (!b) return;
    [...$(id).children].forEach(x => x.classList.toggle("on", x === b));
    state[key] = b.dataset.v;
    if (after) after();
    applyAll();
  });
}
function setMat(v) {
  state.mat = v;
  [...$("#f-mat").children].forEach(x => x.classList.toggle("on", x.dataset.v === v));
  applyAll();
}
bindSeg("#f-win", "win", () => { state.period = null; });
bindSeg("#f-gran", "gran", () => { state.period = null; });
$("#f-mat").addEventListener("click", ev => {
  const b = ev.target.closest("button[data-v]"); if (b) setMat(b.dataset.v);
});
$("#f-kind").addEventListener("change", () => { state.kind = $("#f-kind").value; applyAll(); });
$("#f-src").addEventListener("change", () => { state.source = $("#f-src").value; applyAll(); });
$("#f-cvss").addEventListener("change", () => { state.cvssMin = +$("#f-cvss").value; renderDrill(); });
$("#f-kev").addEventListener("change", () => { state.kevOnly = $("#f-kev").checked; applyAll(); });
$("#s-gran").addEventListener("click", ev => {
  const b = ev.target.closest("button[data-v]"); if (!b) return;
  [...$("#s-gran").children].forEach(x => x.classList.toggle("on", x === b));
  state.sgran = b.dataset.v;
  renderDrill();                      // solo re-dibuja: no hace falta refetch
});
let tdeb;
$("#f-tech").addEventListener("input", () => { clearTimeout(tdeb);
  tdeb = setTimeout(() => { state.tech = $("#f-tech").value.trim(); applyAll(); }, 250); });
$("#f-reset").addEventListener("click", () => {
  Object.assign(state, { win: "ytd", gran: "month", mat: "all", period: null,
                         tech: "", kind: "all", source: "", kevOnly: false, cvssMin: 0, sgran: "week" });
  [...$("#s-gran").children].forEach(x => x.classList.toggle("on", x.dataset.v === "week"));
  $("#f-tech").value = ""; $("#f-kind").value = "all"; $("#f-src").value = "";
  $("#f-cvss").value = "0"; $("#f-kev").checked = false;
  [["#f-win", "ytd"], ["#f-gran", "month"], ["#f-mat", "all"]].forEach(([id, v]) =>
    [...$(id).children].forEach(x => x.classList.toggle("on", x.dataset.v === v)));
  ctx.a = Math.max(0, CTXS.length - 12); ctx.b = CTXS.length; renderCtx();
  applyAll();
});

/* ================= arranque ================= */
bindCrosshair();
loadStatic().then(applyAll);
