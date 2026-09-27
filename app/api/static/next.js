// Dashboard "inminente" (/next). Script EXTERNO (la CSP es script-src 'self').
// Bilingüe EN/ES, inglés por defecto; conmutador en la cabecera.
"use strict";
const $ = s => document.querySelector(s);

// ---------------- i18n ----------------
const I18N = {
  en: {
    "hd.sub": "early radar · imminent view",
    "hd.status": "status",
    "theme.title": "theme",
    "lang.title": "language",
    "explain.summary": "What this panel measures",
    "explain.lede": "Foreshock tracks public sources — GitHub and OSV advisories, commits, vendor bulletins, ZDI, MSRC, exploit lists — looking for vulnerabilities that <b>don't appear in NVD yet</b>, the official database. That time gap is the <b>lead</b> everything here measures. Each pending item is in one of three blue states (light to dark) until NVD publishes and it moves to the final, grey stage.",
    "pyr.goal.label": "Published CVE",
    "pyr.goal.sub": "the goal · exits the pyramid",
    "pyr.arrow": "▲ more official · matures toward the published CVE",
    "pyr.L3": "Reserved CVE",
    "pyr.L2": "Pre-reserved CVE",
    "pyr.L1": "pre-CVE",
    "pyr.L0": "Blind zone",
    "pyr.indeterminate": "Indeterminate",
    "pyr.desc.pub": "<b>Published CVE</b> — NVD publishes its analysis: it stops being pending and closes the cycle (the goal, outside the pyramid).",
    "pyr.desc.reserved": "<b>Reserved CVE</b> — <b>MITRE already has a record</b>, but NVD hasn't published its analysis yet. The last step before going official.",
    "pyr.desc.prereserved": "<b>Pre-reserved CVE</b> — a CVE number is already circulating (cited in a commit or advisory) but <b>MITRE has no record yet</b>. The earliest signal with a number.",
    "pyr.desc.precve": "<b>pre-CVE</b> — only the native code from its source (GHSA-, RUSTSEC-, ZDI-CAN-, VU#…); no CVE number assigned yet. This is where what Foreshock DOES see begins.",
    "pyr.desc.blind": "<b>Blind zone</b> — the (huge, unquantified) set that <b>only the vendor and whoever reported it know about</b>: no public signal of any kind exists yet. That's why its indicator is <b>Indeterminate</b> — you can't count what nobody has made public.",
    "gloss.score": "<b>Foreshock Score (0–100)</b> — criticality to act now: active exploitation (KEV, +50), public PoC (+20), CVSS/severity (0–40) and how early the source warns (tier, 1–15).",
    "gloss.lead": "<b>Lead / days ahead</b> — days between Foreshock's first detection and NVD publication (<span class=\"mono\">present</span>, against our own observation).",
    "gloss.red": "<span class=\"rd\">Red</span> — <b>KEV</b> (active exploitation confirmed by CISA) marks the row with a strong red accent; <b>CVSS ≥ 9</b> also in red, one notch below.",
    "gloss.cvss": "<b>CVSS · EPSS</b> — severity (0–10) and probability of exploitation within 30 days (0–1). <b>tier</b> — how early the source is (1 = the one that leads most).",
    "sec.imm.title": "Imminent — what to watch today",
    "sec.imm.sub": "Candidates with actionable signal, ranked by <b>Foreshock Score</b>. The golden cross: exploit/signal while the CVE is still pre-published. Click a row to see <b>the race</b>.",
    "surface.ph": "My surface: filter by product (e.g. rabbitmq, ghost, n8n)…",
    "sec.lag.title": "Lead over NVD",
    "sec.lag.sub": "Of the pending items that <b>already got published</b> in NVD: how many days ahead Foreshock saw them. Each bar = <b>number of vulnerabilities</b> in that lead range; the sum = total measured (n). Only detections <b>since Foreshock started</b>, not earlier CVEs.",
    "sec.srcs.title": "Source leaderboard",
    "sec.srcs.sub": "Average lead per source — who to trust first.",
    "sec.trend.title": "Monthly trend",
    "sec.trend.sub": "Pre-CVE vs pre-reserved vs published (first detection).",
    "sec.evo.title": "Evolution: when the current pending items were detected",
    "sec.evo.sub": "How many of the current pending items were first detected each month, by maturity. Tall recent column = lots of new signal; old columns = NVD has gone months without publishing them.",
    "sec.queue.title": "Waiting queue: how long they've been pending in NVD",
    "sec.queue.sub": "Age of the pending items (days since the first signal), separating those without a CVE number yet from those that already have one. The right-hand tail = vulnerabilities NVD is dragging unpublished.",
    "sec.vel.title": "Velocity: signals captured per day",
    "sec.vel.sub": "Foreshock's own clock (<span class=\"mono\">candidates.created_at</span>), last 60 days. Real capture rate, independent of the advisory date.",
    "foot": "Foreshock — early vulnerability radar. The <b>Foreshock Score</b> and maturity are computed server-side (<span class=\"mono\">/api/pending/critical</span>). Operational status at <span class=\"mono\">/pending_status</span>.",
    "kpi.imm.l": "Imminent now", "kpi.imm.s": "score ≥ 60 · exploit/KEV/severity",
    "kpi.lead.l": "Median lead (days)", "kpi.lead.s": "p90 = {p90} · n={n}",
    "kpi.new.l": "New in radar today", "kpi.new.s": "first detection = today",
    "kpi.pending.l": "Pending in NVD", "kpi.pending.s": "pre-CVE {precve} · since {since}",
    "mat.pre_cve": "pre-CVE", "mat.cve_prereserved": "pre-reserved", "mat.cve_reserved": "reserved",
    "imm.noresults": "no results for «{q}»", "imm.nocve": "no CVE", "imm.seen": "seen {n}d ago",
    "chip.poc": "public PoC",
    "sb.title": "Where the score comes from", "sb.total": "Foreshock Score",
    "sb.kev": "Active exploitation (KEV)", "sb.poc": "Public PoC",
    "sb.sev.cvss": "Severity · CVSS {c} × 4", "sb.sev.hint": "Severity · {h}", "sb.sev.nodata": "no data",
    "sb.tier": "Source earliness (tier {t})",
    "sb.note": "Sum of: KEV (+50) · public PoC (+20) · CVSS×4 or severity (0–40) · source earliness by tier (1→15, 2→10, 3→6, 4→3). Higher = more urgent to act.",
    "lag.head": "Half were detected <b>≥ {median} day(s)</b> before NVD (median); the top 10%, <b>≥ {p90} days</b>. Over <b>{n}</b> measured since {since} (Foreshock start).",
    "queue.head": "Median wait: <b>{un} d</b> without CVE · <b>{as} d</b> with CVE. The further right, the longer NVD has left them unpublished.",
    "queue.leg.sin": "without CVE", "queue.leg.con": "with CVE (reserved)",
    "leg.precve": "pre-CVE", "leg.prereserved": "pre-reserved", "leg.published": "published", "leg.reserved": "reserved",
    "dw.lead.published": "<b>{d} days</b> of lead over NVD publication (from the first radar signal).",
    "dw.lead.open": "CVE still <b>{status}</b> — NVD hasn't published data yet. The signal has been in the radar for <b>{age}</b>. Window open.",
    "dw.days": "{n} days", "dw.race": "The race — signals in order of arrival",
    "dw.nvdfinish": "NVD publishes the CVE (finish line)", "dw.finish": "finish",
    "dw.nosignals": "no signals", "dw.affected": "Affected software", "dw.cvss": "CVSS",
    "dw.ids": "Identifiers", "dw.refs": "References", "dw.error": "error loading the candidate",
    "loading": "loading…", "nodata": "no data", "unavailable": "not available",
    "pyr.since": "All figures: population detected since {date} (Foreshock start)",
  },
  es: {
    "hd.sub": "radar temprano · vista inminente",
    "hd.status": "estado",
    "theme.title": "tema",
    "lang.title": "idioma",
    "explain.summary": "Qué mide este panel",
    "explain.lede": "Foreshock rastrea fuentes públicas — avisos de GitHub y OSV, commits, boletines de fabricante, ZDI, MSRC, listas de exploits — buscando vulnerabilidades que <b>todavía no aparecen en NVD</b>, la base de datos oficial. Ese hueco temporal es la <b>ventaja</b> que mide todo lo que ves aquí. Cada pendiente está en uno de tres estados azules (de claro a oscuro) hasta que NVD publica y pasa a la fase final, en gris.",
    "pyr.goal.label": "CVE público",
    "pyr.goal.sub": "la meta · sale de la pirámide",
    "pyr.arrow": "▲ más oficial · madura hacia el CVE público",
    "pyr.L3": "CVE reservado",
    "pyr.L2": "CVE pre-reservado",
    "pyr.L1": "pre-CVE",
    "pyr.L0": "Zona ciega",
    "pyr.indeterminate": "Indeterminado",
    "pyr.desc.pub": "<b>CVE público</b> — NVD publica su análisis: deja de estar pendiente y cierra el ciclo (la meta, fuera de la pirámide).",
    "pyr.desc.reserved": "<b>CVE reservado</b> — <b>MITRE ya tiene ficha</b>, pero NVD aún no ha publicado su análisis. Último paso antes de hacerse oficial.",
    "pyr.desc.prereserved": "<b>CVE pre-reservado</b> — ya circula un número CVE (citado en un commit o aviso) pero <b>MITRE aún no tiene ficha</b>. La señal más temprana con número.",
    "pyr.desc.precve": "<b>pre-CVE</b> — solo el código nativo de su fuente (GHSA-, RUSTSEC-, ZDI-CAN-, VU#…); nadie le ha asignado aún un número CVE. Aquí empieza lo que Foreshock SÍ ve.",
    "pyr.desc.blind": "<b>Zona ciega</b> — el conjunto (enorme, sin cuantificar) que <b>solo conocen quien tiene el producto y quien la ha reportado</b>: aún no existe señal pública de ningún tipo. Por eso su indicador es <b>Indeterminado</b> — no se puede contar lo que nadie ha hecho público.",
    "gloss.score": "<b>Foreshock Score (0–100)</b> — criticidad para actuar ya: explotación activa (KEV, +50), PoC público (+20), gravedad CVSS/severidad (0–40) y lo pronto que avisa la fuente (tier, 1–15).",
    "gloss.lead": "<b>Ventaja / días de adelanto</b> — días entre la primera detección en Foreshock y la publicación en NVD (<span class=\"mono\">present</span>, sobre nuestra propia observación).",
    "gloss.red": "<span class=\"rd\">Rojo</span> — <b>KEV</b> (explotación activa confirmada por CISA) marca la fila con acento rojo intenso; <b>CVSS ≥ 9</b> también en rojo, un escalón por debajo.",
    "gloss.cvss": "<b>CVSS · EPSS</b> — gravedad (0–10) y probabilidad de explotación a 30 días (0–1). <b>tier</b> — cómo de temprana es la fuente (1 = la que más se adelanta).",
    "sec.imm.title": "Inminente — lo que hay que mirar hoy",
    "sec.imm.sub": "Candidates con señal accionable, ordenados por <b>Foreshock Score</b>. El cruce de oro: exploit/señal mientras el CVE sigue pre-publicado. Pulsa una fila para ver <b>la carrera</b>.",
    "surface.ph": "Mi superficie: filtra por producto (p.ej. rabbitmq, ghost, n8n)…",
    "sec.lag.title": "Ventaja sobre NVD",
    "sec.lag.sub": "De las pendientes que <b>ya se publicaron</b> en NVD: con cuántos días de antelación las vio Foreshock. Cada barra = <b>nº de vulnerabilidades</b> en ese rango de adelanto; la suma = total medido (n). Solo detecciones <b>desde el arranque de Foreshock</b>, no CVEs anteriores.",
    "sec.srcs.title": "Leaderboard de fuentes",
    "sec.srcs.sub": "Adelanto medio por fuente — a quién creer antes.",
    "sec.trend.title": "Tendencia mensual",
    "sec.trend.sub": "Pre-CVE vs prereservado vs publicado (primera detección).",
    "sec.evo.title": "Evolución: cuándo se detectaron las pendientes actuales",
    "sec.evo.sub": "Cuántas de las pendientes actuales se detectaron por primera vez en cada mes, por madurez. Columna alta y reciente = mucha señal nueva; columnas antiguas = NVD lleva meses sin publicarlas.",
    "sec.queue.title": "Cola de espera: cuánto llevan pendientes de NVD",
    "sec.queue.sub": "Antigüedad de las pendientes (días desde la primera señal), separando las que aún no tienen número CVE de las que ya lo tienen. La cola de la derecha = vulnerabilidades que NVD arrastra sin publicar.",
    "sec.vel.title": "Velocidad: señales capturadas por día",
    "sec.vel.sub": "Reloj propio de Foreshock (<span class=\"mono\">candidates.created_at</span>), últimos 60 días. Ritmo real de captura, independiente de la fecha del aviso.",
    "foot": "Foreshock — radar temprano de vulnerabilidades. El <b>Foreshock Score</b> y la madurez los calcula el servidor (<span class=\"mono\">/api/pending/critical</span>). Estado operativo en <span class=\"mono\">/pending_status</span>.",
    "kpi.imm.l": "Inminentes ahora", "kpi.imm.s": "score ≥ 60 · exploit/KEV/severidad",
    "kpi.lead.l": "Ventaja mediana (días)", "kpi.lead.s": "p90 = {p90} · n={n}",
    "kpi.new.l": "Nuevos hoy en el radar", "kpi.new.s": "primera detección = hoy",
    "kpi.pending.l": "Pendientes de NVD", "kpi.pending.s": "pre-CVE {precve} · desde {since}",
    "mat.pre_cve": "pre-CVE", "mat.cve_prereserved": "prereservado", "mat.cve_reserved": "reservado",
    "imm.noresults": "sin resultados para «{q}»", "imm.nocve": "sin CVE", "imm.seen": "visto hace {n} d",
    "chip.poc": "PoC público",
    "sb.title": "De dónde sale el score", "sb.total": "Foreshock Score",
    "sb.kev": "Explotación activa (KEV)", "sb.poc": "PoC público",
    "sb.sev.cvss": "Gravedad · CVSS {c} × 4", "sb.sev.hint": "Gravedad · {h}", "sb.sev.nodata": "sin dato",
    "sb.tier": "Prontitud de la fuente (tier {t})",
    "sb.note": "Suma de: KEV (+50) · PoC público (+20) · gravedad CVSS×4 o severidad (0–40) · prontitud de la fuente por tier (1→15, 2→10, 3→6, 4→3). Más alto = más urgente actuar.",
    "lag.head": "La mitad se detectaron <b>≥ {median} día(s)</b> antes que NVD (mediana); el 10% más adelantado, <b>≥ {p90} días</b>. Sobre <b>{n}</b> medidas desde {since} (arranque de Foreshock).",
    "queue.head": "Mediana de espera: <b>{un} d</b> sin CVE · <b>{as} d</b> con CVE. Cuanto más a la derecha, más lleva NVD sin publicarlas.",
    "queue.leg.sin": "sin CVE", "queue.leg.con": "con CVE (reservado)",
    "leg.precve": "pre-CVE", "leg.prereserved": "prereservado", "leg.published": "publicado", "leg.reserved": "reservado",
    "dw.lead.published": "<b>{d} días</b> de ventaja sobre la publicación en NVD (desde la primera señal del radar).",
    "dw.lead.open": "CVE aún <b>{status}</b> — NVD todavía no ha publicado datos. La señal lleva <b>{age}</b> en el radar. Ventana abierta.",
    "dw.days": "{n} días", "dw.race": "La carrera — señales por orden de llegada",
    "dw.nvdfinish": "NVD publica el CVE (línea de meta)", "dw.finish": "meta",
    "dw.nosignals": "sin señales", "dw.affected": "Software afectado", "dw.cvss": "CVSS",
    "dw.ids": "Identificadores", "dw.refs": "Referencias", "dw.error": "error cargando el candidate",
    "loading": "cargando…", "nodata": "sin datos", "unavailable": "no disponible",
    "pyr.since": "Todas las cifras: población detectada desde {date} (arranque de Foreshock)",
  },
};
let LANG = "en";
try { const l = localStorage.getItem("fs-lang"); if (l === "es" || l === "en") LANG = l; } catch (e) {}
function t(k, vars) {
  let s = (I18N[LANG] && I18N[LANG][k] != null) ? I18N[LANG][k] : (I18N.en[k] != null ? I18N.en[k] : k);
  if (vars) for (const name in vars) s = s.split("{" + name + "}").join(vars[name]);
  return s;
}
function applyI18n() {
  document.documentElement.setAttribute("lang", LANG);
  document.querySelectorAll("[data-i18n]").forEach(el => { el.textContent = t(el.getAttribute("data-i18n")); });
  document.querySelectorAll("[data-i18n-html]").forEach(el => { el.innerHTML = t(el.getAttribute("data-i18n-html")); });
  document.querySelectorAll("[data-i18n-ph]").forEach(el => { el.setAttribute("placeholder", t(el.getAttribute("data-i18n-ph"))); });
  document.querySelectorAll("[data-i18n-title]").forEach(el => { el.setAttribute("title", t(el.getAttribute("data-i18n-title"))); });
}
const langBtn = $("#langbtn");
if (langBtn) {
  langBtn.textContent = LANG === "en" ? "ES" : "EN";
  langBtn.onclick = () => { try { localStorage.setItem("fs-lang", LANG === "en" ? "es" : "en"); } catch (e) {} location.reload(); };
}

// ---------------- helpers ----------------
const fmtDate = s => s ? String(s).slice(0, 10) : "—";
const daysAgo = s => { if (!s) return null; const d = (Date.now() - new Date(s)) / 86400000; return Math.round(d); };
const esc = s => (s == null ? "" : String(s)).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const safeUrl = u => { try { const p = new URL(u, location.origin); return (p.protocol === "http:" || p.protocol === "https:") ? p.href : null; } catch (e) { return null; } };
const _MONTHS = {
  en: ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
  es: ["ene", "feb", "mar", "abr", "may", "jun", "jul", "ago", "sep", "oct", "nov", "dic"],
};
const _mo = () => _MONTHS[LANG] || _MONTHS.en;
const monthYear = s => { if (!s) return "?"; const d = new Date(s); return isNaN(d) ? String(s).slice(0, 7) : _mo()[d.getUTCMonth()] + " " + d.getUTCFullYear(); };
const fmtLongDate = s => { if (!s) return ""; const d = new Date(String(s).slice(0, 10) + "T00:00:00Z"); return isNaN(d) ? String(s) : d.getUTCDate() + " " + _mo()[d.getUTCMonth()] + " " + d.getUTCFullYear(); };

// tema
const tb = $("#themebtn");
tb.onclick = () => {
  const r = document.documentElement;
  const cur = r.getAttribute("data-theme") || (matchMedia("(prefers-color-scheme:dark)").matches ? "dark" : "light");
  r.setAttribute("data-theme", cur === "dark" ? "light" : "dark");
  try { localStorage.setItem("fs-theme", r.getAttribute("data-theme")); } catch (e) {}
};
try { const th = localStorage.getItem("fs-theme"); if (th) document.documentElement.setAttribute("data-theme", th); } catch (e) {}

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
const matLabel = m => t("mat." + m, {}) !== "mat." + m ? t("mat." + m) : (m || "");

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
    { l: t("sb.kev"), v: row.in_kev ? 50 : 0, on: !!row.in_kev },
    { l: t("sb.poc"), v: row.has_public_poc ? 20 : 0, on: !!row.has_public_poc },
    { l: row.cvss != null ? t("sb.sev.cvss", { c: esc(row.cvss) }) : t("sb.sev.hint", { h: esc(row.severity_hint || t("sb.sev.nodata")) }), v: sev, on: sev > 0 },
    { l: t("sb.tier", { t: esc(row.min_tier != null ? row.min_tier : "?") }), v: tierPoints(row.min_tier), on: true },
  ];
  const items = parts.map(p => `<div class="sb-row ${p.on ? "" : "off"}"><span>${p.l}</span><b>+${p.v}</b></div>`).join("");
  return `<h3>${t("sb.title")}</h3>
    <div class="sb-total">${t("sb.total")} <b>${esc(row.score)}</b> / 100</div>
    <div class="sbrk">${items}</div>
    <p class="sbnote">${t("sb.note")}</p>`;
}

function renderLag(el, headEl, lag) {
  const since = monthYear(lag.operational_start);
  headEl.innerHTML = `<div class="lead" style="margin:0 0 12px">${t("lag.head", {
    median: "<b>" + esc(lag.median) + "</b>", p90: "<b>" + esc(lag.p90) + "</b>",
    n: "<b>" + (lag.count || 0).toLocaleString() + "</b>", since: esc(since),
  })}</div>`;
  barChart(el, (lag.bins || []).map(b => ({ label: b.label + " d", v: b.count })), {});
}

function renderQueueAge(el, headEl, qa) {
  const un = (qa && qa.unassigned) || { bins: [] }, as = (qa && qa.assigned) || { bins: [] };
  const labels = (un.bins || []).map(b => b.label);
  const rows = labels.map((lab, i) => ({
    label: lab, sin: ((un.bins[i] || {}).count) || 0, con: ((as.bins && as.bins[i] || {}).count) || 0,
  }));
  headEl.innerHTML = `<div class="lead" style="margin:0 0 12px">${t("queue.head", {
    un: "<b>" + esc(un.median_days) + "</b>", as: "<b>" + esc(as.median_days) + "</b>",
  })}</div>`;
  const keys = [["sin", "var(--m1)", t("queue.leg.sin")], ["con", "var(--m3)", t("queue.leg.con")]];
  const W = 940, H = 200, padL = 34, padB = 30, padT = 8;
  const tot = rows.map(r => r.sin + r.con), max = Math.max(1, ...tot), n = rows.length, bw = (W - padL - 6) / n;
  const ticks = 4; let gl = "";
  for (let ti = 0; ti <= ticks; ti++) {
    const v = Math.round(max * ti / ticks), y = padT + (H - padT - padB) * (1 - ti / ticks);
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
  el.innerHTML = `<svg class="evo-svg" viewBox="0 0 ${W} ${H}" width="100%" role="img">${gl}${bars}${labs}</svg>
    <div class="lgd">${keys.map(([, c, lab]) => `<span><i style="background:${c}"></i>${esc(lab)}</span>`).join("")}</div>`;
}

let IMM = [];
function renderImm(filter) {
  const q = (filter || "").trim().toLowerCase();
  const rows = IMM.filter(r => !q || (r.product || "").toLowerCase().includes(q) || (r.cve_id || "").toLowerCase().includes(q));
  if (!rows.length) { $("#imm").innerHTML = '<div class="empty">' + esc(t("imm.noresults", { q: q })) + '</div>'; return; }
  $("#imm").innerHTML = rows.slice(0, 60).map(r => {
    const isCvssHigh = r.cvss != null && r.cvss >= 9.0;
    const chips = [];
    if (r.in_kev) chips.push('<span class="chip kev">KEV</span>');
    if (r.has_public_poc) chips.push('<span class="chip poc">' + esc(t("chip.poc")) + '</span>');
    if (r.cvss != null) chips.push('<span class="chip ' + (isCvssHigh ? "cvss10" : "cvss") + '">CVSS ' + esc(r.cvss) + '</span>');
    if (r.min_tier != null) chips.push('<span class="chip">tier ' + esc(r.min_tier) + '</span>');
    const mat = matLabel(r.maturity);
    const age = daysAgo(r.first_seen_at);
    const rowcls = r.in_kev ? "imm kev" : (isCvssHigh ? "imm red" : "imm");
    return `<div class="${rowcls}" data-id="${esc(r.id)}">
      ${dial(r.score)}
      <div class="body">
        <div class="prod">${esc(r.product || r.cve_id || "—")}</div>
        <div class="meta"><span class="mono">${esc(r.cve_id || t("imm.nocve"))}</span>
          · <span class="badge-mat mat-${esc(r.maturity)}">${esc(mat)}</span>
          ${age != null ? " · " + esc(t("imm.seen", { n: age })) : ""}</div>
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
  if (!series || !series.length) { el.innerHTML = '<div class="empty">' + esc(t("nodata")) + '</div>'; return; }
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
  const labs = series.map((s, i) => { const cx = (pad + i * bw + bw / 2).toFixed(1);
    return `<text x="${cx}" y="${H + 2}" font-size="8" fill="var(--muted)" text-anchor="end"
      transform="rotate(-40 ${cx} ${H + 2})">${esc(String(s.period).slice(2))}</text>`; }).join("");
  el.innerHTML = `<svg viewBox="0 0 ${W} ${H + 26}" width="100%">${bars}${labs}</svg>
    <div class="lgd">
      <span><i style="background:var(--m1)"></i>${esc(t("leg.precve"))}</span>
      <span><i style="background:var(--m2)"></i>${esc(t("leg.prereserved"))}</span>
      <span><i style="background:var(--ctx)"></i>${esc(t("leg.published"))}</span></div>`;
}

function renderEvolution(el, series) {
  if (!series || !series.length) { el.innerHTML = '<div class="empty">' + esc(t("nodata")) + '</div>'; return; }
  const keys = [["pre_cve", "var(--m1)", t("leg.precve")], ["cve_prereserved", "var(--m2)", t("leg.prereserved")], ["cve_reserved", "var(--m3)", t("leg.reserved")]];
  const W = 940, H = 240, padL = 34, padB = 22, padT = 8;
  const tot = series.map(s => keys.reduce((a, [k]) => a + (s[k] || 0), 0));
  const max = Math.max(1, ...tot), n = series.length, bw = (W - padL - 6) / n;
  const ticks = 4; let gl = "";
  for (let ti = 0; ti <= ticks; ti++) {
    const v = Math.round(max * ti / ticks), y = padT + (H - padT - padB) * (1 - ti / ticks);
    gl += `<line x1="${padL}" y1="${y.toFixed(1)}" x2="${W}" y2="${y.toFixed(1)}" stroke="var(--grid)" stroke-width="1"/>`;
    gl += `<text x="${padL - 5}" y="${(y + 3).toFixed(1)}" font-size="9" text-anchor="end">${v}</text>`;
  }
  let bars = "";
  series.forEach((s, i) => {
    let y = H - padB; const x = padL + i * bw;
    keys.forEach(([k, c]) => {
      const h = (s[k] || 0) / max * (H - padT - padB); y -= h;
      if (h > 0) bars += `<rect x="${(x + 2).toFixed(1)}" y="${y.toFixed(1)}" width="${(bw - 4).toFixed(1)}" height="${h.toFixed(1)}" fill="${c}"><title>${esc(s.period)}: ${tot[i]}</title></rect>`;
    });
  });
  const labs = series.map((s, i) => { const cx = (padL + i * bw + bw / 2).toFixed(1);
    return `<text x="${cx}" y="${H - 6}" font-size="9" text-anchor="end"
      transform="rotate(-35 ${cx} ${H - 6})">${esc(String(s.period).slice(2))}</text>`; }).join("");
  el.innerHTML = `<svg class="evo-svg" viewBox="0 0 ${W} ${H}" width="100%" role="img">${gl}${bars}${labs}</svg>
    <div class="lgd">${keys.map(([, c, lab]) => `<span><i style="background:${c}"></i>${esc(lab)}</span>`).join("")}</div>`;
}

function lineChart(el, series) {
  if (!series.length) { el.innerHTML = '<div class="empty">' + esc(t("nodata")) + '</div>'; return; }
  const W = 940, H = 180, padL = 34, padB = 22, padT = 10;
  const max = Math.max(1, ...series.map(s => s.count)), n = series.length;
  const px = i => padL + (i / Math.max(1, n - 1)) * (W - padL - 6);
  const py = v => H - padB - (v / max) * (H - padT - padB);
  let grid = "";
  for (let ti = 0; ti <= 4; ti++) { const gy = padT + (H - padT - padB) * ti / 4;
    grid += `<line x1="${padL}" y1="${gy.toFixed(1)}" x2="${W}" y2="${gy.toFixed(1)}" stroke="var(--grid)"/><text x="${padL - 5}" y="${(gy + 3).toFixed(1)}" font-size="9" text-anchor="end" fill="var(--muted)">${Math.round(max * (1 - ti / 4))}</text>`; }
  const path = series.map((s, i) => `${i ? "L" : "M"}${px(i).toFixed(1)} ${py(s.count).toFixed(1)}`).join(" ");
  const area = `M${padL} ${H - padB} ` + series.map((s, i) => `L${px(i).toFixed(1)} ${py(s.count).toFixed(1)}`).join(" ") + ` L${px(n - 1).toFixed(1)} ${H - padB} Z`;
  const step = Math.max(1, Math.ceil(n / 8));
  const labs = series.map((s, i) => (i % step === 0) ? `<text x="${px(i).toFixed(1)}" y="${H - 7}" font-size="8" text-anchor="middle" fill="var(--muted)">${esc(String(s.day).slice(5))}</text>` : "").join("");
  el.innerHTML = `<svg class="scatter" viewBox="0 0 ${W} ${H}" width="100%">${grid}<path d="${area}" fill="var(--accent-wash)"/><path d="${path}" fill="none" stroke="var(--accent)" stroke-width="1.5"/>${labs}</svg>`;
}
function renderVelocity(el, data) { lineChart(el, data.series || []); }

async function openDrawer(id) {
  $("#scrim").classList.add("on"); $("#drawer").classList.add("on"); $("#drawer").setAttribute("aria-hidden", "false");
  $("#dbody").innerHTML = '<div class="empty">' + esc(t("loading")) + '</div>';
  const row = IMM.find(x => String(x.id) === String(id));
  try {
    const c = await jget("/api/candidate/" + encodeURIComponent(id));
    $("#dtitle").textContent = c.cve_id || ("cand " + String(id).slice(0, 8));
    const cv = (c.cvss && c.cvss[0]) || null;
    const aff = (c.affected || []).map(a => esc([a.vendor, a.product].filter(Boolean).join(" / ") + (a.ecosystem ? " (" + a.ecosystem + ")" : ""))).join("<br>") || "—";
    const tl = (c.timeline || []).slice().sort((a, b) => new Date(a.seen_at) - new Date(b.seen_at));
    const first = tl.length ? tl[0].seen_at : c.first_seen_at;
    let leadHtml = "";
    if (c.days_ahead_present != null) {
      leadHtml = `<div class="lead">${t("dw.lead.published", { d: esc(c.days_ahead_present) })}</div>`;
    } else if (c.status !== "published") {
      const age = daysAgo(first);
      leadHtml = `<div class="lead">${t("dw.lead.open", { status: esc(c.status), age: age != null ? t("dw.days", { n: age }) : "—" })}</div>`;
    }
    const race = (tl.length ? tl : []).map(e => `<div class="ev"><span class="d">${fmtDate(e.seen_at)}</span>
      <span class="t"><span class="src">${esc(e.source)}</span> — ${esc(e.title || "")}</span></div>`).join("")
      + (c.status === "published"
        ? `<div class="ev fin"><span class="d">${esc(t("dw.finish"))}</span><span class="t">${esc(t("dw.nvdfinish"))}</span></div>` : "");
    const chips = [];
    if (c.in_kev) chips.push('<span class="chip kev">KEV ' + fmtDate(c.kev_date) + '</span>');
    if (c.has_public_poc) chips.push('<span class="chip poc">' + esc(t("chip.poc")) + '</span>');
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
      <h3>${t("dw.race")}</h3>
      <div class="race">${race || '<div class="empty">' + esc(t("dw.nosignals")) + '</div>'}</div>
      <h3>${t("dw.affected")}</h3><div class="kv">${aff}</div>
      <h3>${t("dw.cvss")}</h3><div class="kv">${cv ? ('<b>' + esc(cv.base_score) + '</b> ' + esc(cv.base_severity || "") + ' · <span class="mono">' + esc(cv.vector || "") + '</span> · ' + esc(cv.provenance) + '/' + esc(cv.source)) : "—"}</div>
      <h3>${t("dw.ids")}</h3><div class="kv mono">${(c.identifiers || []).map(i => esc(i.scheme + ":" + i.value)).join(" · ") || "—"}</div>
      <h3>${t("dw.refs")}</h3><div class="reflist">${refs}</div>`;
  } catch (e) { $("#dbody").innerHTML = '<div class="empty">' + esc(t("dw.error")) + '</div>'; }
}
function closeDrawer() { $("#scrim").classList.remove("on"); $("#drawer").classList.remove("on"); $("#drawer").setAttribute("aria-hidden", "true"); }
$("#scrim").onclick = closeDrawer; $("#dclose").onclick = closeDrawer;
addEventListener("keydown", e => { if (e.key === "Escape") closeDrawer(); });
$("#surface").oninput = e => renderImm(e.target.value);

applyI18n();

async function load() {
  const eps = ["/api/pending/critical?limit=60", "/api/lag/histogram", "/api/stats",
    "/api/trend?months=12", "/api/emerging?limit=100",
    "/api/queue/age", "/api/velocity?days=60", "/api/funnel"];
  const res = await Promise.allSettled(eps.map(jget));
  const val = i => res[i].status === "fulfilled" ? res[i].value : null;
  const [crit, lag, stats, trend, emerging, queue, vel, funnel] =
    [val(0), val(1), val(2), val(3), val(4), val(5), val(6), val(7)];
  const fail = () => `<div class="empty">${esc(t("unavailable"))}</div>`;

  if (crit) { IMM = crit.rows || []; renderImm(""); } else { $("#imm").innerHTML = fail(); }

  const imminent = IMM.filter(r => (r.score || 0) >= 60).length;
  const today = new Date().toISOString().slice(0, 10);
  const newToday = ((emerging && emerging.rows) || []).filter(r => String(r.first_seen_at || "").slice(0, 10) === today).length;
  $("#kpis").innerHTML = [
    { n: crit ? imminent : "—", c: "crit", l: t("kpi.imm.l"), s: t("kpi.imm.s") },
    { n: lag && lag.median != null ? lag.median : "—", c: "good", l: t("kpi.lead.l"), s: t("kpi.lead.s", { p90: lag && lag.p90 != null ? lag.p90 : "—", n: lag ? lag.count || 0 : "—" }) },
    { n: emerging ? newToday : "—", c: "", l: t("kpi.new.l"), s: t("kpi.new.s") },
    { n: funnel ? (funnel.pre_cve + funnel.cve_prereserved + funnel.cve_reserved).toLocaleString() : "—", c: "", l: t("kpi.pending.l"), s: t("kpi.pending.s", { precve: funnel ? funnel.pre_cve.toLocaleString() : "—", since: funnel ? monthYear(funnel.operational_start) : "—" }) },
  ].map(k => `<div class="kpi"><div class="n ${k.c}">${k.n}</div><div class="l">${esc(k.l)}</div><div class="s">${esc(k.s)}</div></div>`).join("");

  const f = funnel || {};
  const setk = (id, v) => { const e = document.getElementById(id); if (e) e.textContent = v == null ? "—" : Number(v).toLocaleString(); };
  setk("sk-pre_cve", f.pre_cve);
  setk("sk-cve_prereserved", f.cve_prereserved);
  setk("sk-cve_reserved", f.cve_reserved);
  setk("sk-published", f.published);
  const sinceEl = document.getElementById("pyr-since");
  if (sinceEl) sinceEl.textContent = f.operational_start ? t("pyr.since", { date: fmtLongDate(f.operational_start) }) : "";

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
