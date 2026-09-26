"use strict";

let snapshot = null;
let timer = null;

const $ = (id) => document.getElementById(id);
const nf = new Intl.NumberFormat("es-ES");
const dtf = new Intl.DateTimeFormat("es-ES", {
  dateStyle: "short", timeStyle: "medium",
});

function number(value) {
  return value == null ? "—" : nf.format(value);
}

function bytes(value) {
  if (value == null) return "—";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let n = Number(value);
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i += 1; }
  return `${n >= 10 || i === 0 ? n.toFixed(0) : n.toFixed(1)} ${units[i]}`;
}

function duration(seconds) {
  if (seconds == null) return "nunca";
  const s = Math.max(0, Number(seconds));
  if (s < 60) return `${Math.round(s)} s`;
  if (s < 3600) return `${Math.round(s / 60)} min`;
  if (s < 86400) return `${(s / 3600).toFixed(s < 7200 ? 1 : 0)} h`;
  return `${(s / 86400).toFixed(s < 172800 ? 1 : 0)} d`;
}

function date(value) {
  return value ? dtf.format(new Date(value)) : "—";
}

function node(tag, text, className) {
  const el = document.createElement(tag);
  if (text != null) el.textContent = String(text);
  if (className) el.className = className;
  return el;
}

function pill(state, label = state) {
  return node("span", label, `pill ${state}`);
}

function setKpis(data) {
  const s = data.summary;
  $("k-health").textContent = data.health === "ok" ? "OK" : data.health === "degraded" ? "DEGRADADO" : "CRÍTICO";
  $("k-health").className = `value ${data.health === "ok" ? "ok" : data.health === "degraded" ? "warning" : "critical"}`;
  $("k-workers").textContent = `${s.workers_online}/${s.workers_expected} workers online`;
  $("k-processes").textContent = number(s.processes);
  $("k-threads").textContent = number(s.threads);
  $("k-zombies").textContent = number(s.zombies);
  $("k-zombies").className = `value ${s.zombies ? "critical" : "ok"}`;
  $("k-fetchers").textContent = `${s.fetchers_enabled}/${s.fetchers_total}`;
  const fs = data.fetchers.summary;
  $("k-fetcher-state").textContent = `${fs.active} ejecutando · ${fs.queued} en cola · ${fs.error + fs.stale} requieren atención`;
  $("k-pending").textContent = number(s.pending_operational);
  $("k-history").textContent = number(s.historical_inconsistencies);
}

function renderWorkers(rows) {
  const root = $("workers");
  root.replaceChildren();
  rows.forEach((worker) => {
    const box = node("article", null, "worker");
    const head = node("div", null, "worker-head");
    head.append(node("span", worker.role, "worker-name"));
    head.append(pill(worker.online ? "ok" : "offline", worker.online ? "online" : "offline"));
    box.append(head);

    const grid = node("div", null, "kv");
    const values = [
      ["Heartbeat", worker.online ? `hace ${duration(worker.heartbeat_age_seconds)}` : "sin señal"],
      ["Procesos", number(worker.process_count)],
      ["Hilos", number(worker.thread_count)],
      ["Zombies", number(worker.zombie_count)],
      ["PIDs cgroup", worker.pids_current == null ? "—" : `${number(worker.pids_current)} / ${worker.pids_limit == null ? "∞" : number(worker.pids_limit)}`],
      ["Tareas", (worker.active || []).join(", ") || "ninguna"],
      ["En cola", (worker.queued || []).join(", ") || "ninguna"],
    ];
    values.forEach(([key, value]) => { grid.append(node("span", key)); grid.append(node("span", value)); });
    box.append(grid);
    if (worker.memory_current_bytes != null) {
      const limit = worker.memory_limit_bytes;
      const percent = limit ? Math.min(100, worker.memory_current_bytes / limit * 100) : 0;
      const bar = node("div", null, "bar");
      const fill = node("i");
      fill.style.width = `${percent}%`;
      bar.append(fill);
      box.append(bar);
      box.append(node("div", `${bytes(worker.memory_current_bytes)}${limit ? ` / ${bytes(limit)}` : ""} de memoria`, "sub"));
    }
    const names = Object.entries(worker.process_names || {}).map(([name, count]) => `${name}×${count}`).join(" · ");
    if (names) box.append(node("div", names, "footnote"));
    root.append(box);
  });
}

function renderAlerts(alerts) {
  const root = $("alerts");
  root.replaceChildren();
  $("alert-count").textContent = alerts.length ? `${alerts.length} avisos` : "sin avisos";
  $("alert-count").className = `pill ${alerts.some((a) => a.severity === "critical") ? "critical" : alerts.length ? "warning" : "ok"}`;
  if (!alerts.length) {
    root.append(node("div", "No hay alertas operativas.", "empty"));
    return;
  }
  alerts.forEach((alert) => root.append(node("div", alert.message, `alert ${alert.severity}`)));
}

function stateLabel(state) {
  return {
    active: "ejecutando", queued: "en cola", ok: "correcto", error: "error",
    stale: "retrasado", never: "sin completar", disabled: "deshabilitado",
  }[state] || state;
}

function renderSources() {
  if (!snapshot) return;
  const query = $("source-search").value.trim().toLowerCase();
  const wanted = $("source-state").value;
  const rows = snapshot.fetchers.rows.filter((row) =>
    (!query || row.name.toLowerCase().includes(query)) && (!wanted || row.state === wanted)
  );
  const body = $("source-body");
  body.replaceChildren();
  rows.forEach((source) => {
    const tr = document.createElement("tr");
    tr.append(node("td", source.name, "worker-name"));
    const state = node("td"); state.append(pill(source.state, stateLabel(source.state))); tr.append(state);
    tr.append(node("td", source.method));
    tr.append(node("td", source.tier, "num"));
    tr.append(node("td", duration(source.cadence_seconds)));
    tr.append(node("td", source.last_success_at ? `${date(source.last_success_at)} · hace ${duration(source.success_age_seconds)}` : "nunca"));
    tr.append(node("td", source.has_error ? (source.error_class || "error") : "—", "wrap"));
    body.append(tr);
  });
  const s = snapshot.fetchers.summary;
  $("source-summary").textContent = `${rows.length} visibles · ${s.ok} correctos · ${s.active} ejecutando · ${s.queued} en cola · ${s.disabled} deshabilitados`;
}

function metric(root, value, label, className = "") {
  const box = node("div", null, "metric");
  box.append(node("b", value, className));
  box.append(node("span", label));
  root.append(box);
}

function renderDatabase(db) {
  $("db-version").textContent = `${db.migration ? "migraciones aplicadas" : "sin migraciones"} · ${bytes(db.size_bytes)}`;
  const root = $("db-metrics"); root.replaceChildren();
  metric(root, number(db.total), "conexiones");
  metric(root, number(db.active), "activas", db.active > 8 ? "warning" : "");
  metric(root, number(db.idle), "idle");
  metric(root, number(db.idle_in_transaction), "idle en transacción", db.long_idle_in_transaction ? "warning" : "");
  metric(root, number(db.long_idle_in_transaction), "idle tx >30 s", db.long_idle_in_transaction ? "warning" : "ok");
  metric(root, number(db.blocked), "esperando lock", db.blocked ? "critical" : "ok");
  metric(root, duration(db.max_transaction_age_seconds), "transacción más larga");
}

function renderIngestion(ing) {
  const root = $("ingest-metrics"); root.replaceChildren();
  metric(root, number(ing.published_cves), "CVEs en baseline");
  metric(root, number(ing.nvd_published), "presentes en NVD");
  metric(root, number(ing.candidates), "candidatos vivos");
  metric(root, number(ing.mentions), "menciones");
  metric(root, number(ing.affected_products), "productos afectados");
  metric(root, number(ing.rejected_cves), "CVEs rechazados");
  metric(root, number(ing.historical_pending), "pendientes históricas excluidas");
  metric(root, number(ing.source_inconsistencies), "inconsistencias de identificador");
  metric(root, number(ing.github_repos.commits_scanned), `repos commits escaneados de ${number(ing.github_repos.total)}`);
  metric(root, number(ing.github_repos.commits_pending), "repos pendientes de commits", ing.github_repos.commits_pending ? "warning" : "ok");
  metric(root, number(ing.github_repos.advisories_scanned), `repos advisories escaneados de ${number(ing.github_repos.total)}`);
  metric(root, number(ing.github_repos.advisories_pending), "repos pendientes de advisories", ing.github_repos.advisories_pending ? "warning" : "ok");
}

function renderTables(rows) {
  const body = $("table-body"); body.replaceChildren();
  rows.forEach((row) => {
    const tr = document.createElement("tr");
    tr.append(node("td", row.table_name, "worker-name"));
    tr.append(node("td", number(row.estimated_rows), "num"));
    tr.append(node("td", number(row.dead_rows), `num ${row.dead_rows > row.estimated_rows * 0.2 ? "warning" : ""}`));
    tr.append(node("td", date(row.last_autoanalyze)));
    body.append(tr);
  });
}

function renderSync(rows) {
  const body = $("sync-body"); body.replaceChildren();
  if (!rows.length) {
    const tr = document.createElement("tr");
    const td = node("td", "Todavía no hay cursores confirmados.", "sub");
    td.colSpan = 3; tr.append(td); body.append(tr); return;
  }
  rows.forEach((row) => {
    const tr = document.createElement("tr");
    tr.append(node("td", row.id, "worker-name"));
    tr.append(node("td", row.updated_at ? `${date(row.updated_at)} · hace ${duration(row.age_seconds)}` : "—"));
    tr.append(node("td", row.cursor || "—", "wrap"));
    body.append(tr);
  });
}

function render(data) {
  snapshot = data;
  $("stamp").textContent = `snapshot ${date(data.generated_at)} · refresco automático 30 s`;
  setKpis(data);
  renderWorkers(data.workers);
  renderAlerts(data.alerts);
  renderSources();
  renderDatabase(data.database);
  renderIngestion(data.ingestion);
  renderTables(data.ingestion.tables);
  renderSync(data.sync);
}

async function load() {
  const button = $("refresh");
  const error = $("load-error");
  button.disabled = true;
  try {
    const response = await fetch("/api/admin/status", {cache: "no-store"});
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    render(await response.json());
    error.style.display = "none";
  } catch (exc) {
    error.textContent = `No se pudo cargar el estado: ${exc.message}`;
    error.style.display = "block";
  } finally {
    button.disabled = false;
  }
}

const themes = ["auto", "light", "dark"];
let themeIndex = 0;
function cycleTheme() {
  themeIndex = (themeIndex + 1) % themes.length;
  const theme = themes[themeIndex];
  if (theme === "auto") document.documentElement.removeAttribute("data-theme");
  else document.documentElement.dataset.theme = theme;
  $("theme").textContent = `Tema: ${theme}`;
  localStorage.setItem("foreshock-admin-theme", theme);
}

const savedTheme = localStorage.getItem("foreshock-admin-theme");
if (themes.includes(savedTheme)) {
  themeIndex = themes.indexOf(savedTheme);
  if (savedTheme !== "auto") document.documentElement.dataset.theme = savedTheme;
  $("theme").textContent = `Tema: ${savedTheme}`;
}
$("theme").addEventListener("click", cycleTheme);
$("refresh").addEventListener("click", load);
$("source-search").addEventListener("input", renderSources);
$("source-state").addEventListener("change", renderSources);
load();
timer = window.setInterval(load, 30000);
window.addEventListener("beforeunload", () => window.clearInterval(timer));
