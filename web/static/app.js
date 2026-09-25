/* Dashboard front-end. Polls the JSON API a few times a second and paints the
   page. All POSTs carry the CSRF token the server handed us at login. */
"use strict";

const CSRF = window.CSRF;
const $ = (id) => document.getElementById(id);

async function api(path, method = "GET", body = null) {
  const opt = { method, headers: {} };
  if (body) {
    opt.headers["Content-Type"] = "application/json";
    opt.headers["X-CSRF-Token"] = CSRF;
    opt.body = JSON.stringify(body);
  }
  const r = await fetch(path, opt);
  if (r.status === 401) { location.href = "/"; return null; }
  try { return await r.json(); } catch (e) { return null; }
}

/* ---------- charts ---------- */
let ppsChart, protoChart;
function initCharts() {
  if (!window.Chart) return;
  const gridColor = "#2a2f3a", tick = "#8a93a2";
  ppsChart = new Chart($("ppsChart"), {
    type: "line",
    data: { labels: [], datasets: [{ data: [], borderColor: "#4f8cff",
      backgroundColor: "rgba(79,140,255,.15)", fill: true, tension: .3,
      pointRadius: 0, borderWidth: 2 }] },
    options: { plugins: { legend: { display: false } },
      scales: { x: { display: false }, y: { beginAtZero: true, grid: { color: gridColor },
        ticks: { color: tick, precision: 0 } } } }
  });
  protoChart = new Chart($("protoChart"), {
    type: "doughnut",
    data: { labels: [], datasets: [{ data: [],
      backgroundColor: ["#4f8cff","#39d98a","#ffb020","#ff5c7c","#a06bff","#57c7d4"] }] },
    options: { plugins: { legend: { position: "right",
      labels: { color: "#e7ecf3", boxWidth: 12 } } } }
  });
}

/* ---------- painters ---------- */
function paintStatus(s) {
  if (!s || !s.engine) { $("modeBadge").textContent = "offline"; return; }
  const badge = $("modeBadge");
  badge.textContent = s.mode;
  badge.className = "badge " + s.mode;
  $("btnMonitor").classList.toggle("on", s.mode === "monitor");
  $("btnEnforce").classList.toggle("on", s.mode === "enforce");

  const st = s.stats || {};
  $("sTotal").textContent = st.total ?? 0;
  $("sAllowed").textContent = st.allowed ?? 0;
  $("sDenied").textContent = st.denied ?? 0;
  $("sAlerts").textContent = st.alerts ?? 0;
  $("sBlocked").textContent = s.blocked ?? 0;
  $("sConns").textContent = s.connections ?? 0;

  if (ppsChart && st.pps) {
    ppsChart.data.labels = st.pps.map(p => p.t);
    ppsChart.data.datasets[0].data = st.pps.map(p => p.n);
    ppsChart.update("none");
  }
  if (protoChart && st.by_proto) {
    protoChart.data.labels = Object.keys(st.by_proto);
    protoChart.data.datasets[0].data = Object.values(st.by_proto);
    protoChart.update("none");
  }
  paintRows("talkers", (st.top_talkers || []).map(t => [t.ip, t.packets]));
  paintRows("targets", (st.top_targets || []).map(t => ["port " + t.port, t.packets]));
  paintAi(s.ai);
}
function paintRows(id, rows) {
  $(id).innerHTML = rows.map(r => `<tr><td>${esc(r[0])}</td><td>${r[1]}</td></tr>`).join("")
    || `<tr><td class="muted">no data yet</td><td></td></tr>`;
}

function timeStr(ts) { return new Date(ts * 1000).toLocaleTimeString(); }
function esc(s) { return String(s).replace(/[&<>"]/g, c =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])); }

async function paintEvents() {
  const ev = await api("/api/events?limit=80"); if (!ev) return;
  $("eventsBody").innerHTML = ev.map(e => `<tr>
    <td class="muted">${timeStr(e.ts)}</td><td>${e.direction}</td><td>${esc(e.proto)}</td>
    <td>${esc(e.src)}${e.sport ? ":" + e.sport : ""}</td>
    <td>${esc(e.dst)}${e.dport ? ":" + e.dport : ""}</td>
    <td class="muted">${e.length}</td>
    <td><span class="pill ${e.action}">${e.action}</span></td>
    <td class="muted">${esc(e.reason || "")}</td></tr>`).join("")
    || `<tr><td class="muted" colspan="8">No traffic recorded yet.</td></tr>`;
}
async function paintAlerts() {
  const al = await api("/api/alerts?limit=80"); if (!al) return;
  $("alertsBody").innerHTML = al.map(a => `<tr>
    <td class="muted">${timeStr(a.ts)}</td><td>${esc(a.kind)}</td><td>${esc(a.src)}</td>
    <td><span class="pill sev-${a.severity}">${a.severity}</span></td>
    <td>${esc(a.detail)}</td><td class="muted">${esc(a.acted || "logged only")}</td></tr>`).join("")
    || `<tr><td class="muted" colspan="6">No alerts. Good.</td></tr>`;
}
async function paintBlocks() {
  const b = await api("/api/blocks"); if (!b) return;
  $("blocksBody").innerHTML = (b.active || []).map(x => `<tr>
    <td>${esc(x.ip)}</td><td>${esc(x.reason)}</td><td>${esc(x.source)}</td>
    <td class="muted">${x.age}</td>
    <td class="muted">${x.remaining == null ? "permanent" : x.remaining + "s"}</td>
    <td><span class="link-danger" data-unblock="${esc(x.ip)}">unblock</span></td></tr>`).join("")
    || `<tr><td class="muted" colspan="6">Nothing blocked right now.</td></tr>`;
  document.querySelectorAll("[data-unblock]").forEach(el =>
    el.onclick = async () => { await api("/api/unblock", "POST", { ip: el.dataset.unblock }); paintBlocks(); });
}
async function paintRules() {
  const rl = await api("/api/rules"); if (!rl) return;
  $("rulesBody").innerHTML = rl.map(r => `<tr>
    <td class="muted">${r.id}</td>
    <td><span class="pill ${r.action}">${r.action}</span></td>
    <td>${r.direction}</td><td>${r.protocol}</td>
    <td>${esc(r.src)}</td><td>${esc(r.dst)}</td>
    <td>${esc(fmtPorts(r.dst_ports))}</td><td class="muted">${esc(r.comment || "")}</td>
    <td><span class="link-danger" data-del="${r.id}">delete</span></td></tr>`).join("");
  document.querySelectorAll("[data-del]").forEach(el =>
    el.onclick = async () => { await api("/api/rules/" + el.dataset.del, "DELETE"); paintRules(); });
}
function fmtPorts(p) {
  if (p === "any" || p == null || p === "") return "any";
  return Array.isArray(p) ? p.join(",") : p;
}
function paintAi(ai) {
  if (!ai) return;
  const lines = [
    `scikit-learn available : ${ai.have_sklearn}`,
    `model trained          : ${ai.ready ? "yes (" + ai.trained_rows + " samples)" : "no"}`,
    `currently learning     : ${ai.learning ? "yes — collected " + ai.collected_rows + " samples" : "no"}`,
    `features watched       : ${(ai.features || []).join(", ")}`,
  ];
  $("aiStatus").textContent = lines.join("\n");
  $("btnLearn").disabled = ai.learning;
  $("btnStopLearn").disabled = !ai.learning;
}

/* ---------- actions ---------- */
function wire() {
  document.querySelectorAll(".tab").forEach(t => t.onclick = () => {
    document.querySelectorAll(".tab").forEach(x => x.classList.remove("active"));
    document.querySelectorAll(".tabpane").forEach(x => x.classList.remove("active"));
    t.classList.add("active");
    $("tab-" + t.dataset.tab).classList.add("active");
    refreshActive(t.dataset.tab);
  });
  $("btnMonitor").onclick = () => api("/api/mode", "POST", { mode: "monitor" }).then(tick);
  $("btnEnforce").onclick = () => {
    if (confirm("Enforce mode will actually drop packets and block sources. Continue?"))
      api("/api/mode", "POST", { mode: "enforce" }).then(tick);
  };
  $("btnBlock").onclick = async () => {
    const ip = $("blockIp").value.trim(); if (!ip) return;
    const secs = parseInt($("blockSecs").value || "0", 10);
    const r = await api("/api/block", "POST", { ip, seconds: secs });
    if (r && r.error) alert(r.error);
    $("blockIp").value = ""; paintBlocks();
  };
  $("btnAddRule").onclick = async () => {
    const body = {
      action: $("rAction").value, direction: $("rDir").value, protocol: $("rProto").value,
      src: $("rSrc").value.trim() || "any", dst: $("rDst").value.trim() || "any",
      dst_ports: $("rDport").value.trim() || "any", comment: $("rComment").value.trim(),
    };
    const r = await api("/api/rules", "POST", body);
    if (r && r.error) { alert(r.error); return; }
    ["rSrc","rDst","rDport","rComment"].forEach(i => $(i).value = "");
    paintRules();
  };
  $("btnLearn").onclick = () => api("/api/ai/learn", "POST", { action: "start" }).then(tick);
  $("btnStopLearn").onclick = () => api("/api/ai/learn", "POST", { action: "stop" }).then(tick);
  $("btnTrain").onclick = async () => {
    const r = await api("/api/ai/train", "POST", {});
    alert(r && r.ok ? `Trained on ${r.rows} samples across ${r.features} features.`
                    : "Train failed: " + (r && r.error));
    tick();
  };
  $("autoBlock").onchange = () => api("/api/ai/autoblock", "POST", { enabled: $("autoBlock").checked });
  const pw = $("pwChange");
  if (pw) pw.onclick = async () => {
    const p = prompt("New dashboard password (min 6 chars):");
    if (!p) return;
    const r = await api("/api/change-password", "POST", { password: p });
    if (r && r.ok) { alert("Password changed."); $("pwBanner").style.display = "none"; }
    else alert(r && r.error);
  };
  if (window.MUST_CHANGE) $("pwBanner").style.display = "block";
}

function refreshActive(tab) {
  if (tab === "events") paintEvents();
  else if (tab === "alerts") paintAlerts();
  else if (tab === "blocks") paintBlocks();
  else if (tab === "rules") paintRules();
}
function activeTab() {
  const t = document.querySelector(".tab.active");
  return t ? t.dataset.tab : "events";
}

async function tick() {
  const s = await api("/api/status");
  paintStatus(s);
  refreshActive(activeTab());
}

document.addEventListener("DOMContentLoaded", () => {
  initCharts(); wire();
  paintRules();
  tick();
  setInterval(tick, 1500);
});
