/* ============================================================
   NetGuard IDS — Frontend Simulation Engine
   ============================================================ */

// ---------- STATE ----------
const state = {
  packets: 0,
  suspicious: 0,
  alerts: [],
  traffic: [],
  paused: false,
  alertId: 1,
  trafficHistory: [], // for chart (packets per tick)
  currentAlertFilter: "ALL",
  currentProtocolFilter: "ALL",
  searchTerm: "",
};

const PROTOCOLS = ["TCP", "UDP", "ICMP"];
const SOURCE_IPS = [
  ...Array.from({ length: 12 }, (_, i) => `192.168.1.${i + 2}`),
  "10.0.0.5", "10.0.0.8", "172.16.0.10", "203.0.113.42", "198.51.100.7",
];
const DEST_IPS = ["8.8.8.8", "1.1.1.1", "10.0.0.1", "142.250.72.14", "104.16.132.229"];
const SAFE_PORTS = [80, 443, 53, 8080, 3000, 8443];
const SENSITIVE_PORTS = [22, 23, 3389, 445, 1433, 3306];

const rand = (a, b) => Math.floor(Math.random() * (b - a + 1)) + a;
const pick = (arr) => arr[rand(0, arr.length - 1)];
const now = () => new Date().toLocaleTimeString("en-GB", { hour12: false });

// ---------- PACKET GENERATOR ----------
function generatePacket() {
  const r = Math.random();
  let pkt = {
    src: pick(SOURCE_IPS),
    dst: pick(DEST_IPS),
    port: pick(SAFE_PORTS),
    proto: pick(PROTOCOLS),
    size: rand(40, 1200),
    time: now(),
    status: "normal",
  };

  if (r < 0.04) {
    // Port scan
    pkt.port = rand(1, 300);
    pkt.size = rand(40, 120);
    pkt.proto = "TCP";
    pkt.status = "scan";
  } else if (r < 0.09) {
    // Oversized
    pkt.size = rand(1400, 1650);
    pkt.status = "oversized";
  } else if (r < 0.13) {
    // Sensitive port
    pkt.port = pick(SENSITIVE_PORTS);
    pkt.proto = "TCP";
    pkt.status = "sensitive";
  }
  return pkt;
}

// ---------- DETECTION RULES ----------
function analyzePacket(pkt) {
  state.packets++;

  if (pkt.status === "scan") {
    addAlert("HIGH", "Port Scan", pkt.src,
      `Port scanning detected from ${pkt.src} targeting ${pkt.port}.`);
    state.suspicious++;
  } else if (pkt.status === "oversized") {
    addAlert("MEDIUM", "Oversized Packet", pkt.src,
      `Unusually large packet (${pkt.size} bytes) from ${pkt.src}.`);
    state.suspicious++;
  } else if (pkt.status === "sensitive") {
    addAlert("LOW", "Sensitive Port Access", pkt.src,
      `Access attempt to sensitive port ${pkt.port} by ${pkt.src}.`);
    state.suspicious++;
  }

  // UDP flood heuristic
  const recentUDP = state.traffic.slice(-30).filter(t => t.proto === "UDP").length;
  if (recentUDP > 22 && Math.random() < 0.3) {
    addAlert("HIGH", "Possible UDP Flood", pkt.src,
      "High UDP traffic volume detected — possible flood attack.");
    state.suspicious++;
  }

  state.traffic.push(pkt);
  if (state.traffic.length > 300) state.traffic.shift();
}

// ---------- ALERT CREATION ----------
function addAlert(severity, type, source, description) {
  // Debounce duplicates
  const recent = state.alerts.slice(0, 4);
  if (recent.some(a => a.type === type && a.source === source)) return;

  state.alerts.unshift({
    id: state.alertId++,
    severity,
    type,
    source,
    description,
    time: new Date().toLocaleString("en-GB", { hour12: false }),
  });
  if (state.alerts.length > 100) state.alerts.pop();
}

// ---------- NAVIGATION ----------
function navigateTo(pageId) {
  document.querySelectorAll(".page").forEach(p => p.classList.remove("active"));
  document.getElementById(`page-${pageId}`).classList.add("active");
  document.querySelectorAll(".nav-link").forEach(l => {
    l.classList.toggle("active", l.dataset.page === pageId);
  });
  window.scrollTo({ top: 0, behavior: "smooth" });
  if (pageId === "dashboard") drawChart();
}

document.querySelectorAll(".nav-link").forEach(link => {
  link.addEventListener("click", (e) => {
    e.preventDefault();
    navigateTo(link.dataset.page);
  });
});
document.querySelectorAll("[data-goto]").forEach(btn => {
  btn.addEventListener("click", () => navigateTo(btn.dataset.goto));
});
document.querySelector(".brand").addEventListener("click", (e) => {
  e.preventDefault();
  navigateTo("home");
});

// ---------- RENDER: STATS ----------
function renderStats() {
  const high = state.alerts.filter(a => a.severity === "HIGH").length;
  const medium = state.alerts.filter(a => a.severity === "MEDIUM").length;
  const low = state.alerts.filter(a => a.severity === "LOW").length;

  document.getElementById("stat-packets").textContent = state.packets.toLocaleString();
  document.getElementById("stat-suspicious").textContent = state.suspicious.toLocaleString();
  document.getElementById("stat-high").textContent = high;
  document.getElementById("stat-alerts").textContent = state.alerts.length;

  document.getElementById("home-packets").textContent = state.packets.toLocaleString();
  document.getElementById("home-alerts").textContent = state.alerts.length;

  // Severity bars
  const total = Math.max(high + medium + low, 1);
  document.getElementById("sev-high-fill").style.width = `${(high / total) * 100}%`;
  document.getElementById("sev-medium-fill").style.width = `${(medium / total) * 100}%`;
  document.getElementById("sev-low-fill").style.width = `${(low / total) * 100}%`;
  document.getElementById("sev-high-count").textContent = high;
  document.getElementById("sev-medium-count").textContent = medium;
  document.getElementById("sev-low-count").textContent = low;

  document.getElementById("last-update").textContent = "just now";
}

// ---------- RENDER: DASHBOARD ALERTS ----------
function renderDashAlerts() {
  const el = document.getElementById("dash-alerts");
  const items = state.alerts.slice(0, 5);
  if (!items.length) {
    el.innerHTML = `<div class="empty-msg">No alerts yet. Waiting for suspicious activity…</div>`;
    return;
  }
  el.innerHTML = items.map(a => `
    <div class="alert-item ${a.severity.toLowerCase()}">
      <div class="alert-head">
        <span class="badge ${a.severity.toLowerCase()}">${a.severity}</span>
        <strong>${a.type}</strong>
        <span class="alert-time">${a.time.split(", ")[1] || a.time}</span>
      </div>
      <p>${a.description}</p>
    </div>
  `).join("");
}

// ---------- RENDER: LIVE TRAFFIC ----------
function renderTraffic() {
  const tbody = document.getElementById("traffic-body");
  const empty = document.getElementById("traffic-empty");

  const filtered = state.traffic.slice(-60).reverse().filter(p => {
    if (state.currentProtocolFilter !== "ALL" && p.proto !== state.currentProtocolFilter) return false;
    if (state.searchTerm) {
      const s = state.searchTerm.toLowerCase();
      if (!p.src.includes(s) && !p.dst.includes(s) && !p.proto.toLowerCase().includes(s)) return false;
    }
    return true;
  });

  if (!filtered.length) {
    tbody.innerHTML = "";
    empty.style.display = "block";
    return;
  }
  empty.style.display = "none";

  tbody.innerHTML = filtered.map(p => {
    const warn = p.size > 1400 || p.status !== "normal";
    let status = `<span class="status-pill status-ok">OK</span>`;
    if (p.status === "scan") status = `<span class="status-pill status-bad">SCAN</span>`;
    else if (p.status === "oversized") status = `<span class="status-pill status-warn">BIG</span>`;
    else if (p.status === "sensitive") status = `<span class="status-pill status-warn">RISK</span>`;

    return `
      <tr class="${warn ? "row-warn" : ""}">
        <td>${p.time}</td>
        <td>${p.src}</td>
        <td>${p.dst}</td>
        <td>${p.port}</td>
        <td><span class="proto-pill">${p.proto}</span></td>
        <td>${p.size}</td>
        <td>${status}</td>
      </tr>`;
  }).join("");
}

// ---------- RENDER: ALERTS PAGE ----------
function renderAlertsPage() {
  const container = document.getElementById("alerts-container");
  const filtered = state.currentAlertFilter === "ALL"
    ? state.alerts
    : state.alerts.filter(a => a.severity === state.currentAlertFilter);

  if (!filtered.length) {
    container.innerHTML = `<div class="empty-msg">No alerts match this filter.</div>`;
    return;
  }
  container.innerHTML = filtered.map(a => `
    <div class="alert-item ${a.severity.toLowerCase()}">
      <div class="alert-head">
        <span class="badge ${a.severity.toLowerCase()}">${a.severity}</span>
        <strong>${a.type}</strong>
        <span class="alert-time">${a.time}</span>
      </div>
      <p>${a.description}</p>
      <small>Source: ${a.source} · Alert #${a.id}</small>
    </div>
  `).join("");
}

// ---------- RENDER: HISTORY TIMELINE ----------
function renderHistory() {
  const el = document.getElementById("history-timeline");
  const recent = state.alerts.slice(0, 30);
  if (!recent.length) {
    el.innerHTML = `<div class="empty-msg">No events logged yet.</div>`;
    return;
  }
  el.innerHTML = recent.map(a => `
    <div class="timeline-item ${a.severity.toLowerCase()}">
      <div class="tl-head">
        <span class="badge ${a.severity.toLowerCase()}">${a.severity}</span>
        <strong>${a.type}</strong>
        <span class="tl-time">${a.time}</span>
      </div>
      <p>${a.description}</p>
    </div>
  `).join("");
}

// ---------- CHART (Canvas mini-chart) ----------
function drawChart() {
  const canvas = document.getElementById("trafficChart");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  const cssW = canvas.parentElement.clientWidth;
  const cssH = 180;
  canvas.width = cssW * dpr;
  canvas.height = cssH * dpr;
  canvas.style.width = cssW + "px";
  canvas.style.height = cssH + "px";
  ctx.scale(dpr, dpr);

  const data = state.trafficHistory.slice(-30);
  if (data.length < 2) {
    ctx.fillStyle = "#64748b";
    ctx.font = "13px Inter, sans-serif";
    ctx.textAlign = "center";
    ctx.fillText("Collecting data…", cssW / 2, cssH / 2);
    return;
  }

  const max = Math.max(...data, 5);
  const pad = 12;
  const w = cssW - pad * 2;
  const h = cssH - pad * 2;
  const step = w / (data.length - 1);

  // Grid
  ctx.strokeStyle = "rgba(34,49,79,0.6)";
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = pad + (h / 4) * i;
    ctx.beginPath();
    ctx.moveTo(pad, y);
    ctx.lineTo(pad + w, y);
    ctx.stroke();
  }

  // Gradient fill
  const grad = ctx.createLinearGradient(0, pad, 0, pad + h);
  grad.addColorStop(0, "rgba(56,189,248,0.35)");
  grad.addColorStop(1, "rgba(56,189,248,0)");

  ctx.beginPath();
  ctx.moveTo(pad, pad + h);
  data.forEach((v, i) => {
    const x = pad + i * step;
    const y = pad + h - (v / max) * h;
    ctx.lineTo(x, y);
  });
  ctx.lineTo(pad + w, pad + h);
  ctx.closePath();
  ctx.fillStyle = grad;
  ctx.fill();

  // Line
  ctx.beginPath();
  data.forEach((v, i) => {
    const x = pad + i * step;
    const y = pad + h - (v / max) * h;
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.strokeStyle = "#38bdf8";
  ctx.lineWidth = 2;
  ctx.stroke();

  // Last point dot
  const lastX = pad + (data.length - 1) * step;
  const lastY = pad + h - (data[data.length - 1] / max) * h;
  ctx.beginPath();
  ctx.arc(lastX, lastY, 4, 0, Math.PI * 2);
  ctx.fillStyle = "#38bdf8";
  ctx.fill();
  ctx.strokeStyle = "#0b1120";
  ctx.lineWidth = 2;
  ctx.stroke();
}

// ---------- FILTERS ----------
document.querySelectorAll(".filter-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".filter-btn").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    state.currentAlertFilter = btn.dataset.filter;
    renderAlertsPage();
  });
});

document.getElementById("traffic-protocol").addEventListener("change", (e) => {
  state.currentProtocolFilter = e.target.value;
  renderTraffic();
});

document.getElementById("traffic-search").addEventListener("input", (e) => {
  state.searchTerm = e.target.value;
  renderTraffic();
});

// ---------- PAUSE BUTTON ----------
document.getElementById("pause-btn").addEventListener("click", (e) => {
  state.paused = !state.paused;
  e.target.textContent = state.paused ? "▶ Resume" : "⏸ Pause";
});

// ---------- EXPORT ----------
document.getElementById("export-btn").addEventListener("click", () => {
  const data = {
    exported: new Date().toISOString(),
    stats: {
      packets: state.packets,
      suspicious: state.suspicious,
      alerts: state.alerts.length,
    },
    alerts: state.alerts,
  };
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `netguard-history-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
});

// ---------- SIMULATION LOOP ----------
let packetsThisTick = 0;

function tick() {
  if (state.paused) return;

  // Generate 2–5 packets per tick
  const n = rand(2, 5);
  for (let i = 0; i < n; i++) {
    const pkt = generatePacket();
    analyzePacket(pkt);
    packetsThisTick++;
  }

  // Record traffic history for chart
  state.trafficHistory.push(packetsThisTick);
  if (state.trafficHistory.length > 60) state.trafficHistory.shift();
  packetsThisTick = 0;

  // Update renders
  renderStats();
  renderDashAlerts();
  renderTraffic();
  renderAlertsPage();
  renderHistory();
  drawChart();
}

// Kick things off
setInterval(tick, 1000);
window.addEventListener("resize", drawChart);
navigateTo("home");