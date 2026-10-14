// VendorGuard dashboard — talks to the local Go server's /api endpoints.
"use strict";

const state = { meta: null, analysis: null, controls: new Set(), filters: { sev: "", acc: "", stage: "" } };
const SEV_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3 };
const SEV_COLOR = { Critical: "var(--crit)", High: "var(--high)", Medium: "var(--med)", Low: "var(--low)" };

const RULES = [
  ["UNKNOWN_VENDOR", 1, "An event names a vendor that is not in the vendor register."],
  ["UNKNOWN_LOCATION", 1, "A vendor login comes from a country outside the vendor's allowed list."],
  ["BRUTE_FORCE", 2, "An account fails to log in 3+ times within 10 minutes."],
  ["NO_MFA", 2, "A vendor login succeeds without multi-factor authentication."],
  ["OFF_HOURS", 2, "A login happens outside the vendor's approved working hours."],
  ["EXPIRED_ACCESS", 2, "A login happens after the vendor's just-in-time window ended, or the vendor is inactive."],
  ["UNKNOWN_ACCOUNT", 2, "A login uses an account not issued to that vendor."],
  ["PRIV_ESCALATION", 2, "An account's role is raised above the vendor's maximum role."],
  ["DISCOVERY_ACCOUNTS", 3, "A vendor session enumerates directory accounts."],
  ["DISCOVERY_NETWORK", 3, "A vendor session scans the network for services."],
  ["LATERAL_MOVEMENT", 4, "A remote session opens to a system or zone outside the vendor's scope."],
  ["SCOPE_VIOLATION", 5, "Data is read from a system or zone outside the vendor's scope."],
  ["LARGE_TRANSFER", 6, "More than 500 MB leaves in a single transfer."],
  ["MASS_ENCRYPTION", 7, "200+ files are rewritten in one burst, a sign of encryption."],
];

// ---------- helpers ----------
const $ = (s, el = document) => el.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const pill = (sev) => `<span class="pill ${esc(sev)}">${esc(sev)}</span>`;
const fmtTime = (iso) => {
  const d = new Date(iso);
  if (isNaN(d)) return "";
  // Show the log's own clock time (the server sends the original offset).
  const m = /T(\d{2}:\d{2})/.exec(iso);
  const day = iso.slice(8, 10) + " " + ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"][+iso.slice(5, 7) - 1];
  return `${day} ${m ? m[1] : ""}`;
};
const controlName = (id) => (state.meta?.controls.find((c) => c.id === id) || { name: id }).name;
const stageName = (n) => (state.meta?.chain.find((s) => s.number === n) || { name: "" }).name;

async function api(path, opts) {
  const r = await fetch(path, opts);
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(body.error || `Request failed (${r.status})`);
  return body;
}

// ---------- tabs ----------
function showTab(name) {
  document.querySelectorAll(".tabs button").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.tab === name)));
  document.querySelectorAll(".tab").forEach((t) => (t.hidden = t.id !== "tab-" + name));
  try { localStorage.setItem("vg-tab", name); } catch (_) {}
}
document.querySelectorAll(".tabs button").forEach((b) => b.addEventListener("click", () => showTab(b.dataset.tab)));

// ---------- overview ----------
function renderOverview() {
  const a = state.analysis;
  const observed = a.chain.filter((s) => s.observed).length;
  const top = a.accountRisk[0];
  const alarm = top && top.verdict.startsWith("Probable");
  const hl = $("#headline");
  hl.className = "headline" + (alarm ? " alarm" : "");
  hl.innerHTML = top
    ? `<div><div>${alarm ? "<b>Ransomware kill chain detected.</b> " : ""}${esc(a.headline)}</div>
       <div class="verdict">${esc(top.account)} · ${esc(top.vendor)} — ${esc(top.verdict)}</div></div>`
    : `<div>${esc(a.headline)}</div>`;

  const flagged = a.accountRisk.length;
  const tiles = [
    ["Log events", a.events, `${a.vendors} vendors · ${a.accounts} accounts`],
    ["Alerts", a.alerts.length, `${a.bySeverity.High || 0} high · ${a.bySeverity.Medium || 0} medium`],
    ["Critical alerts", a.bySeverity.Critical || 0, "privilege, exfiltration, encryption", "crit"],
    ["Accounts flagged", flagged, `of ${a.accounts} active accounts`],
    ["Attack-chain stages", `${observed}/7`, observed === 7 ? "full chain observed" : "stages with alerts", observed >= 4 ? "crit" : ""],
  ];
  $("#tiles").innerHTML = tiles
    .map(([l, v, s, cls]) => `<div class="tile ${cls || ""}"><div class="label">${l}</div><div class="value">${v}</div><div class="sub">${s}</div></div>`)
    .join("");

  $("#strip").innerHTML = a.chain
    .map((s) => `<li class="${s.observed ? "hit" : ""}"><span class="n">${s.number}</span>
      <span><b>${esc(s.name)}</b> <span class="muted small">${s.techniques.map((t) => t.id).join(", ")}</span></span>
      <span class="when">${s.observed ? `${s.alerts} alert${s.alerts > 1 ? "s" : ""} · ${fmtTime(s.firstSeen)}` : "not seen"}</span></li>`)
    .join("");

  $("#accountsMini").innerHTML = a.accountRisk.length
    ? a.accountRisk
        .map((r) => {
          const color = r.score >= 60 ? "var(--crit)" : r.score >= 20 ? "var(--high)" : "var(--med)";
          return `<div class="acc"><div class="top-line"><span><span class="name">${esc(r.account)}</span> <span class="muted small">${esc(r.vendor)}</span></span>
            <span class="score">${r.score}<span class="muted small">/100</span></span></div>
            <div class="bar"><span style="width:${r.score}%;background:${color}"></span></div>
            <div class="small muted">${esc(r.verdict)} · ${r.alerts} alert${r.alerts > 1 ? "s" : ""}</div></div>`;
        })
        .join("")
    : `<p class="muted">No accounts flagged.</p>`;
}

// ---------- alerts ----------
function fillFilters() {
  const a = state.analysis;
  const accs = [...new Set(a.alerts.map((x) => x.account))].sort();
  $("#fAcc").innerHTML = `<option value="">All</option>` + accs.map((x) => `<option>${esc(x)}</option>`).join("");
  $("#fStage").innerHTML = `<option value="">All</option>` + state.meta.chain.map((s) => `<option value="${s.number}">${s.number}. ${esc(s.name)}</option>`).join("");
  $("#fSev").value = $("#fAcc").value = $("#fStage").value = "";
  state.filters = { sev: "", acc: "", stage: "" };
}

function filteredAlerts() {
  const f = state.filters;
  return state.analysis.alerts.filter((x) => (!f.sev || x.severity === f.sev) && (!f.acc || x.account === f.acc) && (!f.stage || String(x.stage) === f.stage));
}

function renderAlerts() {
  const rows = filteredAlerts();
  $("#alertCount").textContent = `${rows.length} of ${state.analysis.alerts.length} alerts`;
  $("#alertTable tbody").innerHTML = rows.length
    ? rows
        .map((x) => `<tr>
          <td class="time">${fmtTime(x.time)}</td>
          <td>${pill(x.severity)}</td>
          <td class="small">${x.stage}. ${esc(stageName(x.stage))}</td>
          <td><span class="tag">${esc(x.technique)}</span></td>
          <td><b>${esc(x.account)}</b><div class="detail">${esc(x.vendor)}</div></td>
          <td>${esc(x.title)}<div class="detail">${esc(x.detail)}</div></td>
          <td>${x.controls.map((c) => `<span class="ctl">${esc(controlName(c))}</span>`).join(" ")}</td></tr>`)
        .join("")
    : `<tr><td colspan="7" class="empty">No alerts match these filters.</td></tr>`;

  $("#accTable tbody").innerHTML = state.analysis.accountRisk
    .map((r) => `<tr><td><b>${esc(r.account)}</b></td><td>${esc(r.vendor)}</td><td class="num"><b>${r.score}</b></td><td class="num">${r.alerts}</td>
      <td>${r.stages.map((s) => `<span class="tag">${s}</span>`).join("")}</td><td>${esc(r.verdict)}</td></tr>`)
    .join("") || `<tr><td colspan="6" class="empty">No accounts flagged.</td></tr>`;

  const w = state.analysis.warnings || [];
  $("#warnings").innerHTML = w.length ? `<div class="warn"><b>${w.length} row(s) skipped:</b> ${w.slice(0, 5).map(esc).join("; ")}${w.length > 5 ? "…" : ""}</div>` : "";
}

["fSev", "fAcc", "fStage"].forEach((id) =>
  $("#" + id).addEventListener("change", (e) => {
    state.filters[{ fSev: "sev", fAcc: "acc", fStage: "stage" }[id]] = e.target.value;
    renderAlerts();
  })
);

$("#exportBtn").addEventListener("click", () => {
  const head = ["time", "severity", "stage", "technique", "vendor", "account", "rule", "title", "detail", "controls", "log_line"];
  const q = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
  const lines = filteredAlerts().map((x) =>
    [x.time, x.severity, x.stage, x.technique, x.vendor, x.account, x.rule, x.title, x.detail, x.controls.map(controlName).join("; "), x.line].map(q).join(",")
  );
  const blob = new Blob([head.join(",") + "\n" + lines.join("\n")], { type: "text/csv" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "vendorguard_alerts.csv";
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
});

// ---------- attack chain ----------
function renderChain() {
  $("#chain").innerHTML = state.analysis.chain
    .map((s) => `<div class="stage ${s.observed ? "hit" : ""}">
      <div class="rail"><div class="dot">${s.number}</div><div class="line"></div></div>
      <div class="card">
        <div class="head"><h3>${esc(s.name)}</h3>
          <span class="status ${s.observed ? "hit" : "clear"}">${s.observed ? `Observed · ${s.alerts} alert${s.alerts > 1 ? "s" : ""} · first ${fmtTime(s.firstSeen)}` : "Not observed in this log"}</span></div>
        <p class="muted">${esc(s.description)}</p>
        <div class="cols">
          <div><h4>MITRE ATT&amp;CK</h4>${s.techniques.map((t) => `<div><span class="tag">${esc(t.id)}</span> ${esc(t.name)}</div>`).join("")}</div>
          <div><h4>Controls that break it</h4>${s.prevent.map((c) => `<span class="ctl">${esc(controlName(c))}</span>`).join(" ")}</div>
          <div><h4>Detected by</h4>${s.detect.map((r) => `<span class="tag">${esc(r)}</span>`).join(" ")}</div>
        </div>
      </div></div>`)
    .join("");
}

// ---------- risk register ----------
function renderControls() {
  $("#controls").innerHTML = state.meta.controls
    .map((c) => `<label><input type="checkbox" value="${esc(c.id)}" ${state.controls.has(c.id) ? "checked" : ""}>
      <span><span class="cname">${esc(c.name)}</span> <span class="sec">${/^\d/.test(c.section) ? "§" + esc(c.section) : esc(c.section)}</span><div class="cdesc">${esc(c.description)}</div></span></label>`)
    .join("");
  $("#controls").querySelectorAll("input").forEach((i) =>
    i.addEventListener("change", () => {
      i.checked ? state.controls.add(i.value) : state.controls.delete(i.value);
      loadRisk();
    })
  );
}

async function loadRisk() {
  const data = await api("/api/risk?controls=" + encodeURIComponent([...state.controls].join(",")));
  const s = data.summary;
  const crit = (c) => c.Critical || 0;
  $("#riskTiles").innerHTML = [
    ["Total risk score", `${s.inherentTotal} → ${s.residualTotal}`, `sum of 8 threats (max 128)`],
    ["Risk reduction", `${s.reductionPct}%`, `${state.controls.size} of ${state.meta.controls.length} controls applied`],
    ["Critical threats", `${crit(s.inherentCount)} → ${crit(s.residualCount)}`, `${s.residualCount.High || 0} high · ${s.residualCount.Medium || 0} medium · ${s.residualCount.Low || 0} low after controls`, crit(s.residualCount) ? "crit" : ""],
  ]
    .map(([l, v, sub, cls]) => `<div class="tile ${cls || ""}"><div class="label">${l}</div><div class="value">${v}</div><div class="sub">${sub}</div></div>`)
    .join("");

  $("#riskTable tbody").innerHTML = data.threats
    .map((t) => {
      const changed = t.residualScore !== t.inherentScore;
      const lvl = ["", "Low", "Medium", "High", "Very High"];
      return `<tr>
        <td><b>${esc(t.name)}</b></td>
        <td>${t.techniques.map((x) => `<span class="tag">${esc(x)}</span>`).join("")}</td>
        <td>${changed && t.residualLikelihood !== t.likelihood ? `<s class="muted">${t.likelihoodLabel}</s> ${lvl[t.residualLikelihood]}` : t.likelihoodLabel}</td>
        <td>${changed && t.residualImpact !== t.impact ? `<s class="muted">${t.impactLabel}</s> ${lvl[t.residualImpact]}` : t.impactLabel}</td>
        <td><span class="riskcell"><span class="sc">${t.inherentScore}</span>${pill(t.inherentRating)}</span></td>
        <td><span class="riskcell"><span class="sc">${t.residualScore}</span>${pill(t.residualRating)}${changed ? `<span class="down">−${t.reductionPct}%</span>` : ""}</span></td>
        <td>${t.missingControls.length ? t.missingControls.map((c) => `<span class="ctl">${esc(controlName(c))}</span>`).join(" ") : `<span class="muted small">none</span>`}</td></tr>`;
    })
    .join("");
}

$("#allCtl").addEventListener("click", () => { state.meta.controls.forEach((c) => state.controls.add(c.id)); renderControls(); loadRisk(); });
$("#noCtl").addEventListener("click", () => { state.controls.clear(); renderControls(); loadRisk(); });

// ---------- about ----------
function renderAbout() {
  $("#rulesTable tbody").innerHTML = RULES.map(([r, st, d]) => `<tr><td><span class="tag">${r}</span></td><td>${st}</td><td class="small">${esc(d)}</td></tr>`).join("");
  $("#ver").textContent = "VendorGuard v" + state.meta.version;
}

// ---------- load own log ----------
const dlg = $("#loadDlg");
$("#loadBtn").addEventListener("click", () => { $("#loadErr").hidden = true; dlg.showModal(); });
const readFile = (f) => (f ? f.text() : Promise.resolve(""));

$("#runBtn").addEventListener("click", async () => {
  const lf = $("#logFile").files[0];
  const pf = $("#polFile").files[0];
  const err = $("#loadErr");
  if (!lf) { err.textContent = "Choose an access-log CSV first."; err.hidden = false; return; }
  try {
    const [logs, vendors] = await Promise.all([readFile(lf), readFile(pf)]);
    const res = await api("/api/analyze", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ logs, vendors }) });
    setAnalysis(res, lf.name + (pf ? " + " + pf.name : ""));
    dlg.close();
  } catch (e) {
    err.textContent = e.message;
    err.hidden = false;
  }
});
$("#resetBtn").addEventListener("click", async () => {
  setAnalysis(await api("/api/analysis"), "Built-in sample log");
  dlg.close();
});

function setAnalysis(a, label) {
  state.analysis = a;
  $("#sourceLabel").textContent = label;
  fillFilters();
  renderOverview();
  renderAlerts();
  renderChain();
}

// ---------- start ----------
(async function init() {
  try {
    state.meta = await api("/api/meta");
    setAnalysis(await api("/api/analysis"), "Built-in sample log");
    renderControls();
    renderAbout();
    await loadRisk();
    let tab = "overview";
    try { tab = localStorage.getItem("vg-tab") || tab; } catch (_) {}
    showTab(tab);
  } catch (e) {
    document.querySelector("main").innerHTML = `<div class="card"><h2>Could not reach VendorGuard</h2><p class="muted">${esc(e.message)}. Make sure the VendorGuard window is still open, then refresh this page.</p></div>`;
  }
})();
