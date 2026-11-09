"use strict";

// Dashboard logic. All server data is inserted with textContent, never innerHTML,
// because header values come from arbitrary third-party websites.

const GRADE_COLOURS = { A: "--pass", B: "--pass", C: "--warn", D: "--warn", E: "--fail", F: "--fail" };
const STATUS_LABEL = { pass: "Pass", warn: "Warn", fail: "Fail" };
const STATUS_ORDER = { fail: 0, warn: 1, pass: 2 };

const $ = (sel, root = document) => root.querySelector(sel);

function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  Object.assign(node, props);
  for (const child of children) node.append(child);
  return node;
}

// On GitHub Pages there is no server, so the page shows reports produced by the
// scheduled scan workflow (data/index.json). Locally it calls the live API.
let DEMO = null;
const REPO_URL = "https://github.com/LM-Ninio001/headerguard";

function hostOf(input) {
  const text = input.trim().toLowerCase();
  try {
    return new URL(text.includes("://") ? text : `https://${text}`).hostname.replace(/^www\./, "");
  } catch {
    return text;
  }
}

function demoSite(url) {
  const host = hostOf(url);
  return DEMO.sites.find(s => s.host === host || s.host.replace(/^www\./, "") === host);
}

async function loadDemoReport(url) {
  const site = demoSite(url);
  if (!site) {
    throw new Error(`${url} isn't in this demo's daily scan list. Pick one of the sites above, or install HeaderGuard to scan any site.`);
  }
  const res = await fetch(`data/${encodeURIComponent(site.file)}`);
  if (!res.ok) throw new Error(`The saved report for ${site.host} could not be loaded.`);
  return res.json();
}

function isReport(data) {
  return data && typeof data === "object" && data.grade && typeof data.grade.score === "number"
    && /^[A-F]$/.test(data.grade.letter) && Array.isArray(data.findings) && typeof data.final_url === "string";
}

async function scan(url) {
  // Daily-scanned sites load instantly from saved reports; anything else needs
  // the live API (hosted separately when the page itself is on GitHub Pages).
  if (DEMO && (demoSite(url) || !DEMO.api_url)) return loadDemoReport(url);
  const endpoint = DEMO ? `${DEMO.api_url.replace(/\/$/, "")}/api/scan` : "api/scan";
  let res;
  try {
    res = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
  } catch {
    throw new Error(`${url}: the scanning server could not be reached. Try again in a minute.`);
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const detail = typeof data.detail === "string" ? data.detail : "Enter a website address, like example.com.";
    throw new Error(`${url}: ${detail}`);
  }
  return data;
}

function drawTicks(svg) {
  const group = $(".ticks", svg);
  for (let i = 0; i <= 10; i++) {
    const angle = Math.PI * (1 - i / 10);
    const inner = i % 5 === 0 ? 62 : 68;
    const x1 = 110 + inner * Math.cos(angle), y1 = 110 - inner * Math.sin(angle);
    const x2 = 110 + 74 * Math.cos(angle), y2 = 110 - 74 * Math.sin(angle);
    const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
    line.setAttribute("x1", x1); line.setAttribute("y1", y1);
    line.setAttribute("x2", x2); line.setAttribute("y2", y2);
    group.append(line);
  }
}

function renderTLS(container, report) {
  const tls = report.tls;
  if (!tls) {
    container.append(el("p", { className: "tls-problem", textContent: "This site was served over plain HTTP, so nothing is encrypted." }));
    return;
  }
  if (tls.error) {
    container.append(el("p", { className: "tls-problem", textContent: `The certificate could not be verified: ${tls.error}` }));
    return;
  }
  const dl = el("dl");
  const rows = [
    ["Issued by", tls.issuer || "Unknown"],
    ["Issued to", tls.subject || tls.host],
    ["Protocol", tls.version || "Unknown"],
    ["Expires", tls.not_after ? new Date(tls.not_after).toLocaleDateString() : "Unknown"],
  ];
  for (const [term, value] of rows) dl.append(el("dt", { textContent: term }), el("dd", { textContent: value }));
  container.append(dl);

  if (typeof tls.days_left === "number") {
    const days = tls.days_left;
    const colour = days < 0 ? "--fail" : days < 30 ? "--warn" : "--pass";
    const bar = el("div", { className: "expiry-bar" });
    bar.setAttribute("role", "img");
    bar.setAttribute("aria-label", `${days} days until the certificate expires`);
    const fill = el("span");
    fill.style.width = `${Math.max(0, Math.min(days, 365)) / 365 * 100}%`;
    fill.style.setProperty("--bar", `var(${colour})`);
    bar.append(fill);
    const label = days < 0 ? `Expired ${-days} days ago` : `${days} days left (bar shows up to one year)`;
    container.append(bar, el("p", { className: "expiry-label", textContent: label }));
  }
}

function renderFinding(f) {
  const details = el("details", { className: `finding ${f.status}` });
  const name = el("span", { className: "name", textContent: f.header });
  name.append(el("span", { className: "msg", textContent: f.message }));
  details.append(el("summary", {}, el("span", { className: "badge", textContent: STATUS_LABEL[f.status] }), name));

  const detail = el("div", { className: "detail" });
  if (f.status === "pass") {
    detail.append(el("p", { textContent: `Protects against: ${f.risk}` }));
  } else {
    detail.append(el("p", { textContent: f.risk }), el("p", { textContent: "How to fix it:" }), el("code", { textContent: f.fix }));
  }
  if (f.value) detail.append(el("p", { className: "meta", textContent: `Current value: ${f.value}` }));
  details.append(detail);
  return details;
}

function renderReport(report) {
  const node = $("#result-tpl").content.firstElementChild.cloneNode(true);
  const g = report.grade;
  report = { ...report, findings: report.findings.filter(f => f && f.status in STATUS_LABEL) };
  node.style.setProperty("--grade-colour", `var(${GRADE_COLOURS[g.letter] || "--steel"})`);
  node.setAttribute("aria-label", `${report.final_url}: grade ${g.letter}, ${g.score} out of 100`);

  drawTicks($("svg", node));
  $(".letter", node).textContent = g.letter;
  $(".site", node).textContent = new URL(report.final_url).host;
  $(".score-num", node).textContent = g.score;
  $(".c-pass", node).textContent = `${g.passed} passed`;
  $(".c-warn", node).textContent = `${g.warnings} ${g.warnings === 1 ? "warning" : "warnings"}`;
  $(".c-fail", node).textContent = `${g.failed} failed`;
  $(".meta", node).textContent = `${report.final_url} returned HTTP ${report.status}. Scanned ${new Date(report.scanned_at).toLocaleString()}.`;

  renderTLS($(".tls-body", node), report);

  const list = $(".finding-list", node);
  const sorted = [...report.findings].sort((a, b) => STATUS_ORDER[a.status] - STATUS_ORDER[b.status]);
  for (const f of sorted) list.append(renderFinding(f));

  // The single orchestrated moment: the needle swings to the score.
  requestAnimationFrame(() => requestAnimationFrame(() => {
    $(".fill", node).style.strokeDasharray = `${g.score} 100`;
    $(".needle", node).style.transform = `rotate(${-90 + g.score * 1.8}deg)`;
    node.classList.add("ready");
  }));
  return node;
}

function setStatus(text, isError = false) {
  const status = $("#status");
  status.textContent = text;
  status.classList.toggle("error", isError);
}

async function onSubmit(event) {
  event.preventDefault();
  const comparing = $("#compare-toggle").checked;
  const urls = [$("#url-a").value.trim(), comparing ? $("#url-b").value.trim() : ""].filter(Boolean);
  if (!urls.length) {
    setStatus("Enter a website address to scan, like example.com.", true);
    $("#url-a").focus();
    return;
  }

  const button = $("#scan-btn");
  const results = $("#results");
  button.disabled = true;
  const live = !DEMO || urls.some(u => !demoSite(u));
  const verb = live ? "Scanning" : "Loading";
  const wake = DEMO && DEMO.api_url && live ? " The first live scan can take up to a minute while the server wakes up." : "";
  setStatus((urls.length > 1 ? `${verb} ${urls.join(" and ")}…` : `${verb} ${urls[0]}…`) + wake);

  const outcomes = await Promise.allSettled(urls.map(scan));
  button.disabled = false;

  const reports = outcomes.filter(o => o.status === "fulfilled").map(o => o.value);
  const errors = outcomes.filter(o => o.status === "rejected").map(o => o.reason.message);

  results.replaceChildren(...reports.map(renderReport));
  results.classList.toggle("compare", reports.length > 1);

  if (reports.length === 2) {
    const [a, b] = reports;
    if (a.grade.score !== b.grade.score) {
      const winner = a.grade.score > b.grade.score ? 0 : 1;
      results.children[winner].classList.add("winner");
      const diff = Math.abs(a.grade.score - b.grade.score);
      const name = new URL(reports[winner].final_url).host;
      setStatus(`${name} scores ${diff} points higher.`);
    } else {
      setStatus("Both sites have the same score.");
    }
  } else if (reports.length === 1 && !errors.length) {
    setStatus(`Scan complete: grade ${reports[0].grade.letter}.`);
  }
  if (errors.length) setStatus(errors.join(" "), true);
}

function showReports(reports) {
  const results = $("#results");
  results.replaceChildren(...reports.map(renderReport));
  results.classList.toggle("compare", reports.length > 1);
}

async function onReportFile(event) {
  const file = event.target.files[0];
  if (!file) return;
  try {
    const data = JSON.parse(await file.text());
    if (!isReport(data)) throw new Error("not a report");
    $("#compare-toggle").checked = false;
    $("#field-b").hidden = true;
    showReports([data]);
    setStatus(`Opened report for ${new URL(data.final_url).host}: grade ${data.grade.letter}.`);
  } catch {
    setStatus(`${file.name} isn't a HeaderGuard report. Create one with: headerguard yoursite.com --json > report.json`, true);
  }
}

function onChip(host) {
  const a = $("#url-a"), b = $("#url-b");
  if (!$("#compare-toggle").checked) {
    a.value = host;
    $("#scan-form").requestSubmit();
    return;
  }
  // Compare mode: the first pick fills "Website", the second fills "Compare with".
  if (!a.value.trim() || b.value.trim()) {
    a.value = host;
    b.value = "";
    setStatus(`Now pick a site to compare with ${host}.`);
  } else if (hostOf(a.value) === host) {
    setStatus(`${host} is already selected. Pick a different site to compare with.`);
  } else {
    b.value = host;
    $("#scan-form").requestSubmit();
  }
}

async function detectDemo() {
  try {
    const res = await fetch("data/index.json", { cache: "no-store" });
    if (!res.ok) return;
    const index = await res.json();
    if (!Array.isArray(index.sites) || !index.sites.length) return;
    DEMO = index;
  } catch {
    return;
  }
  const when = new Date(DEMO.generated_at);
  const lastRun = `${when.toLocaleDateString()} at ${when.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
  $("#demo-note").textContent = DEMO.api_url
    ? `Type any website above and scan it live, or pick one of these sites from the daily scan (last run ${lastRun}). ` +
      `Tick "Compare two sites" to put two side by side.`
    : `This online demo shows real results from HeaderGuard's daily scan, last run ${lastRun}. ` +
      `Pick a site, or tick "Compare two sites" and pick two. To scan any site you like, install HeaderGuard from GitHub.`;
  const chips = $("#site-chips");
  for (const site of [...DEMO.sites].sort((x, y) => y.score - x.score)) {
    const chip = el("button", { type: "button", className: "chip" });
    chip.setAttribute("aria-label", `${site.host}, grade ${site.letter}`);
    const badge = el("span", { className: "g", textContent: site.letter });
    badge.style.setProperty("--g", `var(${GRADE_COLOURS[site.letter] || "--steel"})`);
    chip.append(badge, site.host);
    chip.addEventListener("click", () => onChip(site.host));
    chips.append(chip);
  }
  $("#demo-panel").hidden = false;
  if (!DEMO.api_url) $("#scan-btn").textContent = "Show results";
  const top = $("#top-link");
  top.href = REPO_URL;
  top.textContent = "Source on GitHub";
}

document.addEventListener("DOMContentLoaded", async () => {
  await detectDemo();
  $("#report-file").addEventListener("change", onReportFile);
  $("#scan-form").addEventListener("submit", onSubmit);
  $("#compare-toggle").addEventListener("change", (e) => {
    $("#field-b").hidden = !e.target.checked;
    if (e.target.checked) $("#url-b").focus();
  });
  const preset = new URLSearchParams(location.search).get("url");
  if (preset) {
    $("#url-a").value = preset;
    $("#scan-form").requestSubmit();
  }
});
