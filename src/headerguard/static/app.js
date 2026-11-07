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

async function scan(url) {
  const res = await fetch("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });
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
  setStatus(urls.length > 1 ? `Scanning ${urls.join(" and ")}…` : `Scanning ${urls[0]}…`);

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

document.addEventListener("DOMContentLoaded", () => {
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
