"use strict";

// Depends on data/federal-domains.js, dns.js and checks.js.

const DOMAINS = window.FEDERAL_DOMAINS || [];
const CONCURRENCY = 6;

// Display order for the summary and the filter, best to worst.
const CATEGORIES = [
  ["compliant", "cat-compliant"],
  ["reject, no DHS reports", "cat-warn"],
  ["reject, pct < 100", "cat-warn"],
  ["reject, SPF missing", "cat-warn"],
  ["p=quarantine", "cat-warn"],
  ["p=none", "cat-bad"],
  ["invalid DMARC", "cat-bad"],
  ["no DMARC", "cat-bad"],
  ["lookup failed", "cat-bad"],
];
const CATEGORY_CLASS = Object.fromEntries(CATEGORIES);

const $ = id => document.getElementById(id);
let results = [];

function esc(s) {
  return String(s ?? "").replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
}

function agencyName(org, sub) {
  return sub && sub !== org ? `${org} / ${sub}` : org;
}

async function scanOne([domain, org, sub]) {
  try {
    return { ...(await checkBod1801(domain)), agency: agencyName(org, sub) };
  } catch {
    return { domain, agency: agencyName(org, sub), category: "lookup failed", policy: "", pct: "", dhsReports: false, spf: "", dmarcRecord: "" };
  }
}

async function scanAll(onProgress) {
  const out = new Array(DOMAINS.length);
  let next = 0, done = 0;

  async function worker() {
    while (next < DOMAINS.length) {
      const i = next++;
      out[i] = await scanOne(DOMAINS[i]);
      onProgress(++done);
    }
  }
  await Promise.all(Array.from({ length: CONCURRENCY }, worker));
  return out;
}

function renderSummary() {
  const counts = {};
  for (const r of results) counts[r.category] = (counts[r.category] || 0) + 1;

  const compliant = counts.compliant || 0;
  const items = [[`meet the DNS rules`, `${compliant} of ${results.length}`]];
  for (const [cat] of CATEGORIES.slice(1)) {
    if (counts[cat]) items.push([cat, counts[cat]]);
  }
  $("summary").innerHTML = items.map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${esc(v)}</dd></div>`).join("");

  $("category").innerHTML = '<option value="">all results</option>' +
    CATEGORIES.filter(([cat]) => counts[cat]).map(([cat]) => `<option>${esc(cat)}</option>`).join("");
}

function renderTable() {
  const q = $("q").value.trim().toLowerCase();
  const cat = $("category").value;
  const rows = results.filter(r =>
    (!cat || r.category === cat) &&
    (!q || r.domain.includes(q) || r.agency.toLowerCase().includes(q)));

  $("shown").textContent = `${rows.length.toLocaleString()} shown`;
  $("rows").innerHTML = rows.map(r => `
    <tr>
      <td class="mono">${esc(r.domain)}</td>
      <td>${esc(r.agency)}</td>
      <td class="nowrap ${CATEGORY_CLASS[r.category] || ""}">${esc(r.category)}</td>
      <td class="mono" title="${esc(r.dmarcRecord)}">${esc(r.policy || "–")}</td>
      <td>${esc(r.pct)}</td>
      <td>${r.policy ? (r.dhsReports ? "yes" : "no") : ""}</td>
      <td>${esc(r.spf)}</td>
    </tr>`).join("");
}

function csvCell(v) {
  const s = String(v ?? "");
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function downloadCsv() {
  const header = ["domain", "agency", "result", "dmarc_policy", "pct", "dhs_reports", "spf", "dmarc_record"];
  const lines = [header.join(",")].concat(results.map(r =>
    [r.domain, r.agency, r.category, r.policy, r.pct, r.dhsReports, r.spf, r.dmarcRecord].map(csvCell).join(",")));
  const blob = new Blob([lines.join("\n") + "\n"], { type: "text/csv" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `bod-18-01-scan-${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(a.href);
}

$("domain-count").textContent = DOMAINS.length.toLocaleString();
$("list-date").textContent = `list fetched ${(window.FEDERAL_META || {}).fetched || "unknown"}`;

$("run").addEventListener("click", async () => {
  $("run").disabled = true;
  $("export").hidden = true;
  const started = performance.now();

  results = await scanAll(done => {
    $("progress").textContent = `${done.toLocaleString()} / ${DOMAINS.length.toLocaleString()} domains checked`;
  });
  results.sort((a, b) => a.agency.localeCompare(b.agency) || a.domain.localeCompare(b.domain));

  const seconds = Math.round((performance.now() - started) / 1000);
  const failed = results.filter(r => r.category === "lookup failed").length;
  $("progress").textContent = `Checked ${results.length.toLocaleString()} domains in ${seconds}s on ${new Date().toLocaleString()}.` +
    (failed > results.length / 2
      ? ` Most lookups failed. Your network is probably blocking DNS-over-HTTPS (workplace, school and some building networks do); try another network.`
      : "");
  $("run").disabled = false;
  $("run").textContent = "Run again";
  $("export").hidden = false;
  $("output").hidden = false;
  renderSummary();
  renderTable();
});

$("export").addEventListener("click", downloadCsv);
$("q").addEventListener("input", renderTable);
$("category").addEventListener("input", renderTable);
