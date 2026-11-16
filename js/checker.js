"use strict";

// Depends on dns.js and checks.js.

const form = document.getElementById("form");
const input = document.getElementById("domain");
const statusLine = document.getElementById("status");
const result = document.getElementById("result");

function esc(s) {
  return String(s ?? "").replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
}

function row(label, check) {
  return `
    <tr>
      <th>${label}</th>
      <td class="state ${check.status}">${check.status}</td>
      <td>
        <div>${esc(check.summary)}</div>
        <div class="muted">${esc(check.detail)}</div>
        ${check.record ? `<pre>${esc(check.record)}</pre>` : ""}
      </td>
    </tr>`;
}

async function run(rawDomain) {
  const domain = normalizeDomain(rawDomain);
  input.value = domain;
  result.hidden = true;

  if (!isValidDomain(domain)) {
    statusLine.textContent = `"${rawDomain}" doesn't look like a domain name.`;
    return;
  }

  try { history.replaceState(null, "", `?d=${encodeURIComponent(domain)}`); } catch { /* some browsers block this on file:// */ }
  statusLine.textContent = `Looking up ${domain}…`;

  let spf, dmarc, dkim, mx;
  try {
    [spf, dmarc, dkim, mx] = await Promise.all([checkSpf(domain), checkDmarc(domain), checkDkim(domain), checkMx(domain)]);
  } catch (err) {
    statusLine.textContent = `DNS lookup failed (${err.message}). Check your connection and try again.`;
    return;
  }

  if (!spf.record && !dmarc.record && !mx.record && !/^Found/.test(dkim.summary)) {
    statusLine.textContent = `${domain} has no mail-related DNS records at all. Check the spelling.`;
  } else {
    statusLine.textContent = "";
  }

  const v = verdict(dmarc, spf, mx);
  document.getElementById("verdict").className = `verdict ${v.level}`;
  document.getElementById("verdict").innerHTML = `<h2>${esc(domain)}: ${esc(v.title)}</h2><p>${esc(v.text)}</p>`;
  document.getElementById("rows").innerHTML =
    row("DMARC", dmarc) + row("SPF", spf) + row("DKIM", dkim) + row("MX", mx);
  result.hidden = false;
}

form.addEventListener("submit", e => {
  e.preventDefault();
  run(input.value);
});

const initial = new URLSearchParams(location.search).get("d");
if (initial) run(initial);
