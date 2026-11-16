"use strict";

// Depends on lookup() from dns.js.

const OK = "ok", WARN = "warning", BAD = "problem", INFO = "info";

// DKIM keys live at <selector>._domainkey.<domain> and there's no way to list
// selectors, so we can only try well-known ones.
const DKIM_SELECTORS = [
  "google", "selector1", "selector2", "default", "k1", "k2", "k3", "s1", "s2",
  "dkim", "mail", "smtp", "mandrill", "mxvault", "everlytickey1", "everlytickey2",
  "fm1", "fm2", "fm3", "protonmail", "protonmail2", "protonmail3", "zoho", "sig1", "pm",
];

// Public suffixes with two labels. Only used to guess the organizational
// domain for DMARC; a full Public Suffix List would be more accurate.
const TWO_LABEL_SUFFIXES = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk",
  "com.au", "net.au", "org.au", "edu.au", "gov.au",
  "co.nz", "org.nz", "co.jp", "ne.jp", "or.jp", "co.in", "org.in", "gov.in",
  "com.br", "com.cn", "com.mx", "co.za", "com.sg", "com.hk", "co.kr", "com.tr",
]);

function normalizeDomain(input) {
  let d = input.trim().toLowerCase();
  d = d.replace(/^[a-z]+:\/\//, "").split(/[/?#]/)[0];   // tolerate pasted URLs
  d = d.replace(/^.*@/, "");                             // and email addresses
  d = d.replace(/\.$/, "").replace(/^www\./, "");
  return d;
}

function isValidDomain(d) {
  return /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$/.test(d);
}

function orgDomain(domain) {
  const labels = domain.split(".");
  const lastTwo = labels.slice(-2).join(".");
  return labels.slice(TWO_LABEL_SUFFIXES.has(lastTwo) ? -3 : -2).join(".");
}

// ---------- SPF ----------

function spfRecords(txt) {
  return txt.map(r => r.trim()).filter(r => /^v=spf1(\s|$)/i.test(r));
}

function spfAllQualifier(record) {
  const term = record.split(/\s+/).find(t => /^[+\-~?]?all$/i.test(t));
  if (!term) return null;
  return /^[+\-~?]/.test(term) ? term[0] : "+";
}

// Counts the DNS-querying terms SPF evaluation would need (include, a, mx,
// ptr, exists, redirect), following includes and redirects. RFC 7208 caps
// this at 10; past that, receivers return a permanent error.
async function countSpfLookups(record, seen = new Set(), counter = { n: 0 }) {
  for (const raw of record.split(/\s+/).slice(1)) {
    const term = raw.replace(/^[+\-~?]/, "").toLowerCase();
    const [mech, arg] = term.split(/[:=]/, 2);

    if (["a", "mx", "ptr", "exists"].includes(mech.split("/")[0])) {
      counter.n++;
    } else if (mech === "include" || mech === "redirect") {
      counter.n++;
      if (!arg || seen.has(arg) || counter.n > 20) continue;
      seen.add(arg);
      const target = spfRecords(await lookup(arg, "TXT"))[0];
      if (target) await countSpfLookups(target, seen, counter);
    }
  }
  return counter.n;
}

async function checkSpf(domain) {
  const records = spfRecords(await lookup(domain, "TXT"));

  if (records.length === 0) {
    return { status: BAD, record: null, summary: "No SPF record.",
      detail: "Nothing tells receivers which servers may send mail for this domain." };
  }
  if (records.length > 1) {
    return { status: BAD, record: records.join("\n"), summary: "More than one SPF record.",
      detail: "A domain may only have one. With several, SPF fails with a permanent error." };
  }

  const record = records[0];
  let qualifier = spfAllQualifier(record);
  let viaRedirect = null;
  if (qualifier === null) {
    const redirect = record.split(/\s+/).find(t => /^redirect=/i.test(t));
    if (redirect) {
      viaRedirect = redirect.split("=")[1];
      const target = spfRecords(await lookup(viaRedirect, "TXT"))[0];
      qualifier = target ? spfAllQualifier(target) : null;
    }
  }

  let lookups = null;
  try { lookups = await countSpfLookups(record); } catch { /* leave unknown */ }

  const from = viaRedirect ? ` (from redirect to ${viaRedirect})` : "";
  let result;
  if (qualifier === "-") {
    result = { status: OK, summary: `Ends in -all${from}.`,
      detail: "Mail from servers not on the list fails SPF." };
  } else if (qualifier === "~") {
    result = { status: OK, summary: `Ends in ~all${from}.`,
      detail: "Mail from servers not on the list soft-fails. That's normal when DMARC is enforced." };
  } else if (qualifier === "?" || qualifier === "+") {
    result = { status: BAD, summary: `Ends in ${qualifier}all${from}.`,
      detail: qualifier === "+" ? "Any server in the world passes SPF for this domain."
                                : "Unlisted servers get a neutral result, which protects nothing." };
  } else {
    result = { status: WARN, summary: "No \"all\" term.",
      detail: "Servers not on the list get a neutral result by default." };
  }

  if (lookups !== null && lookups > 10) {
    result.status = result.status === OK ? WARN : result.status;
    result.detail += ` It also needs ${lookups} DNS lookups; the limit is 10, so some receivers will treat SPF as broken.`;
  } else if (lookups !== null) {
    result.detail += ` ${lookups} of 10 allowed DNS lookups used.`;
  }

  return { ...result, record };
}

// ---------- DMARC ----------

function parseTags(record) {
  const tags = {};
  for (const part of record.split(";")) {
    const i = part.indexOf("=");
    if (i === -1) continue;
    tags[part.slice(0, i).trim().toLowerCase()] = part.slice(i + 1).trim();
  }
  return tags;
}

function dmarcRecords(txt) {
  return txt.map(r => r.trim()).filter(r => /^v=DMARC1\s*(;|$)/i.test(r));
}

async function findDmarc(domain) {
  const names = [domain];
  const org = orgDomain(domain);
  if (org !== domain) names.push(org);

  for (const name of names) {
    const records = dmarcRecords(await lookup(`_dmarc.${name}`, "TXT"));
    if (records.length) return { at: name, records };
  }
  return { at: null, records: [] };
}

function describeDmarc(domain, found) {
  if (found.records.length === 0) {
    return { status: BAD, record: null, policy: null, summary: "No DMARC record.",
      detail: `Looked at _dmarc.${domain}${found.at === null && orgDomain(domain) !== domain ? ` and _dmarc.${orgDomain(domain)}` : ""}. ` +
              "Without DMARC, nothing asks receivers to act on SPF or DKIM failures for the From address people see." };
  }
  if (found.records.length > 1) {
    return { status: BAD, record: found.records.join("\n"), policy: null, summary: "More than one DMARC record.",
      detail: "Receivers ignore DMARC when there's more than one record." };
  }

  const record = found.records[0];
  const tags = parseTags(record);
  const inherited = found.at !== domain;
  const policy = ((inherited && tags.sp) || tags.p || "").toLowerCase();
  const pct = tags.pct === undefined ? 100 : Number(tags.pct);
  const rua = (tags.rua || "").split(",").map(s => s.trim().replace(/^mailto:/i, "").toLowerCase()).filter(Boolean);

  const where = inherited ? ` Inherited from ${found.at}${tags.sp ? " (sp= tag)" : ""}.` : "";
  const reports = rua.length ? ` Aggregate reports go to ${rua.join(", ")}.` : " No aggregate report address (rua).";
  const base = { record, policy, pct, rua, at: found.at };

  if (!["none", "quarantine", "reject"].includes(policy)) {
    return { ...base, status: BAD, summary: "Record has no valid p= policy.",
      detail: "Receivers ignore a DMARC record without a valid policy." + where };
  }
  if (policy === "none") {
    return { ...base, status: BAD, summary: "p=none (monitoring only).",
      detail: "Failing mail is reported but still delivered as usual." + where + reports };
  }
  const partial = pct < 100 ? ` Only applied to ${pct}% of failing mail.` : "";
  if (policy === "quarantine") {
    return { ...base, status: WARN, summary: `p=quarantine${pct < 100 ? `, pct=${pct}` : ""}.`,
      detail: "Failing mail should go to spam rather than the inbox." + partial + where + reports };
  }
  return { ...base, status: pct < 100 ? WARN : OK, summary: `p=reject${pct < 100 ? `, pct=${pct}` : ""}.`,
    detail: "Receivers should refuse mail that fails DMARC." + partial + where + reports };
}

async function checkDmarc(domain) {
  return describeDmarc(domain, await findDmarc(domain));
}

// ---------- DKIM ----------

async function checkDkim(domain) {
  const results = await Promise.allSettled(
    DKIM_SELECTORS.map(async sel => {
      const txt = await lookup(`${sel}._domainkey.${domain}`, "TXT");
      return txt.some(r => /(^|;)\s*p=/i.test(r) || /v=DKIM1/i.test(r)) ? sel : null;
    })
  );
  const found = results.filter(r => r.status === "fulfilled" && r.value).map(r => r.value);

  if (found.length) {
    return { status: INFO, record: found.map(s => `${s}._domainkey.${domain}`).join("\n"),
      summary: `Found ${found.length} key${found.length > 1 ? "s" : ""}.`,
      detail: "DKIM signatures prove a message wasn't altered and was signed by this domain." };
  }
  return { status: INFO, record: null, summary: `None of ${DKIM_SELECTORS.length} common selectors found.`,
    detail: "This doesn't mean there's no DKIM. Selectors can be any name and there's no way to list them from DNS." };
}

// ---------- MX ----------

async function checkMx(domain) {
  const mx = (await lookup(domain, "MX"))
    .map(r => { const [pref, host] = r.split(/\s+/); return { pref: Number(pref), host: (host || "").replace(/\.$/, "") }; })
    .sort((a, b) => a.pref - b.pref);

  if (mx.length === 1 && mx[0].host === "") {
    return { status: INFO, record: "0 .", sendsMail: false, summary: "Null MX.",
      detail: "The domain says it doesn't accept mail at all." };
  }
  if (mx.length === 0) {
    return { status: INFO, record: null, sendsMail: false, summary: "No MX records.",
      detail: "The domain doesn't receive mail. It can still be forged in the From line unless SPF and DMARC say otherwise." };
  }
  return { status: INFO, record: mx.map(m => `${m.pref} ${m.host}`).join("\n"), sendsMail: true,
    summary: `${mx.length} mail server${mx.length > 1 ? "s" : ""}.`, detail: `Mail is delivered to ${mx[0].host}.` };
}

// ---------- verdict ----------

function verdict(dmarc, spf, mx) {
  if (dmarc.status === OK) {
    return { level: OK, title: "Hard to spoof",
      text: "DMARC is set to reject. Mail providers that check DMARC (Gmail, Outlook, Yahoo and most others) " +
            "should refuse email that fakes this domain in the From line." };
  }
  if (dmarc.policy === "quarantine" || dmarc.policy === "reject") {
    return { level: WARN, title: "Partly protected",
      text: "DMARC is enforced, but not fully. Faked email will mostly land in spam rather than being refused outright." };
  }
  const noMail = mx && mx.sendsMail === false;
  return { level: BAD, title: "Can be spoofed",
    text: "Nothing in this domain's DNS asks receivers to block email that fakes its From address. " +
          "Whether a forged message reaches the inbox is up to each receiver's own spam filtering." +
          (spf.status === OK ? " SPF alone doesn't fix this: it checks the hidden envelope sender, not the From address people see." : "") +
          (noMail ? " Domains that don't send mail at all are an easy target unless they publish \"v=spf1 -all\" and a DMARC reject policy." : "") };
}

// ---------- BOD 18-01 (federal scan) ----------

const DHS_RUA = "reports@dmarc.cyber.dhs.gov";

// Checks the parts of BOD 18-01 that are visible in DNS: one valid SPF record,
// DMARC p=reject at 100%, and DHS included in aggregate reports.
async function checkBod1801(domain) {
  const [txt, dmarcTxt] = await Promise.all([lookup(domain, "TXT"), lookup(`_dmarc.${domain}`, "TXT")]);
  const spf = spfRecords(txt);
  const dmarc = describeDmarc(domain, { at: domain, records: dmarcRecords(dmarcTxt) });
  const spfOk = spf.length === 1;

  let category;
  if (!dmarc.record) category = "no DMARC";
  else if (!dmarc.policy || !["none", "quarantine", "reject"].includes(dmarc.policy)) category = "invalid DMARC";
  else if (dmarc.policy === "none") category = "p=none";
  else if (dmarc.policy === "quarantine") category = "p=quarantine";
  else if (dmarc.pct < 100) category = "reject, pct < 100";
  else if (!dmarc.rua.includes(DHS_RUA)) category = "reject, no DHS reports";
  else if (!spfOk) category = "reject, SPF missing";
  else category = "compliant";

  return {
    domain,
    category,
    policy: dmarc.policy || (dmarc.record ? "?" : ""),
    pct: dmarc.record ? dmarc.pct : "",
    dhsReports: dmarc.record ? dmarc.rua.includes(DHS_RUA) : false,
    spf: spf.length === 0 ? "missing" : spf.length > 1 ? "multiple" : "ok",
    dmarcRecord: dmarc.record || "",
  };
}
