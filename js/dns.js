"use strict";

// DNS over HTTPS (JSON API). Both resolvers allow cross-origin requests,
// so lookups can run straight from the browser.
const RESOLVERS = [
  { name: "Google Public DNS", url: (n, t) => `https://dns.google/resolve?name=${encodeURIComponent(n)}&type=${t}` },
  { name: "Cloudflare", url: (n, t) => `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(n)}&type=${t}` },
];

const RR_TYPE = { TXT: 16, MX: 15 };
const cache = new Map();

// TXT data comes back as one or more quoted strings ("v=spf1 " "include:...")
// from some resolvers and unquoted from others. Records longer than 255 bytes
// are always split into several strings that have to be joined back together.
function joinTxt(data) {
  if (!data.startsWith('"')) return data;
  const parts = data.match(/"((?:[^"\\]|\\.)*)"/g) || [];
  return parts.map(p => p.slice(1, -1).replace(/\\(.)/g, "$1")).join("");
}

async function query(resolver, name, type) {
  const res = await fetch(resolver.url(name, type), { headers: { accept: "application/dns-json" } });
  if (!res.ok) throw new Error(`${resolver.name}: HTTP ${res.status}`);
  const body = await res.json();
  // 0 = NOERROR, 3 = NXDOMAIN. Anything else (SERVFAIL, REFUSED) is a failed lookup.
  if (body.Status !== 0 && body.Status !== 3) throw new Error(`${resolver.name}: DNS status ${body.Status}`);
  const answers = (body.Answer || []).filter(a => a.type === RR_TYPE[type]);
  return answers.map(a => (type === "TXT" ? joinTxt(a.data) : a.data));
}

// Returns an array of record strings ([] if the name has none).
// Throws only if every resolver failed.
async function lookup(name, type) {
  const key = `${type} ${name.toLowerCase()}`;
  if (cache.has(key)) return cache.get(key);

  const promise = (async () => {
    let lastError;
    for (const resolver of RESOLVERS) {
      try {
        return await query(resolver, name, type);
      } catch (err) {
        lastError = err;
      }
    }
    throw lastError;
  })();

  cache.set(key, promise);
  promise.catch(() => cache.delete(key)); // don't cache failures
  return promise;
}
