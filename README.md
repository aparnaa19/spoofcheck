# spoofcheck

Checks whether a domain's DNS stops other people from sending email that pretends to come from it.

Two pages, both static, with no build step or dependencies:

- **`index.html`** checks a single domain. It looks up the domain's SPF, DMARC, DKIM and MX records and explains
  in plain English whether a forged "From" address would get through.
- **`federal.html`** checks all 1,173 US federal executive branch `.gov` domains against the email
  rules in [BOD 18-01](https://www.cisa.gov/binding-operational-directive-18-01).

All lookups happen in your browser, over DNS-over-HTTPS to Google Public DNS (with Cloudflare as a fallback).
Nothing else is sent anywhere, and there's no server-side component.

## Running

```
git clone https://github.com/appu-019/spoofcheck
cd spoofcheck
```

Then open `index.html` in a browser (double-clicking it works). You can link straight to a result with
`index.html?d=example.com`, or publish the folder with GitHub Pages.

## What the single-domain check looks at

| record | what's checked |
|---|---|
| DMARC | Policy (`p=`, and `sp=` when inherited by a subdomain), `pct`, and report addresses. Falls back to the parent domain's record when a subdomain has none. |
| SPF | Exactly one record, the `all` qualifier (following `redirect=`), and the number of DNS lookups including nested `include:`s, against the limit of 10 in RFC 7208. |
| DKIM | Probes 25 common selectors. DNS has no way to list selectors, so "none found" isn't proof there's no DKIM. |
| MX | Whether the domain receives mail, including null MX (`0 .`). |

The verdict is driven by DMARC, because it's the only one of these that protects the visible From address.
SPF on its own only checks the envelope sender.

Known limitations:
- The parent domain for DMARC is guessed with a short built-in list of two-label suffixes (like `co.uk`),
  not the full Public Suffix List.
- It reads DNS only. It can't see whether a particular receiver actually enforces DMARC, or how its spam
  filtering treats a message.

## The federal scan

BOD 18-01 (October 2017) required every federal executive branch second-level domain to have, by
October 16, 2018:

- a valid SPF record,
- a DMARC policy of `p=reject`,
- DMARC aggregate reports sent to DHS at `reports@dmarc.cyber.dhs.gov`.

`federal.html` checks those three things for every domain on CISA's list, about 2,300 DNS lookups in all.
It shows a summary, a filterable table and a CSV export. The directive's other requirements (STARTTLS, HTTPS) aren't
tested.

The domain list in `data/federal-domains.js` comes from [cisagov/dotgov-data](https://github.com/cisagov/dotgov-data),
filtered to "Federal - Executive". To refresh it:

```
python3 scripts/update_domains.py
```

## License

MIT. The domain list is published by CISA.
