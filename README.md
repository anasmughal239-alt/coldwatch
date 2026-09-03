# coldwatch

Deliverability-infrastructure health checks for cold-email sending domains.
Give it a domain (or a list); it evaluates the DNS records that decide whether
your mail authenticates, scores each domain, and exits non-zero when something
is broken — so it drops straight into CI or a cron job.

No API keys. No account. Every lookup is DNS-over-HTTPS.

```
npx coldwatch stripe.com
npx coldwatch --file domains.txt --json
npx coldwatch acme.com --selector mailo --fail-on warn
```

```
acme.com  C · 62/100 · at-risk
  spf    [CRIT] More than 10 DNS lookups (permerror)
         Resolving this SPF record requires 12 DNS-querying terms; RFC 7208 allows 10.
         Chain: acme.com -> _spf.vendor.com -> spf.hubspot.com -> ...
         fix: Reduce include: nesting, or use a hosted SPF-flattening service.
  dkim   [ OK ] Valid DKIM key at selector "mailo"
  dmarc  [WARN] Policy is `p=none`
         Meets Gmail/Yahoo/Microsoft minimum, but spoofed mail is still delivered.
  mx     [ OK ] Mailbox provider: Google Workspace
```

## What it checks

| Check | What it catches |
|---|---|
| **SPF** (RFC 7208) | the 10-DNS-lookup `permerror` (the #1 silent cold-email killer), >10 void lookups, multiple SPF records, `+all` / missing `all`, deprecated `ptr`, include/redirect loops, flattened records |
| **DMARC** (RFC 7489) | missing record, `p=` absent/misplaced, `p=none` (weak), `pct<100`, missing `rua=`, subdomain policy via organizational-domain tree-walk, unauthorized external report destinations |
| **DKIM** (RFC 6376) | key present at the provider's expected selector (or a caller-supplied one, or a common-selector scan), revoked (`p=` empty), test-mode (`t=y`), approximate RSA key size, `*._domainkey` wildcards |
| **MX** | no MX / null MX (replies and bounces are lost), MX pointing at an IP or private host, mailbox-provider fingerprint (used to guess the DKIM selector) |

## Exit codes

`0` every domain meets the threshold · `1` at least one domain is below it
(`--fail-on crit` by default, `--fail-on warn` to be strict) · `2` usage error.

## Library

```ts
import { checkDomain } from "coldwatch";

const report = await checkDomain("stripe.com");
// { domain, score, grade, readiness, checks: [{ check, status, findings, data }] }
```

Inject a resolver to point at other DoH endpoints or to test offline:

```ts
import { checkDomain, DohResolver } from "coldwatch";
await checkDomain("stripe.com", {
  resolver: new DohResolver({ endpoints: ["https://dns.google/resolve"] }),
  dkimSelectors: ["s1", "mailo"],
});
```

## Known limitations (by design, this release)

- SPF macros (`%{...}`) are flagged, not expanded.
- DKIM key size is estimated from the base64 blob length — accurate enough to
  flag 512/768-bit keys, not a substitute for parsing the key.
- DKIM selector discovery is provider-defaults + a common-selector scan; a key
  under a custom selector needs `--selector`.
- No blacklist / DNSBL checks yet — that needs a data feed and lands in a later
  milestone.

## Develop

```
npm install
npm run check      # typecheck (src + tests) then vitest
npm run dev -- stripe.com
npm run build
```

Tests use an in-memory resolver (`test/helpers/mock-resolver.ts`) and never
touch the network.

## License

MIT
