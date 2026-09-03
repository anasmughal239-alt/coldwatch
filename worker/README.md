# coldwatch-web

The free public single-domain checker — a Cloudflare Worker that runs the
`coldwatch` library against one domain and renders the report. No database, no
keys. Report results are cached (Cache API) for an hour so popular domains and
reloads don't re-run the DNS lookups.

## Run locally

```
npm install          # from the repo root (npm workspace)
cd worker
npm run dev          # wrangler dev -> http://localhost:8787
```

Try: `http://localhost:8787/?domain=stripe.com` or
`http://localhost:8787/api/check?domain=stripe.com`.

## Deploy (free tier)

```
npx wrangler login
cd worker
npm run deploy       # publishes to https://coldwatch-web.<subdomain>.workers.dev
```

## Configure the waitlist CTA

Point the button at a form (Tally, Formspree, a Google Form):

```
npx wrangler deploy --var WAITLIST_URL:https://tally.so/r/xxxxxx
```

Or capture emails yourself in KV:

```
npx wrangler kv namespace create WAITLIST
# uncomment the [[kv_namespaces]] block in wrangler.toml, paste the id
npm run deploy
```

With the `WAITLIST` binding present, the page shows an inline email field that
POSTs to `/api/waitlist` and writes `email:<addr>` into the namespace.

## Endpoints

| Route | |
|---|---|
| `GET /` | HTML page; `?domain=<d>` renders a report inline |
| `GET /api/check?domain=<d>` | JSON report (`access-control-allow-origin: *`) |
| `POST /api/waitlist` | form field `email`; stored if the KV binding exists |
| `GET /health` | `ok` |

## Limits it respects

`MAX_DKIM_PROBES = 14` keeps total DNS subrequests per check well under the
Workers free-plan cap of 50. The DoH resolver is configured with a 3s timeout
and 2 retries so a slow chain can't hang the request.

---

## M2 — continuous monitoring (D1 + Cron)

A `scheduled()` handler runs every 10 minutes, checks whichever domains are
due, and stores an append-only history plus a derived current-state row per
check. All native Cloudflare, still free.

### One-time setup

```
npx wrangler d1 create coldwatch
#   -> paste database_id into wrangler.toml
npx wrangler d1 migrations apply coldwatch --remote
npx wrangler secret put CW_ADMIN_TOKEN        # any long random string
npm run deploy
```

For local dev, put `CW_ADMIN_TOKEN=devtoken` in `worker/.dev.vars`, then
`npx wrangler d1 migrations apply coldwatch --local` and
`npm run dev -- --test-scheduled` (invoke the cron with
`curl localhost:8787/__scheduled`).

### Admin API (Bearer `CW_ADMIN_TOKEN`)

| | |
|---|---|
| `POST /api/domains` | `{ "domain": "acme.com", "label"?, "dkimSelectors"?: [], "checkIntervalSeconds"?: 21600 }` |
| `GET /api/domains` | all monitored domains + last-run summary |
| `GET /api/domains/:domain` | detail incl. per-check state |
| `DELETE /api/domains/:domain` | stop monitoring |
| `GET /api/domains/:domain/history?limit=50` | recent runs |

```
curl -X POST https://coldwatch-web.<you>.workers.dev/api/domains \
  -H "authorization: Bearer $CW_ADMIN_TOKEN" \
  -H "content-type: application/json" \
  -d '{"domain":"acme.com"}'
```

### Capacity

8 domains per cron fire × every 10 min ≈ **1,150 domain-checks/day**. Enough
for validation. Past that, the scheduler fans out via self-`fetch` (one
sub-invocation per domain) — a config change, not a rewrite.

### Data model

`domain` → `check_run` (one per time-slot, `UNIQUE(domain_id, slot_ts)` =
idempotency) → `check_result` (append-only) · `domain_check_state` (current
status per check, `since` / `consecutive_count` feed M4 alerting).

---

## M3 — blacklist checks (Spamhaus DQS)

When `DQS_KEY` is set, the scheduler adds a `blacklist` check: the domain
against Spamhaus **DBL**, and its known sending IPs against **ZEN**.

```
npx wrangler secret put DQS_KEY        # free Spamhaus Data Query Service key
```

Verify the key works first — this must return `127.0.0.2`, not REFUSED:

```
nslookup -type=A <key>.2.0.0.127.zen.dq.spamhaus.net
```

### How the shared free key is protected

One key serves every domain, so every lookup passes through a metering gateway:

- **Cache** (`dnsbl_cache`, keyed by `zone`+`entity`) — "not listed" cached 12h,
  "listed" 2h. Because IPs are shared across domains this is also the dedup
  layer.
- **Daily budget** (`dqs_budget`) — atomic reserve against `DQS_DAILY_CEILING`
  (default 200k, below the real free-tier limit). Over budget ⇒ the check
  reports `unknown`, never a false "clean".
- **Circuit breaker** — a `127.255.255.x` reply (bad key / quota) or repeated
  DQS errors trips it for the rest of the run; remaining lookups short-circuit
  to `unknown`.
- **Per-domain IP cap** — at most 12 sending IPs checked per domain,
  manual-entered before SPF-derived.

### Sending IPs

- Discovered automatically from `ip4:` / `ip6:` literals in the SPF record.
- Set explicitly: `sendingIps` in `POST /api/domains`, or
  `PUT /api/domains/:domain/ips` with `{ "ips": ["203.0.113.10", ...] }`.
- Without `DQS_KEY` the scheduler simply runs the DNS-auth checks and skips this
  stage.
