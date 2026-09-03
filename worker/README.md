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
