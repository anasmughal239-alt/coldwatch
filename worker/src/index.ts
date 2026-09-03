/**
 * coldwatch-web — the free public single-domain checker.
 *
 * Routes:
 *   GET  /                     HTML page; ?domain=<d> renders a report inline
 *   GET  /api/check?domain=<d> JSON report
 *   POST /api/waitlist         stores an email if the WAITLIST KV binding exists
 *   GET  /health               liveness
 *
 * Reports are cached (Cache API) for CACHE_TTL so popular domains and reloads
 * don't re-run ~30 DNS lookups. Nothing about a visitor is stored.
 */

import { checkDomain, DohResolver } from "../../src/index.js";
import type { DomainReport } from "../../src/index.js";
import { renderPage } from "./page.js";
import { renderReport } from "./render.js";
import { isEmail, normalizeDomainInput } from "./validate.js";

interface Env {
  WAITLIST_URL?: string;
  WAITLIST?: KVNamespace;
}

const CACHE_TTL = 3600; // seconds
const MAX_DKIM_PROBES = 14; // keep total subrequests well under the free-plan cap

const HTML_HEADERS: Record<string, string> = {
  "content-type": "text/html; charset=utf-8",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "cache-control": `public, max-age=${CACHE_TTL}`,
};

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(req.url);

    if (url.pathname === "/health") {
      return new Response("ok", { headers: { "content-type": "text/plain" } });
    }

    if (url.pathname === "/api/check") {
      return handleApiCheck(url, ctx);
    }

    if (url.pathname === "/api/waitlist") {
      return handleWaitlist(req, env);
    }

    if (url.pathname === "/") {
      return handlePage(url, env, ctx);
    }

    return new Response("Not found", { status: 404 });
  },
};

async function handlePage(
  url: URL,
  env: Env,
  ctx: ExecutionContext,
): Promise<Response> {
  const waitlistUrl = env.WAITLIST_URL ?? "";
  const waitlistEnabled = Boolean(env.WAITLIST);
  const joined = url.searchParams.get("joined") === "1";
  const rawDomain = url.searchParams.get("domain");

  const base = {
    waitlistUrl,
    waitlistEnabled,
    ...(joined ? { waitlistMessage: "You're on the list — thanks." } : {}),
  };

  if (!rawDomain) {
    return new Response(renderPage(base), { headers: HTML_HEADERS });
  }

  const domain = normalizeDomainInput(rawDomain);
  if (!domain) {
    return new Response(
      renderPage({
        ...base,
        domain: rawDomain,
        error: "That doesn't look like a domain. Try something like acme.com.",
      }),
      { status: 400, headers: HTML_HEADERS },
    );
  }

  try {
    const report = await checkWithCache(domain, ctx);
    return new Response(
      renderPage({ ...base, domain, reportHtml: renderReport(report) }),
      { headers: HTML_HEADERS },
    );
  } catch (err) {
    return new Response(
      renderPage({
        ...base,
        domain,
        error: `Could not complete the check: ${errMessage(err)}`,
      }),
      { status: 502, headers: HTML_HEADERS },
    );
  }
}

async function handleApiCheck(
  url: URL,
  ctx: ExecutionContext,
): Promise<Response> {
  const cors = { "access-control-allow-origin": "*" };
  const domain = normalizeDomainInput(url.searchParams.get("domain") ?? "");
  if (!domain) {
    return json({ error: "invalid or missing ?domain" }, 400, cors);
  }
  try {
    const report = await checkWithCache(domain, ctx);
    return json(report, 200, {
      ...cors,
      "cache-control": `public, max-age=${CACHE_TTL}`,
    });
  } catch (err) {
    return json({ error: errMessage(err) }, 502, cors);
  }
}

async function handleWaitlist(req: Request, env: Env): Promise<Response> {
  if (req.method !== "POST") return new Response("Method not allowed", { status: 405 });

  const form = await req.formData();
  const email = String(form.get("email") ?? "").trim();
  if (!isEmail(email)) {
    return Response.redirect(new URL("/?joined=0", req.url).toString(), 303);
  }

  if (env.WAITLIST) {
    await env.WAITLIST.put(
      `email:${email.toLowerCase()}`,
      JSON.stringify({ at: new Date().toISOString() }),
      { metadata: { source: "public-checker" } },
    );
  }
  // If no KV binding is configured the submission is simply acknowledged.
  return Response.redirect(new URL("/?joined=1", req.url).toString(), 303);
}

async function checkWithCache(
  domain: string,
  ctx: ExecutionContext,
): Promise<DomainReport> {
  const cache = caches.default;
  const cacheKey = new Request(`https://coldwatch.internal/report/${domain}`);

  const hit = await cache.match(cacheKey);
  if (hit) return (await hit.json()) as DomainReport;

  const resolver = new DohResolver({ retries: 2, timeoutMs: 3000 });
  const report = await checkDomain(domain, {
    resolver,
    maxDkimProbes: MAX_DKIM_PROBES,
  });

  const toCache = new Response(JSON.stringify(report), {
    headers: { "cache-control": `public, max-age=${CACHE_TTL}` },
  });
  ctx.waitUntil(cache.put(cacheKey, toCache));

  return report;
}

function json(
  body: unknown,
  status = 200,
  extra: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", ...extra },
  });
}

function errMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
