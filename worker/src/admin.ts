/**
 * Admin API for managing monitored domains. Bearer-token auth
 * (`CW_ADMIN_TOKEN`). Returns `null` when the path is not an admin route so
 * the main router can continue.
 *
 *   POST   /api/domains                 { domain, label?, dkimSelectors?, checkIntervalSeconds? }
 *   GET    /api/domains
 *   GET    /api/domains/:domain
 *   DELETE /api/domains/:domain
 *   GET    /api/domains/:domain/history?limit=50
 */

import { D1Store } from "./store.js";
import { normalizeDomainInput } from "./validate.js";

interface AdminEnv {
  DB?: D1Database;
  CW_ADMIN_TOKEN?: string;
}

export async function handleAdmin(
  req: Request,
  url: URL,
  env: AdminEnv,
): Promise<Response | null> {
  const parts = url.pathname.split("/").filter(Boolean); // ["api","domains",...]
  if (parts[0] !== "api" || parts[1] !== "domains") return null;

  if (!env.CW_ADMIN_TOKEN) {
    return json({ error: "admin API not configured (set CW_ADMIN_TOKEN)" }, 503);
  }
  if (!bearerOk(req, env.CW_ADMIN_TOKEN)) {
    return json({ error: "unauthorized" }, 401);
  }
  if (!env.DB) {
    return json({ error: "database not configured (bind DB)" }, 503);
  }

  const store = new D1Store(env.DB);
  const rawTarget = parts[2] ? decodeURIComponent(parts[2]) : null;
  const sub = parts[3] ?? null;

  // /api/domains
  if (!rawTarget) {
    if (req.method === "GET") return json(await store.listDomains());
    if (req.method === "POST") return addDomain(req, store);
    return json({ error: "method not allowed" }, 405);
  }

  const domain = normalizeDomainInput(rawTarget);
  if (!domain) return json({ error: "invalid domain" }, 400);

  // /api/domains/:domain/history
  if (sub === "history") {
    if (req.method !== "GET") return json({ error: "method not allowed" }, 405);
    const limit = clampInt(url.searchParams.get("limit"), 50, 1, 500);
    return json(await store.getHistory(domain, limit));
  }

  // /api/domains/:domain
  if (sub === null) {
    if (req.method === "GET") {
      const detail = await store.getDomainDetail(domain);
      return detail ? json(detail) : json({ error: "not found" }, 404);
    }
    if (req.method === "DELETE") {
      const removed = await store.removeDomain(domain);
      return json({ removed }, removed ? 200 : 404);
    }
    return json({ error: "method not allowed" }, 405);
  }

  return json({ error: "not found" }, 404);
}

async function addDomain(req: Request, store: D1Store): Promise<Response> {
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return json({ error: "invalid JSON body" }, 400);
  }
  const b = (body ?? {}) as Record<string, unknown>;

  const domain = normalizeDomainInput(String(b.domain ?? ""));
  if (!domain) return json({ error: "invalid or missing `domain`" }, 400);

  const dkimSelectors = Array.isArray(b.dkimSelectors)
    ? b.dkimSelectors.map(String).filter(Boolean).slice(0, 20)
    : undefined;
  const checkIntervalSeconds =
    b.checkIntervalSeconds !== undefined
      ? clampInt(String(b.checkIntervalSeconds), 21600, 900, 604800)
      : undefined;
  const label = b.label !== undefined ? String(b.label).slice(0, 200) : undefined;

  const res = await store.addDomain(
    {
      domain,
      ...(label !== undefined ? { label } : {}),
      ...(dkimSelectors ? { dkimSelectors } : {}),
      ...(checkIntervalSeconds !== undefined ? { checkIntervalSeconds } : {}),
    },
    new Date().toISOString(),
  );

  return json({ id: res.id, domain, created: res.created }, res.created ? 201 : 200);
}

function bearerOk(req: Request, expected: string): boolean {
  const header = req.headers.get("authorization") ?? "";
  const m = /^Bearer\s+(.+)$/i.exec(header);
  if (!m) return false;
  const got = m[1]!;
  if (got.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < got.length; i++) diff |= got.charCodeAt(i) ^ expected.charCodeAt(i);
  return diff === 0;
}

function clampInt(
  raw: string | null,
  fallback: number,
  lo: number,
  hi: number,
): number {
  const n = Number(raw);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(lo, Math.min(hi, Math.trunc(n)));
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}
