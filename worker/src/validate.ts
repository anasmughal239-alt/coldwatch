/**
 * Normalize and validate free-text domain input BEFORE running ~30 DNS
 * lookups against it. Accepts things a user is likely to paste (a URL, an
 * email address, a trailing dot) and rejects anything that isn't a public
 * hostname.
 */

const LABEL = "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?";
const DOMAIN_RE = new RegExp(`^(?:${LABEL}\\.)+[a-z]{2,63}$`);

export function normalizeDomainInput(raw: string): string | null {
  if (typeof raw !== "string") return null;

  let s = raw.trim().toLowerCase();
  s = s.replace(/^[a-z]+:\/\//, ""); // scheme
  s = s.replace(/^mailto:/, "");
  if (s.includes("@")) s = s.slice(s.lastIndexOf("@") + 1);
  s = s.replace(/[/?#].*$/, ""); // path / query / fragment
  s = s.replace(/:\d+$/, ""); // port
  s = s.replace(/\.$/, ""); // root dot

  if (!s || s.length > 253) return null;
  if (s === "localhost" || s.endsWith(".local") || s.endsWith(".localhost"))
    return null;
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(s)) return null; // IPv4
  if (s.includes(":")) return null; // IPv6 / leftover
  if (!DOMAIN_RE.test(s)) return null;

  return s;
}

export function isEmail(raw: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(raw.trim());
}
