/**
 * Pure DNSBL / Spamhaus DQS query mechanics. No I/O.
 *
 * DQS query name:
 *   IP:      <key>.<reversed-ip>.<zone>.dq.spamhaus.net
 *   domain:  <key>.<domain>.<zone>.dq.spamhaus.net
 *
 * Response A records:
 *   NXDOMAIN        -> not listed
 *   127.0.0.x       -> listed on `zen` (bitmask meaning per code)
 *   127.0.1.x       -> listed on `dbl`
 *   127.255.255.x   -> ERROR (bad key, open resolver, excessive queries) —
 *                      never "listed", never "clean"
 */

export type Zone = "zen" | "dbl";

export interface DnsblParse {
  listed: boolean;
  lists: string[];
  error: string | null;
}

const ZEN_CODES: Record<string, string> = {
  "127.0.0.2": "SBL",
  "127.0.0.3": "SBL-CSS",
  "127.0.0.4": "XBL",
  "127.0.0.5": "XBL",
  "127.0.0.6": "XBL",
  "127.0.0.7": "XBL",
  "127.0.0.9": "SBL-DROP",
  "127.0.0.10": "PBL",
  "127.0.0.11": "PBL",
};

const DBL_CODES: Record<string, string> = {
  "127.0.1.2": "DBL-spam",
  "127.0.1.4": "DBL-phish",
  "127.0.1.5": "DBL-malware",
  "127.0.1.6": "DBL-botnetC2",
  "127.0.1.102": "DBL-abused-legit-spam",
  "127.0.1.103": "DBL-abused-spammed-redirector",
  "127.0.1.104": "DBL-abused-legit-phish",
  "127.0.1.105": "DBL-abused-legit-malware",
  "127.0.1.106": "DBL-abused-legit-botnetC2",
};

export function parseDnsbl(zone: Zone, records: string[]): DnsblParse {
  const lists: string[] = [];
  for (const r of records) {
    const code = r.trim();
    if (/^127\.255\.255\.\d+$/.test(code)) {
      return {
        listed: false,
        lists: [],
        error: `DQS returned ${code} (key/resolver/quota problem)`,
      };
    }
    const name =
      zone === "zen" ? ZEN_CODES[code] : DBL_CODES[code];
    lists.push(name ?? `${zone}:${code}`);
  }
  return { listed: lists.length > 0, lists: [...new Set(lists)], error: null };
}

export function dqsQueryName(
  key: string,
  entity: string,
  zone: Zone,
): string {
  const isIp = looksLikeIp(entity);
  const label = isIp
    ? entity.includes(":")
      ? reverseIpv6(entity)
      : reverseIpv4(entity)
    : entity.replace(/\.$/, "").toLowerCase();
  return `${key}.${label}.${zone}.dq.spamhaus.net`;
}

export function reverseIpv4(ip: string): string {
  const parts = stripCidr(ip).split(".");
  if (parts.length !== 4) throw new Error(`not an IPv4 address: ${ip}`);
  return parts.reverse().join(".");
}

export function reverseIpv6(ip: string): string {
  const hex = expandIpv6(stripCidr(ip)).replace(/:/g, "");
  if (hex.length !== 32) throw new Error(`not an IPv6 address: ${ip}`);
  return hex.split("").reverse().join(".");
}

export function expandIpv6(ip: string): string {
  const [head, tail] = ip.split("::");
  const headGroups = head ? head.split(":") : [];
  const tailGroups = tail ? tail.split(":") : [];
  const missing = 8 - headGroups.length - tailGroups.length;
  if (missing < 0 && !ip.includes("::")) {
    // already full
  }
  const groups =
    ip.includes("::")
      ? [...headGroups, ...Array(Math.max(missing, 0)).fill("0"), ...tailGroups]
      : ip.split(":");
  if (groups.length !== 8) throw new Error(`invalid IPv6 address: ${ip}`);
  return groups.map((g) => g.padStart(4, "0").toLowerCase()).join(":");
}

/**
 * True only for a single address (bare, /32, or /128). Provider ip4 ranges
 * wider than a host are meaningless to DNSBL-check and are skipped.
 */
export function isIndividualIp(term: string): boolean {
  const m = /^([^/]+)(?:\/(\d+))?$/.exec(term.trim());
  if (!m) return false;
  const addr = m[1]!;
  const prefix = m[2] ? Number(m[2]) : null;
  if (addr.includes(":")) {
    return isIpv6(addr) && (prefix === null || prefix === 128);
  }
  return isIpv4(addr) && (prefix === null || prefix === 32);
}

function looksLikeIp(s: string): boolean {
  return isIpv4(stripCidr(s)) || isIpv6(stripCidr(s));
}

function isIpv4(s: string): boolean {
  const p = s.split(".");
  return (
    p.length === 4 &&
    p.every((x) => /^\d{1,3}$/.test(x) && Number(x) >= 0 && Number(x) <= 255)
  );
}

function isIpv6(s: string): boolean {
  if (!s.includes(":")) return false;
  try {
    expandIpv6(s);
    return true;
  } catch {
    return false;
  }
}

function stripCidr(s: string): string {
  return s.split("/")[0]!.trim();
}
