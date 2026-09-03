import { describe, expect, it } from "vitest";
import { evaluateBlacklist, type BlacklistDqs } from "../src/checks/blacklist.js";
import type { DqsResult } from "../src/dqs.js";
import type { Zone } from "../src/dnsbl.js";

const codes = (r: { findings: { code: string }[] }) => r.findings.map((f) => f.code);

function dqs(verdicts: Record<string, Partial<DqsResult>>): BlacklistDqs {
  return {
    async checkMany(targets: Array<{ entity: string; zone: Zone }>) {
      return targets.map((t) => {
        const v = verdicts[`${t.zone}|${t.entity}`] ?? { status: "ok" as const };
        return {
          entity: t.entity,
          zone: t.zone,
          status: v.status ?? "ok",
          listed: v.status === "listed",
          lists: v.lists ?? [],
          reason: v.reason,
        } as DqsResult;
      });
    },
  };
}

describe("evaluateBlacklist", () => {
  it("passes a clean domain + IP", async () => {
    const r = await evaluateBlacklist(
      "acme.com",
      [{ ip: "192.0.2.7", source: "spf" }],
      dqs({}),
    );
    expect(r.status).toBe("ok");
    expect(codes(r)).toContain("blacklist.ok");
  });

  it("flags a domain listed on the DBL", async () => {
    const r = await evaluateBlacklist(
      "spammy.com",
      [],
      dqs({ "dbl|spammy.com": { status: "listed", lists: ["DBL-spam"] } }),
    );
    expect(r.status).toBe("crit");
    expect(codes(r)).toContain("blacklist.domain_listed");
  });

  it("flags a listed sending IP", async () => {
    const r = await evaluateBlacklist(
      "acme.com",
      [{ ip: "10.0.0.9", source: "manual" }],
      dqs({ "zen|10.0.0.9": { status: "listed", lists: ["SBL", "XBL"] } }),
    );
    expect(r.status).toBe("crit");
    expect(codes(r)).toContain("blacklist.ip_listed");
  });

  it("reports budget exhaustion as unknown, not a pass", async () => {
    const r = await evaluateBlacklist(
      "acme.com",
      [{ ip: "192.0.2.7", source: "spf" }],
      dqs({
        "dbl|acme.com": { status: "unknown", reason: "quota" },
        "zen|192.0.2.7": { status: "unknown", reason: "quota" },
      }),
    );
    expect(r.status).toBe("unknown");
    expect(codes(r)).toContain("blacklist.quota");
  });

  it("passes cleanly but flags reduced coverage when no IPs are known", async () => {
    const r = await evaluateBlacklist("acme.com", [], dqs({}));
    expect(r.status).toBe("ok");
    expect(codes(r)).toContain("blacklist.ok");
    expect(r.findings[0]!.title).toMatch(/no individual sending IPs known/i);
  });

  it("caps the number of sending IPs checked, manual before SPF", async () => {
    const manual = Array.from({ length: 4 }, (_, i) => ({
      ip: `10.0.0.${i}`,
      source: "manual",
    }));
    const spf = Array.from({ length: 15 }, (_, i) => ({
      ip: `192.0.2.${i}`,
      source: "spf",
    }));
    const r = await evaluateBlacklist("acme.com", [...spf, ...manual], dqs({}), {
      maxIps: 12,
    });

    // 12 IPs + 1 domain
    expect((r.data.checked as { entity: string }[]).length).toBe(13);
    expect(r.data.knownIpCount).toBe(19);
    expect(codes(r)).toContain("blacklist.ips_capped");

    const checkedIps = (r.data.checked as { entity: string; zone: string }[])
      .filter((c) => c.zone === "zen")
      .map((c) => c.entity);
    // all 4 manual IPs must be in the checked set
    for (const m of manual) expect(checkedIps).toContain(m.ip);
  });

  it("ignores CIDR ranges wider than a host", async () => {
    const r = await evaluateBlacklist(
      "acme.com",
      [{ ip: "192.0.2.0/24", source: "spf" }],
      dqs({}),
    );
    // only the domain (dbl) should have been checked
    expect((r.data.checked as unknown[]).length).toBe(1);
    expect(r.status).toBe("ok");
  });
});
