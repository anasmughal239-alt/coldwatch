import { describe, expect, it } from "vitest";
import { evaluateSpf } from "../src/checks/spf.js";
import { MockResolver } from "./helpers/mock-resolver.js";

const codes = (r: { findings: { code: string }[] }) => r.findings.map((f) => f.code);

describe("evaluateSpf", () => {
  it("accepts a valid single-include record ending in -all", async () => {
    const dns = new MockResolver()
      .txt("example.com", "v=spf1 include:_spf.google.com -all")
      .txt("_spf.google.com", "v=spf1 ip4:35.190.247.0/24 ~all");

    const r = await evaluateSpf("example.com", dns);
    expect(r.status).toBe("ok");
    expect(codes(r)).toContain("spf.ok");
    expect(r.data.lookups).toBe(1);
  });

  it("flags permerror when DNS lookups exceed 10", async () => {
    const dns = new MockResolver();
    const includes = Array.from({ length: 11 }, (_, i) => `include:i${i}.com`);
    dns.txt("example.com", `v=spf1 ${includes.join(" ")} -all`);
    for (let i = 0; i < 11; i++) dns.txt(`i${i}.com`, "v=spf1 -all");

    const r = await evaluateSpf("example.com", dns);
    expect(r.status).toBe("crit");
    expect(codes(r)).toContain("spf.too_many_lookups");
  });

  it("flags multiple SPF records as permerror", async () => {
    const dns = new MockResolver().txt("example.com", [
      "v=spf1 -all",
      "v=spf1 include:x.com -all",
    ]);
    const r = await evaluateSpf("example.com", dns);
    expect(r.status).toBe("crit");
    expect(codes(r)).toContain("spf.multiple_records");
  });

  it("warns when there is no SPF record", async () => {
    const dns = new MockResolver().nodata("example.com");
    const r = await evaluateSpf("example.com", dns);
    expect(r.status).toBe("warn");
    expect(codes(r)).toContain("spf.missing");
  });

  it("flags +all as critical", async () => {
    const dns = new MockResolver().txt("example.com", "v=spf1 +all");
    const r = await evaluateSpf("example.com", dns);
    expect(codes(r)).toContain("spf.plus_all");
    expect(r.status).toBe("crit");
  });

  it("warns when the record has no `all` mechanism", async () => {
    const dns = new MockResolver()
      .txt("example.com", "v=spf1 include:x.com")
      .txt("x.com", "v=spf1 -all");
    const r = await evaluateSpf("example.com", dns);
    expect(codes(r)).toContain("spf.no_all");
  });

  it("accepts ~all without a no_all warning", async () => {
    const dns = new MockResolver()
      .txt("example.com", "v=spf1 include:x.com ~all")
      .txt("x.com", "v=spf1 -all");
    const r = await evaluateSpf("example.com", dns);
    expect(codes(r)).not.toContain("spf.no_all");
    expect(r.status).toBe("ok");
  });

  it("warns on the deprecated ptr mechanism", async () => {
    const dns = new MockResolver().txt("example.com", "v=spf1 ptr -all");
    const r = await evaluateSpf("example.com", dns);
    expect(codes(r)).toContain("spf.ptr_used");
  });

  it("detects include loops", async () => {
    const dns = new MockResolver()
      .txt("a.com", "v=spf1 include:b.com -all")
      .txt("b.com", "v=spf1 include:a.com -all");
    const r = await evaluateSpf("a.com", dns);
    expect(codes(r)).toContain("spf.loop");
    expect(r.status).toBe("crit");
  });

  it("flags permerror for too many void lookups", async () => {
    const dns = new MockResolver().txt(
      "example.com",
      "v=spf1 include:v1.com include:v2.com include:v3.com -all",
    );
    // v1..v3 are left as NXDOMAIN by the mock default
    const r = await evaluateSpf("example.com", dns);
    expect(codes(r)).toContain("spf.too_many_void_lookups");
    expect(r.status).toBe("crit");
  });

  it("notes a flattened record", async () => {
    const dns = new MockResolver().txt(
      "example.com",
      "v=spf1 ip4:1.1.1.0/24 ip4:2.2.2.0/24 ip4:3.3.3.0/24 -all",
    );
    const r = await evaluateSpf("example.com", dns);
    expect(codes(r)).toContain("spf.flattened");
  });

  it("returns unknown when the root lookup errors", async () => {
    const dns = new MockResolver().error("example.com", "TXT");
    const r = await evaluateSpf("example.com", dns);
    expect(r.status).toBe("unknown");
    expect(codes(r)).toContain("spf.lookup_error");
  });

  const withIncludes = (n: number) => {
    const dns = new MockResolver().txt(
      "example.com",
      `v=spf1 ${Array.from({ length: n }, (_, i) => `include:i${i}.example.net`).join(" ")} ~all`,
    );
    for (let i = 0; i < n; i++) dns.txt(`i${i}.example.net`, "v=spf1 ip4:192.0.2.1 -all");
    return dns;
  };

  it("warns when SPF is at 9 or 10 of 10 lookups", async () => {
    for (const n of [9, 10]) {
      const r = await evaluateSpf("example.com", withIncludes(n));
      expect(r.status).toBe("warn");
      expect(codes(r)).toContain("spf.near_lookup_limit");
    }
    const ok = await evaluateSpf("example.com", withIncludes(8));
    expect(codes(ok)).toEqual(["spf.ok"]);
  });

  it("does not report a missing `all` when evaluation stops at the lookup limit", async () => {
    const r = await evaluateSpf("example.com", withIncludes(11));
    expect(codes(r)).toContain("spf.too_many_lookups");
    expect(codes(r)).not.toContain("spf.no_all");
  });
});
