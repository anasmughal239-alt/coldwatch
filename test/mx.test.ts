import { describe, expect, it } from "vitest";
import { evaluateMx } from "../src/checks/mx.js";
import { MockResolver } from "./helpers/mock-resolver.js";

const codes = (r: { findings: { code: string }[] }) => r.findings.map((f) => f.code);

describe("evaluateMx", () => {
  it("fingerprints a known provider", async () => {
    const dns = new MockResolver().mx("example.com", ["10 aspmx.l.google.com."]);
    const r = await evaluateMx("example.com", dns);
    expect(r.provider?.id).toBe("google");
    expect(r.status).toBe("ok");
    expect(codes(r)).toContain("mx.provider");
  });

  it("warns when there are no MX records", async () => {
    const dns = new MockResolver().nodata("example.com", "MX");
    const r = await evaluateMx("example.com", dns);
    expect(r.status).toBe("warn");
    expect(codes(r)).toContain("mx.none");
  });

  it("warns on a null MX", async () => {
    const dns = new MockResolver().mx("example.com", ["0 ."]);
    const r = await evaluateMx("example.com", dns);
    expect(codes(r)).toContain("mx.null");
  });

  it("flags MX pointing at an IP literal", async () => {
    const dns = new MockResolver().mx("example.com", ["10 192.168.1.1"]);
    const r = await evaluateMx("example.com", dns);
    expect(r.status).toBe("crit");
    expect(codes(r)).toContain("mx.invalid_host");
  });

  it("accepts a valid MX from an unrecognised provider", async () => {
    const dns = new MockResolver().mx("example.com", ["10 mail.custom-host.net."]);
    const r = await evaluateMx("example.com", dns);
    expect(r.status).toBe("ok");
    expect(r.provider).toBeUndefined();
    expect(codes(r)).toContain("mx.ok");
  });

  it("returns unknown when the MX lookup errors", async () => {
    const dns = new MockResolver().error("example.com", "MX");
    const r = await evaluateMx("example.com", dns);
    expect(r.status).toBe("unknown");
  });
});
