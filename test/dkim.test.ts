import { describe, expect, it } from "vitest";
import { estimateRsaBits, evaluateDkim } from "../src/checks/dkim.js";
import { PROVIDERS } from "../src/providers.js";
import { fakeRsaKey, MockResolver } from "./helpers/mock-resolver.js";

const google = PROVIDERS.find((p) => p.id === "google")!;
const codes = (r: { findings: { code: string }[] }) => r.findings.map((f) => f.code);

describe("estimateRsaBits", () => {
  it("bins base64 blobs by approximate modulus size", () => {
    expect(estimateRsaBits(fakeRsaKey(512))).toBe(512);
    expect(estimateRsaBits(fakeRsaKey(1024))).toBe(1024);
    expect(estimateRsaBits(fakeRsaKey(2048))).toBe(2048);
    expect(estimateRsaBits(fakeRsaKey(4096))).toBe(4096);
  });
});

describe("evaluateDkim", () => {
  it("accepts a valid key at the provider's default selector", async () => {
    const dns = new MockResolver().txt(
      "google._domainkey.example.com",
      `v=DKIM1; k=rsa; p=${fakeRsaKey(2048)}`,
    );
    const r = await evaluateDkim("example.com", dns, { provider: google });
    expect(r.status).toBe("ok");
    expect(codes(r)).toContain("dkim.ok");
  });

  it("warns when the provider's expected selector is absent", async () => {
    const r = await evaluateDkim("example.com", new MockResolver(), {
      provider: google,
    });
    expect(r.status).toBe("warn");
    expect(codes(r)).toContain("dkim.expected_missing");
  });

  it("returns unknown (not crit) when no selector can be guessed", async () => {
    const r = await evaluateDkim("example.com", new MockResolver());
    expect(r.status).toBe("unknown");
    expect(codes(r)).toContain("dkim.no_selector_found");
  });

  it("flags a revoked key (empty p=)", async () => {
    const dns = new MockResolver().txt(
      "google._domainkey.example.com",
      "v=DKIM1; k=rsa; p=",
    );
    const r = await evaluateDkim("example.com", dns, { provider: google });
    expect(r.status).toBe("crit");
    expect(codes(r)).toContain("dkim.revoked");
  });

  it("warns on test-mode keys (t=y)", async () => {
    const dns = new MockResolver().txt(
      "google._domainkey.example.com",
      `v=DKIM1; k=rsa; t=y; p=${fakeRsaKey(2048)}`,
    );
    const r = await evaluateDkim("example.com", dns, { provider: google });
    expect(codes(r)).toContain("dkim.testing_mode");
  });

  it("flags keys weaker than 1024 bits", async () => {
    const dns = new MockResolver().txt(
      "google._domainkey.example.com",
      `v=DKIM1; k=rsa; p=${fakeRsaKey(512)}`,
    );
    const r = await evaluateDkim("example.com", dns, { provider: google });
    expect(r.status).toBe("crit");
    expect(codes(r)).toContain("dkim.weak_key");
  });

  it("probes caller-supplied selectors first", async () => {
    const dns = new MockResolver().txt(
      "custom._domainkey.example.com",
      `v=DKIM1; k=rsa; p=${fakeRsaKey(2048)}`,
    );
    const r = await evaluateDkim("example.com", dns, { selectors: ["custom"] });
    expect(r.status).toBe("ok");
    expect(codes(r)).toContain("dkim.ok");
  });
});
