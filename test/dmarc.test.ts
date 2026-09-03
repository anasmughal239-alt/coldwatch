import { describe, expect, it } from "vitest";
import { evaluateDmarc } from "../src/checks/dmarc.js";
import { MockResolver } from "./helpers/mock-resolver.js";

const codes = (r: { findings: { code: string }[] }) => r.findings.map((f) => f.code);

describe("evaluateDmarc", () => {
  it("accepts p=reject with a same-org rua", async () => {
    const dns = new MockResolver().txt(
      "_dmarc.example.com",
      "v=DMARC1; p=reject; rua=mailto:d@example.com",
    );
    const r = await evaluateDmarc("example.com", dns);
    expect(r.status).toBe("ok");
    expect(codes(r)).toContain("dmarc.policy_enforced");
  });

  it("flags a missing record as critical", async () => {
    const r = await evaluateDmarc("example.com", new MockResolver());
    expect(r.status).toBe("crit");
    expect(codes(r)).toContain("dmarc.missing");
  });

  it("warns on p=none", async () => {
    const dns = new MockResolver().txt(
      "_dmarc.example.com",
      "v=DMARC1; p=none; rua=mailto:d@example.com",
    );
    const r = await evaluateDmarc("example.com", dns);
    expect(r.status).toBe("warn");
    expect(codes(r)).toContain("dmarc.policy_none");
  });

  it("resolves a subdomain to the org record and applies sp=", async () => {
    const dns = new MockResolver().txt(
      "_dmarc.example.com",
      "v=DMARC1; p=none; sp=quarantine; rua=mailto:d@example.com",
    );
    const r = await evaluateDmarc("mail.example.com", dns);
    expect(r.data.source).toBe("org");
    expect(r.data.effectivePolicy).toBe("quarantine");
    expect(r.status).toBe("ok");
  });

  it("applies org p= to a subdomain when sp= is absent", async () => {
    const dns = new MockResolver().txt(
      "_dmarc.example.com",
      "v=DMARC1; p=reject; rua=mailto:d@example.com",
    );
    const r = await evaluateDmarc("mail.example.com", dns);
    expect(r.data.effectivePolicy).toBe("reject");
  });

  it("warns when rua is missing", async () => {
    const dns = new MockResolver().txt("_dmarc.example.com", "v=DMARC1; p=reject");
    const r = await evaluateDmarc("example.com", dns);
    expect(codes(r)).toContain("dmarc.no_rua");
    expect(r.status).toBe("warn");
  });

  it("warns on partial enforcement (pct<100)", async () => {
    const dns = new MockResolver().txt(
      "_dmarc.example.com",
      "v=DMARC1; p=reject; pct=50; rua=mailto:d@example.com",
    );
    const r = await evaluateDmarc("example.com", dns);
    expect(codes(r)).toContain("dmarc.pct_partial");
  });

  it("flags multiple DMARC records as permerror", async () => {
    const dns = new MockResolver().txt("_dmarc.example.com", [
      "v=DMARC1; p=none",
      "v=DMARC1; p=reject",
    ]);
    const r = await evaluateDmarc("example.com", dns);
    expect(r.status).toBe("crit");
    expect(codes(r)).toContain("dmarc.multiple_records");
  });

  it("warns on an unauthorized external rua destination", async () => {
    const dns = new MockResolver().txt(
      "_dmarc.example.com",
      "v=DMARC1; p=reject; rua=mailto:dmarc@reports.thirdparty.com",
    );
    const r = await evaluateDmarc("example.com", dns);
    expect(codes(r)).toContain("dmarc.external_rua_unauthorized");
  });

  it("accepts an authorized external rua destination", async () => {
    const dns = new MockResolver()
      .txt(
        "_dmarc.example.com",
        "v=DMARC1; p=reject; rua=mailto:dmarc@reports.thirdparty.com",
      )
      .txt("example.com._report._dmarc.reports.thirdparty.com", "v=DMARC1");
    const r = await evaluateDmarc("example.com", dns);
    expect(codes(r)).not.toContain("dmarc.external_rua_unauthorized");
  });

  it("flags a record with no p= tag as permerror", async () => {
    const dns = new MockResolver().txt(
      "_dmarc.example.com",
      "v=DMARC1; rua=mailto:d@example.com",
    );
    const r = await evaluateDmarc("example.com", dns);
    expect(r.status).toBe("crit");
    expect(codes(r)).toContain("dmarc.no_policy_tag");
  });
});
