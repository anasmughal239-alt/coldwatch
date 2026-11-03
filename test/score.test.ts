import { describe, expect, it } from "vitest";
import { checkDomain } from "../src/index.js";
import { result } from "../src/checks/types.js";
import { scoreReport } from "../src/score.js";
import { MockResolver } from "./helpers/mock-resolver.js";

describe("scoreReport readiness", () => {
  it("is unverified when a required lookup failed", () => {
    const s = scoreReport([
      result("spf", [
        { code: "spf.lookup_error", severity: "unknown", title: "Could not read" },
      ]),
      result("mx", [{ code: "mx.provider", severity: "ok", title: "Google" }]),
    ]);
    expect(s.readiness).toBe("unverified");
  });

  it("does not treat a missing DKIM selector as unverified", () => {
    const s = scoreReport([
      result("spf", [{ code: "spf.ok", severity: "ok", title: "ok" }]),
      result("dkim", [
        { code: "dkim.lookup_error", severity: "unknown", title: "probe failed" },
      ]),
    ]);
    expect(s.readiness).toBe("at-risk");
  });

  it("still reports not-ready when a definite failure was found", () => {
    const s = scoreReport([
      result("spf", [{ code: "spf.missing", severity: "crit", title: "No SPF" }]),
      result("mx", [
        { code: "mx.lookup_error", severity: "unknown", title: "Could not read" },
      ]),
    ]);
    expect(s.readiness).toBe("not-ready");
  });
});

describe("checkDomain with a failing resolver", () => {
  it("marks the domain unverified instead of passing it", async () => {
    const dns = new MockResolver()
      .error("example.com", "TXT")
      .error("_dmarc.example.com", "TXT")
      .error("example.com", "MX");
    const r = await checkDomain("example.com", { resolver: dns, maxDkimProbes: 2 });
    expect(r.readiness).toBe("unverified");
  });
});
