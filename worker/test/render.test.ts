import { describe, expect, it } from "vitest";
import type { DomainReport } from "../../src/index.js";
import { escapeHtml, renderReport } from "../src/render.js";

const sample: DomainReport = {
  domain: "acme.com",
  checkedAt: "2026-09-03T00:00:00.000Z",
  score: 62,
  grade: "C",
  readiness: "at-risk",
  checks: [
    {
      check: "spf",
      status: "crit",
      findings: [
        {
          code: "spf.too_many_lookups",
          severity: "crit",
          title: "More than 10 DNS lookups (permerror)",
          detail: "requires 12 terms",
          fix: "reduce include nesting",
        },
      ],
      data: {},
    },
    { check: "dkim", status: "ok", findings: [], data: {} },
  ],
};

describe("escapeHtml", () => {
  it("escapes angle brackets, ampersands and quotes", () => {
    expect(escapeHtml('<a href="x">&')).toBe("&lt;a href=&quot;x&quot;&gt;&amp;");
  });
});

describe("renderReport", () => {
  const html = renderReport(sample);

  it("renders the scorecard", () => {
    expect(html).toContain("scorecard at-risk");
    expect(html).toContain(">C<");
    expect(html).toContain("62");
  });

  it("renders findings with severity classes and fixes", () => {
    expect(html).toContain("sev-crit");
    expect(html).toContain("More than 10 DNS lookups (permerror)");
    expect(html).toContain("Fix: reduce include nesting");
  });

  it("shows a synthetic OK row for a check with no findings", () => {
    expect(html).toContain("No issues found");
  });
});
