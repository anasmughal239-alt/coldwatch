import { describe, expect, it } from "vitest";
import {
  decodeTxt,
  parseDohResponse,
  parseMxRecords,
} from "../src/dns/resolver.js";

describe("parseDohResponse", () => {
  it("maps rcode 3 to nxdomain", () => {
    expect(parseDohResponse({ Status: 3 }, "TXT")).toEqual({ kind: "nxdomain" });
  });

  it("maps rcode 2 to a retryable error", () => {
    const out = parseDohResponse({ Status: 2 }, "TXT");
    expect(out).toMatchObject({ kind: "error", rcode: 2 });
  });

  it("maps NOERROR with no matching answers to nodata", () => {
    const out = parseDohResponse(
      { Status: 0, Answer: [{ name: "x", type: 5, data: "cname.example." }] },
      "TXT",
    );
    expect(out).toEqual({ kind: "nodata" });
  });

  it("returns TXT answers with the minimum TTL", () => {
    const out = parseDohResponse(
      {
        Status: 0,
        Answer: [
          { name: "x", type: 16, TTL: 600, data: '"v=spf1 -all"' },
          { name: "x", type: 16, TTL: 120, data: '"other"' },
        ],
      },
      "TXT",
    );
    expect(out).toEqual({
      kind: "answers",
      records: ["v=spf1 -all", "other"],
      ttl: 120,
    });
  });
});

describe("decodeTxt", () => {
  it("concatenates multi-string TXT with no separator", () => {
    expect(decodeTxt('"v=spf1 include:a.com " "include:b.com -all"')).toBe(
      "v=spf1 include:a.com include:b.com -all",
    );
  });

  it("handles a single quoted string", () => {
    expect(decodeTxt('"v=DMARC1; p=none"')).toBe("v=DMARC1; p=none");
  });

  it("unescapes embedded quotes", () => {
    expect(decodeTxt('"a\\"b"')).toBe('a"b');
  });
});

describe("parseMxRecords", () => {
  it("parses and sorts by ascending preference, stripping trailing dots", () => {
    expect(
      parseMxRecords(["20 backup.example.com.", "10 primary.example.com."]),
    ).toEqual([
      { preference: 10, exchange: "primary.example.com" },
      { preference: 20, exchange: "backup.example.com" },
    ]);
  });
});
