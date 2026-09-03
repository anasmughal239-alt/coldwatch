import { describe, expect, it } from "vitest";
import {
  dqsQueryName,
  expandIpv6,
  isIndividualIp,
  parseDnsbl,
  reverseIpv4,
  reverseIpv6,
} from "../src/dnsbl.js";

describe("reverseIpv4", () => {
  it("reverses the octets", () => {
    expect(reverseIpv4("192.0.2.7")).toBe("7.2.0.192");
    expect(reverseIpv4("192.0.2.7/32")).toBe("7.2.0.192");
  });
});

describe("expandIpv6 / reverseIpv6", () => {
  it("expands :: and zero-fills groups", () => {
    expect(expandIpv6("2001:db8::1")).toBe(
      "2001:0db8:0000:0000:0000:0000:0000:0001",
    );
  });
  it("produces 32 nibble-reversed labels", () => {
    const r = reverseIpv6("2001:db8::1");
    expect(r.split(".")).toHaveLength(32);
    expect(r.startsWith("1.0.0.0.")).toBe(true);
  });
});

describe("dqsQueryName", () => {
  it("builds an IP query", () => {
    expect(dqsQueryName("KEY", "192.0.2.7", "zen")).toBe(
      "KEY.7.2.0.192.zen.dq.spamhaus.net",
    );
  });
  it("builds a domain query", () => {
    expect(dqsQueryName("KEY", "Evil.com.", "dbl")).toBe(
      "KEY.evil.com.dbl.dq.spamhaus.net",
    );
  });
});

describe("parseDnsbl", () => {
  it("maps zen return codes to list names", () => {
    expect(parseDnsbl("zen", ["127.0.0.2"])).toEqual({
      listed: true,
      lists: ["SBL"],
      error: null,
    });
    expect(parseDnsbl("zen", ["127.0.0.4", "127.0.0.10"]).lists).toEqual([
      "XBL",
      "PBL",
    ]);
  });
  it("maps dbl return codes", () => {
    expect(parseDnsbl("dbl", ["127.0.1.2"]).lists).toEqual(["DBL-spam"]);
  });
  it("treats 127.255.255.x as an error, never listed", () => {
    const r = parseDnsbl("zen", ["127.255.255.254"]);
    expect(r.listed).toBe(false);
    expect(r.error).toMatch(/127\.255\.255\.254/);
  });
  it("empty answer is not listed", () => {
    expect(parseDnsbl("zen", [])).toEqual({ listed: false, lists: [], error: null });
  });
});

describe("isIndividualIp", () => {
  it("accepts a bare host, /32 and /128; rejects wider ranges", () => {
    expect(isIndividualIp("1.2.3.4")).toBe(true);
    expect(isIndividualIp("1.2.3.4/32")).toBe(true);
    expect(isIndividualIp("1.2.3.0/24")).toBe(false);
    expect(isIndividualIp("2001:db8::1")).toBe(true);
    expect(isIndividualIp("2001:db8::/32")).toBe(false);
    expect(isIndividualIp("not-an-ip")).toBe(false);
  });
});
