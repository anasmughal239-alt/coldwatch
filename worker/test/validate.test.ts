import { describe, expect, it } from "vitest";
import { isEmail, normalizeDomainInput } from "../src/validate.js";

describe("normalizeDomainInput", () => {
  it("accepts a bare domain", () => {
    expect(normalizeDomainInput("acme.com")).toBe("acme.com");
  });

  it("strips scheme, path, query, port and trailing dot", () => {
    expect(normalizeDomainInput("https://Acme.com:443/path?x=1")).toBe("acme.com");
    expect(normalizeDomainInput("acme.com.")).toBe("acme.com");
  });

  it("extracts the domain from an email address", () => {
    expect(normalizeDomainInput("jane.doe@mail.acme.co.uk")).toBe(
      "mail.acme.co.uk",
    );
  });

  it("rejects IPs, localhost, and junk", () => {
    expect(normalizeDomainInput("192.168.1.1")).toBeNull();
    expect(normalizeDomainInput("localhost")).toBeNull();
    expect(normalizeDomainInput("not a domain")).toBeNull();
    expect(normalizeDomainInput("")).toBeNull();
    expect(normalizeDomainInput("acme")).toBeNull();
    expect(normalizeDomainInput("acme.c")).toBeNull();
  });

  it("rejects an over-long input", () => {
    expect(normalizeDomainInput("a".repeat(260) + ".com")).toBeNull();
  });
});

describe("isEmail", () => {
  it("does a loose sanity check", () => {
    expect(isEmail("you@company.com")).toBe(true);
    expect(isEmail("nope")).toBe(false);
    expect(isEmail("a@b")).toBe(false);
  });
});
