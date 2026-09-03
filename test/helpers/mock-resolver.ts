import type { DnsOutcome, RecordType, Resolver } from "../../src/dns/resolver.js";

/**
 * In-memory resolver for tests. Unconfigured names return NXDOMAIN, matching
 * "this name does not exist". Configure the ones a scenario needs.
 */
export class MockResolver implements Resolver {
  private zone = new Map<string, DnsOutcome>();
  public readonly calls: Array<{ name: string; type: RecordType }> = [];

  private key(name: string, type: RecordType): string {
    return `${type}:${name.toLowerCase().replace(/\.$/, "")}`;
  }

  txt(name: string, records: string | string[]): this {
    this.zone.set(this.key(name, "TXT"), {
      kind: "answers",
      records: Array.isArray(records) ? records : [records],
      ttl: 300,
    });
    return this;
  }

  mx(name: string, records: string[]): this {
    this.zone.set(this.key(name, "MX"), {
      kind: "answers",
      records,
      ttl: 300,
    });
    return this;
  }

  a(name: string, records: string[] = ["192.0.2.1"]): this {
    this.zone.set(this.key(name, "A"), { kind: "answers", records, ttl: 300 });
    return this;
  }

  nodata(name: string, type: RecordType = "TXT"): this {
    this.zone.set(this.key(name, type), { kind: "nodata" });
    return this;
  }

  nxdomain(name: string, type: RecordType = "TXT"): this {
    this.zone.set(this.key(name, type), { kind: "nxdomain" });
    return this;
  }

  error(name: string, type: RecordType = "TXT", reason = "SERVFAIL"): this {
    this.zone.set(this.key(name, type), { kind: "error", reason });
    return this;
  }

  async query(name: string, type: RecordType): Promise<DnsOutcome> {
    this.calls.push({ name: name.toLowerCase().replace(/\.$/, ""), type });
    return this.zone.get(this.key(name, type)) ?? { kind: "nxdomain" };
  }
}

/** A base64 blob of roughly the byte length an RSA key of `bits` produces. */
export function fakeRsaKey(bits: 512 | 1024 | 2048 | 4096): string {
  const bytes = { 512: 74, 1024: 162, 2048: 294, 4096: 550 }[bits];
  return "A".repeat(Math.ceil((bytes * 4) / 3));
}
