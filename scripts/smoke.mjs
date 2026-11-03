// Live smoke test: runs the built CLI against real domains over real DNS.
// Fails if any domain comes back "unverified" (lookups failed) or the CLI
// crashes. Prints one GitHub annotation per domain with its result.
import { execFileSync } from "node:child_process";

const domains = process.argv.slice(2);
if (domains.length === 0) domains.push("stripe.com", "google.com", "github.com");

let out;
try {
  out = execFileSync("node", ["dist/cli.js", ...domains, "--json"], { encoding: "utf8" });
} catch (err) {
  // Exit 1 (a domain below threshold) is a valid result for a smoke test.
  if (err.status !== 1) {
    console.error(err.stdout || err.message);
    console.log(`::error::coldwatch exited ${err.status}`);
    process.exit(1);
  }
  out = err.stdout;
}

const reports = JSON.parse(out);
let bad = 0;
for (const r of reports) {
  const checks = r.checks.map((c) => `${c.check}:${c.status}`).join(" ");
  const line = `${r.domain} ${r.grade} ${r.score}/100 ${r.readiness} | ${checks}`;
  if (r.readiness === "unverified") {
    bad++;
    console.log(`::error::${line}`);
  } else {
    console.log(`::notice::${line}`);
  }
}
process.exit(bad ? 1 : 0);
