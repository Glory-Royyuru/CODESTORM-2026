import { seedGateway } from "../src/lib/gateway/seed";
import { verifyReceipt } from "../src/lib/gateway/receipts";
import type { DecisionReceipt } from "../src/lib/gateway/types";
const t = performance.now();
const gw = seedGateway();
console.log("seed ms", (performance.now() - t).toFixed(0), "entries", gw.ledger.length, "approvals", gw.approvals.length);
for (const e of gw.ledger) {
  const b = e.receipt.body;
  const fired = b.findings.map((f) => `${f.ruleId}:${f.outcome}`).join(",");
  console.log(`${(e.scenario ?? "-").padEnd(3)} ${e.groundTruth.padEnd(6)} ${b.tool.padEnd(20)} ${b.verdict.padEnd(15)} det=${b.deterministicVerdict.padEnd(14)} ml=${b.mlVerdict.padEnd(14)} r=${b.riskScore.toFixed(2)} ${Object.entries(b.mlScores).map(([k,v])=>k.slice(0,4)+"="+(v as number).toFixed(2)).join(" ")} | ${fired}`);
}
let prev: DecisionReceipt | null = null, ok = 0;
for (const e of gw.ledger) { if (verifyReceipt(e.receipt, prev).ok) ok++; prev = e.receipt; }
console.log("chain verified", ok, "/", gw.ledger.length);
for (const [n, t] of gw.registry) console.log(n, t.status);
