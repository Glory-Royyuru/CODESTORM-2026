import { Gateway } from "../src/lib/gateway/engine";
import { generateCases, runCase, summarize } from "../src/lib/gateway/benchmarks";
const t = performance.now();
const cases = generateCases();
const gw = new Gateway({ ephemeral: true });
const res = cases.map((c) => runCase(gw, c));
console.log("ms", (performance.now() - t).toFixed(0));
for (const s of ["agentdojo","injecagent","mcptox","egress"]) { const r = res.filter(x=>x.suite===s); console.log(s, JSON.stringify(summarize(r))); }
console.log("ALL", JSON.stringify(summarize(res)));
for (const r of res) if ((r.kind==="attack") !== r.detected) console.log("MISS", r.id, r.env, r.kind, r.verdict);
