# `scripts/` — terminal checks

Small TypeScript scripts that run the gateway engine in Node (through `tsx`), with no browser. They help you check that engine changes still behave as expected.

| Command | File | What it prints |
| --- | --- | --- |
| `npm run check:engine` | `check-engine.ts` | Builds the seeded gateway (the same one the app shows on load), prints one line per decision (scenario, ground truth, tool, final / rule / ML verdicts, risk, the 5 ML scores, which rules fired), then verifies the whole receipt chain (`chain verified 39 / 39`) and lists each tool's registry status. |
| `npm run check:bench` | `check-bench.ts` | Runs all benchmark cases and prints detection rate, false-positive rate and p95 latencies per suite and overall, plus every miss. |

Run both after changing anything in `src/lib/gateway/` — for example, after tuning ML weights, confirm Scenario E still ends at ALLOW and the benchmark numbers don't regress.
