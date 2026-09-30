# `policies/` — Policies & control plane screen (`/policies`)

One file: `PoliciesView.tsx`.

## YAML editor (left)

- Shows the active policy bundle as YAML (`bundleToYaml` in `lib/gateway/policy.ts`), with line numbers.
- As you type it is parsed and validated (`yamlToBundle`): unknown rule ids, wrong parameter types, bad `mode` values and duplicate keys are listed in red, and the badge switches between *valid schema* and *invalid*.
- Each rule has `enabled` (true/false), `mode` (`enforce`, or `monitor` = shadow mode: logged as MONITOR but never blocks) and `params` (allowlists, limits, budgets…).
- Buttons:
  - **Simulate against history** — runs the Time Machine (below).
  - **Publish bundle** — makes the draft live and bumps the version (e.g. `2026.09.3` → `2026.09.4`). New receipts record the new rule versions.
  - **Revert** — discards the draft.
- **Quick edits** apply common changes for you, e.g. *Disable lethal_trifecta*, *Shadow-mode taint_flow*, *Allow exfil-collector.net*, *Tighten SQL max_limit → 20*, *Slow-drip after 2 calls*.

## Policy Time Machine (right, top)

`timeMachine()` in `lib/gateway/runner.ts` takes every recorded call, groups the calls by session, and replays each session twice in throwaway gateways with the same tool outputs: once under the **active** bundle and once under your **draft**. It then compares the verdicts with each call's ground truth:

- **Attacks prevented** — before → after (up is good)
- **Benign calls escalated** — before → after (down is good). Tier-4 operations that legitimately wait for approval count here, which is why this isn't 0.
- A green "safe to publish" or red "regression" verdict
- **Changed decisions** — every call whose verdict would change, e.g. `send_email  attack  BLOCK → STEP_UP`

Example: apply *Disable lethal_trifecta* + *Allow exfil-collector.net* + *Shadow-mode taint_flow* → the Time Machine reports that a historical attack would slip through.

## Control plane (right, bottom)

Gateway mode (ENFORCING / FAIL_CLOSED), an **ML on/off switch** (with ML off the rules still decide — the gateway never fails open), the active bundle version and rule count, the signing key id, and the ingress limits.
