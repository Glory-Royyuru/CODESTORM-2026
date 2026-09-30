# `audit/` — Audit Ledger screen (`/audit`)

## `AuditView.tsx` — the ledger

- **Filter tabs:** All · Allowed (ALLOW, MONITOR) · Blocked (BLOCK, QUARANTINE) · Escalated (STEP_UP, HUMAN_APPROVAL), each with a count.
- **Search** by tool, session id, agent or hash.
- **Table** (newest first): sequence number, time, session, agent, tool, verdict, latency bar (blue = deterministic part, orange = ML part) and receipt hash.
- **Verify entire chain** re-checks every receipt from the first to the last and shows a banner like `47/47 receipts verified`.
- Clicking a row opens the inspector. Other screens link here with `/audit?receipt=<id>`, which opens that receipt directly.

## `ReceiptInspector.tsx` — one receipt in detail

Left column:
- final verdict, rule verdict, ML verdict, abstain flag and risk score,
- the full **canonical receipt JSON** (the exact bytes that were signed) with a copy button,
- the rule findings.

Right column:
- **Ed25519 signature** — public key, signature, SHA-256. **Verify receipt** re-computes the canonical JSON, the hash, the signature check and the chain link, and shows PASS/FAIL for each.
- **Tamper test** — copies the receipt, flips its verdict, and verifies the copy. It fails, which shows that editing a stored receipt is detectable. The real receipt is never modified.
- **Hash chain** — previous hash → this hash → next receipt's `prevHash`, with ✓ linked / ✗ broken.
- **ML feature contributions** — SHAP-style bars: how much each ML score pushed the risk up (orange, right) or down (green, left) compared with a normal call.
- **Counterfactual** — what would have had to be different for the verdict to change, e.g. *"If `to` had targeted an allow-listed domain…"*.
- **Stage latencies** — a bar per pipeline stage (ML in orange).
