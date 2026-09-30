# `approvals/` — Approvals queue screen (`/approvals`)

One file: `ApprovalsView.tsx`.

## Where requests come from

When a call ends with `HUMAN_APPROVAL` (needs **2** approvers — e.g. every Tier-4 tool: `db_admin`, `transfer_funds`) or `STEP_UP` (needs **1** — e.g. the ML flagged it), the engine does **not** execute it and adds an approval request instead. The seed data contains several; the wire transfer already has its first approval.

## The page

- **Acting as** (top right) — choose which operator you are. Two *different* operators are needed for a 2-person approval; the same person can't approve twice, and the requesting user can't approve their own request.
- **Pending** — one card per request: tool, verdict type, Tier-4 tag, agent and user, the step-up reason, the exact arguments, the ML risk bar, and approver slots (filled slots show who approved). Buttons: **Approve as …** and **Reject**.
- **Granted** — once enough approvals arrive, the engine issues a **capability grant**: an Ed25519-signed token bound to the exact tool, the SHA-256 of the canonical arguments, and a 5-minute expiry. The card shows the grant id, expiry, args digest, state (UNUSED / CONSUMED) and signature.
  - **Execute with grant** re-sends the original call with the grant attached. A valid grant satisfies the approval requirement (never a hard block), the call runs in the sandbox, and the grant is marked consumed.
  - **Replay grant (single-use test)** sends the same grant again → **BLOCK**, "already consumed".
- **Rejected** — a compact history list.

Every execution and replay produces a normal signed receipt in the Audit Ledger.
