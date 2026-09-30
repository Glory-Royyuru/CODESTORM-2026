# `gateway/` — Live Gateway screen (`/`)

The home page: the React Bits-style hero on the left, the request editor on the right, then the backend's check trace and verdict, and live stats below.

**This screen is connected to the real SATG backend** (`backend/`, FastAPI). Every verdict shown here comes from `POST /v1/toolcalls`; the console never decides. It does not use the in-browser demo engine (`src/lib/gateway/`).

| File | What it shows |
| --- | --- |
| `GatewayView.tsx` | Page layout. Left column: headline, description, 3 stat chips, CTA buttons. Sends the request with `submitToolCall()` (`lib/satg/client.ts`), records the outcome in `useSatgLog`, scrolls to the trace, and shows a toast when the trace finishes. |
| `AttackStudio.tsx` | The Mac-style window. Example drop-down (`lib/satg/presets.ts`, grouped by what they exercise), an **editable raw body** with JSON highlighting and a byte counter, and **Send Through Gateway**. The "designed for" label says what an example is meant to trigger — it is not a result. |
| `PipelineRun.tsx` | The backend's `checks` (passed / failed) and `checks_not_evaluated` (skipped — the backend stops at the first failure) as tiles, then the policy decision. The **Backend verdict** panel shows verdict, severity, HTTP status, rule ID, reason, stage, ingress schema errors, request ID, agent, tool, tool version, manifest hash, request hash, policy version and the raw response. Backend and network errors get their own "No verdict" panel. A row lists the SATG modules the backend does not implement yet. |
| `LiveTelemetry.tsx` | Stats and the last 8 backend responses from this browser tab (the backend's audit log is server-side and has no read API). |

## What happens when you press Send

1. `GatewayView` calls `submitToolCall(body)`, which POSTs the raw body to `/api/satg/v1/toolcalls` (same origin).
2. The route handler (`src/app/api/satg/v1/toolcalls/route.ts` → `lib/satg/proxy.ts`) forwards the exact bytes and `Content-Type` to the backend and relays its status and body unchanged. If the backend is unreachable or times out, it returns 502/504 with an `x-satg-proxy-error` header and no verdict.
3. `client.ts` classifies the response: a verdict only if it matches the backend's `Verdict` model (and `ALLOW` only with HTTP 200); otherwise a backend or network error.
4. `PipelineRun` is re-mounted (new `key`) and replays the backend's checks.

Outcomes the UI distinguishes: **ALLOW** (allowed, not executed) · **BLOCK** (security policy, including ingress rejections with HTTP 400/413/415/422 and fail-closed internal errors with HTTP 500) · **BACKEND ERROR** · **NETWORK ERROR**.

## Things to try

- Pick **Ingress → Duplicate JSON key** → HTTP 400, `INGRESS-002`.
- In the email example, change `to` to `someone@trusted-partner.com` (allowed) or `someone@company.com.evil.example` (`DEST-001`).
- Change `agent_id` in the email example to `sales-bot-1` → `TOOL-003`.
- Stop the backend and press Send → **NETWORK ERROR**, no verdict; the header indicator turns red.
