# `src/app/` — routes (Next.js App Router)

In the App Router, **every folder with a `page.tsx` is a URL**. The pages here are deliberately thin: each one only renders a "View" component, so all the real UI lives in `src/components/`.

| File | URL | Renders |
| --- | --- | --- |
| `page.tsx` | `/` | `GatewayView` (Live Gateway) |
| `gateway/page.tsx` | `/gateway` | `GatewayView` (same screen, alternate URL) |
| `provenance/page.tsx` | `/provenance` | `ProvenanceView` |
| `sessions/page.tsx` | `/sessions` | redirects to `/provenance` |
| `registry/page.tsx` | `/registry` | `RegistryView` |
| `audit/page.tsx` | `/audit` | `AuditView` (accepts `?receipt=<id>` to open a receipt directly) |
| `eval-lab/page.tsx` | `/eval-lab` | `EvalLabView` |
| `policies/page.tsx` | `/policies` | `PoliciesView` |
| `approvals/page.tsx` | `/approvals` | `ApprovalsView` |
| `docs/page.tsx` | `/docs` | `DocsView` |
| `api/satg/v1/toolcalls/route.ts` | `POST /api/satg/v1/toolcalls` | Proxy to the SATG backend's `POST /v1/toolcalls` (raw body and status relayed unchanged) |
| `api/satg/health/route.ts` | `GET /api/satg/health` | Proxy to the SATG backend's `GET /health` |

The backend address is read server-side from `SATG_BACKEND_URL` (default `http://127.0.0.1:8000`); see `src/lib/satg/proxy.ts`.

## Shared files

- **`layout.tsx`** — wraps every page. Loads the fonts (Inter Tight for text, JetBrains Mono for code/hashes), sets the page title, and wraps children in `AppShell` (background + nav + toasts).
- **`globals.css`** — Tailwind import plus the design tokens:
  - Colour variables (`--bg`, `--fg`, `--muted`, `--panel`, `--line`, …) defined twice: `[data-theme="dark"]` and `[data-theme="light"]`. The theme toggle just flips `data-theme` on `<html>`.
  - `@theme inline` exposes them as Tailwind classes: `bg-bg`, `text-fg`, `text-muted`, `bg-panel`, `border-line`, `text-accent` (#F97316), etc.
  - `.panel` — the glassmorphic card used everywhere (translucent background, hairline border, backdrop blur).
  - `.grain` (film-grain overlay on the background), `.scrollbar-thin`, `.pulse-ring` (the kill switch's pulsing red ring).
  - `body` is transparent on purpose so the fixed background canvas shows through.
- **`favicon.ico`** — tab icon.

## Adding a new screen

1. Create `src/components/<name>/<Name>View.tsx` (start it with `"use client"`).
2. Create `src/app/<name>/page.tsx` that returns `<NameView />`.
3. Add it to the `NAV` array in `src/components/shell/TopNav.tsx`.
