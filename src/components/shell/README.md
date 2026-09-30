# `shell/` — the frame around every page

| File | What it does |
| --- | --- |
| `AppShell.tsx` | Used by `src/app/layout.tsx`. Before hydration it shows "Booting gateway engine…" (the engine must only run in the browser). After that it renders the animated background, `TopNav`, the page content (centered, max 1596 px wide) and `Toasts`. It also writes the current theme to `<html data-theme>`. When the kill switch is on, it passes red settings to the background so the ribbon turns red and speeds up. |
| `TopNav.tsx` | Sticky header. Left: logo + the `NAV` links (the active one gets a sliding pill via Framer Motion `layoutId`; Approvals shows a count of pending requests). Right: backend status, kill switch, theme toggle, GitHub 48.4K. Below 1280 px the links collapse into a menu button that opens a drop-down panel. |
| `BackendStatus.tsx` | Polls the real SATG backend's `GET /health` (via `/api/satg/health`) every 15 s: online / degraded / offline. |
| `KillSwitch.tsx` | Toggles the gateway between `ENFORCING` and `FAIL_CLOSED`. When engaging it immediately sends a probe call to prove the next call is blocked (and shows the latency, ~1 ms, in a toast). Pulses red while engaged. |
| `Toasts.tsx` | Renders `useUi().toasts` in the bottom-right corner with an icon per tone (success / danger / warn / info). |

To add a nav item, edit the `NAV` array at the top of `TopNav.tsx`.
