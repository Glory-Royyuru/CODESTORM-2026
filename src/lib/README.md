# `src/lib/` — logic shared by the whole app

| Path | What it is |
| --- | --- |
| `gateway/` | The security engine (no React). See `gateway/README.md`. |
| `store.ts` | The bridge between React and the engine, plus small UI state. |

## `store.ts` in three parts

1. **The engine singleton** — `getGateway()` creates the gateway once (by running `seedGateway()`) and returns the same instance forever. Use it inside event handlers: `getGateway().simulateRugPull("execute_sql")`.

2. **`useGateway()` hook** — use it in components that *display* engine data. It subscribes to the engine with React's `useSyncExternalStore`, so whenever the engine calls `emit()` (after a call, approval, kill switch…), every component using the hook re-renders with fresh data.

   ```tsx
   const gw = useGateway();
   return <p>{gw.ledger.length} receipts</p>;
   ```

3. **`useUi` (Zustand)** — UI-only state:
   - `theme` / `toggleTheme()` — dark or light
   - `toasts` / `toast({ tone, title, detail })` — the notifications in the bottom-right corner (auto-dismiss after ~5 s)

Also exported: `useIsClient()`. The engine uses live timestamps and a random signing key, so it must never render on the server (the server and browser would disagree). `AppShell` uses this hook to show a short "Booting gateway engine…" message until the browser takes over.
