# `src/` — application source

```
src/
├── app/          Routes (URLs). Thin: each page just renders a View from components/.
├── components/   Everything you see. One folder per screen, plus shared pieces.
└── lib/          Non-visual logic: the gateway engine and the React ↔ engine store.
```

How the three connect:

```
URL (/audit)  →  src/app/audit/page.tsx  →  <AuditView/>  (src/components/audit/)
                                                │
                                                ├─ reads data with useGateway()     (src/lib/store.ts)
                                                └─ calls actions on getGateway()    → Gateway engine (src/lib/gateway/engine.ts)
                                                                                      └─ emit() → every screen re-renders
```

All screens are wrapped by `AppShell` (from `src/app/layout.tsx`), which draws the animated background, the top navigation with the kill switch, and the toasts.
