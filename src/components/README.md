# `src/components/` — all UI

| Folder | Kind | What it contains |
| --- | --- | --- |
| `shell/` | frame | `AppShell` (wraps every page), top navigation, kill switch, toasts |
| `hero/` | visual | The React Bits background (dot grid + orange ribbon) and the logo / GitHub icons |
| `ui/` | building blocks | Buttons, panels, badges, drawer, modal, JSON block, colour tokens |
| `gateway/` | screen `/` | Hero + Attack Studio + pipeline trace + live telemetry |
| `provenance/` | screen `/provenance` | Session list, lethal-trifecta monitor, DAG graph, node drawer |
| `registry/` | screen `/registry` | Tool cards, rug-pull simulation, register-tool drawer |
| `audit/` | screen `/audit` | Receipt ledger table and the receipt inspector modal |
| `eval/` | screen `/eval-lab` | Benchmark runner, gauges, payload mutator |
| `policies/` | screen `/policies` | YAML editor, Policy Time Machine, control plane |
| `approvals/` | screen `/approvals` | Two-person approval cards and capability grants |
| `docs/` | screen `/docs` | Static architecture overview |

## Conventions used everywhere

- Every file starts with `"use client"` — the whole UI runs in the browser because the engine does.
- **Reading data:** `const gw = useGateway();` then use `gw.ledger`, `gw.registry`, `gw.sessions`, `gw.approvals`, `gw.bundle`, `gw.mode`.
- **Changing data:** `getGateway().someAction(...)`, then usually `toast({...})` to tell the user what happened.
- **Styling:** Tailwind classes using the theme tokens (`text-fg`, `text-muted`, `text-subtle`, `border-line`, `bg-surface`, `text-accent`) so light mode works. Hashes, ids and code use `font-mono`.
- **Colours with meaning** come from `ui/tokens.ts`: verdict colours (ALLOW green → BLOCK red), taint colours, tool-status colours.
- **Animation:** Framer Motion for entrances (`initial` / `animate`), drawers/modals (`AnimatePresence`) and animated bars/paths.
