# `ui/` — shared building blocks

Small, reusable pieces used by every screen, so all pages look consistent.

## `primitives.tsx`

| Export | Use it for |
| --- | --- |
| `Panel` | The glass card (`.panel` class). Wrap any section in it. |
| `PageHeader` | The top of each screen: orange mono eyebrow, big title, description, optional action buttons on the right. |
| `SectionTitle` | Small uppercase heading inside a panel, with an optional right-side slot. |
| `Button` | `variant="primary"` (orange), `"secondary"` (outlined), `"danger"` (red), `"ghost"` (text only). |
| `VerdictBadge` | Coloured pill for `ALLOW` … `BLOCK`. `size="lg"` for the big one. |
| `TaintBadge` | Coloured label for `TRUSTED` … `TAINTED`. |
| `StatusBadge` | Tool status: `VERIFIED` / `POISONED` / `QUARANTINED`. |
| `Stat` | A number tile (label, big value, hint). |
| `Hash` | Shortens a long hash to `abcd123456…ef01` (full value on hover). |
| `CopyButton` | Copies text to the clipboard with a "Copied" confirmation. |
| `JsonBlock` | Pretty-printed JSON in a dark mono box. |
| `Drawer` | Panel that slides in from the right (closes on Escape or backdrop click). Used for provenance nodes and tool registration. |
| `Modal` | Centered dialog (closes on Escape or backdrop click). Used for the receipt inspector. |
| `cx(...)` | Joins class names, skipping falsy values. |
| `timeAgo(ms)` | "12s ago", "5m ago", "2h ago". |

## `tokens.ts`

The meaning-carrying colours, in one place:

- `VERDICT_STYLE` — ALLOW green, MONITOR sky, STEP_UP amber, HUMAN_APPROVAL violet, QUARANTINE fuchsia, BLOCK red.
- `TAINT_HEX` — TRUSTED green, INTERNAL blue, UNTRUSTED pink, SENSITIVE amber, SECRET violet, TAINTED red (also used for the provenance graph edges).
- `STATUS_STYLE` — tool statuses.
- `TIER_LABEL` — "Tier 1 · Read-only" … "Tier 4 · Destructive".

Change a colour here and it updates across the whole app.
