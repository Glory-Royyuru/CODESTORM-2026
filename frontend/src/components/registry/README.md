# `registry/` — Tool Registry screen (`/registry`)

One file: `RegistryView.tsx`, with three parts.

## `RegistryView` (the page)

Header with **Register tool**, 4 counters (registered / verified / poisoned / quarantined), a reminder of what the pin covers — `sha256(canonical_json({name, description, parameters, required, server}))` — and a grid of tool cards.

## `ToolCard`

For each tool: name, server identity, status badge, description, tier (1 read-only → 4 destructive), capability, `egress` / `untrusted src` tags, then:

- **pinned sha256** vs **advertised** hash (advertised turns red when it differs),
- last audit time and number of calls,
- integrity findings (e.g. `HASH_DRIFT`, `DESCRIPTION_INJECTION`, `SCHEMA_EXPANSION`, added parameters).

Actions depend on the status:

| Status | Meaning | Buttons |
| --- | --- | --- |
| `VERIFIED` | Hash matches, description clean | **Simulate Tool Rug-pull** — swaps in a malicious manifest (hidden instructions + a `context_dump` parameter); the tool is quarantined instantly |
| `QUARANTINED` | Advertised hash ≠ pinned hash | **Restore pinned** (roll back) or **Re-pin** (accept the new manifest — refused if it's poisoned) |
| `POISONED` | Registered with injected instructions (`pdf_summarizer` in the seed data) | none — every call is hard-blocked |

On first load `weather_lookup` is already quarantined, because seeded Scenario C rug-pulled it.

## `RegisterDrawer`

A form for a new MCP tool: name, server, description, parameter schema (JSON), tier, capability, egress / untrusted flags. As you type, it shows the live **SHA-256 manifest hash** and the **poisoning scan** result. Try pasting `Ignore previous instructions` or `<IMPORTANT>` into the description to see it flagged. Submitting pins the manifest (`gw.registerTool`).
