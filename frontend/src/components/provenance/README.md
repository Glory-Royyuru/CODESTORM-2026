# `provenance/` — Provenance DAG screen (`/provenance`)

One file: `ProvenanceView.tsx`. It explains *where data came from and where it went* inside one agent session.

## Layout

- **Left — session list.** Every session with at least one call, newest first: title, agent, age, worst verdict, and three dots for the trifecta flags (red = active). Scenario A is selected by default.
- **Top right — Lethal trifecta monitor.** Three cards: *Private data acquired*, *Untrusted content ingested*, *Outbound channel available*. When all three are on, the header turns red ("egress hard-vetoed"). Underneath: egress rows/bytes used vs. budget, the slow-drip EWMA and the CUSUM value.
- **Bottom right — the graph.** One column per step, three rows:
  - top: **external targets** (URLs, email recipients, Slack channels, IBANs),
  - middle: the **user prompt** and each **tool call** (with a verdict badge if it wasn't ALLOW),
  - bottom: **returned data** (retrieved document, private records, tool result).
- **Edges** are coloured by taint label (legend at the top right). A dashed edge means the flow was vetoed before it left.

## How the graph is built

The engine builds it while processing calls (`updateSession` in `lib/gateway/engine.ts`):

- prompt → tool call when no tracked data flowed into the arguments ("intent"),
- data node → tool call when atoms from that data were found in the arguments ("atoms") — this is the value-level atom matching,
- tool call → data node for its output ("result"),
- tool call → external node for egress / fetch targets ("egress", "request" or "vetoed").

This component only lays it out: `x = step × 240px`, `y` = the row for the node kind, and edges are SVG curves (straight vertical lines within a column). Nodes are absolutely positioned HTML buttons over the SVG, so they can use the glass styling.

## Node drawer

Clicking a node opens a drawer with its payload (arguments or output), its **data atoms** (value, kind, label, source tool) and its **taint history** (incoming/outgoing edges with labels), plus a link to the receipt.
