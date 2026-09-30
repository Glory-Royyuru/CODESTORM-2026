# `docs/` — Docs screen (`/docs`)

One file: `DocsView.tsx`. It's static content (no engine data), in four sections:

1. **Modules** — a card for each of the 11 modules (M1 Ingress … M11 Control Plane), with a summary and the source file that implements it.
2. **Stage contracts** — table of the 9 pipeline phases: what goes in and which guardrail applies.
3. **Acceptance criteria you can check here** — each criterion from the SATG specification (duplicate keys rejected, kill switch < 2 ms, rug-pull freezes the tool, order 999 denied, tampered receipt fails, SSRF blocked, single-use grant, ML can't lower a veto) and where in the app to see it.
4. **What is real and what is simulated.**

To change the text, edit the `MODULES`, `PHASES` and `ACCEPTANCE` arrays at the top of the file.
