import { Gateway } from "./engine";
import { toWire } from "./ingress";
import type { Scenario, ScenarioStep } from "./scenarios";
import type { Capability, LedgerEntry, PipelineResult, PolicyBundle, Principal, Protocol, SessionState, Verdict } from "./types";
import { severity } from "./util";

export interface Script {
  principal: Principal;
  goal: string;
  scopes: Capability[];
  protocol: Protocol;
  title?: string;
  scenario?: string;
  steps: ScenarioStep[];
}

/** Run a multi-step agent script through the gateway, one call per step. */
export function runScript(
  gw: Gateway,
  script: Script,
  opts: { now?: number; gapMs?: number; finalRaw?: string } = {},
): { session: SessionState; results: PipelineResult[] } {
  let now = opts.now ?? Date.now();
  const session = gw.createSession(script.principal, script.goal, script.scopes, { title: script.title, scenario: script.scenario, now });
  const results: PipelineResult[] = [];
  script.steps.forEach((step, i) => {
    const last = i === script.steps.length - 1;
    const raw = last && opts.finalRaw ? opts.finalRaw : toWire(step.protocol ?? script.protocol, step.tool, step.args);
    results.push(
      gw.process({ raw, sessionId: session.id, scriptedOutput: step.output, rugPull: step.rugPull, groundTruth: step.groundTruth, scenario: script.scenario, now }),
    );
    now += opts.gapMs ?? 1400;
  });
  return { session, results };
}

export const scenarioScript = (s: Scenario): Script => ({
  principal: s.principal,
  goal: s.goal,
  scopes: s.scopes,
  protocol: s.protocol,
  title: s.short,
  scenario: s.id,
  steps: s.steps,
});

export const isEscalated = (v: Verdict) => severity(v) >= severity("STEP_UP");

/* ------------------------------------------------------------------ */
/* Policy Time Machine — replay recorded sessions under a new bundle   */
/* ------------------------------------------------------------------ */

export interface ReplayDiff {
  receiptId: string;
  tool: string;
  groundTruth: "attack" | "benign";
  before: Verdict;
  after: Verdict;
}

export interface ReplayReport {
  calls: number;
  attacks: number;
  benign: number;
  preventedBefore: number;
  preventedAfter: number;
  falsePositivesBefore: number;
  falsePositivesAfter: number;
  diffs: ReplayDiff[];
}

function replayUnder(bundle: PolicyBundle, source: Gateway, groups: LedgerEntry[][]): Map<string, Verdict> {
  const gw = new Gateway({ ephemeral: true, bundle, key: source.key });
  const out = new Map<string, Verdict>();
  for (const group of groups) {
    const first = group[0];
    const original = source.sessions.get(first.envelope.sessionId);
    const session = gw.createSession(first.envelope.principal, first.envelope.userGoal, original?.token.scopes ?? [], { now: Date.parse(first.receipt.body.timestamp) });
    for (const e of group) {
      const res = gw.process({
        raw: e.envelope.rawPayload,
        sessionId: session.id,
        advertisedManifest: e.envelope.advertisedManifest,
        scriptedOutput: e.sandbox?.output || undefined,
        groundTruth: e.groundTruth,
        now: Date.parse(e.receipt.body.timestamp),
      });
      out.set(e.receipt.body.receiptId, res.entry.receipt.body.verdict);
    }
  }
  return out;
}

export function timeMachine(source: Gateway, candidate: PolicyBundle): ReplayReport {
  const history = source.ledger.filter((e) => e.scenario !== "approved-replay" && !e.envelope.grantId);
  const bySession = new Map<string, LedgerEntry[]>();
  for (const e of history) bySession.set(e.envelope.sessionId, [...(bySession.get(e.envelope.sessionId) ?? []), e]);
  const groups = [...bySession.values()];
  const before = replayUnder(source.bundle, source, groups);
  const after = replayUnder(candidate, source, groups);

  const r: ReplayReport = { calls: history.length, attacks: 0, benign: 0, preventedBefore: 0, preventedAfter: 0, falsePositivesBefore: 0, falsePositivesAfter: 0, diffs: [] };
  for (const e of history) {
    const id = e.receipt.body.receiptId;
    const b = before.get(id)!;
    const a = after.get(id)!;
    if (e.groundTruth === "attack") {
      r.attacks++;
      if (isEscalated(b)) r.preventedBefore++;
      if (isEscalated(a)) r.preventedAfter++;
    } else {
      r.benign++;
      if (isEscalated(b)) r.falsePositivesBefore++;
      if (isEscalated(a)) r.falsePositivesAfter++;
    }
    if (a !== b) r.diffs.push({ receiptId: id, tool: e.envelope.tool, groundTruth: e.groundTruth, before: b, after: a });
  }
  return r;
}
