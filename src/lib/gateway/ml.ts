import type { DataAtom, FeatureContribution, MlScores, RegisteredTool, SessionState, ToolCallEnvelope, Verdict } from "./types";
import { clamp, mulberry32, shannonEntropy, sigmoid, stringLeaves } from "./util";

/* M6 — Behavioral ML intelligence (lightweight in-process models)
 *
 * These are small, real models rather than canned numbers:
 *  - p_injection: logistic model over injection lexicon + provenance features
 *  - p_misaligned: hashed char-trigram embeddings, cosine(goal, call)
 *  - isolation_forest_anomaly: a genuine isolation forest trained on benign call features
 *  - trigram_surprise: tool-sequence trigram model with add-k smoothing
 *  - cusum_shift: one-sided CUSUM over per-call risk within the session
 */

/* ---------- sentence embedding stand-in (hashed trigrams) ---------- */

const DIM = 256;
function embed(text: string): Float32Array {
  const v = new Float32Array(DIM);
  const words = text.toLowerCase().replace(/[^a-z0-9@. ]/g, " ").split(/\s+/).filter((w) => w.length > 2);
  for (const w of words) {
    const padded = `^${w}$`;
    for (let i = 0; i < padded.length - 2; i++) {
      let h = 2166136261;
      for (let j = i; j < i + 3; j++) h = Math.imul(h ^ padded.charCodeAt(j), 16777619);
      v[(h >>> 0) % DIM] += 1;
    }
  }
  let n = 0;
  for (const x of v) n += x * x;
  n = Math.sqrt(n) || 1;
  for (let i = 0; i < DIM; i++) v[i] /= n;
  return v;
}
const cosine = (a: Float32Array, b: Float32Array) => a.reduce((s, x, i) => s + x * b[i], 0);

/* ---------- isolation forest ---------- */

type ITree = { f: number; t: number; l: ITree; r: ITree } | { size: number };
const cFactor = (n: number) => (n <= 1 ? 0 : 2 * (Math.log(n - 1) + 0.5772156649) - (2 * (n - 1)) / n);

function buildTree(data: number[][], depth: number, maxDepth: number, rnd: () => number): ITree {
  if (depth >= maxDepth || data.length <= 1) return { size: data.length };
  const f = Math.floor(rnd() * data[0].length);
  let lo = Infinity;
  let hi = -Infinity;
  for (const row of data) {
    lo = Math.min(lo, row[f]);
    hi = Math.max(hi, row[f]);
  }
  if (lo === hi) return { size: data.length };
  const t = lo + rnd() * (hi - lo);
  return {
    f,
    t,
    l: buildTree(data.filter((r) => r[f] < t), depth + 1, maxDepth, rnd),
    r: buildTree(data.filter((r) => r[f] >= t), depth + 1, maxDepth, rnd),
  };
}

function pathLength(x: number[], node: ITree, depth = 0): number {
  if ("size" in node) return depth + cFactor(node.size);
  return pathLength(x, x[node.f] < node.t ? node.l : node.r, depth + 1);
}

export class IsolationForest {
  private trees: ITree[] = [];
  private sample = 128;
  constructor(data: number[][], nTrees = 60, seed = 7) {
    const rnd = mulberry32(seed);
    const maxDepth = Math.ceil(Math.log2(this.sample));
    for (let i = 0; i < nTrees; i++) {
      const s = Array.from({ length: this.sample }, () => data[Math.floor(rnd() * data.length)]);
      this.trees.push(buildTree(s, 0, maxDepth, rnd));
    }
  }
  score(x: number[]) {
    const avg = this.trees.reduce((a, t) => a + pathLength(x, t), 0) / this.trees.length;
    return Math.pow(2, -avg / cFactor(this.sample));
  }
}

function callFeatures(env: ToolCallEnvelope, tool: RegisteredTool): number[] {
  const leaves = stringLeaves(env.arguments);
  const all = leaves.map((l) => l.value).join(" ");
  const nonAlnum = all.length ? (all.match(/[^a-zA-Z0-9 @.,:/_-]/g)?.length ?? 0) / all.length : 0;
  const maxEntropy = Math.max(0, ...leaves.map((l) => shannonEntropy(l.value)));
  return [Math.log1p(all.length), maxEntropy, leaves.length, nonAlnum * 10, tool.tier];
}

function benignTrainingSet(): number[][] {
  const rnd = mulberry32(42);
  const g = (m: number, s: number) => m + (rnd() + rnd() + rnd() - 1.5) * s;
  return Array.from({ length: 800 }, () => [g(3.4, 1.8), g(3.5, 1.1), Math.round(clamp(g(2, 1.6), 1, 4)), clamp(g(0.4, 0.6), 0, 10), 1 + Math.floor(rnd() * 4)]);
}

/* ---------- trigram tool-sequence model ---------- */

const BENIGN_SEQUENCES = [
  ["get_order", "execute_sql", "send_email"],
  ["calendar_read", "slack_post"],
  ["fetch_webpage", "file_system"],
  ["get_order", "get_order", "send_email"],
  ["execute_sql", "execute_sql", "slack_post"],
  ["weather_lookup", "calendar_read", "slack_post"],
  ["file_system", "execute_sql"],
  ["fetch_webpage", "fetch_webpage"],
  ["calendar_read", "send_email"],
  ["execute_sql", "send_email"],
  ["file_system", "file_system", "slack_post"],
  ["get_order", "slack_post"],
];

class TrigramModel {
  private counts = new Map<string, Map<string, number>>();
  private vocab = new Set<string>(["<s>"]);
  constructor(seqs: string[][]) {
    for (const s of seqs) {
      const toks = ["<s>", "<s>", ...s];
      toks.forEach((t) => this.vocab.add(t));
      for (let i = 2; i < toks.length; i++) {
        const ctx = `${toks[i - 2]}|${toks[i - 1]}`;
        const m = this.counts.get(ctx) ?? new Map();
        m.set(toks[i], (m.get(toks[i]) ?? 0) + 1);
        this.counts.set(ctx, m);
      }
    }
  }
  surprise(history: string[], next: string) {
    const h = ["<s>", "<s>", ...history].slice(-2);
    const m = this.counts.get(h.join("|"));
    const k = 0.5;
    const V = this.vocab.size + 12;
    const total = m ? [...m.values()].reduce((a, b) => a + b, 0) : 0;
    const prob = ((m?.get(next) ?? 0) + k) / (total + k * V);
    return -Math.log2(prob); // bits
  }
}

/* ---------- scoring ---------- */

const INJECTION_LEXICON = [
  /ignore (all )?(previous|prior) instructions/i,
  /you must now/i,
  /system prompt/i,
  /do not (tell|mention|inform)/i,
  /(exfiltrat|forward everything|send (all|everything))/i,
  /<\/?(important|system)>/i,
];

export const ML_WEIGHTS: Record<keyof MlScores, number> = {
  p_injection: 4.4,
  p_misaligned: 1.6,
  isolation_forest_anomaly: 1.5,
  trigram_surprise: 1.1,
  cusum_shift: 1.8,
};
const ML_BIAS = -4.1;
export const ML_BASELINE: MlScores = {
  p_injection: 0.05,
  p_misaligned: 0.3,
  isolation_forest_anomaly: 0.35,
  trigram_surprise: 0.35,
  cusum_shift: 0.05,
};
/** Split-conformal band where the prediction set is {benign, attack}. */
export const CONFORMAL_BAND: [number, number] = [0.46, 0.56];

export class MlPipeline {
  private forest = new IsolationForest(benignTrainingSet());
  private trigram = new TrigramModel(BENIGN_SEQUENCES);

  score(env: ToolCallEnvelope, tool: RegisteredTool, session: SessionState, matched: { atom: DataAtom }[]) {
    const argText = stringLeaves(env.arguments).map((l) => l.value).join(" ");

    // p_injection
    const lexHits = INJECTION_LEXICON.filter((re) => re.test(argText)).length;
    const untrustedIn = matched.filter((m) => m.atom.label === "UNTRUSTED" || m.atom.label === "TAINTED").length;
    const instructionAtoms = session.atoms.filter((a) => a.kind === "instruction").length;
    const blob = /[A-Za-z0-9+/=]{40,}|(%[0-9a-f]{2}){6,}/i.test(argText) ? 1 : 0;
    const p_injection = sigmoid(-3.2 + 2.4 * lexHits + 1.6 * Math.min(untrustedIn, 2) + (instructionAtoms ? (tool.egress || tool.sensitiveSource || tool.tier >= 3 ? 2.0 : 0.5) : 0) + 1.2 * blob);

    // p_misaligned — intent drift between the user's goal and the concrete call
    const callText = `${env.tool.replace(/_/g, " ")} ${argText}`;
    const sim = cosine(embed(session.goal), embed(callText));
    const p_misaligned = clamp(sigmoid((0.2 - sim) * 12));

    // isolation forest
    const raw = this.forest.score(callFeatures(env, tool));
    const isolation_forest_anomaly = clamp((raw - 0.45) / 0.25);

    // trigram surprise (normalized bits)
    const trigram_surprise = clamp(this.trigram.surprise(session.toolHistory, env.tool) / 9);

    // CUSUM over per-call evidence
    const x = 0.5 * p_injection + 0.3 * isolation_forest_anomaly + 0.2 * p_misaligned;
    const nextCusum = Math.max(0, session.cusum + x - 0.28);
    const cusum_shift = clamp(nextCusum / 1.2);

    const scores: MlScores = { p_injection, p_misaligned, isolation_forest_anomaly, trigram_surprise, cusum_shift };
    return { scores, nextCusum, ...fuse(scores) };
  }
}

export function fuse(scores: MlScores) {
  const keys = Object.keys(ML_WEIGHTS) as (keyof MlScores)[];
  const logit = keys.reduce((a, k) => a + ML_WEIGHTS[k] * scores[k], ML_BIAS);
  const riskScore = sigmoid(logit);
  const contributions: FeatureContribution[] = keys
    .map((k) => ({ feature: k, value: scores[k], contribution: ML_WEIGHTS[k] * (scores[k] - ML_BASELINE[k]) }))
    .sort((a, b) => Math.abs(b.contribution) - Math.abs(a.contribution));
  const abstained = riskScore >= CONFORMAL_BAND[0] && riskScore <= CONFORMAL_BAND[1];
  let mlVerdict: Verdict = "ALLOW";
  if (riskScore >= 0.9) mlVerdict = "BLOCK";
  else if (riskScore >= 0.75) mlVerdict = "HUMAN_APPROVAL";
  else if (riskScore >= 0.56) mlVerdict = "STEP_UP";
  else if (riskScore >= 0.25) mlVerdict = "MONITOR";
  if (abstained) mlVerdict = "STEP_UP";
  return { riskScore, contributions, mlVerdict, abstained };
}
