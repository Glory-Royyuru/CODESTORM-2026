import type { DataAtom, RegisteredTool, TaintLattice } from "./types";
import { shortId, stringLeaves } from "./util";

/* M4 — Provenance & data-flow firewall (atom-level taint tracking) */

const CONFIDENTIALITY: Record<TaintLattice, number> = {
  TRUSTED: 0,
  INTERNAL: 1,
  UNTRUSTED: 1,
  SENSITIVE: 2,
  SECRET: 3,
  TAINTED: 3,
};

const isUntrusted = (l: TaintLattice) => l === "UNTRUSTED" || l === "TAINTED";
const isPrivate = (l: TaintLattice) => l === "SENSITIVE" || l === "SECRET" || l === "TAINTED";

/**
 * Lattice join. Integrity (untrusted) and confidentiality (sensitive) are
 * tracked together: their combination collapses to TAINTED.
 */
export function join(a: TaintLattice, b: TaintLattice): TaintLattice {
  if (a === b) return a;
  if ((isUntrusted(a) && isPrivate(b)) || (isUntrusted(b) && isPrivate(a))) return "TAINTED";
  if (isUntrusted(a) || isUntrusted(b)) return CONFIDENTIALITY[a] >= CONFIDENTIALITY[b] && isUntrusted(a) ? a : isUntrusted(b) ? b : a;
  return CONFIDENTIALITY[a] >= CONFIDENTIALITY[b] ? a : b;
}

export const joinAll = (labels: TaintLattice[]) => labels.reduce<TaintLattice>((acc, l) => join(acc, l), "TRUSTED");

export function sourceLabel(tool: RegisteredTool): TaintLattice {
  if (tool.capability === "secrets:read") return "SECRET";
  if (tool.untrustedSource) return "UNTRUSTED";
  if (tool.sensitiveSource) return "SENSITIVE";
  return "INTERNAL";
}

const ATOM_EXTRACTORS: { kind: DataAtom["kind"]; re: RegExp; label?: TaintLattice }[] = [
  { kind: "secret", re: /\b(AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{30,}|eyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]{10,})\b/g, label: "SECRET" },
  { kind: "email", re: /\b[\w.+-]+@[\w-]+(\.[\w-]+)+\b/g },
  { kind: "url", re: /\bhttps?:\/\/[^\s"'<>)]+/g },
  { kind: "pii", re: /\b\d{3}-\d{2}-\d{4}\b|\b(?:\d[ -]?){13,16}\b/g, label: "SENSITIVE" },
  { kind: "id", re: /\b(ORD|ACCT|INV)-\d{4,}\b/g },
  {
    kind: "instruction",
    re: /[^.\n]*(ignore (all )?(previous|prior) instructions|you must now|as an ai assistant,? you|send (it|them|all|the)[^.\n]* to)[^.\n]*/gi,
    label: "UNTRUSTED",
  },
];

/** Split a tool response into labelled data atoms. */
export function extractAtoms(output: string, tool: RegisteredTool, nodeId: string, now: number): DataAtom[] {
  const base = sourceLabel(tool);
  const seen = new Set<string>();
  const atoms: DataAtom[] = [];
  for (const ex of ATOM_EXTRACTORS) {
    for (const m of output.matchAll(ex.re)) {
      const value = m[0].trim();
      if (value.length < 5 || seen.has(value.toLowerCase())) continue;
      seen.add(value.toLowerCase());
      atoms.push({
        id: shortId("atom"),
        value,
        kind: ex.kind,
        label: ex.label ? join(base, ex.label) : base,
        sourceNodeId: nodeId,
        sourceTool: tool.manifest.name,
        createdAt: now,
      });
    }
  }
  return atoms;
}

const norm = (s: string) => s.toLowerCase().replace(/[^a-z0-9@.]/g, "");

/** Dynamic atom matching: which known atoms appear inside the call arguments? */
export function matchAtoms(args: Record<string, unknown>, atoms: DataAtom[]) {
  const leaves = stringLeaves(args);
  const hits: { atom: DataAtom; path: string }[] = [];
  for (const atom of atoms) {
    const needle = norm(atom.value);
    if (needle.length < 5) continue;
    const leaf = leaves.find((l) => norm(l.value).includes(needle));
    if (leaf) hits.push({ atom, path: leaf.path });
  }
  return hits;
}

export const TAINT_ORDER: TaintLattice[] = ["TRUSTED", "INTERNAL", "UNTRUSTED", "SENSITIVE", "SECRET", "TAINTED"];
export { isPrivate, isUntrusted };
