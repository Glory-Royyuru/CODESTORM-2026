"use client";

import { create } from "zustand";
import type { SatgOutcome } from "./client";

/**
 * Outcomes of the real backend calls made from this browser tab.
 * The backend's audit log is server-side and has no read API, so this is
 * the only history the console can show truthfully. Resets on reload.
 */
export interface SatgLogEntry {
  seq: number;
  at: number;
  presetTitle: string;
  outcome: SatgOutcome;
  /** The exact body passed to submitToolCall() for this outcome. In memory only. */
  requestBody: string;
  /** Which Live Gateway control sent it: the request studio (presets / manual call) or the agent console. */
  source: "studio" | "agent";
}

interface SatgLogState {
  entries: SatgLogEntry[];
  add: (presetTitle: string, outcome: SatgOutcome, requestBody: string, source: SatgLogEntry["source"]) => SatgLogEntry;
}

let seq = 0;

export const useSatgLog = create<SatgLogState>((set, get) => ({
  entries: [],
  add: (presetTitle, outcome, requestBody, source) => {
    const entry = { seq: ++seq, at: Date.now(), presetTitle, outcome, requestBody, source };
    set({ entries: [...get().entries.slice(-199), entry] });
    return entry;
  },
}));
