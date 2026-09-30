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
}

interface SatgLogState {
  entries: SatgLogEntry[];
  add: (presetTitle: string, outcome: SatgOutcome) => SatgLogEntry;
}

let seq = 0;

export const useSatgLog = create<SatgLogState>((set, get) => ({
  entries: [],
  add: (presetTitle, outcome) => {
    const entry = { seq: ++seq, at: Date.now(), presetTitle, outcome };
    set({ entries: [...get().entries.slice(-199), entry] });
    return entry;
  },
}));
