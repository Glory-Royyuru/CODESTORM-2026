"use client";

import { useSyncExternalStore } from "react";
import { create } from "zustand";
import type { Gateway } from "./gateway/engine";
import { seedGateway } from "./gateway/seed";

/* ---------- Gateway engine singleton (client only) ---------- */

let instance: Gateway | null = null;

export function getGateway(): Gateway {
  if (!instance) instance = seedGateway();
  return instance;
}

/** Subscribe a component to engine mutations; re-renders on every emit(). */
export function useGateway(): Gateway {
  const gw = getGateway();
  useSyncExternalStore(gw.subscribe, gw.getVersion, gw.getVersion);
  return gw;
}

/** Subscribe to the append-only anomaly ledger (its own pub/sub, independent of engine emits). */
export function useAnomalyLedger() {
  const ledger = getGateway().anomalies;
  useSyncExternalStore(ledger.subscribe, ledger.getVersion, ledger.getVersion);
  return ledger.records();
}

const noopSubscribe = () => () => {};
/** true only after hydration — the engine is seeded with live timestamps, so it never renders on the server. */
export const useIsClient = () => useSyncExternalStore(noopSubscribe, () => true, () => false);

/* ---------- UI store ---------- */

export type ToastTone = "success" | "danger" | "warn" | "info";
export interface Toast {
  id: number;
  tone: ToastTone;
  title: string;
  detail?: string;
}

interface UiState {
  theme: "dark" | "light";
  toasts: Toast[];
  toggleTheme: () => void;
  toast: (t: Omit<Toast, "id">) => void;
  dismiss: (id: number) => void;
}

let toastSeq = 0;

export const useUi = create<UiState>((set, get) => ({
  theme: "dark",
  toasts: [],
  toggleTheme: () => set({ theme: get().theme === "dark" ? "light" : "dark" }),
  toast: (t) => {
    const id = ++toastSeq;
    set({ toasts: [...get().toasts.slice(-3), { ...t, id }] });
    setTimeout(() => get().dismiss(id), 5200);
  },
  dismiss: (id) => set({ toasts: get().toasts.filter((t) => t.id !== id) }),
}));
