"use client";

import { AnimatePresence, motion } from "framer-motion";
import { AlertTriangle, CheckCircle2, Info, ShieldAlert, X } from "lucide-react";
import { useUi, type ToastTone } from "@/lib/store";

const TONE: Record<ToastTone, { icon: typeof Info; cls: string }> = {
  success: { icon: CheckCircle2, cls: "text-emerald-400" },
  danger: { icon: ShieldAlert, cls: "text-red-400" },
  warn: { icon: AlertTriangle, cls: "text-amber-400" },
  info: { icon: Info, cls: "text-sky-400" },
};

export default function Toasts() {
  const { toasts, dismiss } = useUi();
  return (
    <div aria-live="polite" className="pointer-events-none fixed bottom-4 right-4 z-[60] flex w-[min(400px,calc(100%-2rem))] flex-col gap-2">
      <AnimatePresence initial={false}>
        {toasts.map((t) => {
          const { icon: Icon, cls } = TONE[t.tone];
          return (
            <motion.div
              key={t.id}
              layout
              initial={{ opacity: 0, y: 16, scale: 0.97 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, x: 40 }}
              className="pointer-events-auto flex items-start gap-3 rounded-xl border border-line bg-panel-strong p-3.5 shadow-2xl backdrop-blur-xl"
            >
              <Icon className={`mt-0.5 h-4 w-4 shrink-0 ${cls}`} />
              <div className="min-w-0 flex-1">
                <p className="text-[13.5px] font-semibold text-fg">{t.title}</p>
                {t.detail && <p className="mt-0.5 break-words font-mono text-[11.5px] text-muted">{t.detail}</p>}
              </div>
              <button type="button" onClick={() => dismiss(t.id)} aria-label="Dismiss" className="text-subtle hover:text-fg">
                <X className="h-3.5 w-3.5" />
              </button>
            </motion.div>
          );
        })}
      </AnimatePresence>
    </div>
  );
}
