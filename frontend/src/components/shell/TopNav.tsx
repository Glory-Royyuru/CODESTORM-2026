"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { AnimatePresence, motion } from "framer-motion";
import { Menu, Moon, Sun, X } from "lucide-react";
import { useState } from "react";
import { GitHubIcon, LogoIcon } from "@/components/hero/icons";
import { cx } from "@/components/ui/primitives";
import { useGateway, useUi } from "@/lib/store";
import BackendStatus from "./BackendStatus";
import KillSwitch from "./KillSwitch";

export const NAV = [
  { href: "/docs", label: "Docs" },
  { href: "/", label: "Live Gateway" },
  { href: "/provenance", label: "Provenance DAG" },
  { href: "/registry", label: "Tool Registry" },
  { href: "/audit", label: "Audit Ledger" },
  { href: "/eval-lab", label: "Eval Lab" },
  { href: "/policies", label: "Policies" },
  { href: "/approvals", label: "Approvals" },
];

export default function TopNav() {
  const pathname = usePathname();
  const gw = useGateway();
  const { theme, toggleTheme } = useUi();
  const [open, setOpen] = useState(false);
  const pending = gw.approvals.filter((a) => a.status === "PENDING").length;

  const isActive = (href: string) => (href === "/" ? pathname === "/" || pathname === "/gateway" : pathname.startsWith(href));

  return (
    <header className="sticky top-0 z-30 border-b border-transparent backdrop-blur-md [background:linear-gradient(to_bottom,color-mix(in_srgb,var(--bg)_85%,transparent),color-mix(in_srgb,var(--bg)_40%,transparent))]">
      <nav className="flex h-[76px] items-center justify-between gap-4 px-4 sm:px-8 xl:h-[88px] xl:px-[54px]">
        <div className="flex min-w-0 items-center gap-4 2xl:gap-6">
          <Link href="/" className="flex shrink-0 items-center gap-2 text-fg">
            <LogoIcon className="h-7 w-7" />
            <span className="text-[19px] font-medium tracking-[-0.02em]">
              SATG<span className="text-subtle"> · Gateway</span>
            </span>
          </Link>
          <span className="hidden text-[22px] font-light text-fg/40 xl:inline">/</span>
          <ul className="hidden items-center gap-1 xl:flex">
            {NAV.map((item) => (
              <li key={item.href}>
                <Link
                  href={item.href}
                  className={cx(
                    "relative rounded-lg px-2.5 py-2 text-[14.5px] font-semibold transition-colors 2xl:px-3.5",
                    isActive(item.href) ? "text-fg" : "text-fg/60 hover:text-fg",
                  )}
                >
                  {isActive(item.href) && (
                    <motion.span layoutId="nav-pill" className="absolute inset-0 -z-10 rounded-lg bg-surface-hover ring-1 ring-line" transition={{ type: "spring", damping: 30, stiffness: 380 }} />
                  )}
                  {item.label}
                  {item.href === "/approvals" && pending > 0 && (
                    <span className="ml-1.5 rounded-full bg-violet-500/20 px-1.5 py-px font-mono text-[10.5px] text-violet-300">{pending}</span>
                  )}
                </Link>
              </li>
            ))}
          </ul>
        </div>

        <div className="flex shrink-0 items-center gap-2.5">
          <BackendStatus />
          <KillSwitch />
          <button
            type="button"
            onClick={toggleTheme}
            aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
            className="hidden h-10 w-10 place-items-center rounded-xl border border-line bg-surface text-fg transition-colors hover:bg-surface-hover sm:grid"
          >
            {theme === "dark" ? <Sun className="h-[17px] w-[17px]" /> : <Moon className="h-[17px] w-[17px]" />}
          </button>
          <a
            href="https://github.com/Glory-Royyuru/CODESTORM-2026"
            target="_blank"
            rel="noreferrer"
            title="SATG source on GitHub"
            className="hidden h-10 items-center gap-2 rounded-xl border border-line bg-surface px-3.5 text-[14px] font-semibold text-fg transition-colors hover:bg-surface-hover md:flex"
          >
            <GitHubIcon className="h-[18px] w-[18px]" />
            GitHub
          </a>
          <button
            type="button"
            onClick={() => setOpen(true)}
            aria-label="Open navigation"
            className="grid h-10 w-10 place-items-center rounded-xl border border-line bg-surface text-fg xl:hidden"
          >
            <Menu className="h-[18px] w-[18px]" />
          </button>
        </div>
      </nav>

      <AnimatePresence>
        {open && (
          <motion.div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm xl:hidden" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={() => setOpen(false)}>
            <motion.div
              initial={{ y: -16, opacity: 0 }}
              animate={{ y: 0, opacity: 1 }}
              exit={{ y: -16, opacity: 0 }}
              onClick={(e) => e.stopPropagation()}
              className="m-3 rounded-2xl border border-line bg-panel-strong p-3 backdrop-blur-xl"
            >
              <div className="mb-2 flex items-center justify-between px-3 py-2">
                <span className="font-mono text-[12px] uppercase tracking-[0.14em] text-subtle">Navigate</span>
                <button type="button" onClick={() => setOpen(false)} aria-label="Close navigation" className="rounded-lg p-2 text-muted hover:bg-surface">
                  <X className="h-4 w-4" />
                </button>
              </div>
              {NAV.map((item) => (
                <Link
                  key={item.href}
                  href={item.href}
                  onClick={() => setOpen(false)}
                  className={cx("flex items-center justify-between rounded-xl px-4 py-3 text-[16px] font-semibold", isActive(item.href) ? "bg-surface-hover text-fg" : "text-fg/70")}
                >
                  {item.label}
                  {item.href === "/approvals" && pending > 0 && <span className="rounded-full bg-violet-500/20 px-2 font-mono text-[12px] text-violet-300">{pending}</span>}
                </Link>
              ))}
              <button type="button" onClick={toggleTheme} className="mt-2 flex w-full items-center gap-2 rounded-xl px-4 py-3 text-[15px] font-semibold text-fg/70 sm:hidden">
                {theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />} Toggle theme
              </button>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </header>
  );
}
