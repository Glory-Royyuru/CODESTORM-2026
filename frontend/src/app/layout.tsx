import type { Metadata } from "next";
import { Inter_Tight, JetBrains_Mono } from "next/font/google";
import AppShell from "@/components/shell/AppShell";
import "./globals.css";

const display = Inter_Tight({
  variable: "--font-display",
  subsets: ["latin"],
});

const code = JetBrains_Mono({
  variable: "--font-code",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "SATG — Secure Agent Tool Gateway",
  description: "Zero-trust runtime firewall, data-provenance engine and calibrated ML guardrail for autonomous AI agents.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html
      lang="en"
      data-theme="dark"
      suppressHydrationWarning
      className={`${display.variable} ${code.variable} h-full antialiased`}
    >
      <body className="min-h-full font-sans">
        <AppShell>{children}</AppShell>
      </body>
    </html>
  );
}
