import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import Link from "next/link";
import "./globals.css";
import { ProgressProvider } from "@/lib/progress";
import { ScorePill } from "@/components/Scoreboard";
import { TerminalDrawer } from "@/components/TerminalDrawer";
import { risks } from "@/content/risks";

const inter = Inter({ subsets: ["latin"], variable: "--font-sans", display: "swap" });
const mono = JetBrains_Mono({ subsets: ["latin"], variable: "--font-mono", display: "swap" });

export const metadata: Metadata = {
  title: "OWASP Kubernetes Top 10 - Learn, Exploit, Defend",
  description:
    "An interactive playground for the OWASP Kubernetes Top 10: detailed overviews, hands-on labs on a real cluster, defense guides, and an automated checker.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${inter.variable} ${mono.variable}`}>
      <body>
        <ProgressProvider>
          <header className="sticky top-0 z-40 border-b border-slate-200/70 bg-white/80 backdrop-blur-md">
            <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
              <Link href="/" className="flex items-center gap-2.5 font-bold tracking-tight">
                <span className="grid h-9 w-9 place-items-center rounded-xl bg-gradient-to-br from-brand-500 to-brand-700 text-white shadow-glow">
                  ⎈
                </span>
                <span className="flex flex-col leading-none">
                  <span className="text-base font-bold text-slate-900 sm:text-lg">
                    OWASP <span className="text-brand-600">K8s</span> Top 10
                  </span>
                  <span className="mt-0.5 text-[11px] font-medium uppercase tracking-wider text-slate-400">
                    NimbusMart CTF · 2025
                  </span>
                </span>
              </Link>
              <nav className="flex items-center gap-4 text-sm font-medium text-slate-600 sm:gap-6">
                <Link href="/#how-it-works" className="hidden hover:text-brand-700 transition sm:inline">
                  How it works
                </Link>
                <Link href="/#challenges" className="hidden hover:text-brand-700 transition sm:inline">
                  Challenges
                </Link>
                <a
                  href="https://owasp.org/www-project-kubernetes-top-ten/"
                  target="_blank"
                  rel="noreferrer"
                  className="hidden hover:text-brand-700 transition sm:inline"
                >
                  OWASP ↗
                </a>
                <ScorePill risks={risks} />
                <Link href="/#getting-started" className="btn-primary !px-4 !py-2">
                  Get started
                </Link>
              </nav>
            </div>
          </header>
          <main className="mx-auto max-w-6xl px-6">{children}</main>
          <TerminalDrawer />
        </ProgressProvider>
        <footer className="mt-24 border-t border-slate-200/70 py-10 text-center text-sm text-slate-500">
          <p>
            Built for learning. Run the labs only on throwaway clusters (
            <code className="rounded bg-brand-50 px-1.5 py-0.5 text-brand-700">kind</code> /{" "}
            <code className="rounded bg-brand-50 px-1.5 py-0.5 text-brand-700">minikube</code>).
          </p>
          <p className="mt-1">
            Based on the{" "}
            <a
              className="text-brand-600 hover:underline"
              href="https://owasp.org/www-project-kubernetes-top-ten/"
              target="_blank"
              rel="noreferrer"
            >
              OWASP Kubernetes Top 10 (2025)
            </a>
            .
          </p>
          <p className="mt-2">
            Built by{" "}
            <a
              className="font-semibold text-brand-600 hover:underline"
              href="https://github.com/hac01"
              target="_blank"
              rel="noreferrer"
            >
              @hac01
            </a>
            .
          </p>
        </footer>
      </body>
    </html>
  );
}
