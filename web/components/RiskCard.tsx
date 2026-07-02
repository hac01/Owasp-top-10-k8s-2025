"use client";

import Link from "next/link";
import type { Risk } from "@/content/types";
import { difficultyMeta } from "@/content/company";
import { useProgress } from "@/lib/progress";

export function RiskCard({ risk, index }: { risk: Risk; index: number }) {
  const { solved, hydrated } = useProgress();
  const isSolved = hydrated && !!solved[risk.id];
  const diff = difficultyMeta[risk.challenge.difficulty];

  return (
    <Link
      href={`/k/${risk.slug}`}
      className={`card group flex flex-col gap-4 p-6 animate-fade-up ${
        isSolved ? "border-emerald-300 bg-emerald-50/30" : ""
      }`}
      style={{ animationDelay: `${index * 40}ms` }}
    >
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-3">
          <span className="grid h-11 w-11 place-items-center rounded-xl bg-brand-50 text-2xl">
            {risk.icon}
          </span>
          <span className="font-mono text-sm font-semibold text-brand-600">{risk.id}</span>
        </div>
        {isSolved ? (
          <span className="chip bg-emerald-100 text-emerald-700">🚩 Solved</span>
        ) : (
          <span className={`chip ${diff.className}`}>
            <span className={`h-1.5 w-1.5 rounded-full ${diff.dot}`} />
            {risk.challenge.difficulty}
          </span>
        )}
      </div>
      <div>
        <h3 className="text-lg font-semibold text-slate-900 group-hover:text-brand-700">
          {risk.title}
        </h3>
        <p className="mt-1.5 text-sm leading-relaxed text-slate-500">{risk.tagline}</p>
      </div>
      <div className="mt-auto flex items-center justify-between">
        <span className="inline-flex items-center gap-1 text-sm font-semibold text-brand-600">
          {isSolved ? "Review" : "Start challenge"}
          <span className="transition group-hover:translate-x-1">→</span>
        </span>
        <span className="text-xs font-medium text-slate-400">{risk.challenge.points} pts</span>
      </div>
    </Link>
  );
}
