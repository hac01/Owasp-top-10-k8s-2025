"use client";

import type { Risk } from "@/content/types";
import { useProgress } from "@/lib/progress";

function tally(risks: Risk[], solved: Record<string, boolean>) {
  const total = risks.length;
  const totalPoints = risks.reduce((s, r) => s + r.challenge.points, 0);
  const solvedRisks = risks.filter((r) => solved[r.id]);
  const points = solvedRisks.reduce((s, r) => s + r.challenge.points, 0);
  return { total, totalPoints, solvedCount: solvedRisks.length, points };
}

export function Scoreboard({ risks }: { risks: Risk[] }) {
  const { solved, hydrated, reset } = useProgress();
  const { total, totalPoints, solvedCount, points } = tally(risks, solved);
  const pct = totalPoints ? Math.round((points / totalPoints) * 100) : 0;

  return (
    <div className="card overflow-hidden p-0">
      <div className="flex flex-wrap items-center justify-between gap-4 bg-gradient-to-br from-brand-600 to-brand-800 px-6 py-5 text-white">
        <div>
          <h2 className="text-lg font-bold">Your progress</h2>
          <p className="text-sm text-brand-100">NimbusMart engagement scoreboard</p>
        </div>
        <div className="flex items-center gap-6">
          <div className="text-right">
            <div className="text-2xl font-extrabold">
              {hydrated ? solvedCount : 0}
              <span className="text-brand-200">/{total}</span>
            </div>
            <div className="text-xs text-brand-200">flags</div>
          </div>
          <div className="text-right">
            <div className="text-2xl font-extrabold">
              {hydrated ? points : 0}
              <span className="text-brand-200">/{totalPoints}</span>
            </div>
            <div className="text-xs text-brand-200">points</div>
          </div>
        </div>
      </div>
      <div className="px-6 py-4">
        <div className="h-2.5 w-full overflow-hidden rounded-full bg-slate-100">
          <div
            className="h-full rounded-full bg-gradient-to-r from-brand-400 to-brand-600 transition-all duration-700"
            style={{ width: `${hydrated ? pct : 0}%` }}
          />
        </div>
        <div className="mt-3 flex items-center justify-between text-sm">
          <span className="text-slate-500">
            {hydrated && solvedCount === total
              ? "🏆 Full clear - NimbusMart is hardened. Nice work."
              : `${hydrated ? pct : 0}% of the engagement complete`}
          </span>
          {hydrated && solvedCount > 0 && (
            <button
              onClick={() => {
                if (confirm("Reset all captured flags?")) reset();
              }}
              className="text-xs text-slate-400 hover:text-red-500"
            >
              Reset progress
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

export function ScorePill({ risks }: { risks: Risk[] }) {
  const { solved, hydrated } = useProgress();
  const { total, solvedCount } = tally(risks, solved);
  return (
    <span className="chip bg-brand-50 text-brand-700 ring-1 ring-brand-200">
      🚩 {hydrated ? solvedCount : 0}/{total}
    </span>
  );
}
