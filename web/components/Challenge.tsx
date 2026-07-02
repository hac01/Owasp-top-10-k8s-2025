"use client";

import { useState } from "react";
import type { Risk } from "@/content/types";
import { difficultyMeta } from "@/content/company";
import { useProgress, sha256Hex } from "@/lib/progress";
import { InlineText } from "@/lib/text";
import { GuidedLab } from "./GuidedLab";

export function DifficultyBadge({ risk }: { risk: Risk }) {
  const meta = difficultyMeta[risk.challenge.difficulty];
  return (
    <span className={`chip ${meta.className}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${meta.dot}`} />
      {risk.challenge.difficulty} · {risk.challenge.points} pts
    </span>
  );
}

function Hints({ hints }: { hints: string[] }) {
  const [revealed, setRevealed] = useState(0);
  return (
    <div className="card p-5">
      <div className="mb-3 flex items-center justify-between">
        <h3 className="text-lg font-bold text-slate-900">💡 Hints</h3>
        <span className="text-xs text-slate-400">
          {revealed}/{hints.length} revealed
        </span>
      </div>
      <ol className="space-y-2">
        {hints.slice(0, revealed).map((h, i) => (
          <li key={i} className="flex gap-2.5 text-sm text-slate-600 animate-fade-up">
            <span className="font-mono text-brand-500">{i + 1}.</span>
            <span>
              <InlineText>{h}</InlineText>
            </span>
          </li>
        ))}
      </ol>
      {revealed < hints.length ? (
        <button
          onClick={() => setRevealed((r) => r + 1)}
          className="btn-ghost mt-3 !py-2 text-xs"
        >
          Reveal hint {revealed + 1} ↓
        </button>
      ) : (
        <p className="mt-3 text-xs text-slate-400">All hints revealed.</p>
      )}
    </div>
  );
}

function FlagBox({ risk }: { risk: Risk }) {
  const { solved, solve, hydrated } = useProgress();
  const isSolved = hydrated && !!solved[risk.id];
  const [value, setValue] = useState("");
  const [status, setStatus] = useState<"idle" | "wrong" | "checking">("idle");

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const guess = value.trim();
    if (!guess) return;
    setStatus("checking");
    const hash = await sha256Hex(guess);
    if (hash === risk.challenge.flagHash) {
      solve(risk.id);
      setStatus("idle");
      setValue("");
    } else {
      setStatus("wrong");
    }
  };

  if (isSolved) {
    return (
      <div className="rounded-2xl border border-emerald-300 bg-emerald-50 p-6 text-center">
        <div className="text-3xl">🚩</div>
        <p className="mt-2 text-lg font-bold text-emerald-800">Flag captured!</p>
        <p className="text-sm text-emerald-700">
          {risk.challenge.points} points banked for {risk.id}.
        </p>
      </div>
    );
  }

  return (
    <form onSubmit={submit} className="rounded-2xl border border-brand-200 bg-brand-50/50 p-6">
      <div className="flex items-center gap-2">
        <span className="text-xl">🚩</span>
        <h3 className="text-lg font-bold text-slate-900">Submit the flag</h3>
      </div>
      <p className="mt-1 text-sm text-slate-500">
        Capture it from the cluster, then paste it here. Format:{" "}
        <code className="rounded bg-white px-1.5 py-0.5 font-mono text-xs text-brand-700">
          {risk.challenge.flagFormat}
        </code>
      </p>
      <div className="mt-4 flex flex-col gap-2 sm:flex-row">
        <input
          value={value}
          onChange={(e) => {
            setValue(e.target.value);
            setStatus("idle");
          }}
          placeholder="FLAG{...}"
          spellCheck={false}
          className={`flex-1 rounded-xl border bg-white px-4 py-2.5 font-mono text-sm outline-none transition focus:ring-2 ${
            status === "wrong"
              ? "border-red-300 focus:ring-red-300"
              : "border-slate-200 focus:border-brand-400 focus:ring-brand-300"
          }`}
        />
        <button type="submit" className="btn-primary" disabled={status === "checking"}>
          {status === "checking" ? "Checking…" : "Capture 🚩"}
        </button>
      </div>
      {status === "wrong" && (
        <p className="mt-2 text-sm text-red-600">
          Not quite - that flag doesn&apos;t match. Re-check your exploit output.
        </p>
      )}
    </form>
  );
}

function Spoiler({ risk }: { risk: Risk }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="rounded-2xl border border-slate-200 bg-white">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center justify-between px-5 py-4 text-left"
      >
        <span className="flex items-center gap-2 font-semibold text-slate-900">
          <span>{open ? "🔓" : "🙈"}</span>
          Full walkthrough (spoiler)
        </span>
        <span className="text-sm text-brand-600">{open ? "Hide ↑" : "Reveal ↓"}</span>
      </button>
      {open && (
        <div className="border-t border-slate-100 px-5 py-5 animate-fade-up">
          <p className="mb-4 text-sm text-slate-500">
            Stuck? Here is the complete solution, step by step. Try the hints first.
          </p>
          <GuidedLab steps={risk.lab.steps} />
        </div>
      )}
    </div>
  );
}

export function Challenge({ risk }: { risk: Risk }) {
  return (
    <div className="grid gap-8 lg:grid-cols-3">
      <div className="space-y-6 lg:col-span-2">
        <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6 text-slate-100">
          <div className="mb-3 flex items-center gap-3">
            <span className="text-xl">🎯</span>
            <span className="font-mono text-xs uppercase tracking-widest text-brand-300">
              Mission briefing
            </span>
          </div>
          <p className="leading-relaxed text-slate-200">
            <InlineText>{risk.challenge.scenario}</InlineText>
          </p>
          <div className="mt-4 rounded-xl border border-brand-500/40 bg-brand-500/10 p-4">
            <span className="text-xs font-semibold uppercase tracking-wide text-brand-300">
              Objective
            </span>
            <p className="mt-1 text-slate-100">
              <InlineText>{risk.challenge.objective}</InlineText>
            </p>
          </div>
        </div>

        <FlagBox risk={risk} />
        <Spoiler risk={risk} />
      </div>

      <div className="space-y-6">
        <Hints hints={risk.challenge.hints} />
        <div className="card p-5">
          <h3 className="mb-3 text-lg font-bold text-slate-900">Prerequisites</h3>
          <ul className="space-y-2">
            {risk.lab.prerequisites.map((p, i) => (
              <li key={i} className="flex gap-2.5 text-sm text-slate-600">
                <span className="text-brand-500">›</span>
                <InlineText>{p}</InlineText>
              </li>
            ))}
          </ul>
        </div>
        <div className="card p-5">
          <h3 className="mb-3 text-lg font-bold text-slate-900">Manifests</h3>
          <div className="space-y-2 font-mono text-sm">
            {risk.lab.setupManifest && (
              <div className="flex items-center gap-2 rounded-lg bg-slate-100 px-3 py-2 text-slate-600">
                <span>🌱</span>
                <span className="break-all">{risk.lab.setupManifest}</span>
              </div>
            )}
            <div className="flex items-center gap-2 rounded-lg bg-red-50 px-3 py-2 text-red-700">
              <span>🔓</span>
              <span className="break-all">{risk.lab.vulnerableManifest}</span>
            </div>
            <div className="flex items-center gap-2 rounded-lg bg-emerald-50 px-3 py-2 text-emerald-700">
              <span>🔒</span>
              <span className="break-all">{risk.lab.fixedManifest}</span>
            </div>
          </div>
        </div>
        <div className="rounded-xl border border-amber-200 bg-amber-50 p-4 text-sm text-amber-800">
          ⚠️ Run only on the local kind cluster. These manifests are deliberately exploitable.
        </div>
      </div>
    </div>
  );
}
