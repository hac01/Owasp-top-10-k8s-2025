"use client";

import { useState } from "react";
import type { LabStep } from "@/content/types";
import { InlineText } from "@/lib/text";

const kindMeta: Record<LabStep["kind"], { label: string; className: string; dot: string }> = {
  setup: { label: "Setup", className: "bg-slate-100 text-slate-600", dot: "bg-slate-400" },
  attack: { label: "Exploit", className: "bg-red-50 text-red-700", dot: "bg-red-500" },
  fix: { label: "Remediate", className: "bg-brand-50 text-brand-700", dot: "bg-brand-500" },
  verify: { label: "Verify", className: "bg-emerald-50 text-emerald-700", dot: "bg-emerald-500" },
};

function CopyableCommand({ command }: { command: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(command);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* noop */
    }
  };
  return (
    <div className="overflow-hidden rounded-xl border border-slate-800 bg-slate-900">
      <div className="flex items-center justify-between border-b border-slate-800 px-3 py-1.5">
        <div className="flex gap-1.5">
          <span className="h-2.5 w-2.5 rounded-full bg-red-400/80" />
          <span className="h-2.5 w-2.5 rounded-full bg-amber-400/80" />
          <span className="h-2.5 w-2.5 rounded-full bg-emerald-400/80" />
        </div>
        <button
          onClick={copy}
          className="rounded px-2 py-0.5 text-xs text-slate-300 transition hover:bg-slate-800 hover:text-white"
        >
          {copied ? "✓ Copied" : "Copy"}
        </button>
      </div>
      <pre className="overflow-x-auto px-4 py-3 text-sm leading-relaxed">
        <code className="font-mono text-emerald-300">
          <span className="select-none text-brand-400">$ </span>
          {command}
        </code>
      </pre>
    </div>
  );
}

export function GuidedLab({ steps }: { steps: LabStep[] }) {
  const [done, setDone] = useState<boolean[]>(() => steps.map(() => false));
  const completed = done.filter(Boolean).length;
  const pct = Math.round((completed / steps.length) * 100);

  const toggle = (i: number) =>
    setDone((prev) => prev.map((v, idx) => (idx === i ? !v : v)));

  return (
    <div>
      <div className="mb-6 flex items-center gap-4">
        <div className="h-2 flex-1 overflow-hidden rounded-full bg-slate-100">
          <div
            className="h-full rounded-full bg-gradient-to-r from-brand-400 to-brand-600 transition-all duration-500"
            style={{ width: `${pct}%` }}
          />
        </div>
        <span className="whitespace-nowrap text-sm font-semibold text-brand-700">
          {completed}/{steps.length} steps
        </span>
      </div>

      <ol className="relative space-y-4 border-l-2 border-slate-100 pl-6">
        {steps.map((step, i) => {
          const meta = kindMeta[step.kind];
          const isDone = done[i];
          return (
            <li key={i} className="relative">
              <span
                className={`absolute -left-[31px] top-1.5 grid h-5 w-5 place-items-center rounded-full ring-4 ring-white ${
                  isDone ? "bg-brand-600" : meta.dot
                }`}
              >
                {isDone && <span className="text-[10px] text-white">✓</span>}
              </span>
              <div
                className={`rounded-xl border p-4 transition ${
                  isDone ? "border-brand-200 bg-brand-50/40" : "border-slate-200 bg-white"
                }`}
              >
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <span className={`chip ${meta.className} mb-1.5`}>{meta.label}</span>
                    <h4 className="font-semibold text-slate-900">
                      {i + 1}. {step.title}
                    </h4>
                  </div>
                  <button
                    onClick={() => toggle(i)}
                    className={`shrink-0 rounded-lg px-3 py-1.5 text-xs font-semibold transition ${
                      isDone
                        ? "bg-brand-600 text-white"
                        : "bg-slate-100 text-slate-600 hover:bg-brand-100 hover:text-brand-700"
                    }`}
                  >
                    {isDone ? "Done ✓" : "Mark done"}
                  </button>
                </div>
                <p className="mt-2 text-sm leading-relaxed text-slate-600">
                  <InlineText>{step.description}</InlineText>
                </p>
                {step.command && (
                  <div className="mt-3">
                    <CopyableCommand command={step.command} />
                  </div>
                )}
                {step.expected && (
                  <p className="mt-2 text-sm text-slate-500">
                    <span className="font-semibold text-slate-600">Expected: </span>
                    <InlineText>{step.expected}</InlineText>
                  </p>
                )}
              </div>
            </li>
          );
        })}
      </ol>
    </div>
  );
}
