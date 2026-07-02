"use client";

import { useState } from "react";

export function CodeBlock({
  code,
  lang = "bash",
  label,
}: {
  code: string;
  lang?: string;
  label?: string;
}) {
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    } catch {
      /* clipboard unavailable */
    }
  };

  return (
    <div className="group relative overflow-hidden rounded-xl border border-slate-800 bg-slate-900">
      <div className="flex items-center justify-between border-b border-slate-800 px-4 py-2">
        <span className="font-mono text-xs uppercase tracking-wider text-slate-400">
          {label ?? lang}
        </span>
        <button
          onClick={copy}
          className="rounded-md px-2 py-1 text-xs font-medium text-slate-300 transition hover:bg-slate-800 hover:text-white"
        >
          {copied ? "✓ Copied" : "Copy"}
        </button>
      </div>
      <pre className="overflow-x-auto px-4 py-3.5 text-sm leading-relaxed">
        <code className="font-mono text-slate-100">{code}</code>
      </pre>
    </div>
  );
}
