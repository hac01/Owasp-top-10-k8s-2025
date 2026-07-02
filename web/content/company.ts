import type { Difficulty } from "./types";

/** NimbusMart - the fictional company the whole CTF is set inside. */
export const company = {
  name: "NimbusMart",
  tagline: "everything, delivered by the cloud",
  brief:
    "NimbusMart is a fast-growing online retailer. Growth outpaced security, so the board hired you - an external red team - to assess their Kubernetes platform. You start with a foothold in a single web pod and work deeper: each challenge below is a real OWASP Kubernetes Top 10 weakness in NimbusMart's cluster, and each one hides a flag that proves the impact.",
};

export const difficultyMeta: Record<
  Difficulty,
  { className: string; dot: string }
> = {
  Easy: { className: "bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200", dot: "bg-emerald-500" },
  Medium: { className: "bg-amber-50 text-amber-700 ring-1 ring-amber-200", dot: "bg-amber-500" },
  Hard: { className: "bg-red-50 text-red-700 ring-1 ring-red-200", dot: "bg-red-500" },
};
