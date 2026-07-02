"use client";

import { createContext, useCallback, useContext, useEffect, useState } from "react";

const STORAGE_KEY = "nimbusmart-ctf-progress-v1";

interface ProgressState {
  /** set of solved risk ids, e.g. {"K01": true} */
  solved: Record<string, boolean>;
  solve: (id: string) => void;
  unsolve: (id: string) => void;
  reset: () => void;
  hydrated: boolean;
}

const ProgressContext = createContext<ProgressState | null>(null);

export function ProgressProvider({ children }: { children: React.ReactNode }) {
  const [solved, setSolved] = useState<Record<string, boolean>>({});
  const [hydrated, setHydrated] = useState(false);

  useEffect(() => {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (raw) setSolved(JSON.parse(raw));
    } catch {
      /* ignore */
    }
    setHydrated(true);
  }, []);

  const persist = useCallback((next: Record<string, boolean>) => {
    setSolved(next);
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
    } catch {
      /* ignore */
    }
  }, []);

  const solve = useCallback((id: string) => persist({ ...readLatest(), [id]: true }), [persist]);
  const unsolve = useCallback(
    (id: string) => {
      const next = { ...readLatest() };
      delete next[id];
      persist(next);
    },
    [persist],
  );
  const reset = useCallback(() => persist({}), [persist]);

  return (
    <ProgressContext.Provider value={{ solved, solve, unsolve, reset, hydrated }}>
      {children}
    </ProgressContext.Provider>
  );
}

// Read the freshest value straight from storage to avoid stale closures when
// several solves happen quickly.
function readLatest(): Record<string, boolean> {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : {};
  } catch {
    return {};
  }
}

export function useProgress(): ProgressState {
  const ctx = useContext(ProgressContext);
  if (!ctx) throw new Error("useProgress must be used within ProgressProvider");
  return ctx;
}

/** SHA-256 hex of the input, using the Web Crypto API (browser only). */
export async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
