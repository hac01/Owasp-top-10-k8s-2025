"use client";

import { useEffect, useRef, useState } from "react";
import "@xterm/xterm/css/xterm.css";

type Status = "connecting" | "open" | "closed" | "error";

// The terminal backend is exposed on its own NodePort (30091). We reach it on
// the same host the browser is using. Override with NEXT_PUBLIC_TERMINAL_WS.
function wsUrl(): string {
  const override = process.env.NEXT_PUBLIC_TERMINAL_WS;
  if (override) return override;
  if (typeof window === "undefined") return "";
  const proto = window.location.protocol === "https:" ? "wss" : "ws";
  const port = process.env.NEXT_PUBLIC_TERMINAL_PORT || "30091";
  return `${proto}://${window.location.hostname}:${port}`;
}

export function TerminalDrawer() {
  const [open, setOpen] = useState(false);
  const [status, setStatus] = useState<Status>("connecting");
  const hostRef = useRef<HTMLDivElement>(null);
  const cleanupRef = useRef<(() => void) | null>(null);

  useEffect(() => {
    if (!open || !hostRef.current) return;
    let disposed = false;

    // Load xterm lazily so it never touches the server bundle.
    (async () => {
      const { Terminal } = await import("@xterm/xterm");
      const { FitAddon } = await import("@xterm/addon-fit");
      if (disposed || !hostRef.current) return;

      const term = new Terminal({
        fontFamily: "var(--font-mono), monospace",
        fontSize: 13,
        cursorBlink: true,
        theme: {
          background: "#0f0f17",
          foreground: "#e5e7eb",
          cursor: "#a78bfa",
          selectionBackground: "#5b21b6",
        },
      });
      const fit = new FitAddon();
      term.loadAddon(fit);
      term.open(hostRef.current);
      fit.fit();

      setStatus("connecting");
      const socket = new WebSocket(wsUrl());

      const sendResize = () => {
        try {
          socket.send(JSON.stringify({ type: "resize", cols: term.cols, rows: term.rows }));
        } catch {
          /* socket not open yet */
        }
      };

      socket.onopen = () => {
        setStatus("open");
        sendResize();
        term.focus();
      };
      socket.onmessage = (e) => term.write(typeof e.data === "string" ? e.data : "");
      socket.onclose = () => setStatus((s) => (s === "error" ? s : "closed"));
      socket.onerror = () => setStatus("error");

      term.onData((data) => {
        if (socket.readyState === WebSocket.OPEN) {
          socket.send(JSON.stringify({ type: "input", data }));
        }
      });

      const onResize = () => {
        try {
          fit.fit();
          sendResize();
        } catch {
          /* not mounted */
        }
      };
      window.addEventListener("resize", onResize);
      const ro = new ResizeObserver(onResize);
      ro.observe(hostRef.current);

      cleanupRef.current = () => {
        window.removeEventListener("resize", onResize);
        ro.disconnect();
        socket.close();
        term.dispose();
      };
    })();

    return () => {
      disposed = true;
      cleanupRef.current?.();
      cleanupRef.current = null;
    };
  }, [open]);

  const statusMeta: Record<Status, { dot: string; label: string }> = {
    connecting: { dot: "bg-amber-400", label: "connecting…" },
    open: { dot: "bg-emerald-400", label: "connected" },
    closed: { dot: "bg-slate-400", label: "disconnected" },
    error: { dot: "bg-red-400", label: "backend unreachable" },
  };

  return (
    <>
      {/* Launcher */}
      <button
        onClick={() => setOpen((o) => !o)}
        className="fixed bottom-5 right-5 z-50 flex items-center gap-2 rounded-full bg-slate-900 px-4 py-3 text-sm font-semibold text-white shadow-glow transition hover:bg-slate-800"
        aria-label="Toggle terminal"
      >
        <span className="font-mono text-brand-300">&gt;_</span>
        {open ? "Hide terminal" : "Terminal"}
      </button>

      {/* Drawer */}
      <div
        className={`fixed inset-x-0 bottom-0 z-40 transition-transform duration-300 ${
          open ? "translate-y-0" : "translate-y-[110%]"
        }`}
      >
        <div className="mx-auto max-w-6xl px-4 pb-4">
          <div className="overflow-hidden rounded-t-2xl border border-slate-800 bg-[#0f0f17] shadow-glow">
            <div className="flex items-center justify-between border-b border-slate-800 px-4 py-2.5">
              <div className="flex items-center gap-2.5">
                <span className="font-mono text-sm font-semibold text-brand-300">&gt;_ cluster terminal</span>
                <span className="flex items-center gap-1.5 text-xs text-slate-400">
                  <span className={`h-1.5 w-1.5 rounded-full ${statusMeta[status].dot}`} />
                  {statusMeta[status].label}
                </span>
              </div>
              <button
                onClick={() => setOpen(false)}
                className="rounded px-2 py-1 text-xs text-slate-400 transition hover:bg-slate-800 hover:text-white"
              >
                Close ✕
              </button>
            </div>
            {status === "error" && (
              <div className="border-b border-slate-800 bg-red-500/10 px-4 py-2 text-xs text-red-300">
                Can&apos;t reach the terminal backend. Deploy the platform with{" "}
                <code className="font-mono text-red-200">make up</code>, or run it locally with{" "}
                <code className="font-mono text-red-200">make terminal-local</code>.
              </div>
            )}
            <div ref={hostRef} className="h-[42vh] w-full px-3 py-2" />
          </div>
        </div>
      </div>
    </>
  );
}
