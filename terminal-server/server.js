// NimbusMart CTF — in-browser terminal backend.
//
// A WebSocket server that spawns a real PTY (bash) per connection and relays
// bytes to/from an xterm.js terminal in the web app. In-cluster, the shell's
// kubectl automatically uses the pod's ServiceAccount, so the terminal operates
// on the very cluster the platform runs in. Locally, it uses ~/.kube/config.
//
// SECURITY: this executes arbitrary shell commands with whatever privileges the
// process (or its ServiceAccount) has. It is meant for a local, disposable lab
// cluster reached over localhost only. Never expose it to an untrusted network.

const http = require("http");
const os = require("os");
// Prebuilt multiarch node-pty (no native compile needed → tiny, reliable image).
const pty = require("@homebridge/node-pty-prebuilt-multiarch");
const { WebSocketServer } = require("ws");

const PORT = parseInt(process.env.PORT || "7681", 10);
const CWD = process.env.TERMINAL_CWD || process.cwd();
// Optional shared secret: if set, clients must connect with ?token=...
const TOKEN = process.env.TERMINAL_TOKEN || "";
const SHELL = process.env.TERMINAL_SHELL || (os.platform() === "win32" ? "powershell.exe" : "bash");

const banner = [
  "\x1b[35m",
  "  ╔═══════════════════════════════════════════════════════════╗",
  "  ║   NimbusMart CTF — live cluster terminal                   ║",
  "  ║   kubectl talks to THIS cluster. Try:                      ║",
  "  ║     kubectl get ns                                         ║",
  "  ║     kubectl apply -f labs/k01-insecure-workload/setup.yaml ║",
  "  ║     owasp-k8s-checker --list                               ║",
  "  ╚═══════════════════════════════════════════════════════════╝",
  "\x1b[0m",
  "",
].join("\r\n");

const server = http.createServer((req, res) => {
  // Simple health endpoint for k8s probes.
  if (req.url === "/healthz") {
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("ok");
    return;
  }
  res.writeHead(404);
  res.end();
});

const wss = new WebSocketServer({ server });

wss.on("connection", (ws, req) => {
  if (TOKEN) {
    const url = new URL(req.url, "http://localhost");
    if (url.searchParams.get("token") !== TOKEN) {
      ws.close(1008, "unauthorized");
      return;
    }
  }

  const term = pty.spawn(SHELL, [], {
    name: "xterm-color",
    cols: 80,
    rows: 24,
    cwd: CWD,
    env: { ...process.env, TERM: "xterm-256color", PS1: "\\[\\e[35m\\]nimbusmart\\[\\e[0m\\]:\\w$ " },
  });

  ws.send(banner);

  term.onData((data) => {
    if (ws.readyState === ws.OPEN) ws.send(data);
  });

  term.onExit(() => {
    if (ws.readyState === ws.OPEN) ws.close();
  });

  ws.on("message", (raw) => {
    // Control messages arrive as JSON ({type:"resize"|"input"}); anything else
    // is treated as raw keystrokes.
    let msg;
    try {
      msg = JSON.parse(raw.toString());
    } catch {
      term.write(raw.toString());
      return;
    }
    if (msg.type === "resize" && msg.cols && msg.rows) {
      term.resize(msg.cols, msg.rows);
    } else if (msg.type === "input" && typeof msg.data === "string") {
      term.write(msg.data);
    }
  });

  ws.on("close", () => {
    try {
      term.kill();
    } catch {
      /* already gone */
    }
  });
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`[terminal] PTY WebSocket server listening on :${PORT} (cwd=${CWD}, shell=${SHELL})`);
});
