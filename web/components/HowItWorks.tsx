const steps = [
  {
    icon: "🚀",
    title: "Spin up the range",
    body: "Run ./setup.sh once. It boots a local kind cluster and deploys this whole app plus a built-in terminal into it.",
  },
  {
    icon: "🎯",
    title: "Pick a challenge",
    body: "Each card below is one risk from the OWASP Kubernetes Top 10 (2025). Open it and read the Overview to learn the weakness.",
  },
  {
    icon: "📖",
    title: "Read the briefing",
    body: "The Challenge tab gives you a NimbusMart mission briefing and objective, plus hints you can reveal one at a time.",
  },
  {
    icon: ">_",
    title: "Exploit it in the terminal",
    body: "Click the Terminal button (bottom-right). It is a real shell on the live cluster: deploy the lab manifests and run the exploit.",
  },
  {
    icon: "🚩",
    title: "Capture the flag",
    body: "The exploit reveals a FLAG{...}. Paste it into Submit the flag to bank the points and light up the scoreboard.",
  },
  {
    icon: "🛡️",
    title: "Patch and verify",
    body: "Apply the fixed manifest, then run the checker (Checker tab) to prove the misconfiguration is gone.",
  },
];

export function HowItWorks() {
  return (
    <section id="how-it-works" className="mt-24 scroll-mt-24">
      <div className="mb-8 text-center">
        <span className="chip bg-brand-50 text-brand-700 ring-1 ring-brand-200">
          🧭 New here?
        </span>
        <h2 className="mt-3 text-2xl font-bold text-slate-900">How the CTF works</h2>
        <p className="mx-auto mt-1 max-w-xl text-slate-500">
          Six steps from zero to a captured flag. The loop is always the same: learn it,
          break it, fix it, prove it.
        </p>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {steps.map((s, i) => (
          <div key={s.title} className="card flex gap-4 p-5">
            <div className="flex flex-col items-center">
              <span className="grid h-10 w-10 place-items-center rounded-xl bg-brand-50 font-mono text-lg text-brand-700">
                {s.icon}
              </span>
              {i < steps.length - 1 && (
                <span className="mt-2 hidden w-px flex-1 bg-slate-200 lg:block" />
              )}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold text-brand-500">STEP {i + 1}</span>
              </div>
              <h3 className="mt-0.5 font-semibold text-slate-900">{s.title}</h3>
              <p className="mt-1 text-sm leading-relaxed text-slate-500">{s.body}</p>
            </div>
          </div>
        ))}
      </div>

      <div className="mt-6 flex items-center justify-center gap-3 rounded-2xl border border-slate-800 bg-slate-900 px-6 py-4 text-sm text-slate-200">
        <span className="font-mono text-brand-300">&gt;_</span>
        <span>
          Tip: the <span className="font-semibold text-white">Terminal</span> button lives in the
          bottom-right corner on every page. It runs against the same cluster the app is deployed in.
        </span>
      </div>
    </section>
  );
}
