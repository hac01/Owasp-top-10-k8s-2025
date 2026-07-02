import { risks, bonusRisks } from "@/content/risks";
import { company } from "@/content/company";
import { RiskCard } from "@/components/RiskCard";
import { Scoreboard } from "@/components/Scoreboard";
import { HowItWorks } from "@/components/HowItWorks";

export default function Home() {
  return (
    <div>
      {/* Hero - lead with the OWASP 2025 list, then the company scenario */}
      <section className="py-16 sm:py-24">
        <div className="mx-auto max-w-3xl text-center">
          <span className="chip bg-brand-600 text-white shadow-glow">
            🛡️ 2025 Edition · Hands-on
          </span>
          <h1 className="mt-5 text-4xl font-extrabold leading-[1.05] tracking-tight text-slate-900 sm:text-6xl">
            OWASP{" "}
            <span className="bg-gradient-to-r from-brand-500 to-brand-700 bg-clip-text text-transparent">
              Kubernetes
            </span>{" "}
            Top 10
          </h1>
          <p className="mx-auto mt-4 max-w-2xl text-lg leading-relaxed text-slate-600">
            Every risk on the <strong className="text-slate-800">2025 OWASP Kubernetes Top 10</strong>,
            turned into a live capture-the-flag: exploit the real weakness on a real cluster, grab the
            flag, then patch it and prove the fix with the checker.
          </p>

          {/* The 10 (+ bonus) at a glance */}
          <div className="mx-auto mt-7 flex max-w-2xl flex-wrap justify-center gap-2">
            {risks.map((r) => (
              <a
                key={r.id}
                href={`/k/${r.slug}`}
                className="chip bg-brand-50 text-brand-700 ring-1 ring-brand-200 hover:bg-brand-100"
              >
                <span className="font-mono font-semibold">{r.id}</span>
                <span className="hidden sm:inline">{r.title}</span>
              </a>
            ))}
            <span className="chip bg-slate-100 text-slate-500 ring-1 ring-slate-200">
              <span className="font-mono font-semibold">★</span>
              <span className="hidden sm:inline">Supply Chain (bonus)</span>
            </span>
          </div>

          <div className="mt-8 flex flex-wrap justify-center gap-3">
            <a href="#challenges" className="btn-primary">
              Start the engagement ↓
            </a>
            <a href="#getting-started" className="btn-ghost">
              Set up the range
            </a>
          </div>
        </div>

        {/* The company scenario, called out distinctly */}
        <div className="mx-auto mt-14 max-w-3xl">
          <div className="card overflow-hidden p-0">
            <div className="flex items-center gap-3 border-b border-slate-100 bg-slate-900 px-6 py-4">
              <span className="grid h-10 w-10 place-items-center rounded-xl bg-gradient-to-br from-brand-500 to-brand-700 text-lg">
                🛒
              </span>
              <div>
                <div className="text-xs font-semibold uppercase tracking-widest text-brand-300">
                  The scenario
                </div>
                <div className="font-bold text-white">
                  {company.name} <span className="font-normal text-slate-400">- {company.tagline}</span>
                </div>
              </div>
            </div>
            <p className="px-6 py-5 leading-relaxed text-slate-600">{company.brief}</p>
          </div>
        </div>

        <div className="mx-auto mt-6 max-w-3xl">
          <Scoreboard risks={risks} />
        </div>
      </section>

      {/* How it works tutorial */}
      <HowItWorks />

      {/* Challenge grid */}
      <section id="challenges" className="scroll-mt-24">
        <div className="mb-8 flex items-end justify-between">
          <div>
            <h2 className="text-2xl font-bold text-slate-900">The 10 challenges</h2>
            <p className="mt-1 text-slate-500">
              Each one is a real weakness in {company.name}&apos;s cluster. Pick a target.
            </p>
          </div>
        </div>
        <div className="grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
          {risks.map((risk, i) => (
            <RiskCard key={risk.id} risk={risk} index={i} />
          ))}
        </div>

        {bonusRisks.length > 0 && (
          <div className="mt-12">
            <div className="mb-4 flex items-center gap-3">
              <span className="chip bg-brand-100 text-brand-700">★ Bonus</span>
              <p className="text-sm text-slate-500">
                Retired from the 2025 list, but still a great pivot - extra credit.
              </p>
            </div>
            <div className="grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
              {bonusRisks.map((risk, i) => (
                <RiskCard key={risk.id} risk={risk} index={i} />
              ))}
            </div>
          </div>
        )}
      </section>

      {/* Getting started */}
      <section id="getting-started" className="mt-24 scroll-mt-24">
        <div className="card overflow-hidden p-0">
          <div className="bg-gradient-to-br from-brand-600 to-brand-800 px-8 py-7 text-white">
            <h2 className="text-2xl font-bold">Set up the cyber range</h2>
            <p className="mt-1 text-brand-100">
              {company.name}&apos;s cluster runs locally on kind. Nothing touches production.
            </p>
          </div>
          <div className="grid gap-6 p-8 sm:grid-cols-3">
            {[
              {
                step: "1",
                title: "Spin up the cluster",
                body: "kind create cluster --config labs/kind-cluster.yaml",
              },
              {
                step: "2",
                title: "Deploy a challenge",
                body: "kubectl apply -f labs/k01-insecure-workload/vulnerable.yaml",
              },
              {
                step: "3",
                title: "Verify your fix",
                body: "cd checker && go run . --check k01",
              },
            ].map((s) => (
              <div key={s.step}>
                <div className="mb-2 grid h-8 w-8 place-items-center rounded-lg bg-brand-100 font-bold text-brand-700">
                  {s.step}
                </div>
                <h3 className="font-semibold text-slate-900">{s.title}</h3>
                <code className="mt-2 block break-all rounded-lg bg-slate-900 px-3 py-2 font-mono text-xs text-emerald-300">
                  {s.body}
                </code>
              </div>
            ))}
          </div>
        </div>
      </section>
    </div>
  );
}
