import Link from "next/link";
import { notFound } from "next/navigation";
import { getRisk, risks, allRisks } from "@/content/risks";
import { SeverityBadge } from "@/components/SeverityBadge";
import { Tabs } from "@/components/Tabs";
import { CodeBlock } from "@/components/CodeBlock";
import { Challenge, DifficultyBadge } from "@/components/Challenge";
import { InlineText } from "@/lib/text";

export function generateStaticParams() {
  return allRisks.map((r) => ({ slug: r.slug }));
}

export function generateMetadata({ params }: { params: { slug: string } }) {
  const risk = getRisk(params.slug);
  if (!risk) return {};
  return { title: `${risk.id}: ${risk.title} - OWASP K8s Top 10`, description: risk.tagline };
}

function SectionHeading({ children }: { children: React.ReactNode }) {
  return <h3 className="mb-3 text-lg font-bold text-slate-900">{children}</h3>;
}

function Bullets({ items, marker = "•" }: { items: string[]; marker?: string }) {
  return (
    <ul className="space-y-2">
      {items.map((item, i) => (
        <li key={i} className="flex gap-2.5 text-slate-600">
          <span className="mt-0.5 shrink-0 text-brand-500">{marker}</span>
          <span className="prose-block">
            <InlineText>{item}</InlineText>
          </span>
        </li>
      ))}
    </ul>
  );
}

export default function RiskPage({ params }: { params: { slug: string } }) {
  const risk = getRisk(params.slug);
  if (!risk) notFound();

  const idx = allRisks.findIndex((r) => r.slug === risk.slug);
  const next = allRisks[(idx + 1) % allRisks.length];

  const overview = (
    <div className="grid gap-10 lg:grid-cols-3">
      <div className="lg:col-span-2 space-y-4">
        <SectionHeading>What it is</SectionHeading>
        {risk.overview.map((p, i) => (
          <p key={i} className="prose-block">
            <InlineText>{p}</InlineText>
          </p>
        ))}
        <div className="!mt-8">
          <SectionHeading>How an attacker abuses it</SectionHeading>
          <p className="prose-block mb-4">
            <InlineText>{risk.attackScenario.summary}</InlineText>
          </p>
          <ol className="space-y-3">
            {risk.attackScenario.steps.map((s, i) => (
              <li key={i} className="flex gap-3">
                <span className="grid h-6 w-6 shrink-0 place-items-center rounded-full bg-red-50 text-xs font-bold text-red-600">
                  {i + 1}
                </span>
                <span className="prose-block pt-0.5">
                  <InlineText>{s}</InlineText>
                </span>
              </li>
            ))}
          </ol>
        </div>
      </div>
      <div className="space-y-6">
        <div className="card p-5">
          <SectionHeading>Impact</SectionHeading>
          <Bullets items={risk.impact} marker="⚠" />
        </div>
        <div className="card p-5">
          <SectionHeading>Root causes</SectionHeading>
          <Bullets items={risk.rootCauses} />
        </div>
      </div>
    </div>
  );

  const challenge = <Challenge risk={risk} />;

  const defense = (
    <div className="space-y-8">
      <div className="rounded-xl border border-emerald-200 bg-emerald-50/50 p-5">
        <SectionHeading>🛡️ Defense strategy</SectionHeading>
        <p className="prose-block">
          <InlineText>{risk.defense.summary}</InlineText>
        </p>
      </div>
      <div className="grid gap-6 lg:grid-cols-2">
        {risk.defense.patches.map((patch, i) => (
          <div key={i} className="space-y-3">
            <div>
              <h4 className="font-semibold text-slate-900">
                {i + 1}. {patch.title}
              </h4>
              <p className="mt-1 text-sm text-slate-500">
                <InlineText>{patch.description}</InlineText>
              </p>
            </div>
            <CodeBlock code={patch.code} lang={patch.lang ?? "yaml"} />
          </div>
        ))}
      </div>
      <div className="card p-6">
        <SectionHeading>✅ Best practices checklist</SectionHeading>
        <Bullets items={risk.defense.bestPractices} marker="✓" />
      </div>
    </div>
  );

  const checker = (
    <div className="grid gap-10 lg:grid-cols-3">
      <div className="lg:col-span-2 space-y-5">
        <SectionHeading>Automated verification</SectionHeading>
        <p className="prose-block">
          <InlineText>{risk.checker.whatItChecks}</InlineText>
        </p>
        <div>
          <p className="mb-2 text-sm font-semibold text-slate-600">Run it against your cluster:</p>
          <CodeBlock
            code={`# after applying your fix\ncd checker\ngo run . --check ${risk.checker.checkId}\n\n# or scan everything\ngo run . --all`}
            lang="bash"
          />
        </div>
        <div>
          <p className="mb-2 text-sm font-semibold text-slate-600">Expected on a hardened cluster:</p>
          <CodeBlock
            code={`[PASS] ${risk.checker.checkId} - ${risk.title}\n        No issues found.`}
            label="output"
          />
        </div>
      </div>
      <div className="card h-fit p-5">
        <SectionHeading>Pass criteria</SectionHeading>
        <Bullets items={risk.checker.passCriteria} marker="✓" />
      </div>
    </div>
  );

  return (
    <div className="py-10">
      <Link href="/#risks" className="text-sm font-medium text-brand-600 hover:underline">
        ← All risks
      </Link>

      <div className="mt-4 flex flex-wrap items-center gap-4">
        <span className="grid h-16 w-16 place-items-center rounded-2xl bg-brand-50 text-4xl shadow-soft">
          {risk.icon}
        </span>
        <div>
          <div className="flex flex-wrap items-center gap-3">
            <span className="font-mono text-sm font-bold text-brand-600">{risk.id}</span>
            <SeverityBadge severity={risk.severity} />
            <DifficultyBadge risk={risk} />
          </div>
          <h1 className="mt-1 text-3xl font-extrabold tracking-tight text-slate-900">
            {risk.title}
          </h1>
        </div>
      </div>
      <p className="mt-3 max-w-3xl text-lg text-slate-600">
        <InlineText>{risk.tagline}</InlineText>
      </p>

      <Tabs
        tabs={[
          { id: "overview", label: "Overview", icon: "📖", content: overview },
          { id: "challenge", label: "Challenge", icon: "🚩", content: challenge },
          { id: "defense", label: "Defense", icon: "🛡️", content: defense },
          { id: "checker", label: "Checker", icon: "🤖", content: checker },
        ]}
      />

      <div className="mt-10 flex items-center justify-between border-t border-slate-200 pt-6">
        <span className="text-sm text-slate-500">References</span>
        <Link
          href={`/k/${next.slug}`}
          className="btn-ghost"
        >
          Next: {next.id} {next.title} →
        </Link>
      </div>
      <div className="mt-4 flex flex-wrap gap-3">
        {risk.references.map((ref) => (
          <a
            key={ref.url}
            href={ref.url}
            target="_blank"
            rel="noreferrer"
            className="chip bg-slate-100 text-slate-600 hover:bg-brand-50 hover:text-brand-700"
          >
            {ref.label} ↗
          </a>
        ))}
      </div>
    </div>
  );
}
