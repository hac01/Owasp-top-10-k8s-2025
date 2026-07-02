import type { Severity } from "@/content/types";

const styles: Record<Severity, string> = {
  Critical: "bg-red-50 text-red-700 ring-1 ring-red-200",
  High: "bg-orange-50 text-orange-700 ring-1 ring-orange-200",
  Medium: "bg-amber-50 text-amber-700 ring-1 ring-amber-200",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`chip ${styles[severity]}`}>
      <span className="h-1.5 w-1.5 rounded-full bg-current" />
      {severity}
    </span>
  );
}
