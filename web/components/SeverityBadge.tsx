import clsx from "clsx";

const STYLE: Record<string, string> = {
  critical: "bg-red-500/15 text-red-400 ring-red-500/30",
  high: "bg-orange-500/15 text-orange-400 ring-orange-500/30",
  medium: "bg-amber-500/15 text-amber-400 ring-amber-500/30",
  low: "bg-sky-500/15 text-sky-400 ring-sky-500/30",
  info: "bg-slate-500/15 text-slate-400 ring-slate-500/30",
};

const STATUS_STYLE: Record<string, string> = {
  open: "bg-red-500/15 text-red-400 ring-red-500/30",
  triaging: "bg-amber-500/15 text-amber-400 ring-amber-500/30",
  resolved: "bg-emerald-500/15 text-emerald-400 ring-emerald-500/30",
  false_positive: "bg-slate-500/15 text-slate-400 ring-slate-500/30",
};

function Pill({ value, styles }: { value: string; styles: Record<string, string> }) {
  return (
    <span
      className={clsx(
        "inline-flex items-center rounded-md px-1.5 py-0.5 text-xs font-medium ring-1 ring-inset",
        styles[value] ?? "bg-muted text-foreground/70 ring-border"
      )}
    >
      {value}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: string }) {
  return <Pill value={severity} styles={STYLE} />;
}

export function StatusBadge({ status }: { status: string }) {
  return <Pill value={status} styles={STATUS_STYLE} />;
}
