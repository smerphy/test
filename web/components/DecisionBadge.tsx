import clsx from "clsx";
import { type Decision } from "@/lib/api";

const STYLES: Record<Decision, string> = {
  allow: "bg-success/15 text-success ring-success/30",
  deny: "bg-danger/15 text-danger ring-danger/30",
  transform: "bg-accent/15 text-accent ring-accent/30",
  require_approval: "bg-warning/15 text-warning ring-warning/30",
};

export function DecisionBadge({ decision }: { decision: Decision }) {
  return (
    <span
      className={clsx(
        "inline-flex items-center rounded-md px-2 py-0.5 font-mono text-xs uppercase tracking-wide ring-1 ring-inset",
        STYLES[decision]
      )}
    >
      {decision.replace("_", " ")}
    </span>
  );
}
