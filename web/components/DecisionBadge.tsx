import clsx from "clsx";
import { type Decision } from "@/lib/api";

const STYLES: Record<Decision, string> = {
  allow: "bg-success/15 text-success border-success/40",
  deny: "bg-danger/15 text-danger border-danger/40",
  transform: "bg-accent/15 text-accent border-accent/40",
  require_approval: "bg-warning/15 text-warning border-warning/40",
};

export function DecisionBadge({ decision }: { decision: Decision }) {
  return (
    <span
      className={clsx(
        "inline-flex items-center rounded border px-2 py-0.5 font-mono text-xs uppercase tracking-wide",
        STYLES[decision]
      )}
    >
      {decision.replace("_", " ")}
    </span>
  );
}
