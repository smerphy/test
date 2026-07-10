import { Card, Stat } from "@/components/Card";
import { ErrorNote, PageHeader } from "@/components/Page";
import {
  api,
  type BudgetStatus,
  type CostBreakdownItem,
  type CostSummary,
} from "@/lib/api";

export const dynamic = "force-dynamic";

function usd(v: number): string {
  if (v === 0) return "$0.00";
  return v >= 1 ? `$${v.toFixed(2)}` : `$${v.toFixed(4)}`;
}

function pct(v: number): string {
  return `${(v * 100).toFixed(1)}%`;
}

function Sparkline({ values }: { values: number[] }) {
  const height = 40;
  const width = 260;
  if (values.length === 0) return <div className="h-10 text-foreground/40">—</div>;
  const max = Math.max(...values, Number.EPSILON);
  const step = values.length > 1 ? width / (values.length - 1) : width;
  const points = values
    .map((v, i) => `${i * step},${height - (v / max) * height}`)
    .join(" ");
  return (
    <svg width={width} height={height} className="text-accent">
      <polyline points={points} fill="none" stroke="currentColor" strokeWidth="1.5" />
    </svg>
  );
}

function BudgetBar({ b }: { b: BudgetStatus }) {
  if (b.budget_usd === null) {
    return (
      <p className="text-sm text-foreground/60">
        No monthly budget set — tracking only. An admin can set one via
        <code className="mx-1 font-mono">PATCH /org monthly_cost_budget_usd</code>.
      </p>
    );
  }
  const frac = Math.min(b.pct_used ?? 0, 1);
  const over = (b.pct_used ?? 0) >= 1;
  const barColor = over
    ? "bg-danger"
    : b.forecast_over_budget
      ? "bg-amber-500"
      : "bg-emerald-500";
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between text-sm">
        <span className="tabular-nums">
          {usd(b.agent_spend_usd)} <span className="text-foreground/50">of</span>{" "}
          {usd(b.budget_usd)}
        </span>
        <span
          className={`rounded px-1.5 py-0.5 text-xs font-medium ring-1 ring-inset ${
            over
              ? "bg-danger/15 text-danger ring-danger/30"
              : b.forecast_over_budget
                ? "bg-amber-500/15 text-amber-400 ring-amber-500/30"
                : "bg-emerald-500/15 text-emerald-400 ring-emerald-500/30"
          }`}
        >
          {over
            ? "Over budget"
            : b.forecast_over_budget
              ? "Forecast over"
              : "On track"}
        </span>
      </div>
      <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
        <div
          className={`h-full ${barColor}`}
          style={{ width: `${frac * 100}%` }}
        />
      </div>
      <div className="flex justify-between text-xs text-foreground/50 tabular-nums">
        <span>{b.pct_used !== null ? pct(b.pct_used) : "—"} used</span>
        <span>
          Day {Math.floor(b.days_elapsed)} / {b.days_in_month} ·{" "}
          {usd(b.daily_burn_usd)}/day
        </span>
      </div>
    </div>
  );
}

function BreakdownTable({
  label,
  items,
}: {
  label: string;
  items: CostBreakdownItem[];
}) {
  return (
    <Card title={label}>
      {items.length === 0 ? (
        <p className="text-sm text-foreground/50">No spend in window.</p>
      ) : (
        <table className="w-full text-left font-mono text-xs">
          <thead className="text-foreground/60">
            <tr>
              <th className="py-1 pr-3">Name</th>
              <th className="py-1 pr-3 text-right">Cost</th>
              <th className="py-1 pr-3 text-right">Share</th>
              <th className="py-1 pr-3 text-right">Calls</th>
              <th className="py-1 text-right">Tokens</th>
            </tr>
          </thead>
          <tbody>
            {items.map((it) => (
              <tr key={it.key} className="border-t border-border/50">
                <td className="py-1 pr-3">{it.key}</td>
                <td className="py-1 pr-3 text-right tabular-nums">{usd(it.cost_usd)}</td>
                <td className="py-1 pr-3 text-right tabular-nums">{pct(it.share)}</td>
                <td className="py-1 pr-3 text-right tabular-nums">
                  {it.calls.toLocaleString()}
                </td>
                <td className="py-1 text-right tabular-nums">
                  {it.total_tokens.toLocaleString()}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Card>
  );
}

export default async function FinancePage() {
  let summary: CostSummary | null = null;
  let budget: BudgetStatus | null = null;
  let error: string | null = null;
  try {
    [summary, budget] = await Promise.all([
      api.getCostSummary(),
      api.getBudgetStatus(),
    ]);
  } catch (e) {
    error = (e as Error).message;
  }

  return (
    <div className="space-y-8">
      <PageHeader
        title="Financial tracking"
        description={
          <>Agent LLM spend · month-to-date budget &amp; 30-day breakdown</>
        }
      />

      {error && <ErrorNote message={error} title="Control plane unreachable" />}

      {budget && (
        <>
          <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
            <Stat label={`Spend (${budget.month})`} value={usd(budget.agent_spend_usd)} />
            <Stat label="Projected (EOM)" value={usd(budget.projected_month_usd)} />
            <Stat
              label="Budget"
              value={budget.budget_usd === null ? "—" : usd(budget.budget_usd)}
            />
            <Stat label="Advisory spend" value={usd(budget.advisory_spend_usd)} />
          </div>

          <Card title="Monthly budget">
            <BudgetBar b={budget} />
          </Card>
        </>
      )}

      {summary && (
        <>
          <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
            <Stat label="Spend (30d)" value={usd(summary.total.cost_usd)} />
            <Stat label="Calls (30d)" value={summary.total.calls.toLocaleString()} />
            <Stat
              label="Avg / call"
              value={usd(summary.total.avg_cost_per_call)}
            />
            <Stat label="Error rate" value={pct(summary.total.error_rate)} />
          </div>

          <Card title="Daily spend (30d)">
            <Sparkline values={summary.daily.map((d) => d.cost_usd)} />
          </Card>

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            <BreakdownTable label="By model" items={summary.by_model} />
            <BreakdownTable label="Top agents" items={summary.by_agent} />
            <BreakdownTable label="By project" items={summary.by_project} />
          </div>

          {summary.total.calls === 0 && (
            <Card>
              <p className="text-sm text-foreground/60">
                No metered LLM calls in the last 30 days. Spend is sourced from
                <code className="mx-1 font-mono">MetricEvent.cost_usd</code>
                shipped by the SDK monitor or
                <code className="mx-1 font-mono">POST /metrics/events</code>.
              </p>
            </Card>
          )}
        </>
      )}
    </div>
  );
}
