import { redirect } from "next/navigation";
import { revalidatePath } from "next/cache";
import clsx from "clsx";
import { Card } from "@/components/Card";
import { ErrorNote, PageHeader } from "@/components/Page";
import { api, type AlertEvent, type AlertRule } from "@/lib/api";

export const dynamic = "force-dynamic";

function fail(e: unknown): never {
  redirect(`/alerts?error=${encodeURIComponent((e as Error).message)}`);
}

const METRIC_OPTIONS = [
  "cost_usd",
  "input_tokens",
  "output_tokens",
  "total_tokens",
  "duration_ms",
  "request_count",
  "error_count",
  "error_rate",
  "deny_count",
] as const;

const AGGREGATION_OPTIONS = [
  "sum",
  "avg",
  "p50",
  "p95",
  "p99",
  "max",
  "count",
  "rate",
] as const;

async function createRuleAction(formData: FormData): Promise<void> {
  "use server";
  try {
    await api.createAlertRule({
      name: formData.get("name") as string,
      metric: formData.get("metric") as AlertRule["metric"],
      aggregation: formData.get("aggregation") as AlertRule["aggregation"],
      window_minutes: Number(formData.get("window_minutes")),
      threshold: Number(formData.get("threshold")),
      comparison: formData.get("comparison") as AlertRule["comparison"],
      severity: formData.get("severity") as AlertRule["severity"],
      channel: formData.get("channel") as AlertRule["channel"],
      target: formData.get("target") as string,
      group_by: (formData.get("group_by") as string) || undefined,
      filter_model: (formData.get("filter_model") as string) || undefined,
      cooldown_minutes: Number(formData.get("cooldown_minutes") ?? 15),
    });
  } catch (e) {
    fail(e);
  }
  revalidatePath("/alerts");
}

async function evaluateRuleAction(formData: FormData): Promise<void> {
  "use server";
  try {
    await api.evaluateAlertRule(formData.get("rule_id") as string);
  } catch (e) {
    fail(e);
  }
  revalidatePath("/alerts");
}

async function acknowledgeEventAction(formData: FormData): Promise<void> {
  "use server";
  try {
    await api.acknowledgeAlert(
      formData.get("event_id") as string,
      formData.get("by") as string,
      (formData.get("note") as string) || undefined,
    );
  } catch (e) {
    fail(e);
  }
  revalidatePath("/alerts");
}

const STATE_STYLE: Record<string, string> = {
  firing: "bg-danger/15 text-danger border-danger/40",
  acknowledged: "bg-warning/15 text-warning border-warning/40",
  resolved: "bg-success/15 text-success border-success/40",
};

function StateBadge({ state }: { state: string }) {
  return (
    <span
      className={clsx(
        "inline-flex items-center rounded border px-2 py-0.5 font-mono text-xs uppercase tracking-wide",
        STATE_STYLE[state] ?? "bg-muted text-foreground border-border",
      )}
    >
      {state}
    </span>
  );
}

const SEVERITY_STYLE: Record<string, string> = {
  info: "bg-accent/15 text-accent border-accent/40",
  warning: "bg-warning/15 text-warning border-warning/40",
  critical: "bg-danger/15 text-danger border-danger/40",
};

function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span
      className={clsx(
        "inline-flex items-center rounded border px-2 py-0.5 font-mono text-xs uppercase tracking-wide",
        SEVERITY_STYLE[severity] ?? "bg-muted text-foreground border-border",
      )}
    >
      {severity}
    </span>
  );
}

export default async function AlertsPage({
  searchParams,
}: {
  searchParams: Promise<{ error?: string }>;
}) {
  const params = await searchParams;
  let rules: AlertRule[] = [];
  let events: AlertEvent[] = [];
  let error: string | null = null;
  try {
    rules = await api.listAlertRules();
    events = await api.listAlertEvents(50);
  } catch (e) {
    error = (e as Error).message;
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Alerts"
        description={
          <>Threshold rules over Claude metrics. Routed to Slack, PagerDuty, or
          a webhook on fire.</>
        }
      />

      {params.error && (
        <ErrorNote message={decodeURIComponent(params.error)} title="Action failed" />
      )}
      {error && <ErrorNote message={error} title="Control plane unreachable" />}

      <Card title="Create rule">
        <form action={createRuleAction} className="grid grid-cols-1 gap-3 md:grid-cols-3">
          <label className="flex flex-col gap-1 text-xs md:col-span-3">
            <span className="text-foreground/60">Name</span>
            <input
              name="name"
              required
              placeholder="High Opus spend per hour"
              className="rounded border border-border bg-background px-2 py-1 text-sm"
            />
          </label>
          <label className="flex flex-col gap-1 text-xs">
            <span className="text-foreground/60">Metric</span>
            <select
              name="metric"
              defaultValue="cost_usd"
              className="rounded border border-border bg-background px-2 py-1 text-sm"
            >
              {METRIC_OPTIONS.map((m) => (
                <option key={m} value={m}>
                  {m}
                </option>
              ))}
            </select>
          </label>
          <label className="flex flex-col gap-1 text-xs">
            <span className="text-foreground/60">Aggregation</span>
            <select
              name="aggregation"
              defaultValue="sum"
              className="rounded border border-border bg-background px-2 py-1 text-sm"
            >
              {AGGREGATION_OPTIONS.map((a) => (
                <option key={a} value={a}>
                  {a}
                </option>
              ))}
            </select>
          </label>
          <label className="flex flex-col gap-1 text-xs">
            <span className="text-foreground/60">Window (min)</span>
            <input
              name="window_minutes"
              type="number"
              defaultValue={15}
              min={1}
              max={1440}
              className="rounded border border-border bg-background px-2 py-1 text-sm"
            />
          </label>
          <label className="flex flex-col gap-1 text-xs">
            <span className="text-foreground/60">Threshold</span>
            <input
              name="threshold"
              type="number"
              step="any"
              defaultValue={100}
              required
              className="rounded border border-border bg-background px-2 py-1 text-sm"
            />
          </label>
          <label className="flex flex-col gap-1 text-xs">
            <span className="text-foreground/60">Comparison</span>
            <select
              name="comparison"
              defaultValue="gt"
              className="rounded border border-border bg-background px-2 py-1 text-sm"
            >
              <option value="gt">&gt;</option>
              <option value="gte">≥</option>
              <option value="lt">&lt;</option>
              <option value="lte">≤</option>
            </select>
          </label>
          <label className="flex flex-col gap-1 text-xs">
            <span className="text-foreground/60">Group by</span>
            <select
              name="group_by"
              defaultValue=""
              className="rounded border border-border bg-background px-2 py-1 text-sm"
            >
              <option value="">(none)</option>
              <option value="model">model</option>
              <option value="agent_id">agent_id</option>
              <option value="project_id">project_id</option>
            </select>
          </label>
          <label className="flex flex-col gap-1 text-xs">
            <span className="text-foreground/60">Filter model</span>
            <input
              name="filter_model"
              placeholder="(any)"
              className="rounded border border-border bg-background px-2 py-1 text-sm"
            />
          </label>
          <label className="flex flex-col gap-1 text-xs">
            <span className="text-foreground/60">Severity</span>
            <select
              name="severity"
              defaultValue="warning"
              className="rounded border border-border bg-background px-2 py-1 text-sm"
            >
              <option value="info">info</option>
              <option value="warning">warning</option>
              <option value="critical">critical</option>
            </select>
          </label>
          <label className="flex flex-col gap-1 text-xs">
            <span className="text-foreground/60">Cooldown (min)</span>
            <input
              name="cooldown_minutes"
              type="number"
              defaultValue={15}
              min={0}
              max={1440}
              className="rounded border border-border bg-background px-2 py-1 text-sm"
            />
          </label>
          <label className="flex flex-col gap-1 text-xs">
            <span className="text-foreground/60">Channel</span>
            <select
              name="channel"
              defaultValue="slack"
              className="rounded border border-border bg-background px-2 py-1 text-sm"
            >
              <option value="slack">Slack webhook</option>
              <option value="pagerduty">PagerDuty</option>
              <option value="webhook">Generic webhook</option>
            </select>
          </label>
          <label className="flex flex-col gap-1 text-xs md:col-span-2">
            <span className="text-foreground/60">
              Target (URL or PagerDuty routing key)
            </span>
            <input
              name="target"
              required
              placeholder="https://hooks.slack.com/services/..."
              className="rounded border border-border bg-background px-2 py-1 text-sm"
            />
          </label>
          <button
            type="submit"
            className="md:col-span-3 self-start rounded bg-accent px-3 py-1.5 text-sm font-medium hover:opacity-90"
          >
            Create rule
          </button>
        </form>
      </Card>

      <Card title={`Rules (${rules.length})`}>
        {rules.length === 0 ? (
          <p className="text-sm text-foreground/60">No alert rules yet.</p>
        ) : (
          <table className="w-full text-left font-mono text-xs">
            <thead className="text-foreground/60">
              <tr>
                <th className="py-1 pr-3">Name</th>
                <th className="py-1 pr-3">Severity</th>
                <th className="py-1 pr-3">Metric</th>
                <th className="py-1 pr-3">Threshold</th>
                <th className="py-1 pr-3">Window</th>
                <th className="py-1 pr-3">Channel</th>
                <th className="py-1" />
              </tr>
            </thead>
            <tbody>
              {rules.map((r) => (
                <tr key={r.id} className="border-t border-border/50">
                  <td className="py-1 pr-3">{r.name}</td>
                  <td className="py-1 pr-3">
                    <SeverityBadge severity={r.severity} />
                  </td>
                  <td className="py-1 pr-3">
                    {r.metric} ({r.aggregation})
                    {r.group_by && (
                      <span className="ml-1 text-foreground/60">/{r.group_by}</span>
                    )}
                  </td>
                  <td className="py-1 pr-3 tabular-nums">
                    {r.comparison} {r.threshold}
                  </td>
                  <td className="py-1 pr-3 tabular-nums">{r.window_minutes}m</td>
                  <td className="py-1 pr-3">{r.channel}</td>
                  <td className="py-1">
                    <form action={evaluateRuleAction}>
                      <input type="hidden" name="rule_id" value={r.id} />
                      <button
                        type="submit"
                        className="rounded border border-border px-2 py-0.5 text-xs hover:bg-muted"
                      >
                        Evaluate now
                      </button>
                    </form>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      <Card title={`Recent firings (${events.length})`}>
        {events.length === 0 ? (
          <p className="text-sm text-foreground/60">No firings yet.</p>
        ) : (
          <table className="w-full text-left font-mono text-xs">
            <thead className="text-foreground/60">
              <tr>
                <th className="py-1 pr-3">Time</th>
                <th className="py-1 pr-3">State</th>
                <th className="py-1 pr-3">Rule</th>
                <th className="py-1 pr-3">Group</th>
                <th className="py-1 pr-3 text-right">Value</th>
                <th className="py-1 pr-3 text-right">Threshold</th>
                <th className="py-1 pr-3">Delivered</th>
                <th className="py-1">Ack</th>
              </tr>
            </thead>
            <tbody>
              {events.map((e) => (
                <tr key={e.id} className="border-t border-border/50 align-top">
                  <td className="py-1 pr-3 tabular-nums">
                    {new Date(e.fired_at).toISOString().slice(0, 19)}
                  </td>
                  <td className="py-1 pr-3">
                    <StateBadge state={e.state} />
                  </td>
                  <td className="py-1 pr-3">{e.rule_id.slice(0, 8)}</td>
                  <td className="py-1 pr-3">{e.group_key ?? "—"}</td>
                  <td className="py-1 pr-3 text-right tabular-nums">
                    {e.metric_value.toFixed(4)}
                  </td>
                  <td className="py-1 pr-3 text-right tabular-nums">
                    {e.threshold}
                  </td>
                  <td className="py-1 pr-3">
                    <span className={clsx(e.delivered ? "text-success" : "text-danger")}>
                      {e.delivered ? "ok" : "fail"}
                    </span>
                    {e.delivery_error && (
                      <div className="text-foreground/60">{e.delivery_error}</div>
                    )}
                  </td>
                  <td className="py-1">
                    {e.state === "firing" ? (
                      <form action={acknowledgeEventAction} className="flex gap-1">
                        <input type="hidden" name="event_id" value={e.id} />
                        <input
                          name="by"
                          placeholder="you@team"
                          required
                          className="rounded border border-border bg-background px-1 py-0.5 text-xs"
                        />
                        <button
                          type="submit"
                          className="rounded border border-border px-2 py-0.5 text-xs hover:bg-muted"
                        >
                          Ack
                        </button>
                      </form>
                    ) : e.acknowledged_by ? (
                      <span className="text-foreground/60">{e.acknowledged_by}</span>
                    ) : (
                      ""
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
