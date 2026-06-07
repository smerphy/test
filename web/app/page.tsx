import Link from "next/link";
import { Card, Stat } from "@/components/Card";
import { api, type AlertEvent, type MetricAggregateResponse } from "@/lib/api";

export const dynamic = "force-dynamic";

function formatUsd(v: number): string {
  return v >= 1
    ? `$${v.toFixed(2)}`
    : v > 0
      ? `$${v.toFixed(4)}`
      : "$0.00";
}

function aggregate(metrics: MetricAggregateResponse) {
  let requests = 0;
  let inputTok = 0;
  let outputTok = 0;
  let cost = 0;
  let errors = 0;
  let durSum = 0;
  for (const b of metrics.buckets) {
    requests += b.request_count;
    inputTok += b.input_tokens;
    outputTok += b.output_tokens;
    cost += b.cost_usd;
    errors += b.error_count;
    durSum += b.avg_duration_ms * b.request_count;
  }
  return {
    requests,
    inputTok,
    outputTok,
    cost,
    errors,
    avgDur: requests > 0 ? durSum / requests : 0,
    errorRate: requests > 0 ? errors / requests : 0,
  };
}

export default async function DashboardPage() {
  let metrics: MetricAggregateResponse | null = null;
  let alerts: AlertEvent[] = [];
  let error: string | null = null;
  try {
    metrics = await api.aggregateMetrics({
      since: new Date(Date.now() - 24 * 3600 * 1000).toISOString(),
      bucket_minutes: "60",
    });
    alerts = await api.listAlertEvents(10);
  } catch (e) {
    error = (e as Error).message;
  }

  const agg = metrics ? aggregate(metrics) : null;

  return (
    <div className="space-y-8">
      <header>
        <h1 className="text-2xl font-semibold">Praetor · Claude monitoring</h1>
        <p className="mt-1 text-sm text-foreground/60">
          Token usage, cost, latency, error rate, and alert firings — last 24h.
        </p>
      </header>

      {error ? (
        <Card title="Control plane unreachable">
          <pre className="font-mono text-xs text-danger">{error}</pre>
        </Card>
      ) : (
        agg && (
          <>
            <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
              <Stat label="Requests" value={agg.requests} />
              <Stat label="Cost (24h)" value={formatUsd(agg.cost)} />
              <Stat
                label="Avg latency"
                value={`${(agg.avgDur / 1000).toFixed(2)}s`}
              />
              <Stat
                label="Error rate"
                value={`${(agg.errorRate * 100).toFixed(2)}%`}
              />
            </div>

            <Card title="Recent alert firings">
              {alerts.length === 0 ? (
                <p className="text-sm text-foreground/60">
                  No alerts firing.{" "}
                  <Link href="/alerts" className="text-accent underline">
                    Create one →
                  </Link>
                </p>
              ) : (
                <table className="w-full text-left font-mono text-xs">
                  <thead className="text-foreground/60">
                    <tr>
                      <th className="py-1 pr-3">When</th>
                      <th className="py-1 pr-3">Rule</th>
                      <th className="py-1 pr-3">Group</th>
                      <th className="py-1 pr-3 text-right">Value</th>
                      <th className="py-1 pr-3 text-right">Threshold</th>
                      <th className="py-1">Delivered</th>
                    </tr>
                  </thead>
                  <tbody>
                    {alerts.map((a) => (
                      <tr key={a.id} className="border-t border-border/50">
                        <td className="py-1 pr-3 tabular-nums">
                          {new Date(a.fired_at).toISOString().slice(11, 19)}
                        </td>
                        <td className="py-1 pr-3">{a.rule_id.slice(0, 8)}</td>
                        <td className="py-1 pr-3">{a.group_key ?? "—"}</td>
                        <td className="py-1 pr-3 text-right tabular-nums">
                          {a.metric_value.toFixed(4)}
                        </td>
                        <td className="py-1 pr-3 text-right tabular-nums">
                          {a.threshold}
                        </td>
                        <td className="py-1">
                          {a.delivered ? "ok" : "failed"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </Card>

            <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
              <Card title="Tokens (in / out)">
                <div className="font-mono text-sm">
                  in: <span className="tabular-nums">{agg.inputTok.toLocaleString()}</span>
                </div>
                <div className="font-mono text-sm">
                  out: <span className="tabular-nums">{agg.outputTok.toLocaleString()}</span>
                </div>
              </Card>
              <Card title="Where to go next">
                <ul className="space-y-1 text-sm">
                  <li>
                    <Link href="/monitoring" className="text-accent underline">
                      Monitoring →
                    </Link>{" "}
                    per-model breakdown, latency, errors
                  </li>
                  <li>
                    <Link href="/alerts" className="text-accent underline">
                      Alerts →
                    </Link>{" "}
                    threshold rules + firing history
                  </li>
                  <li>
                    <Link href="/audit" className="text-accent underline">
                      Audit →
                    </Link>{" "}
                    every policy decision, with filters
                  </li>
                </ul>
              </Card>
              <Card title="Compliance">
                <p className="text-sm text-foreground/60">
                  Generate framework-mapped reports →{" "}
                  <Link href="/compliance" className="text-accent underline">
                    open
                  </Link>
                </p>
              </Card>
            </div>
          </>
        )
      )}
    </div>
  );
}
