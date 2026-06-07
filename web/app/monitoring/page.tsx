import { Card, Stat } from "@/components/Card";
import { api, type MetricAggregateResponse } from "@/lib/api";

export const dynamic = "force-dynamic";

function formatUsd(v: number): string {
  return v >= 1
    ? `$${v.toFixed(2)}`
    : v > 0
      ? `$${v.toFixed(4)}`
      : "$0.00";
}

function summarize(agg: MetricAggregateResponse) {
  let requests = 0;
  let inputT = 0;
  let outputT = 0;
  let cost = 0;
  let errors = 0;
  let durSum = 0;
  for (const b of agg.buckets) {
    requests += b.request_count;
    inputT += b.input_tokens;
    outputT += b.output_tokens;
    cost += b.cost_usd;
    errors += b.error_count;
    durSum += b.avg_duration_ms * b.request_count;
  }
  const avgDur = requests > 0 ? durSum / requests : 0;
  const errorRate = requests > 0 ? errors / requests : 0;
  return { requests, inputT, outputT, cost, errors, avgDur, errorRate };
}

function MiniSparkline({
  values,
  height = 32,
  width = 160,
}: {
  values: number[];
  height?: number;
  width?: number;
}) {
  if (values.length === 0) return <div className="h-8 text-foreground/40">—</div>;
  const max = Math.max(...values, 1);
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

export default async function MonitoringPage() {
  let overall: MetricAggregateResponse | null = null;
  let byModel: MetricAggregateResponse | null = null;
  let error: string | null = null;
  try {
    const since = new Date(Date.now() - 24 * 3600 * 1000).toISOString();
    overall = await api.aggregateMetrics({
      since,
      bucket_minutes: "60",
    });
    byModel = await api.aggregateMetrics({
      since,
      bucket_minutes: "60",
      group_by: "model",
    });
  } catch (e) {
    error = (e as Error).message;
  }

  return (
    <div className="space-y-8">
      <header>
        <h1 className="text-2xl font-semibold">Claude monitoring</h1>
        <p className="mt-1 text-sm text-foreground/60">
          Last 24 hours · 1h buckets · token + cost + latency
        </p>
      </header>

      {error && (
        <Card title="Control plane unreachable">
          <pre className="font-mono text-xs text-danger">{error}</pre>
        </Card>
      )}

      {overall && (
        <>
          {(() => {
            const s = summarize(overall);
            const sparkCost = overall.buckets.map((b) => b.cost_usd);
            const sparkTok = overall.buckets.map((b) => b.total_tokens);
            const sparkReq = overall.buckets.map((b) => b.request_count);
            const sparkErr = overall.buckets.map((b) => b.error_count);
            return (
              <>
                <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
                  <Stat label="Requests" value={s.requests} />
                  <Stat label="Spend (24h)" value={formatUsd(s.cost)} />
                  <Stat
                    label="Avg latency"
                    value={`${(s.avgDur / 1000).toFixed(2)}s`}
                  />
                  <Stat
                    label="Error rate"
                    value={`${(s.errorRate * 100).toFixed(2)}%`}
                  />
                </div>

                <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-4">
                  <Card title="Requests">
                    <MiniSparkline values={sparkReq} />
                  </Card>
                  <Card title="Cost (USD)">
                    <MiniSparkline values={sparkCost} />
                  </Card>
                  <Card title="Tokens">
                    <MiniSparkline values={sparkTok} />
                  </Card>
                  <Card title="Errors">
                    <MiniSparkline values={sparkErr} />
                  </Card>
                </div>
              </>
            );
          })()}

          {byModel && Object.keys(byModel.by_group).length > 0 && (
            <Card title="By model">
              <table className="w-full text-left font-mono text-xs">
                <thead className="text-foreground/60">
                  <tr>
                    <th className="py-1 pr-3">Model</th>
                    <th className="py-1 pr-3 text-right">Requests</th>
                    <th className="py-1 pr-3 text-right">Cost</th>
                    <th className="py-1 pr-3 text-right">In tokens</th>
                    <th className="py-1 pr-3 text-right">Out tokens</th>
                    <th className="py-1 text-right">Avg ms</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(byModel.by_group).map(([model, buckets]) => {
                    const s = summarize({ ...byModel, buckets } as MetricAggregateResponse);
                    return (
                      <tr key={model} className="border-t border-border/50">
                        <td className="py-1 pr-3">{model}</td>
                        <td className="py-1 pr-3 text-right tabular-nums">
                          {s.requests}
                        </td>
                        <td className="py-1 pr-3 text-right tabular-nums">
                          {formatUsd(s.cost)}
                        </td>
                        <td className="py-1 pr-3 text-right tabular-nums">
                          {s.inputT.toLocaleString()}
                        </td>
                        <td className="py-1 pr-3 text-right tabular-nums">
                          {s.outputT.toLocaleString()}
                        </td>
                        <td className="py-1 text-right tabular-nums">
                          {s.avgDur.toFixed(0)}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </Card>
          )}

          {overall.buckets.length === 0 && (
            <Card>
              <p className="text-sm text-foreground/60">
                No metric events in the last 24h. Send some via
                <code className="mx-1 font-mono">AnthropicMonitor</code>
                or
                <code className="mx-1 font-mono">POST /metrics/events</code>.
              </p>
            </Card>
          )}
        </>
      )}
    </div>
  );
}
