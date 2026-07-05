import { Card, Stat } from "@/components/Card";
import { api, type SecurityOverview, type TelemetryStats } from "@/lib/api";

export const dynamic = "force-dynamic";

function Bars({ data }: { data: Record<string, number> }) {
  const entries = Object.entries(data).sort((a, b) => b[1] - a[1]);
  const max = Math.max(1, ...entries.map(([, v]) => v));
  if (entries.length === 0) {
    return <p className="text-sm text-foreground/50">None.</p>;
  }
  return (
    <ul className="space-y-2">
      {entries.map(([k, v]) => (
        <li key={k} className="flex items-center gap-3 text-sm">
          <span className="w-32 shrink-0 truncate text-foreground/70">{k}</span>
          <span className="h-2 flex-1 overflow-hidden rounded bg-muted">
            <span
              className="block h-full rounded bg-foreground/40"
              style={{ width: `${(v / max) * 100}%` }}
            />
          </span>
          <span className="w-10 text-right tabular-nums">{v}</span>
        </li>
      ))}
    </ul>
  );
}

export default async function SecurityPage() {
  let overview: SecurityOverview | null = null;
  let telemetry: TelemetryStats | null = null;
  let error: string | null = null;
  try {
    [overview, telemetry] = await Promise.all([
      api.getOverview(),
      api.getTelemetryStats(),
    ]);
  } catch (e) {
    error = (e as Error).message;
  }

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold">Security overview</h1>
        <p className="mt-1 text-sm text-foreground/60">
          Detection &amp; response posture at a glance.
        </p>
      </header>

      {error && (
        <Card title="Error">
          <p className="text-sm text-red-400">{error}</p>
        </Card>
      )}

      {overview && (
        <>
          <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
            <Stat label="Open findings" value={overview.findings.open_total} />
            <Stat
              label="Critical open"
              value={overview.findings.critical_open}
            />
            <Stat
              label="Active quarantines"
              value={overview.quarantines.active}
            />
            <Stat label="Pending approvals" value={overview.approvals.pending} />
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            <Card title="Open findings by severity">
              <Bars data={overview.findings.by_severity} />
            </Card>
            <Card title="Open findings by category">
              <Bars data={overview.findings.by_category} />
            </Card>
          </div>

          <Card title={`Decision activity (24h) — ${overview.activity_24h.total} total`}>
            <Bars data={overview.activity_24h.decisions} />
          </Card>
        </>
      )}

      {telemetry && (
        <Card title="Event store">
          <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
            <Stat label="Hot audit events" value={telemetry.hot_audit_events} />
            <Stat label="Hot metric events" value={telemetry.hot_metric_events} />
            <Stat
              label="Rolled-up events"
              value={telemetry.rollup_events_total}
            />
            <Stat
              label="Retention (days)"
              value={telemetry.retention_days ?? "∞"}
            />
          </div>
          <p className="mt-3 text-xs text-foreground/50">
            Cold archive {telemetry.archive_enabled ? "enabled" : "disabled"}
            {telemetry.oldest_hot_event
              ? ` · hot window since ${new Date(
                  telemetry.oldest_hot_event
                ).toLocaleDateString()}`
              : ""}
            {telemetry.rollup_days
              ? ` · ${telemetry.rollup_days} day(s) rolled up`
              : ""}
            .
          </p>
        </Card>
      )}
    </div>
  );
}
