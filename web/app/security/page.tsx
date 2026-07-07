import { revalidatePath } from "next/cache";
import { Card, Stat } from "@/components/Card";
import {
  api,
  type KillSwitchStatus,
  type Role,
  type SecurityOverview,
  type TelemetryStats,
} from "@/lib/api";
import { roleAtLeast } from "@/lib/rbac";

export const dynamic = "force-dynamic";

async function engageAction(): Promise<void> {
  "use server";
  await api.engageKillSwitch();
  revalidatePath("/security");
}

async function releaseAction(): Promise<void> {
  "use server";
  await api.releaseKillSwitch();
  revalidatePath("/security");
}

async function breakGlassAction(formData: FormData): Promise<void> {
  "use server";
  await api.grantBreakGlass({
    agent_id: formData.get("agent_id") as string,
    reason: formData.get("reason") as string,
    minutes: Number(formData.get("minutes") ?? 60),
  });
  revalidatePath("/security");
}

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

  // Kill-switch + effective role fetched independently so a failure here can't
  // blank the whole security overview.
  let killswitch: KillSwitchStatus | null = null;
  let role: Role | null = null;
  try {
    [killswitch, role] = await Promise.all([
      api.getKillSwitch(),
      api.whoami().then((w) => w.role),
    ]);
  } catch {
    killswitch = null;
  }
  const isOwner = roleAtLeast(role, "owner");
  const isAdmin = roleAtLeast(role, "admin");

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

      {killswitch && (
        <Card title="Kill-switch (EDR emergency stop)">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <div className="flex items-center gap-2">
                <span
                  className={`inline-flex items-center rounded px-2 py-0.5 text-sm font-medium ring-1 ring-inset ${
                    killswitch.halt_all
                      ? "bg-rose-500/15 text-rose-400 ring-rose-500/30"
                      : "bg-emerald-500/15 text-emerald-400 ring-emerald-500/30"
                  }`}
                >
                  {killswitch.halt_all ? "ENGAGED — all agents halted" : "Normal operation"}
                </span>
              </div>
              <p className="mt-1 text-xs text-foreground/50">
                When engaged, every agent is denied inline except those with an
                active break-glass grant.
              </p>
            </div>
            {isOwner ? (
              killswitch.halt_all ? (
                <form action={releaseAction}>
                  <button
                    type="submit"
                    className="rounded bg-emerald-500/15 px-3 py-1.5 text-sm font-medium text-emerald-400 ring-1 ring-inset ring-emerald-500/30 hover:opacity-90"
                  >
                    Release
                  </button>
                </form>
              ) : (
                <form action={engageAction}>
                  <button
                    type="submit"
                    className="rounded bg-rose-500/15 px-3 py-1.5 text-sm font-medium text-rose-400 ring-1 ring-inset ring-rose-500/30 hover:opacity-90"
                  >
                    Engage kill-switch
                  </button>
                </form>
              )
            ) : (
              <span className="text-xs text-foreground/40">
                Owner role required to engage/release.
              </span>
            )}
          </div>

          {killswitch.active_break_glass.length > 0 && (
            <div className="mt-4">
              <div className="mb-2 text-xs uppercase tracking-wide text-foreground/50">
                Active break-glass grants
              </div>
              <ul className="space-y-1">
                {killswitch.active_break_glass.map((g) => (
                  <li
                    key={g.id}
                    className="flex flex-wrap items-center justify-between gap-2 rounded border border-border/60 bg-background/40 px-3 py-1.5 text-xs"
                  >
                    <span className="font-mono">{g.agent_id}</span>
                    <span className="text-foreground/60">{g.reason}</span>
                    <span className="text-foreground/40">
                      until {g.expires_at.slice(0, 19).replace("T", " ")}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {isAdmin && killswitch.halt_all && (
            <form
              action={breakGlassAction}
              className="mt-4 flex flex-wrap items-end gap-3 border-t border-border/60 pt-4"
            >
              <label className="flex flex-col gap-1 text-xs">
                <span className="text-foreground/60">Break-glass agent</span>
                <input
                  name="agent_id"
                  required
                  className="rounded border border-border bg-background px-2 py-1 text-sm"
                />
              </label>
              <label className="flex flex-col gap-1 text-xs">
                <span className="text-foreground/60">Reason</span>
                <input
                  name="reason"
                  required
                  className="rounded border border-border bg-background px-2 py-1 text-sm"
                />
              </label>
              <label className="flex flex-col gap-1 text-xs">
                <span className="text-foreground/60">Minutes</span>
                <input
                  name="minutes"
                  type="number"
                  defaultValue={60}
                  min={1}
                  max={1440}
                  className="w-24 rounded border border-border bg-background px-2 py-1 text-sm"
                />
              </label>
              <button
                type="submit"
                className="rounded bg-accent px-3 py-1.5 text-sm font-medium hover:opacity-90"
              >
                Grant exception
              </button>
            </form>
          )}
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
