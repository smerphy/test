import { Card, Stat } from "@/components/Card";
import { DecisionBadge } from "@/components/DecisionBadge";
import { api, type AuditEvent, type Decision } from "@/lib/api";

export const dynamic = "force-dynamic";

function aggregate(events: AuditEvent[]) {
  const counts: Record<Decision, number> = {
    allow: 0,
    deny: 0,
    transform: 0,
    require_approval: 0,
  };
  const policyCount: Record<string, number> = {};
  for (const e of events) {
    counts[e.decision] += 1;
    if (e.matched_policy_id) {
      policyCount[e.matched_policy_id] =
        (policyCount[e.matched_policy_id] ?? 0) + 1;
    }
  }
  const top = Object.entries(policyCount)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);
  return { counts, top };
}

export default async function DashboardPage() {
  let events: AuditEvent[] = [];
  let error: string | null = null;
  try {
    events = await api.searchAudit({ limit: "500" });
  } catch (e) {
    error = (e as Error).message;
  }

  const { counts, top } = aggregate(events);
  const total = events.length;
  const denyRate = total ? ((counts.deny / total) * 100).toFixed(1) : "0.0";

  return (
    <div className="space-y-8">
      <header>
        <h1 className="text-2xl font-semibold">Dashboard</h1>
        <p className="mt-1 text-sm text-foreground/60">
          Last 500 decisions across all agents.
        </p>
      </header>

      {error ? (
        <Card title="Control plane unreachable">
          <pre className="font-mono text-xs text-danger">{error}</pre>
        </Card>
      ) : (
        <>
          <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
            <Stat label="Total decisions" value={total} />
            <Stat label="Deny rate" value={`${denyRate}%`} />
            <Stat label="Approvals" value={counts.require_approval} />
            <Stat label="Transforms" value={counts.transform} />
          </div>

          <Card title="Top matched policies">
            {top.length === 0 ? (
              <p className="text-sm text-foreground/60">No events yet.</p>
            ) : (
              <ul className="space-y-2 font-mono text-sm">
                {top.map(([id, n]) => (
                  <li key={id} className="flex justify-between">
                    <span>{id}</span>
                    <span className="tabular-nums text-foreground/60">{n}</span>
                  </li>
                ))}
              </ul>
            )}
          </Card>

          <Card title="Recent decisions">
            {events.length === 0 ? (
              <p className="text-sm text-foreground/60">No events yet.</p>
            ) : (
              <table className="w-full text-left font-mono text-xs">
                <thead className="text-foreground/60">
                  <tr>
                    <th className="py-1 pr-3">Timestamp</th>
                    <th className="py-1 pr-3">Agent</th>
                    <th className="py-1 pr-3">Tool</th>
                    <th className="py-1 pr-3">Decision</th>
                    <th className="py-1">Policy</th>
                  </tr>
                </thead>
                <tbody>
                  {events.slice(0, 10).map((e) => (
                    <tr key={e.id} className="border-t border-border/50">
                      <td className="py-1 pr-3 tabular-nums">
                        {new Date(e.timestamp).toISOString().slice(0, 19)}
                      </td>
                      <td className="py-1 pr-3">{e.agent_id}</td>
                      <td className="py-1 pr-3">{e.tool_name}</td>
                      <td className="py-1 pr-3">
                        <DecisionBadge decision={e.decision} />
                      </td>
                      <td className="py-1">{e.matched_policy_id ?? "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Card>
        </>
      )}
    </div>
  );
}
