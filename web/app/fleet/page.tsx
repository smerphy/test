import { Card } from "@/components/Card";
import { ErrorNote, PageHeader } from "@/components/Page";
import { api, type Agent, type Quarantine } from "@/lib/api";

export const dynamic = "force-dynamic";

export default async function FleetPage() {
  let agents: Agent[] = [];
  let quarantines: Quarantine[] = [];
  let error: string | null = null;
  try {
    [agents, quarantines] = await Promise.all([
      api.listAgents(),
      api.listQuarantines(),
    ]);
  } catch (e) {
    error = (e as Error).message;
  }

  const quarantinedAgents = new Set(
    quarantines.map((q) => q.agent_id).filter(Boolean) as string[]
  );

  return (
    <div className="space-y-6">
      <PageHeader
        title="Fleet"
        description={
          <>Registered agent sensors and their health.</>
        }
      />

      {error && <ErrorNote message={error} />}

      <Card title={`${quarantines.length} active quarantines`}>
        {quarantines.length === 0 ? (
          <p className="text-sm text-foreground/50">None.</p>
        ) : (
          <ul className="space-y-1 text-sm">
            {quarantines.map((q) => (
              <li key={q.id} className="flex gap-2">
                <span className="font-mono text-xs text-red-400">
                  {q.agent_id ?? q.session_id}
                </span>
                <span className="text-foreground/60">— {q.reason}</span>
                <span className="text-xs text-foreground/40">({q.source})</span>
              </li>
            ))}
          </ul>
        )}
      </Card>

      <Card title={`${agents.length} agents`}>
        {agents.length === 0 ? (
          <p className="text-sm text-foreground/50">No agents have reported in.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-left text-xs uppercase tracking-wide text-foreground/50">
                <tr>
                  <th className="py-2 pr-4">Agent</th>
                  <th className="py-2 pr-4">Health</th>
                  <th className="py-2 pr-4">SDK</th>
                  <th className="py-2 pr-4">Last seen</th>
                </tr>
              </thead>
              <tbody>
                {agents.map((a) => (
                  <tr key={a.id} className="border-t border-border/60">
                    <td className="py-2 pr-4">
                      <span className="font-mono text-xs">{a.agent_id}</span>
                      {a.name ? (
                        <span className="ml-2 text-foreground/60">{a.name}</span>
                      ) : null}
                      {quarantinedAgents.has(a.agent_id) ? (
                        <span className="ml-2 text-xs text-red-400">quarantined</span>
                      ) : null}
                    </td>
                    <td className="py-2 pr-4">
                      <span
                        className={
                          a.health === "active"
                            ? "text-emerald-400"
                            : "text-amber-400"
                        }
                      >
                        {a.health}
                      </span>
                    </td>
                    <td className="py-2 pr-4 font-mono text-xs text-foreground/60">
                      {a.sdk_version ?? "—"}
                    </td>
                    <td className="py-2 pr-4 text-xs text-foreground/60">
                      {new Date(a.last_seen).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
