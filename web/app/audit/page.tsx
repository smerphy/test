import { Card } from "@/components/Card";
import { DecisionBadge } from "@/components/DecisionBadge";
import { api, type AuditEvent } from "@/lib/api";

export const dynamic = "force-dynamic";

interface SearchParams {
  agent_id?: string;
  tool_name?: string;
  decision?: string;
  session_id?: string;
}

export default async function AuditPage({
  searchParams,
}: {
  searchParams: Promise<SearchParams>;
}) {
  const params = await searchParams;
  let events: AuditEvent[] = [];
  let error: string | null = null;
  try {
    events = await api.searchAudit({ ...params, limit: "200" });
  } catch (e) {
    error = (e as Error).message;
  }

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold">Audit</h1>
        <p className="mt-1 text-sm text-foreground/60">
          Every policy decision, in order. Filters compose; the URL is the
          permalink.
        </p>
      </header>

      <Card title="Filters">
        <form
          method="get"
          className="grid grid-cols-1 gap-3 md:grid-cols-4"
        >
          {(["agent_id", "tool_name", "session_id", "decision"] as const).map(
            (key) => (
              <label key={key} className="flex flex-col gap-1 text-xs">
                <span className="text-foreground/60">{key}</span>
                <input
                  name={key}
                  defaultValue={params[key] ?? ""}
                  className="rounded border border-border bg-background px-2 py-1 font-mono text-sm"
                />
              </label>
            )
          )}
          <button
            type="submit"
            className="md:col-span-4 self-start rounded bg-accent px-3 py-1.5 text-sm font-medium hover:opacity-90"
          >
            Search
          </button>
        </form>
      </Card>

      {error && (
        <Card title="Error">
          <pre className="font-mono text-xs text-danger">{error}</pre>
        </Card>
      )}

      <Card title={`Events (${events.length})`}>
        {events.length === 0 ? (
          <p className="text-sm text-foreground/60">No events match.</p>
        ) : (
          <table className="w-full text-left font-mono text-xs">
            <thead className="text-foreground/60">
              <tr>
                <th className="py-1 pr-3">Time</th>
                <th className="py-1 pr-3">Agent</th>
                <th className="py-1 pr-3">Session</th>
                <th className="py-1 pr-3">Tool</th>
                <th className="py-1 pr-3">Decision</th>
                <th className="py-1 pr-3">Policy</th>
                <th className="py-1">Reason</th>
              </tr>
            </thead>
            <tbody>
              {events.map((e) => (
                <tr key={e.id} className="border-t border-border/50 align-top">
                  <td className="py-1 pr-3 tabular-nums">
                    {new Date(e.timestamp).toISOString().slice(11, 19)}
                  </td>
                  <td className="py-1 pr-3">{e.agent_id}</td>
                  <td className="py-1 pr-3 text-foreground/60">
                    {e.session_id.slice(0, 12)}…
                  </td>
                  <td className="py-1 pr-3">{e.tool_name}</td>
                  <td className="py-1 pr-3">
                    <DecisionBadge decision={e.decision} />
                  </td>
                  <td className="py-1 pr-3">{e.matched_policy_id ?? "-"}</td>
                  <td className="py-1 text-foreground/70">{e.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
