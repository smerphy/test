import { Card } from "@/components/Card";
import { SeverityBadge, StatusBadge } from "@/components/SeverityBadge";
import { api, type Finding } from "@/lib/api";

export const dynamic = "force-dynamic";

interface SearchParams {
  status?: string;
  severity?: string;
  category?: string;
}

export default async function FindingsPage({
  searchParams,
}: {
  searchParams: Promise<SearchParams>;
}) {
  const params = await searchParams;
  let findings: Finding[] = [];
  let error: string | null = null;
  try {
    findings = await api.listFindings({ ...params, limit: "200" });
  } catch (e) {
    error = (e as Error).message;
  }

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold">Findings</h1>
        <p className="mt-1 text-sm text-foreground/60">
          Security detections correlated from agent activity, mapped to MITRE
          ATLAS / OWASP LLM.
        </p>
      </header>

      <Card title="Filters">
        <form method="get" className="flex flex-wrap gap-3 text-sm">
          <select name="status" defaultValue={params.status ?? ""} className="rounded border border-border bg-background px-2 py-1">
            <option value="">any status</option>
            {["open", "triaging", "resolved", "false_positive"].map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
          <select name="severity" defaultValue={params.severity ?? ""} className="rounded border border-border bg-background px-2 py-1">
            <option value="">any severity</option>
            {["critical", "high", "medium", "low", "info"].map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
          <button type="submit" className="rounded bg-foreground px-3 py-1 text-background">
            Apply
          </button>
        </form>
      </Card>

      {error && (
        <Card title="Error">
          <p className="text-sm text-red-400">{error}</p>
        </Card>
      )}

      <Card title={`${findings.length} findings`}>
        {findings.length === 0 ? (
          <p className="text-sm text-foreground/50">No findings.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-left text-xs uppercase tracking-wide text-foreground/50">
                <tr>
                  <th className="py-2 pr-4">Severity</th>
                  <th className="py-2 pr-4">Status</th>
                  <th className="py-2 pr-4">Title</th>
                  <th className="py-2 pr-4">Agent / session</th>
                  <th className="py-2 pr-4">Mapping</th>
                  <th className="py-2 pr-4">Count</th>
                  <th className="py-2 pr-4">Last seen</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f) => (
                  <tr key={f.id} className="border-t border-border/60">
                    <td className="py-2 pr-4"><SeverityBadge severity={f.severity} /></td>
                    <td className="py-2 pr-4"><StatusBadge status={f.status} /></td>
                    <td className="py-2 pr-4">{f.title}</td>
                    <td className="py-2 pr-4 font-mono text-xs text-foreground/70">
                      {f.agent_id ?? "—"}
                      {f.session_id ? ` / ${f.session_id}` : ""}
                    </td>
                    <td className="py-2 pr-4 font-mono text-xs text-foreground/60">
                      {[f.atlas_technique, f.owasp_llm].filter(Boolean).join(" · ") || "—"}
                    </td>
                    <td className="py-2 pr-4 tabular-nums">{f.count}</td>
                    <td className="py-2 pr-4 text-xs text-foreground/60">
                      {new Date(f.last_seen).toLocaleString()}
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
