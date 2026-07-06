import { redirect } from "next/navigation";
import { revalidatePath } from "next/cache";
import { Card } from "@/components/Card";
import { SeverityBadge, StatusBadge } from "@/components/SeverityBadge";
import { api, type Finding, type WhoAmI } from "@/lib/api";
import { roleAtLeast } from "@/lib/rbac";

export const dynamic = "force-dynamic";

interface SearchParams {
  status?: string;
  severity?: string;
  source?: string;
  sort?: string;
  include_low_fidelity?: string;
  error?: string;
}

const SOURCE_LABEL: Record<string, string> = {
  detection_engine: "engine",
  agent_report: "agent report",
  ai_sweep: "AI sweep",
};

function RiskBar({ score }: { score: number }) {
  const hue = score >= 60 ? "bg-red-500" : score >= 30 ? "bg-amber-500" : "bg-sky-500";
  return (
    <span className="flex items-center gap-2">
      <span className="h-1.5 w-16 overflow-hidden rounded bg-muted">
        <span
          className={`block h-full ${hue}`}
          style={{ width: `${Math.min(100, score)}%` }}
        />
      </span>
      <span className="tabular-nums text-xs text-foreground/70">{score}</span>
    </span>
  );
}

async function sweepAction(): Promise<void> {
  "use server";
  try {
    await api.sweepFindings();
  } catch (e) {
    redirect(`/findings?error=${encodeURIComponent((e as Error).message)}`);
  }
  revalidatePath("/findings");
  redirect("/findings");
}

export default async function FindingsPage({
  searchParams,
}: {
  searchParams: Promise<SearchParams>;
}) {
  const params = await searchParams;
  let findings: Finding[] = [];
  let me: WhoAmI | null = null;
  let error: string | null = null;
  try {
    [findings, me] = await Promise.all([
      api.listFindings({
        status: params.status,
        severity: params.severity,
        source: params.source,
        sort: params.sort ?? "risk",
        include_low_fidelity: params.include_low_fidelity,
        limit: "200",
      }),
      api.whoami(),
    ]);
  } catch (e) {
    error = (e as Error).message;
  }
  const canOperate = roleAtLeast(me?.role, "analyst");
  const showingLow = params.include_low_fidelity === "true";

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold">Findings</h1>
        <p className="mt-1 text-sm text-foreground/60">
          Every security signal across the org — from the detection engine,
          agents reporting what they find, and proactive AI sweeps — scored by
          severity, impact, and fidelity, ranked by risk.
        </p>
      </header>

      {params.error && (
        <Card title="Action failed">
          <p className="text-sm text-red-400">{params.error}</p>
        </Card>
      )}

      <Card title="Filters">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <form method="get" className="flex flex-wrap gap-3 text-sm">
            <select name="source" defaultValue={params.source ?? ""} className="rounded border border-border bg-background px-2 py-1">
              <option value="">any source</option>
              {["detection_engine", "agent_report", "ai_sweep"].map((s) => (
                <option key={s} value={s}>{SOURCE_LABEL[s]}</option>
              ))}
            </select>
            <select name="severity" defaultValue={params.severity ?? ""} className="rounded border border-border bg-background px-2 py-1">
              <option value="">any severity</option>
              {["critical", "high", "medium", "low", "info"].map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
            <select name="sort" defaultValue={params.sort ?? "risk"} className="rounded border border-border bg-background px-2 py-1">
              <option value="risk">sort: risk</option>
              <option value="last_seen">sort: newest</option>
            </select>
            <label className="flex items-center gap-1 text-xs text-foreground/70">
              <input type="checkbox" name="include_low_fidelity" value="true" defaultChecked={showingLow} />
              show low-fidelity
            </label>
            <button type="submit" className="rounded bg-foreground px-3 py-1 text-background">
              Apply
            </button>
          </form>
          {canOperate && (
            <form action={sweepAction}>
              <button type="submit" className="rounded border border-border px-3 py-1 text-sm hover:bg-muted">
                Run AI sweep
              </button>
            </form>
          )}
        </div>
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
                  <th className="py-2 pr-4">Risk</th>
                  <th className="py-2 pr-4">Severity</th>
                  <th className="py-2 pr-4">Impact</th>
                  <th className="py-2 pr-4">Fidelity</th>
                  <th className="py-2 pr-4">Title</th>
                  <th className="py-2 pr-4">Source</th>
                  <th className="py-2 pr-4">Status</th>
                  <th className="py-2 pr-4">Mapping</th>
                  <th className="py-2 pr-4">Last seen</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f) => (
                  <tr key={f.id} className="border-t border-border/60">
                    <td className="py-2 pr-4"><RiskBar score={f.risk_score} /></td>
                    <td className="py-2 pr-4"><SeverityBadge severity={f.severity} /></td>
                    <td className="py-2 pr-4 text-xs text-foreground/70">{f.impact}</td>
                    <td className="py-2 pr-4 tabular-nums text-xs text-foreground/70">
                      {(f.fidelity * 100).toFixed(0)}%
                    </td>
                    <td className="py-2 pr-4">{f.title}</td>
                    <td className="py-2 pr-4 text-xs text-foreground/60">
                      {SOURCE_LABEL[f.source] ?? f.source}
                    </td>
                    <td className="py-2 pr-4"><StatusBadge status={f.status} /></td>
                    <td className="py-2 pr-4 font-mono text-xs text-foreground/60">
                      {[f.atlas_technique, f.owasp_llm].filter(Boolean).join(" · ") || "—"}
                    </td>
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
