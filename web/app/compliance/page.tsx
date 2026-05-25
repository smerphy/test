import { revalidatePath } from "next/cache";
import { Card } from "@/components/Card";
import { api, type ComplianceReport } from "@/lib/api";

export const dynamic = "force-dynamic";

const FRAMEWORKS = [
  { value: "nist_ai_rmf", label: "NIST AI RMF" },
  { value: "iso_42001", label: "ISO/IEC 42001" },
  { value: "eu_ai_act", label: "EU AI Act (Art. 14)" },
];

async function generateAction(formData: FormData): Promise<void> {
  "use server";
  await api.createReport({
    framework: formData.get("framework") as string,
    period_start: formData.get("period_start") as string,
    period_end: formData.get("period_end") as string,
  });
  revalidatePath("/compliance");
}

export default async function CompliancePage() {
  let reports: ComplianceReport[] = [];
  let error: string | null = null;
  try {
    reports = await api.listReports();
  } catch (e) {
    error = (e as Error).message;
  }

  const today = new Date().toISOString().slice(0, 10);
  const monthAgo = new Date(Date.now() - 30 * 86_400_000)
    .toISOString()
    .slice(0, 10);

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold">Compliance</h1>
        <p className="mt-1 text-sm text-foreground/60">
          Map policy decisions to framework controls. Reports are
          point-in-time snapshots over a selected period.
        </p>
      </header>

      <Card title="Generate report">
        <form action={generateAction} className="flex flex-wrap items-end gap-3">
          <label className="flex flex-col gap-1 text-xs">
            <span className="text-foreground/60">Framework</span>
            <select
              name="framework"
              className="rounded border border-border bg-background px-2 py-1 text-sm"
            >
              {FRAMEWORKS.map((f) => (
                <option key={f.value} value={f.value}>
                  {f.label}
                </option>
              ))}
            </select>
          </label>
          <label className="flex flex-col gap-1 text-xs">
            <span className="text-foreground/60">From</span>
            <input
              type="date"
              name="period_start"
              defaultValue={monthAgo}
              required
              className="rounded border border-border bg-background px-2 py-1 text-sm"
            />
          </label>
          <label className="flex flex-col gap-1 text-xs">
            <span className="text-foreground/60">To</span>
            <input
              type="date"
              name="period_end"
              defaultValue={today}
              required
              className="rounded border border-border bg-background px-2 py-1 text-sm"
            />
          </label>
          <button
            type="submit"
            className="rounded bg-accent px-3 py-1.5 text-sm font-medium hover:opacity-90"
          >
            Generate
          </button>
        </form>
      </Card>

      {error && (
        <Card title="Error">
          <pre className="font-mono text-xs text-danger">{error}</pre>
        </Card>
      )}

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        {reports.map((r) => (
          <Card key={r.id} title={`${r.framework} · ${r.status}`}>
            <div className="text-xs text-foreground/60">
              {r.period_start.slice(0, 10)} → {r.period_end.slice(0, 10)}
            </div>
            {r.summary ? (
              <div className="mt-3 space-y-2 text-sm">
                <div className="flex justify-between">
                  <span>Total evaluations</span>
                  <span className="tabular-nums">
                    {r.summary.total_evaluations}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span>Deny rate</span>
                  <span className="tabular-nums">
                    {(r.summary.deny_rate * 100).toFixed(1)}%
                  </span>
                </div>
                <div className="flex justify-between">
                  <span>Approval rate</span>
                  <span className="tabular-nums">
                    {(r.summary.approval_rate * 100).toFixed(1)}%
                  </span>
                </div>
                <div className="pt-2 text-xs text-foreground/60">
                  Controls covered: {r.summary.controls.join(", ")}
                </div>
              </div>
            ) : r.error ? (
              <pre className="mt-3 font-mono text-xs text-danger">{r.error}</pre>
            ) : (
              <p className="mt-3 text-sm text-foreground/60">Pending…</p>
            )}
          </Card>
        ))}
      </div>
    </div>
  );
}
