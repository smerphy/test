import { revalidatePath } from "next/cache";
import { Card } from "@/components/Card";
import {
  api,
  type ComplianceReport,
  type ControlStatus,
  type FrameworkPosture,
  type PostureOverview,
} from "@/lib/api";

export const dynamic = "force-dynamic";

const FRAMEWORKS = [
  { value: "nist_ai_rmf", label: "NIST AI RMF" },
  { value: "iso_42001", label: "ISO/IEC 42001" },
  { value: "eu_ai_act", label: "EU AI Act (Art. 14)" },
];

// Frameworks that expose a live posture assessment (control mapping).
const POSTURE_FRAMEWORKS = ["nist_ai_rmf", "eu_ai_act", "owasp_llm"];

const STATUS_STYLE: Record<ControlStatus, string> = {
  satisfied: "bg-emerald-500/15 text-emerald-400 ring-emerald-500/30",
  partial: "bg-amber-500/15 text-amber-400 ring-amber-500/30",
  gap: "bg-rose-500/15 text-rose-400 ring-rose-500/30",
};

function coverageColor(pct: number): string {
  if (pct >= 0.8) return "bg-emerald-500/70";
  if (pct >= 0.5) return "bg-amber-500/70";
  return "bg-rose-500/70";
}

function CoverageBar({ value }: { value: number }) {
  return (
    <span className="flex items-center gap-3">
      <span className="h-2 w-40 overflow-hidden rounded bg-muted">
        <span
          className={`block h-full rounded ${coverageColor(value)}`}
          style={{ width: `${Math.round(value * 100)}%` }}
        />
      </span>
      <span className="w-10 text-right tabular-nums text-sm">
        {Math.round(value * 100)}%
      </span>
    </span>
  );
}

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
  let overview: PostureOverview | null = null;
  let postures: FrameworkPosture[] = [];
  let error: string | null = null;
  try {
    [reports, overview, postures] = await Promise.all([
      api.listReports(),
      api.getPostureOverview(),
      Promise.all(POSTURE_FRAMEWORKS.map((f) => api.getPosture(f))),
    ]);
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
          Live control posture against AI-governance frameworks, plus
          point-in-time evidence reports over a selected period.
        </p>
      </header>

      {error && (
        <Card title="Error">
          <pre className="font-mono text-xs text-danger">{error}</pre>
        </Card>
      )}

      {overview && (
        <Card title="Live posture">
          <div className="space-y-3">
            {overview.frameworks.map((f) => (
              <div
                key={f.framework}
                className="flex flex-wrap items-center justify-between gap-3"
              >
                <div className="min-w-0">
                  <div className="truncate text-sm font-medium">{f.title}</div>
                  <div className="text-xs text-foreground/50">
                    {f.controls_satisfied} satisfied · {f.controls_partial}{" "}
                    partial · {f.controls_gap} gap
                  </div>
                </div>
                <CoverageBar value={f.coverage} />
              </div>
            ))}
          </div>
          {overview.open_critical_findings > 0 && (
            <p className="mt-4 text-xs text-rose-400">
              {overview.open_critical_findings} open critical finding
              {overview.open_critical_findings === 1 ? "" : "s"} — response
              controls should be reviewed.
            </p>
          )}
        </Card>
      )}

      {postures.map((p) => (
        <Card key={p.framework} title={`${p.title} · controls`}>
          <div className="space-y-2">
            {p.controls.map((c) => (
              <div
                key={c.id}
                className="rounded border border-border/60 bg-background/40 p-3"
              >
                <div className="flex items-center justify-between gap-3">
                  <div className="min-w-0">
                    <span className="font-mono text-xs text-foreground/60">
                      {c.id}
                    </span>{" "}
                    <span className="text-sm font-medium">{c.title}</span>
                  </div>
                  <span
                    className={`inline-flex shrink-0 items-center rounded px-1.5 py-0.5 text-xs font-medium ring-1 ring-inset ${STATUS_STYLE[c.status]}`}
                  >
                    {c.status}
                  </span>
                </div>
                <p className="mt-1 text-xs text-foreground/60">
                  {c.description}
                </p>
                {c.remediation.length > 0 && (
                  <ul className="mt-2 list-inside list-disc text-xs text-amber-400/90">
                    {c.remediation.map((r, i) => (
                      <li key={i}>{r}</li>
                    ))}
                  </ul>
                )}
              </div>
            ))}
          </div>
        </Card>
      ))}

      <Card title="Generate evidence report">
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
