import { revalidatePath } from "next/cache";
import { Card } from "@/components/Card";
import {
  api,
  type Playbook,
  type PlaybookExecution,
} from "@/lib/api";

export const dynamic = "force-dynamic";

const SEVERITIES = ["info", "low", "medium", "high", "critical"];
const CATEGORIES = [
  "prompt_injection",
  "data_exfil",
  "abuse",
  "policy_violation",
  "approval_abuse",
  "anomaly",
  "threat_intel",
];
// Parameter-free actions safe to configure from the console. Actions that need
// params (tag / set_status / assign) are managed via the API.
const ACTIONS = [
  { value: "quarantine", label: "Quarantine entity" },
  { value: "notify_connectors", label: "Notify connectors" },
  { value: "forward_siem", label: "Forward to SIEM" },
];

async function createAction(formData: FormData): Promise<void> {
  "use server";
  const conditions: Record<string, unknown> = {};
  const minSev = formData.get("min_severity") as string;
  if (minSev && minSev !== "any") conditions.min_severity = minSev;
  const category = formData.get("category") as string;
  if (category && category !== "any") conditions.categories = [category];

  const actions = ACTIONS.filter((a) => formData.get(`action_${a.value}`)).map(
    (a) => ({ type: a.value })
  );

  await api.createPlaybook({
    name: formData.get("name") as string,
    description: (formData.get("description") as string) || undefined,
    priority: Number(formData.get("priority") ?? 100),
    stop_on_match: formData.get("stop_on_match") === "on",
    conditions,
    actions,
  });
  revalidatePath("/soar");
}

async function toggleAction(formData: FormData): Promise<void> {
  "use server";
  await api.setPlaybookEnabled(
    formData.get("id") as string,
    formData.get("enabled") === "true"
  );
  revalidatePath("/soar");
}

function conditionSummary(c: Record<string, unknown>): string {
  const parts: string[] = [];
  if (c.min_severity) parts.push(`severity ≥ ${c.min_severity}`);
  if (Array.isArray(c.categories))
    parts.push(`category ∈ {${(c.categories as string[]).join(", ")}}`);
  if (Array.isArray(c.rule_ids))
    parts.push(`rule ∈ {${(c.rule_ids as string[]).join(", ")}}`);
  if (typeof c.min_risk_score === "number")
    parts.push(`risk ≥ ${c.min_risk_score}`);
  return parts.length ? parts.join(" · ") : "any finding";
}

export default async function SoarPage() {
  let playbooks: Playbook[] = [];
  let executions: PlaybookExecution[] = [];
  let error: string | null = null;
  try {
    [playbooks, executions] = await Promise.all([
      api.listPlaybooks(),
      api.listPlaybookExecutions(25),
    ]);
  } catch (e) {
    error = (e as Error).message;
  }

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold">Response playbooks</h1>
        <p className="mt-1 text-sm text-foreground/60">
          Automated SOAR response: when a new finding matches a playbook&apos;s
          conditions, its actions run in priority order. Every run is recorded.
        </p>
      </header>

      {error && (
        <Card title="Error">
          <pre className="font-mono text-xs text-danger">{error}</pre>
        </Card>
      )}

      <Card title="Playbooks">
        {playbooks.length === 0 ? (
          <p className="text-sm text-foreground/50">No playbooks configured.</p>
        ) : (
          <ul className="space-y-2">
            {playbooks.map((p) => (
              <li
                key={p.id}
                className="flex flex-wrap items-center justify-between gap-3 rounded border border-border/60 bg-background/40 p-3"
              >
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium">{p.name}</span>
                    <span className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs text-foreground/60">
                      prio {p.priority}
                    </span>
                    {p.stop_on_match && (
                      <span className="rounded bg-muted px-1.5 py-0.5 text-xs text-foreground/60">
                        stop-on-match
                      </span>
                    )}
                  </div>
                  <div className="mt-1 text-xs text-foreground/50">
                    {conditionSummary(p.conditions)} →{" "}
                    {p.actions.map((a) => a.type).join(", ") || "no actions"}
                  </div>
                </div>
                <form action={toggleAction}>
                  <input type="hidden" name="id" value={p.id} />
                  <input
                    type="hidden"
                    name="enabled"
                    value={(!p.enabled).toString()}
                  />
                  <button
                    type="submit"
                    className={`rounded px-2 py-1 text-xs font-medium ring-1 ring-inset ${
                      p.enabled
                        ? "bg-emerald-500/15 text-emerald-400 ring-emerald-500/30"
                        : "bg-slate-500/15 text-slate-400 ring-slate-500/30"
                    }`}
                    title="Toggle enabled"
                  >
                    {p.enabled ? "enabled" : "disabled"}
                  </button>
                </form>
              </li>
            ))}
          </ul>
        )}
      </Card>

      <Card title="New playbook">
        <form action={createAction} className="space-y-3">
          <div className="flex flex-wrap items-end gap-3">
            <label className="flex flex-col gap-1 text-xs">
              <span className="text-foreground/60">Name</span>
              <input
                name="name"
                required
                className="rounded border border-border bg-background px-2 py-1 text-sm"
              />
            </label>
            <label className="flex flex-col gap-1 text-xs">
              <span className="text-foreground/60">Priority</span>
              <input
                name="priority"
                type="number"
                defaultValue={100}
                min={0}
                className="w-24 rounded border border-border bg-background px-2 py-1 text-sm"
              />
            </label>
            <label className="flex flex-col gap-1 text-xs">
              <span className="text-foreground/60">Min severity</span>
              <select
                name="min_severity"
                defaultValue="high"
                className="rounded border border-border bg-background px-2 py-1 text-sm"
              >
                <option value="any">any</option>
                {SEVERITIES.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </select>
            </label>
            <label className="flex flex-col gap-1 text-xs">
              <span className="text-foreground/60">Category</span>
              <select
                name="category"
                defaultValue="any"
                className="rounded border border-border bg-background px-2 py-1 text-sm"
              >
                <option value="any">any</option>
                {CATEGORIES.map((c) => (
                  <option key={c} value={c}>
                    {c}
                  </option>
                ))}
              </select>
            </label>
          </div>
          <label className="flex flex-col gap-1 text-xs">
            <span className="text-foreground/60">Description</span>
            <input
              name="description"
              className="w-full rounded border border-border bg-background px-2 py-1 text-sm"
            />
          </label>
          <fieldset className="flex flex-wrap items-center gap-4">
            <span className="text-xs text-foreground/60">Actions:</span>
            {ACTIONS.map((a) => (
              <label key={a.value} className="flex items-center gap-1.5 text-sm">
                <input type="checkbox" name={`action_${a.value}`} />
                {a.label}
              </label>
            ))}
          </fieldset>
          <div className="flex items-center justify-between">
            <label className="flex items-center gap-1.5 text-sm">
              <input type="checkbox" name="stop_on_match" />
              Stop evaluating lower-priority playbooks on match
            </label>
            <button
              type="submit"
              className="rounded bg-accent px-3 py-1.5 text-sm font-medium hover:opacity-90"
            >
              Create playbook
            </button>
          </div>
        </form>
      </Card>

      <Card title="Recent executions">
        {executions.length === 0 ? (
          <p className="text-sm text-foreground/50">No executions yet.</p>
        ) : (
          <ul className="space-y-2">
            {executions.map((e) => (
              <li
                key={e.id}
                className="rounded border border-border/60 bg-background/40 p-3 text-xs"
              >
                <div className="flex justify-between text-foreground/60">
                  <span className="font-mono">finding {e.finding_id.slice(0, 8)}</span>
                  <span>{e.created_at.slice(0, 19).replace("T", " ")}</span>
                </div>
                <div className="mt-1 flex flex-wrap gap-2">
                  {e.results.map((r, i) => (
                    <span
                      key={i}
                      className={`rounded px-1.5 py-0.5 ring-1 ring-inset ${
                        r.ok
                          ? "bg-emerald-500/15 text-emerald-400 ring-emerald-500/30"
                          : "bg-rose-500/15 text-rose-400 ring-rose-500/30"
                      }`}
                      title={r.detail}
                    >
                      {r.type}
                    </span>
                  ))}
                </div>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
