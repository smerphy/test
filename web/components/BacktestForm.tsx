"use client";

import { useActionState } from "react";
import { Card, Stat } from "@/components/Card";
import { runBacktest, type BacktestState } from "@/app/backtest/actions";

const _PLACEHOLDER = `policies:
  - id: deny-shell
    effect: deny
    when: { op: eq, path: tool.name, value: shell.exec }
    reason: no shell`;

function DecisionBadge({ value }: { value: string }) {
  const style: Record<string, string> = {
    allow: "bg-emerald-500/15 text-emerald-400 ring-emerald-500/30",
    deny: "bg-danger/15 text-danger ring-danger/30",
    transform: "bg-sky-500/15 text-sky-400 ring-sky-500/30",
    require_approval: "bg-amber-500/15 text-amber-400 ring-amber-500/30",
  };
  return (
    <span
      className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs font-medium ring-1 ring-inset ${
        style[value] ?? "bg-slate-500/15 text-slate-400 ring-slate-500/30"
      }`}
    >
      {value}
    </span>
  );
}

export function BacktestForm() {
  const [state, action, pending] = useActionState<BacktestState, FormData>(
    runBacktest,
    null
  );
  const report = state?.report;

  return (
    <div className="space-y-6">
      <form action={action} className="space-y-3">
        <textarea
          name="yaml"
          rows={12}
          spellCheck={false}
          placeholder={_PLACEHOLDER}
          className="w-full rounded-lg border border-border bg-muted/30 p-3 font-mono text-xs outline-none focus:border-accent"
        />
        <div className="flex items-center gap-3">
          <label className="text-xs text-foreground/60">
            Since (optional)
            <input
              type="datetime-local"
              name="since"
              className="ml-2 rounded border border-border bg-muted/30 px-2 py-1 text-xs"
            />
          </label>
          <button
            type="submit"
            disabled={pending}
            className="rounded bg-accent px-3 py-1.5 text-sm font-medium text-background disabled:opacity-50"
          >
            {pending ? "Replaying…" : "Backtest"}
          </button>
        </div>
      </form>

      {state?.error && (
        <Card title="Backtest failed">
          <pre className="whitespace-pre-wrap font-mono text-xs text-danger">
            {state.error}
          </pre>
        </Card>
      )}

      {report && (
        <>
          <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
            <Stat label="Evaluated" value={report.evaluated.toLocaleString()} />
            <Stat label="Changed" value={report.summary.changed.toLocaleString()} />
            <Stat label="Newly denied" value={report.summary.newly_denied.toLocaleString()} />
            <Stat
              label="Tightened / loosened"
              value={`${report.summary.more_restrictive} / ${report.summary.less_restrictive}`}
            />
          </div>

          {Object.keys(report.transitions).length > 0 && (
            <Card title="Decision transitions">
              <ul className="space-y-1 font-mono text-xs">
                {Object.entries(report.transitions)
                  .sort((a, b) => b[1] - a[1])
                  .map(([k, n]) => (
                    <li key={k} className="flex justify-between">
                      <span>{k}</span>
                      <span className="tabular-nums">{n}</span>
                    </li>
                  ))}
              </ul>
            </Card>
          )}

          {report.examples.length > 0 ? (
            <Card title={`Changed decisions (${report.examples.length} shown)`}>
              <table className="w-full text-left font-mono text-xs">
                <thead className="text-foreground/60">
                  <tr>
                    <th className="py-1 pr-3">Tool</th>
                    <th className="py-1 pr-3">Agent</th>
                    <th className="py-1 pr-3">Was → Now</th>
                    <th className="py-1">Reason</th>
                  </tr>
                </thead>
                <tbody>
                  {report.examples.map((ex) => (
                    <tr key={ex.event_id} className="border-t border-border/50">
                      <td className="py-1 pr-3">{ex.tool_name}</td>
                      <td className="py-1 pr-3">{ex.agent_id}</td>
                      <td className="py-1 pr-3">
                        <DecisionBadge value={ex.old_decision} />{" "}
                        <span className="text-foreground/40">→</span>{" "}
                        <DecisionBadge value={ex.new_decision} />
                      </td>
                      <td className="py-1 text-foreground/70">{ex.new_reason}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Card>
          ) : (
            <Card>
              <p className="text-sm text-foreground/60">
                No decisions would change over {report.evaluated.toLocaleString()}{" "}
                evaluated events.
              </p>
            </Card>
          )}
        </>
      )}
    </div>
  );
}
