import { revalidatePath } from "next/cache";
import { Card } from "@/components/Card";
import { api, type ApprovalRequest } from "@/lib/api";

export const dynamic = "force-dynamic";

async function resolveAction(formData: FormData): Promise<void> {
  "use server";
  const id = formData.get("id") as string;
  const decision = formData.get("decision") as string;
  const resolved_by = (formData.get("resolved_by") as string) || undefined;
  await api.resolveApproval(id, decision === "approve", resolved_by);
  revalidatePath("/approvals");
}

export default async function ApprovalsPage() {
  let approvals: ApprovalRequest[] = [];
  let error: string | null = null;
  try {
    approvals = await api.listApprovals("pending");
  } catch (e) {
    error = (e as Error).message;
  }

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold">Approvals</h1>
        <p className="mt-1 text-sm text-foreground/60">
          Tool calls awaiting human authorization.
        </p>
      </header>

      {error && (
        <Card title="Error">
          <pre className="font-mono text-xs text-danger">{error}</pre>
        </Card>
      )}

      {approvals.length === 0 && !error ? (
        <Card>
          <p className="text-sm text-foreground/60">No pending approvals.</p>
        </Card>
      ) : (
        approvals.map((a) => (
          <Card key={a.id}>
            <div className="flex items-start justify-between gap-6">
              <div className="space-y-1">
                <div className="font-mono text-sm font-semibold">
                  {a.tool_name}
                </div>
                <div className="text-xs text-foreground/60">
                  {a.policy_id && (
                    <>
                      policy <code>{a.policy_id}</code> ·{" "}
                    </>
                  )}
                  agent <code>{a.agent_id}</code> · session{" "}
                  <code>{a.session_id}</code>
                </div>
                <p className="text-sm">{a.reason}</p>
                <pre className="overflow-x-auto rounded bg-background p-2 font-mono text-xs">
                  {JSON.stringify(a.tool_arguments, null, 2)}
                </pre>
              </div>

              <form
                action={resolveAction}
                className="flex shrink-0 flex-col gap-2"
              >
                <input type="hidden" name="id" value={a.id} />
                <input
                  name="resolved_by"
                  placeholder="your email"
                  className="rounded border border-border bg-background px-2 py-1 text-xs"
                />
                <div className="flex gap-2">
                  <button
                    type="submit"
                    name="decision"
                    value="approve"
                    className="rounded bg-success px-3 py-1.5 text-xs font-medium text-background hover:opacity-90"
                  >
                    Approve
                  </button>
                  <button
                    type="submit"
                    name="decision"
                    value="deny"
                    className="rounded bg-danger px-3 py-1.5 text-xs font-medium text-background hover:opacity-90"
                  >
                    Deny
                  </button>
                </div>
              </form>
            </div>
          </Card>
        ))
      )}
    </div>
  );
}
