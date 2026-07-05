import { redirect } from "next/navigation";
import { revalidatePath } from "next/cache";
import { Card } from "@/components/Card";
import { api, type Member, type Role, type WhoAmI } from "@/lib/api";
import { ROLE_DESCRIPTION, ROLE_ORDER, roleAtLeast } from "@/lib/rbac";

export const dynamic = "force-dynamic";

const ROLE_STYLE: Record<Role, string> = {
  viewer: "bg-slate-500/15 text-slate-400 ring-slate-500/30",
  analyst: "bg-sky-500/15 text-sky-400 ring-sky-500/30",
  admin: "bg-amber-500/15 text-amber-400 ring-amber-500/30",
  owner: "bg-emerald-500/15 text-emerald-400 ring-emerald-500/30",
};

function RoleBadge({ role }: { role: Role }) {
  return (
    <span
      className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs font-medium ring-1 ring-inset ${ROLE_STYLE[role]}`}
    >
      {role}
    </span>
  );
}

async function updateRoleAction(formData: FormData): Promise<void> {
  "use server";
  const id = formData.get("id") as string;
  const role = formData.get("role") as Role;
  try {
    await api.updateMember(id, { role });
  } catch (e) {
    // Surface control-plane errors (e.g. 409 "cannot demote the last owner")
    // back to the page rather than crashing the request.
    redirect(`/members?error=${encodeURIComponent((e as Error).message)}`);
  }
  revalidatePath("/members");
  redirect("/members");
}

export default async function MembersPage({
  searchParams,
}: {
  searchParams: Promise<{ error?: string }>;
}) {
  const { error: actionError } = await searchParams;

  let me: WhoAmI | null = null;
  let members: Member[] = [];
  let loadError: string | null = null;
  try {
    [me, members] = await Promise.all([api.whoami(), api.listMembers()]);
  } catch (e) {
    loadError = (e as Error).message;
  }

  const canManage = roleAtLeast(me?.role, "owner");

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold">Members</h1>
        <p className="mt-1 text-sm text-foreground/60">
          Workspace members and their access roles.{" "}
          {canManage
            ? "As an owner you can change roles."
            : "Only owners can change roles."}
        </p>
      </header>

      {actionError && (
        <Card title="Could not update role">
          <p className="text-sm text-danger">{actionError}</p>
        </Card>
      )}

      {loadError && (
        <Card title="Error">
          <pre className="overflow-x-auto font-mono text-xs text-danger">
            {loadError}
          </pre>
          <p className="mt-2 text-xs text-foreground/60">
            Listing members requires the admin role or higher.
          </p>
        </Card>
      )}

      {!loadError && (
        <Card title={`${members.length} members`}>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-left text-xs uppercase tracking-wide text-foreground/50">
                <tr>
                  <th className="py-2 pr-4">Member</th>
                  <th className="py-2 pr-4">Role</th>
                  {canManage && <th className="py-2 pr-4">Change role</th>}
                </tr>
              </thead>
              <tbody>
                {members.map((m) => (
                  <tr key={m.id} className="border-t border-border/60">
                    <td className="py-2 pr-4">
                      <div className="font-medium">{m.name ?? m.email}</div>
                      <div className="font-mono text-xs text-foreground/50">
                        {m.email}
                        {me?.user_id === m.id ? " (you)" : ""}
                      </div>
                    </td>
                    <td className="py-2 pr-4">
                      <RoleBadge role={m.role} />
                    </td>
                    {canManage && (
                      <td className="py-2 pr-4">
                        <form action={updateRoleAction} className="flex gap-2">
                          <input type="hidden" name="id" value={m.id} />
                          <select
                            name="role"
                            defaultValue={m.role}
                            className="rounded border border-border bg-background px-2 py-1 text-xs"
                          >
                            {ROLE_ORDER.map((r) => (
                              <option key={r} value={r}>
                                {r}
                              </option>
                            ))}
                          </select>
                          <button
                            type="submit"
                            className="rounded bg-foreground px-3 py-1 text-xs text-background hover:opacity-90"
                          >
                            Save
                          </button>
                        </form>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      <Card title="Roles">
        <ul className="space-y-2 text-sm">
          {ROLE_ORDER.slice()
            .reverse()
            .map((r) => (
              <li key={r} className="flex gap-3">
                <span className="w-16 shrink-0">
                  <RoleBadge role={r} />
                </span>
                <span className="text-foreground/70">
                  {ROLE_DESCRIPTION[r]}
                </span>
              </li>
            ))}
        </ul>
      </Card>
    </div>
  );
}
