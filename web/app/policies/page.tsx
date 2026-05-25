import Link from "next/link";
import { Card } from "@/components/Card";
import { api, type PolicyBundle, type Project } from "@/lib/api";

export const dynamic = "force-dynamic";

export default async function PoliciesPage() {
  let projects: Project[] = [];
  let bundlesByProject: Record<string, PolicyBundle[]> = {};
  let error: string | null = null;
  try {
    projects = await api.listProjects();
    bundlesByProject = Object.fromEntries(
      await Promise.all(
        projects.map(async (p) => [p.id, await api.listBundles(p.id)] as const)
      )
    );
  } catch (e) {
    error = (e as Error).message;
  }

  return (
    <div className="space-y-8">
      <header>
        <h1 className="text-2xl font-semibold">Policies</h1>
        <p className="mt-1 text-sm text-foreground/60">
          Policy bundles grouped by project. New versions are immutable; roll
          back by activating a prior version.
        </p>
      </header>

      {error && (
        <Card title="Control plane unreachable">
          <pre className="font-mono text-xs text-danger">{error}</pre>
        </Card>
      )}

      {projects.length === 0 && !error && (
        <Card>
          <p className="text-sm text-foreground/60">
            No projects yet. Create one with{" "}
            <code className="font-mono text-foreground">
              POST /projects
            </code>{" "}
            on the control plane.
          </p>
        </Card>
      )}

      {projects.map((p) => (
        <Card key={p.id} title={`${p.name} (${p.slug})`}>
          {(bundlesByProject[p.id] ?? []).length === 0 ? (
            <p className="text-sm text-foreground/60">No bundles.</p>
          ) : (
            <ul className="divide-y divide-border">
              {(bundlesByProject[p.id] ?? []).map((b) => (
                <li
                  key={b.id}
                  className="flex items-center justify-between py-2"
                >
                  <div>
                    <Link
                      href={{ pathname: `/policies/${b.id}` }}
                      className="font-medium hover:underline"
                    >
                      {b.name}
                    </Link>
                    {b.description && (
                      <div className="text-xs text-foreground/60">
                        {b.description}
                      </div>
                    )}
                  </div>
                  <div className="font-mono text-xs text-foreground/60">
                    {b.version_count} {b.version_count === 1 ? "version" : "versions"}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Card>
      ))}
    </div>
  );
}
