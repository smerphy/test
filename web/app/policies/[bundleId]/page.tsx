import { Card } from "@/components/Card";
import { ErrorNote, PageHeader } from "@/components/Page";
import { api, type PolicyVersion } from "@/lib/api";

export const dynamic = "force-dynamic";

export default async function BundleDetailPage({
  params,
}: {
  params: Promise<{ bundleId: string }>;
}) {
  const { bundleId } = await params;
  let versions: PolicyVersion[] = [];
  let error: string | null = null;
  try {
    // One call fetches every version with its yaml_text (no per-version N+1).
    versions = await api.listVersionsFull(bundleId);
  } catch (e) {
    error = (e as Error).message;
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Bundle versions"
        description={
          <>{bundleId}</>
        }
      />

      {error && <ErrorNote message={error} />}

      {versions.length === 0 ? (
        <Card>
          <p className="text-sm text-foreground/60">No versions yet.</p>
        </Card>
      ) : (
        versions
          .slice()
          .reverse()
          .map((v) => (
            <Card
              key={v.id}
              title={`v${v.version_number} — ${v.policy_count} ${v.policy_count === 1 ? "policy" : "policies"}`}
            >
              <div className="mb-2 text-xs text-foreground/60">
                {v.author_email && <>by {v.author_email} · </>}
                {new Date(v.created_at).toISOString().slice(0, 19)}
                {v.notes && <> · {v.notes}</>}
              </div>
              <pre className="overflow-x-auto rounded bg-background p-3 font-mono text-xs leading-relaxed">
                {v.yaml_text}
              </pre>
            </Card>
          ))
      )}
    </div>
  );
}
