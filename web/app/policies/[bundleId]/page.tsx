import { Card } from "@/components/Card";
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
    versions = await api.listVersions(bundleId);
  } catch (e) {
    error = (e as Error).message;
  }

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold">Bundle versions</h1>
        <p className="mt-1 font-mono text-xs text-foreground/60">
          {bundleId}
        </p>
      </header>

      {error && (
        <Card title="Error">
          <pre className="font-mono text-xs text-danger">{error}</pre>
        </Card>
      )}

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
