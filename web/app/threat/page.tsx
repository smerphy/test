import { redirect } from "next/navigation";
import { revalidatePath } from "next/cache";
import { Card } from "@/components/Card";
import { ErrorNote, PageHeader } from "@/components/Page";
import { SeverityBadge } from "@/components/SeverityBadge";
import {
  api,
  type ThreatFeed,
  type ThreatIndicator,
  type WhoAmI,
} from "@/lib/api";
import { roleAtLeast } from "@/lib/rbac";

export const dynamic = "force-dynamic";

const INDICATOR_TYPES = [
  "domain",
  "ip",
  "url",
  "sha256",
  "md5",
  "email",
  "tool_name",
  "package",
  "prompt_signature",
  "regex",
];
const FEED_FORMATS = ["plaintext", "json", "csv", "stix", "misp", "taxii"];

const STATUS_STYLE: Record<string, string> = {
  ok: "text-emerald-400",
  error: "text-red-400",
  never: "text-foreground/40",
};

function fail(e: unknown): never {
  redirect(`/threat?error=${encodeURIComponent((e as Error).message)}`);
}

async function addFeedAction(formData: FormData): Promise<void> {
  "use server";
  const body = {
    name: String(formData.get("name") || "").trim(),
    format: String(formData.get("format") || "plaintext"),
    url: String(formData.get("url") || "").trim() || undefined,
    default_indicator_type:
      String(formData.get("default_indicator_type") || "").trim() || undefined,
  };
  try {
    await api.createFeed(body);
  } catch (e) {
    fail(e);
  }
  revalidatePath("/threat");
  redirect("/threat");
}

async function syncFeedAction(formData: FormData): Promise<void> {
  "use server";
  const id = String(formData.get("id"));
  let syncError: string | null = null;
  try {
    const r = await api.syncFeed(id);
    if (r.status === "error") {
      syncError = r.error ?? "sync failed";
    }
  } catch (e) {
    fail(e);
  }
  revalidatePath("/threat");
  // redirect() throws NEXT_REDIRECT, so it must live outside the try — inside,
  // the catch would swallow it and surface "NEXT_REDIRECT" as the error.
  if (syncError !== null) {
    redirect(`/threat?error=${encodeURIComponent(syncError)}`);
  }
  redirect("/threat");
}

async function addIndicatorAction(formData: FormData): Promise<void> {
  "use server";
  const body = {
    type: String(formData.get("type") || "domain"),
    value: String(formData.get("value") || "").trim(),
    severity: String(formData.get("severity") || "high"),
  };
  try {
    await api.createIndicator(body);
  } catch (e) {
    fail(e);
  }
  revalidatePath("/threat");
  redirect("/threat");
}

export default async function ThreatPage({
  searchParams,
}: {
  searchParams: Promise<{ error?: string; q?: string; type?: string }>;
}) {
  const params = await searchParams;

  let me: WhoAmI | null = null;
  let feeds: ThreatFeed[] = [];
  let indicators: ThreatIndicator[] = [];
  let error: string | null = null;
  try {
    [me, feeds, indicators] = await Promise.all([
      api.whoami(),
      api.listFeeds(),
      api.listIndicators({ q: params.q, type: params.type, limit: "200" }),
    ]);
  } catch (e) {
    error = (e as Error).message;
  }

  const canManageFeeds = roleAtLeast(me?.role, "admin");
  const canOperate = roleAtLeast(me?.role, "analyst");

  return (
    <div className="space-y-6">
      <PageHeader
        title="Threat intelligence"
        description={
          <>Ingest IOC feeds (STIX / MISP / CSV / JSON / lists). Indicators are
          matched against agent activity and raise threat-intel findings.</>
        }
      />

      {params.error && (
        <Card title="Action failed">
          <p className="text-sm text-red-400">{params.error}</p>
        </Card>
      )}
      {error && <ErrorNote message={error} />}

      <Card title={`${feeds.length} feeds`}>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-left text-xs uppercase tracking-wide text-foreground/50">
              <tr>
                <th className="py-2 pr-4">Feed</th>
                <th className="py-2 pr-4">Format</th>
                <th className="py-2 pr-4">Status</th>
                <th className="py-2 pr-4">Indicators</th>
                <th className="py-2 pr-4">Last synced</th>
                {canOperate && <th className="py-2 pr-4" />}
              </tr>
            </thead>
            <tbody>
              {feeds.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-3 text-foreground/50">
                    No feeds configured.
                  </td>
                </tr>
              ) : (
                feeds.map((f) => (
                  <tr key={f.id} className="border-t border-border/60">
                    <td className="py-2 pr-4">
                      <div className="font-medium">{f.name}</div>
                      <div className="font-mono text-xs text-foreground/40">
                        {f.url ?? "manual"}
                      </div>
                      {f.last_error ? (
                        <div className="text-xs text-red-400/80">
                          {f.last_error}
                        </div>
                      ) : null}
                    </td>
                    <td className="py-2 pr-4 font-mono text-xs">{f.format}</td>
                    <td
                      className={`py-2 pr-4 ${
                        STATUS_STYLE[f.last_status] ?? "text-foreground/60"
                      }`}
                    >
                      {f.last_status}
                    </td>
                    <td className="py-2 pr-4 tabular-nums">
                      {f.indicator_count}
                    </td>
                    <td className="py-2 pr-4 text-xs text-foreground/60">
                      {f.last_synced_at
                        ? new Date(f.last_synced_at).toLocaleString()
                        : "—"}
                    </td>
                    {canOperate && (
                      <td className="py-2 pr-4">
                        <form action={syncFeedAction}>
                          <input type="hidden" name="id" value={f.id} />
                          <button
                            type="submit"
                            className="rounded border border-border px-2 py-1 text-xs hover:bg-muted"
                          >
                            Sync
                          </button>
                        </form>
                      </td>
                    )}
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {canManageFeeds && (
          <form
            action={addFeedAction}
            className="mt-4 flex flex-wrap items-end gap-2 border-t border-border/60 pt-4 text-sm"
          >
            <input
              name="name"
              required
              placeholder="feed name"
              className="rounded border border-border bg-background px-2 py-1"
            />
            <select
              name="format"
              className="rounded border border-border bg-background px-2 py-1"
            >
              {FEED_FORMATS.map((f) => (
                <option key={f} value={f}>
                  {f}
                </option>
              ))}
            </select>
            <select
              name="default_indicator_type"
              className="rounded border border-border bg-background px-2 py-1"
            >
              <option value="">default type (plaintext/json)</option>
              {INDICATOR_TYPES.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
            <input
              name="url"
              placeholder="https://feed.url (blank = manual)"
              className="min-w-[16rem] flex-1 rounded border border-border bg-background px-2 py-1"
            />
            <button
              type="submit"
              className="rounded bg-foreground px-3 py-1 text-background hover:opacity-90"
            >
              Add feed
            </button>
          </form>
        )}
      </Card>

      <Card title={`${indicators.length} indicators`}>
        <form method="get" className="mb-3 flex flex-wrap gap-2 text-sm">
          <select
            name="type"
            defaultValue={params.type ?? ""}
            className="rounded border border-border bg-background px-2 py-1"
          >
            <option value="">any type</option>
            {INDICATOR_TYPES.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
          <input
            name="q"
            defaultValue={params.q ?? ""}
            placeholder="search value"
            className="rounded border border-border bg-background px-2 py-1"
          />
          <button
            type="submit"
            className="rounded bg-foreground px-3 py-1 text-background"
          >
            Search
          </button>
        </form>

        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-left text-xs uppercase tracking-wide text-foreground/50">
              <tr>
                <th className="py-2 pr-4">Type</th>
                <th className="py-2 pr-4">Value</th>
                <th className="py-2 pr-4">Severity</th>
                <th className="py-2 pr-4">Conf.</th>
                <th className="py-2 pr-4">Source</th>
                <th className="py-2 pr-4">Expires</th>
              </tr>
            </thead>
            <tbody>
              {indicators.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-3 text-foreground/50">
                    No indicators.
                  </td>
                </tr>
              ) : (
                indicators.map((i) => (
                  <tr key={i.id} className="border-t border-border/60">
                    <td className="py-2 pr-4 font-mono text-xs">{i.type}</td>
                    <td className="py-2 pr-4 font-mono text-xs">{i.value}</td>
                    <td className="py-2 pr-4">
                      <SeverityBadge severity={i.severity} />
                    </td>
                    <td className="py-2 pr-4 tabular-nums">{i.confidence}</td>
                    <td className="py-2 pr-4 text-xs text-foreground/50">
                      {i.feed_id ? "feed" : "manual"}
                    </td>
                    <td className="py-2 pr-4 text-xs text-foreground/60">
                      {i.expires_at
                        ? new Date(i.expires_at).toLocaleDateString()
                        : "—"}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {canOperate && (
          <form
            action={addIndicatorAction}
            className="mt-4 flex flex-wrap items-end gap-2 border-t border-border/60 pt-4 text-sm"
          >
            <select
              name="type"
              className="rounded border border-border bg-background px-2 py-1"
            >
              {INDICATOR_TYPES.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
            <input
              name="value"
              required
              placeholder="indicator value"
              className="min-w-[16rem] flex-1 rounded border border-border bg-background px-2 py-1"
            />
            <select
              name="severity"
              defaultValue="high"
              className="rounded border border-border bg-background px-2 py-1"
            >
              {["critical", "high", "medium", "low", "info"].map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
            <button
              type="submit"
              className="rounded bg-foreground px-3 py-1 text-background hover:opacity-90"
            >
              Add indicator
            </button>
          </form>
        )}
      </Card>
    </div>
  );
}
