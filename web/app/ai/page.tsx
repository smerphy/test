import { redirect } from "next/navigation";
import { revalidatePath } from "next/cache";
import { Card } from "@/components/Card";
import { SeverityBadge } from "@/components/SeverityBadge";
import {
  api,
  type AIConfig,
  type RuleSuggestion,
  type WhoAmI,
} from "@/lib/api";
import { roleAtLeast } from "@/lib/rbac";

export const dynamic = "force-dynamic";

function fail(e: unknown): never {
  redirect(`/ai?error=${encodeURIComponent((e as Error).message)}`);
}

async function saveConfigAction(formData: FormData): Promise<void> {
  "use server";
  const body: Record<string, unknown> = {
    ai_enabled: formData.get("ai_enabled") === "on",
    ai_mode: String(formData.get("ai_mode") || "advisory"),
    ai_provider: String(formData.get("ai_provider") || "anthropic"),
    ai_model: String(formData.get("ai_model") || "").trim(),
    ai_base_url: String(formData.get("ai_base_url") || "").trim(),
  };
  const key = String(formData.get("ai_api_key") || "");
  if (key) body.ai_api_key = key;
  try {
    await api.updateAIConfig(body);
  } catch (e) {
    fail(e);
  }
  revalidatePath("/ai");
  redirect("/ai");
}

async function suggestAction(): Promise<void> {
  "use server";
  try {
    await api.suggestRules();
  } catch (e) {
    fail(e);
  }
  revalidatePath("/ai");
  redirect("/ai");
}

async function acceptAction(formData: FormData): Promise<void> {
  "use server";
  try {
    await api.acceptSuggestion(String(formData.get("id")));
  } catch (e) {
    fail(e);
  }
  revalidatePath("/ai");
  redirect("/ai");
}

async function rejectAction(formData: FormData): Promise<void> {
  "use server";
  try {
    await api.rejectSuggestion(String(formData.get("id")));
  } catch (e) {
    fail(e);
  }
  revalidatePath("/ai");
  redirect("/ai");
}

export default async function AIPage({
  searchParams,
}: {
  searchParams: Promise<{ error?: string }>;
}) {
  const { error: actionError } = await searchParams;

  let me: WhoAmI | null = null;
  let config: AIConfig | null = null;
  let suggestions: RuleSuggestion[] = [];
  let error: string | null = null;
  try {
    [me, suggestions] = await Promise.all([
      api.whoami(),
      api.listSuggestions(),
    ]);
    if (roleAtLeast(me.role, "admin")) {
      config = await api.getAIConfig();
    }
  } catch (e) {
    error = (e as Error).message;
  }

  const isAdmin = roleAtLeast(me?.role, "admin");
  const canOperate = roleAtLeast(me?.role, "analyst");
  const pending = suggestions.filter((s) => s.status === "pending");

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold">AI advisory</h1>
        <p className="mt-1 text-sm text-foreground/60">
          Opt-in, bring-your-own-key, vendor-neutral. A multi-agent panel
          advises on ambiguous decisions and proposes rule improvements. The
          deterministic engine stays authoritative — in enforce mode the AI can
          only tighten, never loosen.
        </p>
      </header>

      {actionError && (
        <Card title="Action failed">
          <p className="text-sm text-red-400">{actionError}</p>
        </Card>
      )}
      {error && (
        <Card title="Error">
          <pre className="overflow-x-auto font-mono text-xs text-red-400">
            {error}
          </pre>
        </Card>
      )}

      {isAdmin && config && (
        <Card title="Configuration">
          <form action={saveConfigAction} className="space-y-3 text-sm">
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                name="ai_enabled"
                defaultChecked={config.ai_enabled}
              />
              <span>Enable AI advisory for this workspace</span>
            </label>
            <div className="grid gap-3 md:grid-cols-2">
              <label className="space-y-1">
                <span className="text-xs text-foreground/60">Mode</span>
                <select
                  name="ai_mode"
                  defaultValue={config.ai_mode}
                  className="w-full rounded border border-border bg-background px-2 py-1"
                >
                  <option value="advisory">advisory (recommend only)</option>
                  <option value="enforce">enforce (may tighten)</option>
                </select>
              </label>
              <label className="space-y-1">
                <span className="text-xs text-foreground/60">Provider</span>
                <select
                  name="ai_provider"
                  defaultValue={config.ai_provider || "anthropic"}
                  className="w-full rounded border border-border bg-background px-2 py-1"
                >
                  <option value="anthropic">anthropic (Messages API)</option>
                  <option value="openai_compat">
                    openai_compat (OpenAI / Azure / Groq / Ollama / …)
                  </option>
                </select>
              </label>
              <label className="space-y-1">
                <span className="text-xs text-foreground/60">Model</span>
                <input
                  name="ai_model"
                  defaultValue={config.ai_model}
                  placeholder="claude-… / gpt-… / llama-…"
                  className="w-full rounded border border-border bg-background px-2 py-1"
                />
              </label>
              <label className="space-y-1">
                <span className="text-xs text-foreground/60">
                  Base URL (optional)
                </span>
                <input
                  name="ai_base_url"
                  defaultValue={config.ai_base_url ?? ""}
                  placeholder="https://api.openai.com/v1"
                  className="w-full rounded border border-border bg-background px-2 py-1"
                />
              </label>
              <label className="space-y-1 md:col-span-2">
                <span className="text-xs text-foreground/60">
                  API key{" "}
                  {config.ai_key_set ? "(a key is stored — leave blank to keep)" : ""}
                </span>
                <input
                  name="ai_api_key"
                  type="password"
                  autoComplete="off"
                  placeholder={config.ai_key_set ? "•••••••• stored" : "sk-…"}
                  className="w-full rounded border border-border bg-background px-2 py-1"
                />
              </label>
            </div>
            <button
              type="submit"
              className="rounded bg-foreground px-3 py-1.5 text-background hover:opacity-90"
            >
              Save configuration
            </button>
          </form>
        </Card>
      )}

      <Card title={`Rule suggestions — ${pending.length} pending`}>
        {canOperate && (
          <form action={suggestAction} className="mb-4">
            <button
              type="submit"
              className="rounded border border-border px-3 py-1.5 text-sm hover:bg-muted"
            >
              Generate suggestions from recent activity
            </button>
          </form>
        )}
        {suggestions.length === 0 ? (
          <p className="text-sm text-foreground/50">No suggestions yet.</p>
        ) : (
          <ul className="space-y-3">
            {suggestions.map((s) => (
              <li
                key={s.id}
                className="rounded border border-border/60 p-3 text-sm"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityBadge severity={s.severity} />
                  <span className="font-medium">{s.title}</span>
                  <span className="text-xs text-foreground/40">
                    {s.category} · conf {(s.confidence * 100).toFixed(0)}% ·{" "}
                    {s.status}
                  </span>
                </div>
                <p className="mt-1 text-foreground/70">{s.rationale}</p>
                <pre className="mt-2 overflow-x-auto rounded bg-background p-2 font-mono text-xs text-foreground/70">
                  {JSON.stringify(s.spec, null, 2)}
                </pre>
                {isAdmin && s.status === "pending" && (
                  <div className="mt-2 flex gap-2">
                    <form action={acceptAction}>
                      <input type="hidden" name="id" value={s.id} />
                      <button
                        type="submit"
                        className="rounded bg-emerald-600 px-3 py-1 text-xs font-medium text-white hover:opacity-90"
                      >
                        Accept → create rule
                      </button>
                    </form>
                    <form action={rejectAction}>
                      <input type="hidden" name="id" value={s.id} />
                      <button
                        type="submit"
                        className="rounded border border-border px-3 py-1 text-xs hover:bg-muted"
                      >
                        Reject
                      </button>
                    </form>
                  </div>
                )}
                {s.created_rule_id && (
                  <p className="mt-2 text-xs text-emerald-400">
                    Accepted — detection rule created.
                  </p>
                )}
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
