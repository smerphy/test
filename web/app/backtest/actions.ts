"use server";

import { api, type BacktestReport } from "@/lib/api";

export type BacktestState = { report?: BacktestReport; error?: string } | null;

export async function runBacktest(
  _prev: BacktestState,
  formData: FormData
): Promise<BacktestState> {
  const yaml_text = String(formData.get("yaml") ?? "");
  const since = String(formData.get("since") ?? "").trim() || undefined;
  if (!yaml_text.trim()) {
    return { error: "Paste a policy bundle to backtest." };
  }
  try {
    return { report: await api.backtestPolicy({ yaml_text, since }) };
  } catch (e) {
    return { error: (e as Error).message };
  }
}
