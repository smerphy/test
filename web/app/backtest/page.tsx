import { BacktestForm } from "@/components/BacktestForm";

export const dynamic = "force-dynamic";

export default function BacktestPage() {
  return (
    <div className="space-y-8">
      <header>
        <h1 className="text-2xl font-semibold">Policy backtest</h1>
        <p className="mt-1 text-sm text-foreground/60">
          Replay recorded audit events through a candidate policy bundle and see
          what would change — before you roll it out.
        </p>
      </header>
      <BacktestForm />
    </div>
  );
}
