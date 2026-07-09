import { BacktestForm } from "@/components/BacktestForm";
import { PageHeader } from "@/components/Page";

export const dynamic = "force-dynamic";

export default function BacktestPage() {
  return (
    <div className="space-y-8">
      <PageHeader
        title="Policy backtest"
        description={
          <>Replay recorded audit events through a candidate policy bundle and see
          what would change — before you roll it out.</>
        }
      />
      <BacktestForm />
    </div>
  );
}
