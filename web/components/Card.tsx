import { type ReactNode } from "react";
import clsx from "clsx";

export function Card({
  title,
  children,
  className,
}: {
  title?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={clsx(
        "rounded-lg border border-border bg-muted/40 p-5 shadow-sm",
        className
      )}
    >
      {title && (
        <div className="mb-3 text-sm font-medium uppercase tracking-wide text-foreground/60">
          {title}
        </div>
      )}
      {children}
    </div>
  );
}

export function Stat({ label, value }: { label: string; value: ReactNode }) {
  return (
    <Card>
      <div className="text-xs uppercase tracking-wide text-foreground/60">
        {label}
      </div>
      <div className="mt-2 text-3xl font-semibold tabular-nums">{value}</div>
    </Card>
  );
}
