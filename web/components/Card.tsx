import { type ReactNode } from "react";
import clsx from "clsx";

export function Card({
  title,
  description,
  actions,
  children,
  className,
}: {
  title?: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section
      className={clsx(
        "rounded-xl border border-border bg-surface p-5 shadow-sm",
        className
      )}
    >
      {(title || actions) && (
        <div className="mb-3 flex items-start justify-between gap-3">
          <div className="min-w-0">
            {title && (
              <h2 className="text-xs font-semibold uppercase tracking-wider text-foreground/55">
                {title}
              </h2>
            )}
            {description && (
              <p className="mt-1 text-sm text-foreground/60">{description}</p>
            )}
          </div>
          {actions && <div className="shrink-0">{actions}</div>}
        </div>
      )}
      {children}
    </section>
  );
}

export function Stat({
  label,
  value,
  hint,
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
}) {
  return (
    <div className="rounded-xl border border-border bg-surface p-5 shadow-sm">
      <div className="text-xs font-medium uppercase tracking-wider text-foreground/55">
        {label}
      </div>
      <div className="mt-2 text-3xl font-semibold tabular-nums tracking-tight">
        {value}
      </div>
      {hint && <div className="mt-1 text-xs text-foreground/50">{hint}</div>}
    </div>
  );
}
