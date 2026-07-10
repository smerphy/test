import { type ReactNode } from "react";
import { Card } from "@/components/Card";

/** Standard page header: title + optional description and right-aligned actions. */
export function PageHeader({
  title,
  description,
  actions,
}: {
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <header className="flex flex-wrap items-start justify-between gap-4">
      <div className="min-w-0">
        <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        {description && (
          <p className="mt-1.5 text-sm text-foreground/60">{description}</p>
        )}
      </div>
      {actions && <div className="shrink-0">{actions}</div>}
    </header>
  );
}

/** Consistent error surface for a failed control-plane fetch. */
export function ErrorNote({
  message,
  title = "Error",
}: {
  message: ReactNode;
  title?: string;
}) {
  return (
    <Card title={title}>
      <pre className="overflow-x-auto font-mono text-xs text-danger">
        {message}
      </pre>
    </Card>
  );
}
