"use client";

// Route-level error boundary. Without it, an unhandled Server Action or render
// failure (e.g. the control plane is down when a form is submitted) falls
// through to Next's default full-page error and discards the user's context.
// This degrades gracefully and offers a retry instead.
export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <div className="mx-auto max-w-2xl space-y-4 py-16">
      <h1 className="text-lg font-semibold text-danger">Something went wrong</h1>
      <pre className="overflow-x-auto rounded border border-border bg-muted p-3 font-mono text-xs text-danger">
        {error.message || "Unexpected error"}
      </pre>
      <button
        type="button"
        onClick={reset}
        className="rounded border border-border bg-background px-3 py-1.5 text-sm hover:bg-muted"
      >
        Try again
      </button>
    </div>
  );
}
