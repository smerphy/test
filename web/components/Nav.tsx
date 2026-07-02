import Link from "next/link";

const LINKS: {
  href: "/" | "/monitoring" | "/alerts" | "/policies" | "/audit" | "/approvals" | "/compliance";
  label: string;
}[] = [
  { href: "/", label: "Dashboard" },
  { href: "/monitoring", label: "Monitoring" },
  { href: "/alerts", label: "Alerts" },
  { href: "/policies", label: "Policies" },
  { href: "/audit", label: "Audit" },
  { href: "/approvals", label: "Approvals" },
  { href: "/compliance", label: "Compliance" },
];

export function Nav() {
  return (
    <nav className="border-b border-border bg-muted/30">
      <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-3">
        <Link href="/" className="font-mono text-sm font-semibold tracking-tight">
          praetor<span className="text-foreground/40">/cp</span>
        </Link>
        <ul className="flex items-center gap-4 text-sm">
          {LINKS.map((l) => (
            <li key={l.href}>
              <Link
                href={l.href}
                className="rounded px-2 py-1 text-foreground/80 hover:bg-muted hover:text-foreground"
              >
                {l.label}
              </Link>
            </li>
          ))}
        </ul>
      </div>
    </nav>
  );
}
