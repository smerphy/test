import Link from "next/link";
import { api, type Role } from "@/lib/api";
import { roleAtLeast } from "@/lib/rbac";
import { NavLinks } from "@/components/NavLinks";

type Href =
  | "/"
  | "/monitoring"
  | "/finance"
  | "/security"
  | "/findings"
  | "/soar"
  | "/threat"
  | "/ai"
  | "/fleet"
  | "/alerts"
  | "/policies"
  | "/backtest"
  | "/audit"
  | "/approvals"
  | "/compliance"
  | "/members";

// `minRole` hides a link from principals below that role. Read-only pages are
// visible to everyone (viewer); management surfaces require a higher role.
const LINKS: { href: Href; label: string; minRole?: Role }[] = [
  { href: "/", label: "Dashboard" },
  { href: "/monitoring", label: "Monitoring" },
  { href: "/finance", label: "Cost" },
  { href: "/security", label: "Security" },
  { href: "/findings", label: "Findings" },
  { href: "/soar", label: "SOAR", minRole: "analyst" },
  { href: "/threat", label: "Threat Intel" },
  { href: "/ai", label: "AI" },
  { href: "/fleet", label: "Fleet" },
  { href: "/alerts", label: "Alerts" },
  { href: "/policies", label: "Policies" },
  { href: "/backtest", label: "Backtest", minRole: "admin" },
  { href: "/audit", label: "Audit" },
  { href: "/approvals", label: "Approvals" },
  { href: "/compliance", label: "Compliance" },
  { href: "/members", label: "Members", minRole: "admin" },
];

const ROLE_STYLE: Record<Role, string> = {
  viewer: "bg-muted text-foreground/60 ring-border",
  analyst: "bg-accent/15 text-accent ring-accent/30",
  admin: "bg-warning/15 text-warning ring-warning/30",
  owner: "bg-success/15 text-success ring-success/30",
};

export async function Nav() {
  // The console authenticates with a shared credential; its effective role
  // comes from /whoami. If the control plane is unreachable we fall back to
  // the least-privilege view (management links hidden).
  let role: Role | null = null;
  try {
    role = (await api.whoami()).role;
  } catch {
    role = null;
  }

  const links = LINKS.filter(
    (l) => !l.minRole || roleAtLeast(role, l.minRole)
  );

  return (
    <header className="sticky top-0 z-50 border-b border-border bg-background/80 backdrop-blur supports-[backdrop-filter]:bg-background/65">
      <div className="mx-auto flex max-w-7xl items-center gap-4 px-6 py-2.5">
        <Link
          href="/"
          className="flex shrink-0 items-center gap-2 rounded-md py-1 pr-2 font-mono text-sm font-semibold tracking-tight"
        >
          <span
            aria-hidden
            className="grid h-6 w-6 place-items-center rounded-md bg-accent/15 text-accent ring-1 ring-inset ring-accent/30"
          >
            E
          </span>
          <span>
            ephorate<span className="text-foreground/40">/cp</span>
          </span>
        </Link>

        <nav aria-label="Primary" className="min-w-0 flex-1">
          <NavLinks links={links} />
        </nav>

        {role && (
          <span
            className={`hidden shrink-0 items-center rounded-full px-2 py-0.5 text-xs font-medium capitalize ring-1 ring-inset sm:inline-flex ${ROLE_STYLE[role]}`}
            title="Your effective role in this workspace"
          >
            {role}
          </span>
        )}
      </div>
    </header>
  );
}
