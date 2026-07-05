import Link from "next/link";
import { api, type Role } from "@/lib/api";
import { roleAtLeast } from "@/lib/rbac";

type Href =
  | "/"
  | "/monitoring"
  | "/security"
  | "/findings"
  | "/threat"
  | "/fleet"
  | "/alerts"
  | "/policies"
  | "/audit"
  | "/approvals"
  | "/compliance"
  | "/members";

// `minRole` hides a link from principals below that role. Read-only pages are
// visible to everyone (viewer); management surfaces require a higher role.
const LINKS: { href: Href; label: string; minRole?: Role }[] = [
  { href: "/", label: "Dashboard" },
  { href: "/monitoring", label: "Monitoring" },
  { href: "/security", label: "Security" },
  { href: "/findings", label: "Findings" },
  { href: "/threat", label: "Threat Intel" },
  { href: "/fleet", label: "Fleet" },
  { href: "/alerts", label: "Alerts" },
  { href: "/policies", label: "Policies" },
  { href: "/audit", label: "Audit" },
  { href: "/approvals", label: "Approvals" },
  { href: "/compliance", label: "Compliance" },
  { href: "/members", label: "Members", minRole: "admin" },
];

const ROLE_STYLE: Record<Role, string> = {
  viewer: "bg-slate-500/15 text-slate-400 ring-slate-500/30",
  analyst: "bg-sky-500/15 text-sky-400 ring-sky-500/30",
  admin: "bg-amber-500/15 text-amber-400 ring-amber-500/30",
  owner: "bg-emerald-500/15 text-emerald-400 ring-emerald-500/30",
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
    <nav className="border-b border-border bg-muted/30">
      <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-3">
        <Link href="/" className="font-mono text-sm font-semibold tracking-tight">
          praetor<span className="text-foreground/40">/cp</span>
        </Link>
        <ul className="flex items-center gap-4 text-sm">
          {links.map((l) => (
            <li key={l.href}>
              <Link
                href={l.href}
                className="rounded px-2 py-1 text-foreground/80 hover:bg-muted hover:text-foreground"
              >
                {l.label}
              </Link>
            </li>
          ))}
          {role && (
            <li>
              <span
                className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs font-medium ring-1 ring-inset ${ROLE_STYLE[role]}`}
                title="Your effective role in this workspace"
              >
                {role}
              </span>
            </li>
          )}
        </ul>
      </div>
    </nav>
  );
}
