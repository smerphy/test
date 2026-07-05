import type { Role } from "@/lib/api";

/** Privilege ordering, mirroring the control plane's app/rbac.py. */
const ROLE_LEVEL: Record<Role, number> = {
  viewer: 0,
  analyst: 10,
  admin: 20,
  owner: 30,
};

export const ROLE_ORDER: Role[] = ["viewer", "analyst", "admin", "owner"];

/** True iff `role` is at least as privileged as `minimum`. */
export function roleAtLeast(role: Role | null | undefined, minimum: Role): boolean {
  if (!role) return false;
  return ROLE_LEVEL[role] >= ROLE_LEVEL[minimum];
}

export const ROLE_DESCRIPTION: Record<Role, string> = {
  viewer: "Read-only access to every resource.",
  analyst:
    "SOC operations: triage findings, resolve approvals, manage quarantines, acknowledge alerts.",
  admin: "Configuration: policies, alert rules, detection rules, org settings.",
  owner: "Full access, including member and role management.",
};
