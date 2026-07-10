"use client";

import Link from "next/link";
import type { Route } from "next";
import { usePathname } from "next/navigation";
import clsx from "clsx";

export interface NavLink {
  href: string;
  label: string;
}

function isActive(pathname: string, href: string): boolean {
  if (href === "/") return pathname === "/";
  return pathname === href || pathname.startsWith(href + "/");
}

export function NavLinks({ links }: { links: NavLink[] }) {
  const pathname = usePathname();
  return (
    <ul className="flex items-center gap-0.5 overflow-x-auto">
      {links.map((l) => {
        const active = isActive(pathname, l.href);
        return (
          <li key={l.href}>
            <Link
              href={l.href as Route}
              aria-current={active ? "page" : undefined}
              className={clsx(
                "block whitespace-nowrap rounded-md px-2.5 py-1.5 text-sm transition-colors",
                active
                  ? "bg-accent/12 font-medium text-foreground"
                  : "text-foreground/60 hover:bg-muted/70 hover:text-foreground"
              )}
            >
              {l.label}
            </Link>
          </li>
        );
      })}
    </ul>
  );
}
