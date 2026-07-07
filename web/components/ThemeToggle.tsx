"use client";

import { useEffect, useState } from "react";

type Theme = "dark" | "light";

const STORAGE_KEY = "theme";

function apply(theme: Theme) {
  document.documentElement.dataset.theme = theme;
  try {
    localStorage.setItem(STORAGE_KEY, theme);
  } catch {
    /* storage may be unavailable (private mode) — the attribute still applies */
  }
}

export function ThemeToggle() {
  const [theme, setTheme] = useState<Theme | null>(null);

  // Read the theme the inline head script already resolved (defaults to dark).
  useEffect(() => {
    const current =
      (document.documentElement.dataset.theme as Theme | undefined) ?? "dark";
    setTheme(current);
  }, []);

  const toggle = () => {
    const next: Theme = theme === "light" ? "dark" : "light";
    apply(next);
    setTheme(next);
  };

  // Stable placeholder before mount avoids a hydration mismatch.
  const isLight = theme === "light";
  const label = isLight ? "Switch to dark theme" : "Switch to light theme";

  return (
    <button
      type="button"
      onClick={toggle}
      aria-label={label}
      title={label}
      className="grid h-7 w-7 shrink-0 place-items-center rounded-md text-foreground/70 ring-1 ring-inset ring-border hover:bg-muted hover:text-foreground"
    >
      {isLight ? (
        // Moon — currently light, click to go dark.
        <svg
          width="15"
          height="15"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
          aria-hidden
        >
          <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
        </svg>
      ) : (
        // Sun — currently dark (or unmounted), click to go light.
        <svg
          width="15"
          height="15"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
          aria-hidden
        >
          <circle cx="12" cy="12" r="4" />
          <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41" />
        </svg>
      )}
    </button>
  );
}
