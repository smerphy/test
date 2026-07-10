import type { Config } from "tailwindcss";

/**
 * Colors are driven by CSS variables (space-separated RGB channels defined in
 * globals.css) so opacity utilities like `bg-muted/40` and `text-foreground/60`
 * keep working, and the palette can be themed from a single place.
 */
const withVar = (v: string) => `rgb(var(${v}) / <alpha-value>)`;

const config: Config = {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        background: withVar("--background"),
        surface: withVar("--surface"),
        foreground: withVar("--foreground"),
        muted: withVar("--muted"),
        border: withVar("--border"),
        accent: withVar("--accent"),
        danger: withVar("--danger"),
        warning: withVar("--warning"),
        success: withVar("--success"),
        ring: withVar("--ring"),
      },
      boxShadow: {
        sm: "0 1px 2px 0 rgb(0 0 0 / 0.24)",
        DEFAULT: "0 1px 3px 0 rgb(0 0 0 / 0.30), 0 1px 2px -1px rgb(0 0 0 / 0.30)",
        md: "0 6px 16px -4px rgb(0 0 0 / 0.40)",
      },
      fontFamily: {
        sans: [
          "system-ui",
          "-apple-system",
          "BlinkMacSystemFont",
          "Segoe UI",
          "Roboto",
          "Helvetica Neue",
          "Arial",
          "sans-serif",
        ],
        mono: [
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "Consolas",
          "Liberation Mono",
          "monospace",
        ],
      },
    },
  },
  plugins: [],
};

export default config;
