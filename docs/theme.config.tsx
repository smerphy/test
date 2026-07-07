import type { DocsThemeConfig } from "nextra-theme-docs";

// PROJECT_REPO_URL is the public repo URL. Set this when the repo is
// published; the theme silently omits the GitHub icon if undefined.
const PROJECT_REPO_URL = process.env.NEXT_PUBLIC_EPHORATE_REPO_URL;

const config: DocsThemeConfig = {
  logo: <span style={{ fontFamily: "monospace", fontWeight: 600 }}>ephorate</span>,
  ...(PROJECT_REPO_URL
    ? {
        project: { link: PROJECT_REPO_URL },
        docsRepositoryBase: `${PROJECT_REPO_URL}/tree/main/docs`,
      }
    : {}),
  footer: { content: "Apache 2.0 · Ephorate" },
};

export default config;
