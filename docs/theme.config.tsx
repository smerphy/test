import type { DocsThemeConfig } from "nextra-theme-docs";

const config: DocsThemeConfig = {
  logo: <span style={{ fontFamily: "monospace", fontWeight: 600 }}>praetor</span>,
  project: { link: "https://github.com/praetor/praetor" },
  docsRepositoryBase: "https://github.com/praetor/praetor/tree/main/docs",
  footer: { content: "Apache 2.0 · Praetor" },
};

export default config;
