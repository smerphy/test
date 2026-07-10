# Security policy

Ephorate is a security-relevant product — its job is to gate AI agent
behavior, log decisions tamper-evidently, and back compliance claims.
Vulnerabilities here have real downstream impact. We take reports
seriously.

## Reporting a vulnerability

**Do not open a public GitHub issue.**

Please report via one of:

1. **GitHub Security Advisories** — preferred. Open a private advisory
   on this repository (Security → Advisories → "Report a vulnerability").
2. **Email**: `security@ephorate.dev` *(set up before public launch)*.
   PGP key fingerprint published here at first release.

Include:

- A description of the issue and the component (engine / SDK / control
  plane / web).
- Steps to reproduce, or a minimal proof-of-concept.
- Ephorate version (`pip show ephorate-engine`, `pnpm list @ephorate/sdk`,
  or commit SHA).
- Your assessment of impact.

## What we commit to

- **Acknowledge** receipt within **3 business days**.
- **Triage** with an initial severity assessment within **7 business
  days**.
- **Patch + disclosure** for High / Critical issues within **30 days**
  of confirmation, in coordination with you. Lower severity issues
  follow the normal release cycle but are still tracked publicly in
  the changelog.
- **Credit** in the advisory and changelog unless you'd rather remain
  anonymous.

## In scope

- Policy bypass: tool calls that should match a rule but don't.
- Audit-log integrity: ways to corrupt or undetectably modify a
  chained event.
- Authentication/authorization on the control plane.
- Cross-tenant data exposure.
- SDK middleware allowing a denied tool call to slip through (e.g. by
  a malformed provider response shape).
- Cryptographic weaknesses in the hashing / signing path.
- Injection vulnerabilities in the control plane or web UI.
- Supply-chain risks in our published artifacts (PyPI, npm).

## Out of scope

- Social engineering of maintainers.
- Issues in dependencies — please report upstream and link to that
  report. We'll bump.
- Bugs that require an attacker who already controls the policy
  bundle (the bundle is the trust boundary).
- DoS via expensive regex in user-authored policies (we recommend
  reviewing policies as code).
- Findings that require disabling Ephorate's own enforcement.

## Supported versions

During the `v0.x` series, only the latest minor receives security
patches. Once `v1.0.0` ships, we'll support the latest two minors.

## Public disclosure

After a fix is released, we publish a GitHub Security Advisory with a
CVE (if the issue qualifies) and a changelog entry. Researchers
listed in the advisory (with their permission) are credited.

## Safe harbor

We will not pursue legal action against good-faith security research
that:

- Avoids privacy violations, destruction of data, and interruption or
  degradation of our services.
- Stays within the in-scope list above.
- Gives us reasonable time to remediate before public disclosure.
