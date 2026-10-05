# Security Policy

## Reporting a vulnerability

Please do **not** open a public issue for security problems.
Report privately via GitHub's "Report a vulnerability" (Security tab) or email the maintainer.

Include: affected version, steps to reproduce, impact, and any proof of concept.

| Stage | Target time |
|---|---|
| Acknowledge report | 3 days |
| Initial assessment and severity (CVSS) | 7 days |
| Fix for critical/high issues | 14 days |
| Public disclosure | After the fix is released, coordinated with the reporter |

## Supported versions

Only the latest release on the `main` branch receives security fixes.

## Patch management

- Dependabot opens weekly dependency-update PRs.
- CI runs `npm audit`, Semgrep and Gitleaks on every push; high-severity findings fail the build.
