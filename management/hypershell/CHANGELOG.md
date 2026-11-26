# Changelog

## Unreleased — 0.1.0.dev0

Initial experimental component for Agent Security:

- Strict resource configuration and permission compilation, role grants and user limits.
- JiuwenBox policy projection, Linux managed workspaces, private state and explicit recovery.
- Runtime bundle validation, observed baseline comparison and boundary probes.
- Restricted PTY TUI, authenticated user launcher and demo Web management.
- Source-only installation, bilingual overview and task-oriented documentation.
- Removed default account passwords; account creation prompts per account or reads stdin.
- Standardized environment variables to `HYPERSHELL_*`; update old demo environments
  and reinstall wrappers when upgrading.
- Session leases for long-lived Web/TUI sessions: administrators can list and terminate
  active sessions from the dashboard without blocking `stop`/`recover`.
- Bundled `jiuwenswarm-web` launcher; the control plane supervises one per-user web relay
  and starts/stops it with the instance, with periodic reconciliation.
- Engine identity is recognised across differing control/runtime checkout paths.

This is not a production release. Deployment and security limitations are documented
in [SECURITY.md](SECURITY.md).
