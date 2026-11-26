# Security boundaries

HyperShell is an experimental administrator-operated workspace component. Do not
deploy the demo Web process as a public service or treat it as a certified boundary
between mutually untrusted tenants.

## Trust model

- The host administrator, kernel, control interpreter, HyperShell code and approved
  JiuwenBox/JiuwenSwarm runtime are trusted. Workload users must not modify these
  files, configuration, runtime manifests, or any parent directory.
- Live workloads use dedicated non-root UID/GIDs. Management sockets and state stay
  outside workloads. The TUI is spawned by the restricted backend; the host relay
  only forwards bytes after dropping privileges.
- Startup, doctor, baseline capture and boundary verification validate a static
  runtime bundle before executing the application interpreter as root. The control
  interpreter itself must already be independently trusted.
- `--demo-user` is simulated preview and `--user` is an administrator selector.
  Neither is an authentication mechanism. A user's agents share one outer boundary.

## Known limitations

- Web directly drives privileged lifecycle operations. It has Argon2id, signed
  sessions and CSRF checks, but no login rate limiting, immediate session revocation,
  SSO or production privilege separation. HTTP demo cookies are not Secure.
  Account changes require a Web restart and do not invalidate existing cookies.
  The control plane also supervises one separate relay process per running user;
  each host-side relay runs with control-plane privilege and only forwards raw
  bytes after gateway session gating (the in-sandbox bridge is dropped to the
  workload UID). Cross-user isolation of the web/relay tier is not yet certified.
- Policy changes do not revoke an existing sandbox. Stop affected instances before
  publishing reduced grants or deleting users; recreate them with the new request.
- Runtime hashes detect drift, not publisher authenticity. External Python/Node and
  system libraries are trusted separately; checks are not atomically bound to execution.
- Network support is limited to loopback and approved model public IPv4 TCP 443.
  Direct DNS and external IPv6 are blocked; a general domain proxy is not implemented.
- Recovery handles stale state with reboot evidence and no related residual resources.
  Same-boot orphan recovery and transactional upgrades/revocation are incomplete.
  Other JiuwenBox services performing global cleanup can interfere with managed instances.
- User-writable agent traces are not tamper-proof audit evidence. Unit tests, policy
  readback, diagnostics and real isolation probes provide different kinds of evidence.

See the [design](docs/DESIGN.md) and [user guide](docs/USER_GUIDE.md) for
implementation details and validation scope (Chinese).

## Reporting

Use the [Agent Security security page](https://github.com/openJiuwen-ai/agent-security/security/policy)
to check the repository's current reporting policy. If private vulnerability reporting
is enabled there, use it. Otherwise request a private contact from the maintainers
without posting exploit details. This component does not advertise an unverified
security email address or response-time guarantee.

Never attach passwords, model credentials, full environment dumps, account/session
files or private workspace data to a public issue. Provide a minimal synthetic
reproducer and the affected code revision, OS, dependency and backend versions.
