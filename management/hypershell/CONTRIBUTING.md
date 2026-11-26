# Contributing to HyperShell

HyperShell lives in `management/hypershell` in
[Agent Security](https://github.com/openJiuwen-ai/agent-security). Follow the target
repository's contribution rules and submit component changes as a pull request.
Read the [overview](README.md), [design](docs/DESIGN.md) and [security guide](SECURITY.md).

## Develop and test

Use Python 3.11–3.13 in a virtual environment from `management/hypershell`.

```bash
python -m pip install -e ".[dev,web]"
python -m pytest tests -q -ra --basetemp=.test-tmp/pytest
python examples/demo/run_demo.py
```

The basetemp directory is disposable and pytest clears it. Keep personal files out of it.
Linux tests requiring PTYs, administrator privileges or filesystem primitives are
explicitly skipped when unavailable. Web/authentication tests require the Web extras;
review skip reasons rather than silently accepting missing dependencies.

Include the revision, commands, platform and actual results in your PR. Boundary
changes need negative behavioral tests; model answers or policy readback alone do
not prove isolation. Keep runtime operations out of the pure policy compiler.
Document backend contract changes and update both README entry points when behavior changes.

## Repository hygiene

Do not commit credentials, account files, sessions, raw deployment logs, runtime
bundles, wheels or personal paths. Examples use synthetic data. Keep design discussions
in issues/PRs and maintained behavior in `docs/`; do not add per-run acceptance diaries.

The package and import name remain `hypershell` for source compatibility. Use a
dedicated environment and install from this directory; the unrelated PyPI project
with the same name must not be used to install this component. Package publishing
requires a separately agreed distribution name and release process. The development
version does not claim a released or production-ready `0.1.0`.

When importing into the monorepo, include source, examples, tests and maintained docs;
exclude nested `.git`, caches and local artifacts. GitHub workflows belong at the
monorepo root with a component working directory. Do not import private development
history as part of a source-only contribution.

Use respectful and constructive communication. Report security issues through the
process in [SECURITY.md](SECURITY.md), keeping sensitive details private.
