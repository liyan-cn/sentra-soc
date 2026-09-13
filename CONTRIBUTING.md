# Contributing

1. Open an issue describing the use case and compatibility impact.
2. Never submit real security logs or credentials; add minimal synthetic fixtures.
3. Add tests for parser formats, state transitions, migrations, and failure paths.
4. Run `python -m pytest -q` before opening a pull request.
5. Keep provider-specific behavior in plugins rather than the domain layer.
6. Released migrations are immutable; add a new numbered migration.

Parser plugins should expose an entry point in the `monitor3.parsers` group.
Action, source, notification, and geolocation plugins use their corresponding
`monitor3.*` groups documented in `src/monitor/plugins/registry.py`.

