# Plugin Development

Monitor 3.0 discovers external plugins with Python package entry points. A
plugin package can provide one or more components without changing the core.

## Groups

| Group | Contract |
|---|---|
| `monitor3.sources` | `EventSource` |
| `monitor3.parsers` | `EventParser` |
| `monitor3.actions` | `ActionProvider` |
| `monitor3.notifiers` | `Notifier` |
| `monitor3.geolocation` | `GeoProvider` |
| `monitor3.threat_intel` | `ThreatIntelProvider` |

Contracts and result types are defined in `monitor.plugins.contracts`.

## Parser example

```python
from monitor.domain.models import SecurityEvent

class ExampleParser:
    source = "EXAMPLE_IDS"

    def parse(self, line: str, device_id: str) -> SecurityEvent:
        # Validate every external value and raise ParseError for unsupported data.
        ...

def create_parser():
    return ExampleParser()
```

Register it in the plugin package:

```toml
[project.entry-points."monitor3.parsers"]
example_ids = "monitor3_example:create_parser"
```

Configuration then references `parser: example_ids`. Plugin names must be
stable lowercase identifiers. A parser release should document supported device
and firmware versions and include synthetic fixtures for every known format.

Plugins must not read core configuration files directly, mutate global state,
log secrets, or perform network requests during import. Factories receive their
configuration from the core at runtime.
