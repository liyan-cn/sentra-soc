from monitor.plugins.registry import PluginRegistry


def test_builtin_plugin_registration_and_loading():
    registry = PluginRegistry()
    registry.register("parsers", "example", lambda: "loaded")
    assert "example" in registry.names("parsers")
    assert registry.load("parsers", "example")() == "loaded"
