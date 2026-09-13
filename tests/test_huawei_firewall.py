import pytest

from monitor.common.errors import ExternalServiceError
from monitor.infrastructure.firewall import HuaweiFirewallClient


class StubFirewall(HuaweiFirewallClient):
    def __init__(self, outputs):
        super().__init__({}, "secret")
        self.outputs = outputs
        self.commands = None
    def _commands(self, commands):
        self.commands = commands
        return self.outputs


def test_block_does_not_treat_command_echo_as_confirmation():
    client = StubFirewall(["> sys", "> firewall blacklist item source-ip 8.8.8.8", "> display\nNo entries"])
    with pytest.raises(ExternalServiceError, match="did not confirm"):
        client.block("8.8.8.8", 10, "scanner")


def test_block_uses_only_query_output_and_sanitizes_description():
    client = StubFirewall(["> sys", "> command accepted", "8.8.8.8 active"])
    client.block("8.8.8.8", 10, "scan; quit\nreboot")
    assert client.commands[1].endswith("description scan__quit_reboot")


def test_unblock_requires_query_to_confirm_address_is_absent():
    still_present = StubFirewall(["> sys", "> undo accepted", "8.8.8.8 active"])
    with pytest.raises(ExternalServiceError, match="did not confirm unblocked"):
        still_present.unblock("8.8.8.8")
    removed = StubFirewall(["> sys", "> undo accepted", "No entries"])
    removed.unblock("8.8.8.8")


def test_firewall_rejects_invalid_ip_and_duration_before_transport():
    client = StubFirewall([])
    with pytest.raises(ValueError):
        client.block("8.8.8.8; reboot", 10, "x")
    with pytest.raises(ValueError, match="duration"):
        client.block("8.8.8.8", 0, "x")
    with pytest.raises(ValueError, match="duration"):
        client.block("8.8.8.8", 525601, "x")


def test_firewall_error_detection_avoids_description_false_positive():
    assert HuaweiFirewallClient._failed("description error_scanner accepted") is False
    assert HuaweiFirewallClient._failed("\n% Error: invalid parameter") is True
    assert HuaweiFirewallClient._failed("\n Invalid command: firewall") is True
