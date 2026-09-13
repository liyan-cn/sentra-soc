from types import SimpleNamespace

from monitor.infrastructure.nftables import NftablesActionProvider


class FakeRunner:
    def __init__(self):
        self.blocked = set()
        self.commands = []

    def __call__(self, command, **kwargs):
        self.commands.append(command)
        action = command[1]
        if action == "list":
            return SimpleNamespace(returncode=0, stdout="elements = { " + ", ".join(self.blocked) + " }", stderr="")
        ip = next(part for part in command if part.count(".") == 3)
        if action == "add": self.blocked.add(ip)
        if action == "delete": self.blocked.discard(ip)
        return SimpleNamespace(returncode=0, stdout="", stderr="")


def test_nftables_apply_and_revoke_are_verified_and_idempotent():
    runner = FakeRunner()
    provider = NftablesActionProvider({"family": "inet", "table": "filter", "set": "blocklist"}, runner)
    assert provider.apply({"ip": "8.8.8.8", "minutes": 10}).actual_state == "blocked"
    command_count = len(runner.commands)
    assert provider.apply({"ip": "8.8.8.8", "minutes": 10}).success
    assert len(runner.commands) == command_count + 1  # inspect only
    assert provider.revoke({"ip": "8.8.8.8"}).actual_state == "unblocked"


def test_nftables_rejects_identifier_injection():
    try:
        NftablesActionProvider({"table": "filter;rm", "set": "blocklist"}, FakeRunner())
    except ValueError:
        pass
    else:
        raise AssertionError("unsafe identifier must fail")
