from monitor.infrastructure.generic_notifiers import FanoutNotifier, SMTPNotifier, WebhookNotifier


def test_disabled_notifiers_have_no_external_side_effects():
    WebhookNotifier({"enabled": False}).send("test")
    SMTPNotifier({"enabled": False}).send("test")


def test_webhook_requires_url_when_enabled():
    try:
        WebhookNotifier({"enabled": True}).send("test")
    except Exception as exc:
        assert "URL" in str(exc)
    else:
        raise AssertionError("missing URL must fail")


def test_fanout_can_tolerate_partial_failure():
    class Good:
        def send(self, content): self.content = content
    class Bad:
        def send(self, content): raise RuntimeError("down")
    good = Good()
    FanoutNotifier([good, Bad()], require_all=False).send("alert")
    assert good.content == "alert"
