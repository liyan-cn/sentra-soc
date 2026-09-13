import signal

from monitor.workers.runtime import install_shutdown_handlers


def test_shutdown_signal_sets_worker_event(monkeypatch):
    handlers = {}
    monkeypatch.setattr(signal, "signal", lambda number, handler: handlers.setdefault(number, handler))
    stopping = install_shutdown_handlers()
    assert not stopping.is_set()
    handlers[signal.SIGINT](signal.SIGINT, None)
    assert stopping.is_set()
