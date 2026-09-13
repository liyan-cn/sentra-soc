from pathlib import Path


ROOT = Path(__file__).parents[1]


def test_backup_timer_is_persistent_and_service_is_hardened():
    timer = (ROOT / "deploy/systemd/monitor3-backup.timer").read_text(encoding="utf-8")
    service = (ROOT / "deploy/systemd/monitor3-backup.service").read_text(encoding="utf-8")
    assert "Persistent=true" in timer
    assert "RandomizedDelaySec=" in timer
    assert "-m monitor.workers.backup_worker" in service
    assert "TimeoutStartSec=90min" in service
    assert "Type=oneshot" in service
    assert "NoNewPrivileges=true" in service
    assert "ReadWritePaths=/var/lib/monitor3" in service


def test_discovery_service_is_non_privileged_and_syslog_is_read_only():
    service = (ROOT / "deploy/systemd/monitor3-discovery-home.service").read_text(encoding="utf-8")
    assert "User=monitor3" in service
    assert "NoNewPrivileges=true" in service
    assert "ProtectSystem=strict" in service
    assert "ReadOnlyPaths=/home/syslog" in service
    assert "ReadWritePaths=/home/monitor3.0/data" in service
