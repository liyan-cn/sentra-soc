from datetime import datetime, timezone

from monitor.discovery import discover_source_dirs, fingerprint
from monitor.domain.models import DecisionType, SecurityEvent
from monitor.infrastructure.database import Database
from monitor.services.event_service import EventService


def test_source_directory_discovery_accepts_ip_directories_only(tmp_path):
    (tmp_path / "203.0.113.8").mkdir()
    (tmp_path / "not-a-device").mkdir()
    assert [(ip, path.name) for ip, path in discover_source_dirs(tmp_path)] == [("203.0.113.8", "203.0.113.8")]


def test_huawei_fingerprint_reports_quality_metrics():
    lines = [
        'Jul 13 10:20:30 %%01IPS/4/DETECT SrcIp=8.8.8.8,DstIp=192.0.2.1,Category=Trojan),SignName="C2"',
        'Jul 13 10:20:31 %%01IPS/4/DETECT SrcIp=8.8.4.4,DstIp=192.0.2.1,Category=Scan),SignName="Probe"',
        'Jul 13 10:20:32 %%01IPS/4/DETECT SrcIp=1.1.1.1,DstIp=192.0.2.1,Category=Botnet),SignName="C2"',
    ]
    result = fingerprint(lines)
    assert result.parser == "huawei_waf"
    assert result.confidence >= .9
    assert result.parse_success_rate == 1
    assert result.field_completeness == 1


def test_h3c_waf_fingerprint_can_auto_enter_observation():
    lines = [
        f"May 28 18:52:0{i} localhost H3CWAF: severity_id/2,msg/SQL injection,"
        f"dip/192.0.2.10,sip/203.0.113.{i}" for i in range(1, 4)
    ]
    result = fingerprint(lines)
    assert result.parser == "h3c_waf"
    assert result.confidence >= .9


def test_qianxin_generic_fingerprint_requires_manual_confirmation():
    lines = [
        f"Aug 7 09:00:0{i} QIANXIN NGFW srcip=203.0.113.{i} dstip=192.0.2.20 "
        "attack_name=scan action=deny" for i in range(1, 4)
    ]
    result = fingerprint(lines)
    assert result.parser == "qianxin_ngfw"


def test_h3c_native_permit_traffic_is_recognized_but_not_an_attack():
    line = ("Aug 11 17:42:54 2026 H3C %%10FILTER/6/FILTER_ZONE_IPV4_EXECUTION: "
            "SrcZoneName(5)=Untrust;DstZoneName(5)=Trust;Type(5)=ACL;"
            "SrcIPAddr(5)=36.129.47.145;DstIPAddr(5)=192.168.1.253;Event(5)=Permit;")
    result = fingerprint([line, line, line])
    assert result.parser == "h3c_security"
    assert result.parse_success_rate == 1.0
    assert result.confidence >= 0.9


def test_observation_mode_never_creates_review_or_action(tmp_path):
    db = Database(tmp_path / "observe.db"); db.initialize()
    event = SecurityEvent("TEST", "auto-device", "attack", datetime.now(timezone.utc),
                          "8.8.8.8", "192.0.2.1", "critical", severity="critical", raw_line="one")
    service = EventService(db, {"defaults": {"warn_threshold": 1, "block_threshold": 1}},
                           observation_only=True)
    assert service.submit(event, "US").decision == DecisionType.OBSERVE
    with db.connect() as conn:
        decision = conn.execute("SELECT decision,rule_id FROM policy_decisions").fetchone()
        assert tuple(decision) == ("OBSERVE", "observation-mode")
        assert conn.execute("SELECT COUNT(*) FROM review_cases").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM action_outbox").fetchone()[0] == 0
