from monitor.simulation import replay, simulate


RULES = {"defaults": {"warn_threshold": 2, "block_threshold": 3, "block_minutes": 60}, "policies": []}


def test_simulation_has_no_side_effect_dependency():
    report = simulate(RULES, source="TEST", category="scan", src_ip="8.8.8.8",
                      count=3, location="US")
    assert report["decision"] == "BLOCK"
    assert report["block_minutes"] == 60


def test_replay_reports_decisions_without_writes(tmp_path):
    log = tmp_path / "waf.log"
    log.write_text(
        "Jul 13 10:20:30 2026 %%WAF/WEBATTACK source-ip:8.8.8.8;destination-ip:192.0.2.3;att_level1:SQL;\n" * 3,
        encoding="utf-8",
    )
    rules = {**RULES, "DPTECH_WAF": RULES["defaults"]}
    report = replay(rules, "dptech_waf", "device", log)
    assert report["processed"] == 3
    # Replay defaults to UNKNOWN geography, so the safe legacy policy sends
    # threshold hits to review instead of auto-blocking.
    assert report["decisions"]["MANUAL_REVIEW"] == 2
    assert report["side_effects"] is False
