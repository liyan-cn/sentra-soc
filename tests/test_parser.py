import pytest

from monitor.common.errors import IgnoredLog
from monitor.parsers import get_parser


def test_generic_vendor_parser():
    parser = get_parser("dptech_waf")
    result = parser.parse("Jul 13 10:20:30 2026 %%WAF/WEBATTACK source-ip:8.8.8.8;destination-ip:192.0.2.3;att_level1:SQL Injection;att_level2:Web;att_level3:SQL;", "dev-1")
    assert result.source == "DPTECH_WAF"
    assert result.src_ip == "8.8.8.8"
    assert result.category == "SQL Injection"


def test_huawei_ips_parser():
    parser = get_parser("huawei_ips")
    event = parser.parse('Jul 13 10:20:30 %%01IPS/4/DETECT SrcIp=8.8.8.8,DstIp=192.0.2.1,Category=Trojan),SignName="C2 callback"', "huawei")
    assert event.category == "Trojan"
    assert event.attributes["signature"] == "C2 callback"


def test_huawei_waf_parser_uses_device_type_not_internal_ips_module():
    parser = get_parser("huawei_waf")
    event = parser.parse(
        'Aug 7 08:20:30 %%01IPS/4/DETECT SrcIp=8.8.8.8,DstIp=192.0.2.1,'
        'Category=Trojan,SignName="C2 callback",Action=block', "huawei-waf")
    assert event.source == "HUAWEI_WAF"
    assert event.attributes["device_type"] == "WAF"
    assert event.attributes["action"] == "block"


def test_h3c_waf_official_english_slash_format():
    parser = get_parser("h3c_waf")
    event = parser.parse(
        "May 28 18:52:07 localhost H3CWAF: happentime/2017-05-28 18:52:07,"
        "severity_id/2,msg_id/12010,msg/SQL injection,dip/192.0.2.10,sip/8.8.4.4", "h3c-waf")
    assert event.source == "H3C_WAF"
    assert event.src_ip == "8.8.4.4"
    assert event.dst_ip == "192.0.2.10"
    assert event.category == "SQL injection"


def test_standard_cef_parser():
    parser = get_parser("cef_security")
    event = parser.parse(
        "Aug 7 09:00:00 host CEF:0|Example|NGFW|1.0|1001|Malware callback|9|"
        "src=203.0.113.9 dst=192.0.2.20 act=blocked cat=Botnet", "cef-device")
    assert event.src_ip == "203.0.113.9"
    assert event.category == "Botnet"
    assert event.severity == "high"


def test_qianxin_vendor_parser_accepts_vendor_key_value_sample():
    parser = get_parser("qianxin_ngfw")
    event = parser.parse(
        "Aug 7 09:00:00 QIANXIN NGFW srcip=203.0.113.10 dstip=192.0.2.21 "
        "attack_name=WebShell action=deny", "qax-ngfw")
    assert event.source == "QIANXIN_NGFW"
    assert event.category == "WebShell"


def test_dptech_ips_exploit_parser():
    parser = get_parser("dptech_ips")
    event = parser.parse("Jul 13 10:20:30 2026 log-type:basic-attack;event:alert;source-ip:8.8.4.4;destination-ip:192.0.2.5;attack-name:(12345)Example RCE;", "ips")
    assert event.attributes["vulnerability_id"] == "12345"
    assert event.category == "Example RCE"


def test_dptech_ips_ordinary_url_classification_is_not_an_attack():
    parser = get_parser("dptech_ips")
    line = ("Aug 10 10:59:28 2026 DPTECH log-type:url_class;event:alert;"
            "url_class-name:(1610612736)other type;url_class_host:pan.baidu.com;"
            "url_class_url:unknown;protocol-name:HTTPS;source-ip:172.16.21.215;"
            "destination-ip:182.61.200.162;")
    with pytest.raises(IgnoredLog):
        parser.parse(line, "ips")


def test_dptech_ips_url_telemetry_requires_local_attack_rule():
    parser = get_parser("dptech_ips")
    line = ("Aug 10 10:59:28 2026 DPTECH log-type:url_class;event:alert;"
            "url_class-name:other;url_class_host:example.test;"
            "url_class_url:/search?q=1%20union%20select%20password%20from%20users;"
            "source-ip:203.0.113.9;destination-ip:192.0.2.10;")
    event = parser.parse(line, "ips")
    assert event.category == "SQL_INJECTION"
    assert event.attributes["local_rule_id"] == "web-sql-injection"


def test_topsec_parser():
    parser = get_parser("topsec_waf")
    event = parser.parse("Jul 13 10:20:30 sip='1.1.1.1' dip='192.0.2.4' msg='规则命中（WEB攻击）'", "topsec")
    assert event.category == "WEB攻击"
