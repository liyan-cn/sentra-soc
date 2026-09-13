from __future__ import annotations

from monitor.plugins.registry import PluginRegistry
from .huawei_ips import create_parser as create_huawei_ips
from .huawei_waf import create_parser as create_huawei_waf
from .h3c_waf import create_parser as create_h3c_waf
from .cef_security import create_parser as create_cef_security
from .vendor_security import factory as vendor_factory
from .dptech_ips import create_parser as create_dptech_ips
from .dptech_waf import create_parser as create_dptech_waf
from .topsec_waf import create_parser as create_topsec_waf


BUILTINS = {
    "huawei_ips": create_huawei_ips,
    "huawei_waf": create_huawei_waf,
    "h3c_waf": create_h3c_waf,
    "cef_security": create_cef_security,
    "qianxin_ngfw": vendor_factory("QIANXIN_NGFW", "Qi-Anxin", ("qianxin", "奇安信", "网神", "legendsec")),
    "qianxin_waf": vendor_factory("QIANXIN_WAF", "Qi-Anxin", ("qianxin", "奇安信", "网神", "legendsec")),
    "h3c_security": vendor_factory("H3C_SECURITY", "H3C", (" h3c ", "h3c%", "%%")),
    "sangfor_ngaf": vendor_factory("SANGFOR_NGAF", "Sangfor", ("sangfor", "深信服", "ngaf")),
    "hillstone_ngfw": vendor_factory("HILLSTONE_NGFW", "Hillstone", ("hillstone", "山石", "stoneos")),
    "nsfocus_waf": vendor_factory("NSFOCUS_WAF", "NSFOCUS", ("nsfocus", "绿盟")),
    "venustech_utm": vendor_factory("VENUSTECH_UTM", "Venustech", ("venustech", "启明星辰", "天清")),
    "dptech_ips": create_dptech_ips,
    "dptech_waf": create_dptech_waf,
    "topsec_waf": create_topsec_waf,
}


REGISTRY = PluginRegistry()
for _name, _factory in BUILTINS.items():
    REGISTRY.register("parsers", _name, _factory)


def get_parser(name: str):
    factory = REGISTRY.load("parsers", name)
    return factory()
