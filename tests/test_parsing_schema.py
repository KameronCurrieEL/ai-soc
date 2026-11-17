import pytest

from soc.parsing.schema import Alert, ip_scope, wazuh_severity
from soc.parsing.windows import clean, failure_reason, logon_type


@pytest.mark.parametrize("level,expected", [(0, "low"), (5, "low"), (6, "low"), (7, "medium"),
                                            (10, "medium"), (12, "high"), (14, "high"), (15, "critical")])
def test_wazuh_severity_bands(level, expected):
    assert wazuh_severity(level) == expected


@pytest.mark.parametrize("ip,expected", [("::1", "loopback"), ("127.0.0.1", "loopback"),
                                         ("192.168.1.10", "private"), ("10.0.0.5", "private"),
                                         ("fe80::1", "private"), ("8.8.8.8", "public"), ("172.24.0.5", "private"), ("100.64.1.1", "private"),
                                         ("203.0.113.7", "reserved"), ("0.0.0.0", "reserved"),
                                         ("-", None), (None, None), ("not-an-ip", None)])
def test_ip_scope(ip, expected):
    assert ip_scope(ip) == expected


def test_clean_treats_windows_placeholders_as_missing():
    assert clean("-") is None and clean(" 0x0 ") is None and clean("") is None and clean(None) is None
    assert clean("soc-test-user") == "soc-test-user"


def test_logon_type_translation():
    assert logon_type("10") == "10 remote interactive (RDP)"
    assert logon_type("99") == "99 unknown"
    assert logon_type("-") is None


def test_failure_reason_prefers_substatus():
    assert failure_reason("0xc000006d", "0xc0000064") == "0xc0000064 user does not exist"
    assert failure_reason("0xC000006D", "0x0") == "0xc000006d bad username or password"
    assert failure_reason(None, None) is None


def test_to_dict_is_json_friendly():
    a = Alert("1", "t", "wazuh", "501", 3, "low", "d", "000", "m", mitre_ids=("T1110",))
    assert a.to_dict()["mitre_ids"] == ["T1110"]
