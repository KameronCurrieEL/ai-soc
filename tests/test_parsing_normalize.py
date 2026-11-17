import json
from pathlib import Path

from soc.parsing.normalize import detect_source, normalize

SAMPLES = Path(__file__).parent.parent / "data" / "samples"


def load(name: str) -> dict:
    return json.loads((SAMPLES / name).read_text())


def test_failed_logon_sample():
    a = normalize(load("win_4625_logon_failure_unknown_user.json"))
    assert (a.source, a.rule_id, a.rule_level, a.wazuh_severity) == ("windows_event", "60122", 5, "low")
    assert (a.event_id, a.user, a.src_ip, a.src_ip_scope) == ("4625", "soc-test-user", "::1", "loopback")
    assert a.details["failure_reason"] == "0xc0000064 user does not exist"
    assert a.details["logon_type"] == "2 interactive (keyboard/console)"
    assert a.details["requested_by"] == "labuser"
    assert a.details["process"] == "C:\\Windows\\System32\\svchost.exe"
    assert a.mitre_ids == ("T1531",)  # Wazuh's own (questionable) mapping, kept as-is


def test_brute_force_sample():
    a = normalize(load("win_60204_multiple_logon_failures.json"))
    assert (a.rule_id, a.rule_level, a.wazuh_severity) == ("60204", 10, "medium")
    assert a.mitre_ids == ("T1110",) and "Credential Access" in a.mitre_tactics
    assert a.related_count == 7 and a.user == "soc-test-user"


def test_service_logon_sample_drops_placeholders():
    a = normalize(load("win_4624_logon_success_service.json"))
    assert (a.event_id, a.user, a.src_ip) == ("4624", "SYSTEM", None)
    assert a.details["logon_type"] == "5 service"
    assert "failure_reason" not in a.details and "workstation" not in a.details


def test_fim_registry_value():
    raw = {"decoder": {"name": "syscheck_registry_value_modified"}, "location": "syscheck",
           "rule": {"id": "750", "level": 5, "description": "Registry Value Integrity Checksum Changed"},
           "syscheck": {"path": "HKEY_LOCAL_MACHINE\\System\\X", "value_name": "V", "event": "modified",
                        "changed_attributes": ["md5", "sha1"]}}
    a = normalize(raw)
    assert a.source == "fim"
    assert a.details == {"path": "HKEY_LOCAL_MACHINE\\System\\X\\V", "change": "modified",
                         "changed_attributes": "md5,sha1"}


def test_sca_check():
    raw = {"decoder": {"name": "sca"}, "rule": {"id": "19008", "level": "3"},
           "data": {"sca": {"policy": "CIS Win11", "check": {"title": "Ensure X", "result": "passed"}}}}
    a = normalize(raw)
    assert a.source == "sca" and a.rule_level == 3
    assert a.details == {"policy": "CIS Win11", "check": "Ensure X", "result": "passed"}


def test_generic_linux_style_fields():
    raw = {"decoder": {"name": "sshd"}, "rule": {"id": "5710", "level": 5},
           "data": {"srcip": "203.0.113.7", "dstuser": "root"}}
    a = normalize(raw)
    assert (a.source, a.user, a.src_ip, a.src_ip_scope) == ("other", "root", "203.0.113.7", "reserved")


def test_wazuh_internal_and_trailing_period():
    a = normalize({"decoder": {"name": "ossec"}, "rule": {"id": "751", "level": 5,
                                                         "description": "Registry Value Entry Deleted. "}})
    assert a.source == "wazuh" and a.description == "Registry Value Entry Deleted"


def test_empty_or_broken_alert_never_raises():
    a = normalize({})
    assert a.source == "other" and a.rule_level == 0 and a.details == {}
    b = normalize({"rule": {"level": "high?"}, "data": "not-a-dict"})
    assert b.rule_level == 0


def test_detect_source_by_location_fallback():
    assert detect_source({"location": "syscheck"}) == "fim"


def test_windows_system_event_params_kept_in_order():
    raw = {"decoder": {"name": "windows_eventchannel"}, "rule": {"id": "61104", "level": 3},
           "data": {"win": {"system": {"eventID": "7040"},
                            "eventdata": {"param10": "z", "param2": "auto start", "param1": "BITS svc",
                                          "param3": "demand start", "param4": "-"}}}}
    a = normalize(raw)
    assert a.details["event_params"] == "BITS svc | auto start | demand start | z"
