from soc.wazuh.agents import agents_from_response, format_agent

PAYLOAD = {
    "error": 0,
    "data": {"affected_items": [
        {"id": "000", "name": "wazuh.manager", "ip": "127.0.0.1", "status": "active"},
        {"id": "001", "name": "win-lab01", "ip": "127.0.0.1", "status": "active",
         "version": "Wazuh v4.9.2", "os": {"name": "Microsoft Windows 11 Home"},
         "lastKeepAlive": "2026-11-17T19:41:53+00:00"},
    ]},
}


def test_manager_is_hidden_by_default():
    agents = agents_from_response(PAYLOAD)
    assert [a.id for a in agents] == ["001"]


def test_manager_can_be_included():
    assert len(agents_from_response(PAYLOAD, include_manager=True)) == 2


def test_fields_mapped_including_nested_os():
    a = agents_from_response(PAYLOAD)[0]
    assert (a.name, a.status, a.os) == ("win-lab01", "active", "Microsoft Windows 11 Home")


def test_missing_fields_do_not_crash():
    a = agents_from_response({"data": {"affected_items": [{"id": "002"}]}})[0]
    assert a.status == "unknown" and a.os == ""


def test_empty_or_error_payload_gives_empty_list():
    assert agents_from_response({"error": 1, "data": None}) == []


def test_format_contains_key_fields():
    line = format_agent(agents_from_response(PAYLOAD)[0])
    assert "001" in line and "active" in line and "win-lab01" in line
