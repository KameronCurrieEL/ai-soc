import base64

from soc.wazuh.auth import basic_auth_header, check_wazuh_api, token_from_response


def test_basic_auth_header_is_base64_user_colon_password():
    header = basic_auth_header("wazuh-wui", "p@ss:word")
    assert header.startswith("Basic ")
    assert base64.b64decode(header[6:]).decode() == "wazuh-wui:p@ss:word"


def test_token_extracted_from_wazuh_envelope():
    assert token_from_response({"data": {"token": "a.b.c"}, "error": 0}) == "a.b.c"


def test_missing_token_returns_none():
    assert token_from_response({"error": 1, "data": None}) is None


def test_missing_credentials_fail_cleanly():
    result = check_wazuh_api({"WAZUH_API_URL": "https://127.0.0.1:9"})
    assert not result.ok and ".env" in result.detail


def test_unreachable_api_fails_cleanly():
    env = {"WAZUH_API_URL": "https://127.0.0.1:9", "WAZUH_API_USER": "u", "WAZUH_API_PASSWORD": "p"}
    result = check_wazuh_api(env)
    assert not result.ok and "unreachable" in result.detail
