from soc.checks import (
    check_ollama,
    check_python,
    models_from_tags,
    parse_default_gateway,
    parse_env_lines,
)

ROUTE_TABLE = """Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
eth0\t00000000\t01E018AC\t0003\t0\t0\t0\t00000000\t0\t0\t0
eth0\t00E018AC\t00000000\t0001\t0\t0\t0\t00F0FFFF\t0\t0\t0
"""


def test_parse_env_ignores_comments_and_blanks():
    env = parse_env_lines(["# comment", "", "OLLAMA_MODEL=qwen2.5:3b", 'X="quoted"', "garbage"])
    assert env == {"OLLAMA_MODEL": "qwen2.5:3b", "X": "quoted"}


def test_parse_env_keeps_equals_in_value():
    assert parse_env_lines(["TOKEN=a=b"]) == {"TOKEN": "a=b"}


def test_default_gateway_decoded_from_little_endian_hex():
    assert parse_default_gateway(ROUTE_TABLE) == "172.24.224.1"


def test_no_default_route_returns_none():
    header_only = ROUTE_TABLE.splitlines()[0]
    assert parse_default_gateway(header_only) is None


def test_python_version_gate():
    assert check_python((3, 12)).ok
    assert not check_python((3, 8)).ok


def test_models_from_tags():
    payload = {"models": [{"name": "qwen2.5:3b"}, {"name": "llama3:8b"}]}
    assert models_from_tags(payload) == ["qwen2.5:3b", "llama3:8b"]


def test_ollama_unreachable_fails_cleanly():
    # Port 9 on localhost: nothing listens, so this must fail fast, not crash.
    result = check_ollama("http://127.0.0.1:9", "qwen2.5:3b")
    assert not result.ok and "unreachable" in result.detail


def test_ollama_without_url_fails_cleanly():
    assert not check_ollama(None, "qwen2.5:3b").ok
