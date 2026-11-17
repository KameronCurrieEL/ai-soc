from soc.wazuh.indexer import check_indexer, indexer_settings


def test_settings_none_without_credentials():
    assert indexer_settings({"WAZUH_INDEXER_URL": "https://x:9200"}) is None


def test_settings_defaults_and_trailing_slash():
    s = indexer_settings({"WAZUH_INDEXER_USER": "u", "WAZUH_INDEXER_PASSWORD": "p",
                          "WAZUH_INDEXER_URL": "https://x:9200/"})
    assert s.url == "https://x:9200" and s.tls.verify is False


def test_missing_credentials_fail_cleanly():
    r = check_indexer({})
    assert not r.ok and ".env" in r.detail


def test_unreachable_indexer_fails_cleanly():
    env = {"WAZUH_INDEXER_URL": "https://127.0.0.1:9", "WAZUH_INDEXER_USER": "u", "WAZUH_INDEXER_PASSWORD": "p"}
    r = check_indexer(env)
    assert not r.ok and "unreachable" in r.detail
