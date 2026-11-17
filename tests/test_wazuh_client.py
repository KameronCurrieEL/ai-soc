import ssl

from soc.wazuh.client import TlsConfig, ssl_context, tls_from_env


def test_tls_off_by_default():
    ctx = ssl_context(TlsConfig())
    assert ctx.verify_mode == ssl.CERT_NONE and not ctx.check_hostname


def test_tls_on_verifies_cert_and_hostname():
    ctx = ssl_context(TlsConfig(verify=True))
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname


def test_expected_name_is_kept_for_the_handshake():
    ctx = ssl_context(TlsConfig(verify=True, server_name="wazuh.indexer"))
    assert ctx.expected_name == "wazuh.indexer"


def test_tls_from_env_reads_prefixed_keys():
    env = {"WAZUH_VERIFY_TLS": "true", "WAZUH_INDEXER_CA_FILE": "ca.pem", "WAZUH_INDEXER_TLS_NAME": "wazuh.indexer"}
    assert tls_from_env(env, "WAZUH_INDEXER") == TlsConfig(True, "ca.pem", "wazuh.indexer")
    assert tls_from_env(env, "WAZUH_API") == TlsConfig(True, None, None)


def test_verification_needs_explicit_true():
    assert tls_from_env({"WAZUH_VERIFY_TLS": "yes"}, "X").verify is False
