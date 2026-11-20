import importlib

from soc.web.app import _extra_allowed_hosts, _secret_key, create_app


def test_secret_key_is_stable_across_restarts(tmp_path, monkeypatch):
    monkeypatch.delenv("SOC_SECRET_KEY", raising=False)
    db = tmp_path / "soc.db"
    k1 = _secret_key(db)
    assert (tmp_path / "secret.key").exists()
    assert _secret_key(db) == k1                      # persisted -> same key next start (sessions survive)


def test_secret_key_env_override(tmp_path, monkeypatch):
    monkeypatch.setenv("SOC_SECRET_KEY", "fixed-key-123")
    assert _secret_key(tmp_path / "soc.db") == "fixed-key-123"


def test_extra_allowed_hosts_parsing(monkeypatch):
    monkeypatch.setenv("SOC_ALLOWED_HOSTS", "soc.example.com, lab.example.net:8765 ,")
    assert _extra_allowed_hosts() == {"soc.example.com", "lab.example.net"}


def test_tunnel_host_accepted_and_secure_cookie_over_https(tmp_path, monkeypatch):
    monkeypatch.setenv("SOC_ALLOWED_HOSTS", "soc.example.com")
    monkeypatch.setenv("SOC_HTTPS", "1")
    app = create_app(tmp_path / "soc.db")
    assert app.config["SESSION_COOKIE_SECURE"] is True
    c = app.test_client()
    assert c.get("/login", headers={"Host": "soc.example.com"}).status_code == 200   # tunnel host allowed
    assert c.get("/login", headers={"Host": "evil.example"}).status_code == 400       # others still refused


def test_default_binds_localhost_only(tmp_path, monkeypatch):
    monkeypatch.delenv("SOC_ALLOWED_HOSTS", raising=False)
    monkeypatch.delenv("SOC_HTTPS", raising=False)
    app = create_app(tmp_path / "soc.db")
    assert app.config["SESSION_COOKIE_SECURE"] is False
    c = app.test_client()
    assert c.get("/login", headers={"Host": "localhost"}).status_code == 200
    assert c.get("/login", headers={"Host": "soc.example.com"}).status_code == 400
