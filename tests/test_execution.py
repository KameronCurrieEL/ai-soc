import pytest

from soc.response.actions import plan
from soc.response.execution import (ExecutionPolicy, ExecutionRefused, register_backend, resolve_policy, run)


def fake_settings(d):
    return lambda k, default="": d.get(k, default)


def test_dry_run_by_default_even_with_tenant_live_but_no_env():
    p = resolve_policy(None, fake_settings({"execution_mode": "live", "live_allowlist": '["8.8.8.8"]'}), env={})
    assert p.live is False                                  # env SOC_ALLOW_LIVE missing -> fails closed
    out, was_live = run(plan("block_ip", "8.8.8.8"), p)
    assert was_live is False and out.startswith("[dry-run]")


def test_requires_env_and_tenant_and_allowlist_and_backend(monkeypatch):
    # env on + tenant on, but target not on allowlist -> refuse
    p = resolve_policy(None, fake_settings({"execution_mode": "live", "live_allowlist": '["1.2.3.4"]'}),
                       env={"SOC_ALLOW_LIVE": "1"})
    assert p.live is True
    with pytest.raises(ExecutionRefused, match="allowlist"):
        run(plan("block_ip", "8.8.8.8"), p, platform="rhel")
    # target allowed but no backend wired -> refuse loudly (don't silently simulate)
    p2 = resolve_policy(None, fake_settings({"execution_mode": "live", "live_allowlist": '["8.8.8.8"]'}),
                        env={"SOC_ALLOW_LIVE": "1"})
    with pytest.raises(ExecutionRefused, match="no execution backend"):
        run(plan("block_ip", "8.8.8.8"), p2, platform="rhel")


def test_live_runs_through_a_wired_backend():
    ran = {}

    def backend(pl):
        ran["cmd"] = pl.command
        return "ok: applied"

    register_backend("rhel", backend)
    p = resolve_policy(None, fake_settings({"execution_mode": "live", "live_allowlist": '["8.8.8.8"]'}),
                       env={"SOC_ALLOW_LIVE": "1"})
    out, was_live = run(plan("block_ip", "8.8.8.8", platform="rhel"), p, platform="rhel")
    assert was_live is True and out == "ok: applied" and "firewall-cmd" in ran["cmd"]


def test_investigate_is_never_a_live_command():
    p = ExecutionPolicy(live=True, allow=frozenset({"anything"}))
    out, was_live = run(plan("investigate", "anything"), p)
    assert was_live is False and "no command" in out


def test_bad_allowlist_json_fails_closed():
    p = resolve_policy(None, fake_settings({"execution_mode": "live", "live_allowlist": "not-json"}),
                       env={"SOC_ALLOW_LIVE": "1"})
    assert p.allow == frozenset()
