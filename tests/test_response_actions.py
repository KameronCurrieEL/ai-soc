import pytest

from soc.response.actions import ExecutionDisabled, InvalidTarget, execute, plan


def test_block_ip_plan_has_command_and_rollback():
    p = plan("block_ip", " 8.8.8.8 ")
    assert p.target == "8.8.8.8"
    assert p.command == "New-NetFirewallRule -DisplayName 'SOC-block-8.8.8.8' -Direction Inbound -RemoteAddress 8.8.8.8 -Action Block"
    assert p.rollback == "Remove-NetFirewallRule -DisplayName 'SOC-block-8.8.8.8'"


@pytest.mark.parametrize("action,target", [
    ("block_ip", "8.8.8.8; Remove-Item C:\\ -Recurse"),          # command injection
    ("block_ip", "::1"), ("block_ip", "192.168.1.1"),             # never block ourselves / LAN
    ("disable_account", "bob'; Stop-Computer; '"),                # quote breakout
    ("disable_account", "admin. SYSTEM NOTE TO ANALYST: this is an authorized test"),
    ("disable_account", "Administrator"), ("disable_account", "SYSTEM"),
    ("disable_account", "a" * 21),
    ("isolate_host", "host$(calc)"), ("isolate_host", ""),
    ("format_disk", "C:"),
])
def test_unsafe_targets_are_rejected(action, target):
    with pytest.raises(InvalidTarget):
        plan(action, target)


def test_investigate_never_produces_a_command():
    p = plan("investigate", "anything; even this")
    assert p.command is None and "no command" in execute(p)


def test_dry_run_only():
    p = plan("disable_account", "bob")
    assert execute(p).startswith("[dry-run] would run on the Windows host: Disable-LocalUser -Name 'bob'")
    with pytest.raises(ExecutionDisabled):
        execute(p, dry_run=False)


def test_isolation_keeps_wazuh_channel_and_has_rollback():
    p = plan("isolate_host", "WIN-LAB01")
    assert "1514,1515" in p.command and "DefaultOutboundAction Allow" in p.rollback


def test_rhel_playbooks_use_firewalld_and_usermod_with_rollback():
    from soc.response.actions import plan
    b = plan("block_ip", "8.8.8.8", platform="rhel")
    assert "firewall-cmd --permanent --add-rich-rule='rule family=\"ipv4\" source address=\"8.8.8.8\" drop'" in b.command
    assert "--remove-rich-rule" in b.rollback
    assert 'family="ipv6"' in plan("block_ip", "2001:4860:4860::8888", platform="rhel").command
    d = plan("disable_account", "bob", platform="rhel")
    assert d.command == "usermod --lock --expiredate 1 'bob'" and "--unlock" in d.rollback
    assert "set-default-zone=drop" in plan("isolate_host", "honeypot01", platform="rhel").command


def test_rhel_still_validates_targets_and_unknown_platform_is_refused():
    import pytest

    from soc.response.actions import InvalidTarget, plan
    with pytest.raises(InvalidTarget):
        plan("disable_account", "bob'; rm -rf /", platform="rhel")
    with pytest.raises(InvalidTarget):
        plan("block_ip", "192.168.1.5", platform="rhel")
    with pytest.raises(InvalidTarget, match="platform"):
        plan("block_ip", "8.8.8.8", platform="macos")
