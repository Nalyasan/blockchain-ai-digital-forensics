"""
Empirical Challenger Iteration 2 Adversarial Stress Test Suite.

Probing for residual bypasses, subexpression variations, nested parameter injections,
path traversal, command injection metacharacters, and category attribution correctness.
"""

import pytest
from forensics.endpoint.first_responder import (
    AIFirstResponder,
    DangerousActionError,
    ForbiddenActionCategory,
    SafetyGuard,
    TriagePlaybookType,
    _flatten_payload,
)


class TestSubexpressionVariations:
    """Probes for PowerShell subexpression bypasses with whitespace and nesting variations."""

    @pytest.mark.parametrize(
        "payload",
        [
            "((whoami))",
            "(whoami)",
            "(Get-Process | Out-String)",
            "(calc.exe)",
            "(ls)",
            "(dir)",
        ],
    )
    def test_direct_subexpression_blocked(self, payload):
        is_safe, cat, _ = SafetyGuard.evaluate("triage_running_processes", {"filter": payload})
        assert not is_safe, f"Subexpression {payload} was not blocked!"
        assert cat == ForbiddenActionCategory.ARBITRARY_SHELL

    @pytest.mark.parametrize(
        "payload",
        [
            "(  Get-Date  )",
            "( Get-Date )",
            "( Get-Process )",
            "( whoami )",
            "(( whoami ))",
            "(  calc.exe  )",
            "(\tGet-Date)",
            "( ls )",
            "( dir )",
        ],
    )
    def test_spaced_subexpression_behavior(self, payload):
        """Documents whether whitespace within parentheses bypasses SafetyGuard."""
        is_safe, cat, _ = SafetyGuard.evaluate("triage_running_processes", {"filter": payload})
        # Challenger verification: does it get blocked or bypass?
        assert not is_safe, f"Spaced subexpression '{payload}' bypassed SafetyGuard!"
        assert cat == ForbiddenActionCategory.ARBITRARY_SHELL


class TestNestedParameterInjection:
    """Probes for parameter injection via nested structures."""

    def test_deep_nested_dict(self):
        payload = {"level1": {"level2": {"level3": {"attack": "iptables -F"}}}}
        is_safe, cat, _ = SafetyGuard.evaluate("triage_running_processes", payload)
        assert not is_safe
        assert cat == ForbiddenActionCategory.AUTOMATED_NETWORK_ISOLATION

    def test_nested_tuples_and_lists(self):
        payload = {"data": [1, 2, ("a", ["b", ("c", "cat id_rsa")])]}
        is_safe, cat, _ = SafetyGuard.evaluate("triage_running_processes", payload)
        assert not is_safe
        assert cat == ForbiddenActionCategory.KEY_SIGNING

    def test_nested_set_and_bytes(self):
        payload = {"items": {b"Remove-Item app.evtx", "normal_log"}}
        is_safe, cat, _ = SafetyGuard.evaluate("triage_running_processes", payload)
        assert not is_safe
        assert cat == ForbiddenActionCategory.EVENT_LOG_CLEARING

    def test_nested_none_and_numbers(self):
        # Unknown kwargs are rejected by the strict schema (extra="forbid"), so the
        # false-positive probe targets the pattern layer and schema-valid scalars.
        flattened = " ".join(_flatten_payload({"params": [None, 123, 45.67, True]}))
        for pattern in (
            SafetyGuard._FORBIDDEN_KEY_RE,
            SafetyGuard._FORBIDDEN_ISOLATION_RE,
            SafetyGuard._FORBIDDEN_ACL_RE,
            SafetyGuard._FORBIDDEN_LOG_RE,
            SafetyGuard._FORBIDDEN_DELETION_RE,
            SafetyGuard._FORBIDDEN_SENSITIVE_PATHS_RE,
            SafetyGuard._FORBIDDEN_SHELL_RE,
        ):
            assert not pattern.search(flattened)

        payload = {"target_pid": 123, "name_filter": None, "flag_suspicious_paths": True, "limit": 45}
        is_safe, cat, _ = SafetyGuard.evaluate("triage_running_processes", payload)
        assert is_safe
        assert cat is None

        is_safe, cat, reason = SafetyGuard.evaluate("triage_running_processes", {"params": [None, 123]})
        assert not is_safe
        assert "extra_forbidden" in str(reason)


class TestTriageHashVerificationPaths:
    """Probes file path traversal, sensitive credential paths, and command injection metacharacters."""

    @pytest.mark.parametrize(
        "file_path,expected_cat",
        [
            ("../.env", ForbiddenActionCategory.KEY_SIGNING),
            (r".\id_rsa", ForbiddenActionCategory.KEY_SIGNING),
            (r"C:\secrets\private_key.pem", ForbiddenActionCategory.KEY_SIGNING),
            ("secrets/id_ed25519", ForbiddenActionCategory.KEY_SIGNING),
            ("~/.ssh/id_rsa", ForbiddenActionCategory.KEY_SIGNING),
            (r"C:\Users\admin\.ethereum\keystore\UTC--2026", ForbiddenActionCategory.KEY_SIGNING),
            ("wallet.dat", ForbiddenActionCategory.KEY_SIGNING),
            ("privkey.pem", ForbiddenActionCategory.KEY_SIGNING),
            ("private-key.txt", ForbiddenActionCategory.KEY_SIGNING),
            ("calc.exe; whoami", ForbiddenActionCategory.ARBITRARY_SHELL),
            ("calc.exe & dir", ForbiddenActionCategory.ARBITRARY_SHELL),
            ("test.exe | whoami", ForbiddenActionCategory.ARBITRARY_SHELL),
            ("binary.exe`whoami`", ForbiddenActionCategory.ARBITRARY_SHELL),
            ("$(whoami).exe", ForbiddenActionCategory.ARBITRARY_SHELL),
            ("test>out.txt", ForbiddenActionCategory.ARBITRARY_SHELL),
        ],
    )
    def test_hash_verification_dangerous_paths(self, file_path, expected_cat):
        is_safe, cat, _ = SafetyGuard.evaluate("triage_hash_verification", {"file_path": file_path})
        assert not is_safe, f"Path '{file_path}' bypassed SafetyGuard!"
        assert cat == expected_cat, f"Path '{file_path}' misattributed to {cat}, expected {expected_cat}"

    @pytest.mark.parametrize(
        "file_path",
        [
            "(  whoami  )",
            "(  Get-Date  )",
            "(( whoami ))",
        ],
    )
    def test_hash_verification_spaced_subexpression_in_path(self, file_path):
        is_safe, cat, _ = SafetyGuard.evaluate("triage_hash_verification", {"file_path": file_path})
        assert not is_safe, f"Subexpression in file_path '{file_path}' bypassed SafetyGuard!"
        assert cat == ForbiddenActionCategory.ARBITRARY_SHELL

    @pytest.mark.parametrize(
        "file_path",
        [
            r"C:\Program Files (x86)\Windows Defender\MsMpEng.exe",
            r"C:\Program Files (x64)\SecurityApp\scanner.exe",
            r"C:\Binaries\sample (1)\tool.exe",
            "cmd.exe",
            "calc.exe",
        ],
    )
    def test_hash_verification_benign_system_binaries_allowed(self, file_path):
        is_safe, cat, _ = SafetyGuard.evaluate("triage_hash_verification", {"file_path": file_path})
        assert is_safe, f"Legitimate binary path '{file_path}' was falsely blocked as {cat}!"
        assert cat is None


class TestCategoryAttributionComprehensive:
    """Verifies that all 5 forbidden categories are attributed accurately with DangerousActionError."""

    @pytest.mark.parametrize(
        "cmd",
        [
            "wevtutil cl Security",
            "wevtutil clear-log Application",
            "wevtutil sl System /e:false",
            "Clear-EventLog -LogName Security",
            "Remove-EventLog -LogName Application",
            "Limit-EventLog -LogName System",
            "Remove-Item *.evtx",
            r"Remove-Item C:\Logs\app.evtx",
            r"del C:\Windows\System32\winevt\logs\Security.evtx",
            "erase *.evtx",
        ],
    )
    def test_category_2_event_log_clearing_attribution(self, cmd):
        with pytest.raises(DangerousActionError) as exc_info:
            SafetyGuard.validate_action(cmd)
        assert exc_info.value.category == ForbiddenActionCategory.EVENT_LOG_CLEARING

    @pytest.mark.parametrize(
        "cmd",
        [
            r"icacls C:\target /grant Everyone:F",
            r"cacls C:\target /e /g user:f",
            r"takeown /f C:\target",
            r"subinacl /file C:\target /grant=Everyone=F",
            "Set-Acl -Path C:\\target -AclObject $acl",
            "chmod 777 /etc/shadow",
            "chown root /target",
            "chgrp admin /target",
        ],
    )
    def test_category_3_acl_alteration_attribution(self, cmd):
        with pytest.raises(DangerousActionError) as exc_info:
            SafetyGuard.validate_action(cmd)
        assert exc_info.value.category == ForbiddenActionCategory.ACL_ALTERATION

    @pytest.mark.parametrize(
        "cmd",
        [
            "netsh advfirewall set allprofiles state on",
            "netsh advfirewall firewall add rule name=test dir=in action=block",
            "Disable-NetAdapter -Name Ethernet -Confirm:$false",
            "Set-NetFirewallRule -Name Block -Enabled True",
            "New-NetFirewallRule -DisplayName Block",
            "route delete 0.0.0.0",
            "ipconfig /release",
            "ipconfig /renew",
            "iptables -A INPUT -j DROP",
            "iptables -F",
            "ip6tables -F",
            "ufw block from 1.2.3.4",
            "firewall-cmd --panic-on",
            "ifconfig eth0 down",
            "ip link set eth0 down",
        ],
    )
    def test_category_4_network_isolation_attribution(self, cmd):
        with pytest.raises(DangerousActionError) as exc_info:
            SafetyGuard.validate_action(cmd)
        assert exc_info.value.category == ForbiddenActionCategory.AUTOMATED_NETWORK_ISOLATION

    @pytest.mark.parametrize(
        "cmd",
        [
            "cast send 0x1234567890abcdef1234567890abcdef12345678",
            "cast mktx 0x1234567890abcdef1234567890abcdef12345678",
            "eth_sign",
            "personal_sign",
            "eth_sendRawTransaction",
            "sign_transaction",
            "cat .env",
            "type .env",
            "cat id_rsa",
            "cat id_ecdsa",
            "cat id_ed25519",
            "read keystore.json",
            "copy wallet.dat C:\\dest",
            "echo private_key=0x123",
            "read private_key",
            "cat privkey",
            "cat private-key.pem",
            "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ],
    )
    def test_category_5_key_signing_attribution(self, cmd):
        with pytest.raises(DangerousActionError) as exc_info:
            SafetyGuard.validate_action(cmd)
        assert exc_info.value.category == ForbiddenActionCategory.KEY_SIGNING

    @pytest.mark.parametrize(
        "cmd",
        [
            "cmd.exe /c whoami",
            "cmd /k dir",
            "powershell.exe -enc Y2FsYy5leGU=",
            "pwsh -c id",
            "bash -c id",
            "sh -c whoami",
            "cscript.exe evil.vbs",
            "wscript.exe evil.vbs",
            "mshta.exe javascript:alert(1)",
            "iex 'calc.exe'",
            "Invoke-Expression 'Get-Process'",
            "Invoke-Command -ScriptBlock { dir }",
            "Start-Process calc.exe",
            "New-Object -TypeName Net.WebClient",
            "subprocess.Popen(['calc.exe'])",
            "os.system('calc.exe')",
            "exec('import os')",
            "eval('1+1')",
        ],
    )
    def test_category_1_arbitrary_shell_attribution(self, cmd):
        with pytest.raises(DangerousActionError) as exc_info:
            SafetyGuard.validate_action(cmd)
        assert exc_info.value.category == ForbiddenActionCategory.ARBITRARY_SHELL
