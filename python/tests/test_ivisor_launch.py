"""The iVisor launch seam maps a goal envelope onto iVisor's CLI. These test the
flag construction only; running the guest needs iVisor built (Apple Silicon)."""
from __future__ import annotations

import pytest

from agentauth.capabilities.sandbox.ivisor import IVisorLaunch, launch_from_envelope


def test_command_maps_envelope_to_flags():
    launch = IVisorLaunch(
        elf="/usr/bin/python3", guest_args=("-c", "print(1)"),
        allow_domains=("intranet.corp.com", "api.corp.com"),
        workspace="/work", rootfs="/rootfs")
    cmd = launch.command()
    assert cmd[0] == "ivisor"
    assert cmd[cmd.index("--rootfs") + 1] == "/rootfs"
    assert cmd[cmd.index("--workspace") + 1] == "/work"
    # domains are sorted and comma-joined into a single --allow spec
    assert cmd[cmd.index("--allow") + 1] == "api.corp.com,intranet.corp.com"
    # the run subcommand precedes the elf, then the guest args
    r = cmd.index("run")
    assert cmd[r + 1] == "/usr/bin/python3"
    assert cmd[r + 2:] == ["-c", "print(1)"]


def test_default_deny_egress_when_no_domains():
    # No allow set means no --allow flag, and iVisor egress is default-deny.
    cmd = IVisorLaunch(elf="/bin/sh").command()
    assert "--allow" not in cmd
    assert cmd == ["ivisor", "run", "/bin/sh"]


def test_launch_from_envelope_lowers_only_network_and_paths():
    class _Egress:
        allowed_domains = {"evil.test", "ok.example"}
        allowed_recipients = {"GB123"}  # stays in the monitor, must NOT reach iVisor

    class _Scope:
        allowed_paths = ["/work/project"]

    launch = launch_from_envelope("/usr/bin/python3", egress=_Egress(), scope=_Scope())
    cmd = launch.command()
    assert cmd[cmd.index("--allow") + 1] == "evil.test,ok.example"
    assert cmd[cmd.index("--workspace") + 1] == "/work/project"
    # the financial recipient is not a network destination and never lowers
    assert "GB123" not in cmd


def test_missing_binary_raises_actionable_error():
    launch = IVisorLaunch(elf="/bin/sh", ivisor_bin="definitely-not-a-real-ivisor-bin")
    with pytest.raises(FileNotFoundError, match="cargo build"):
        launch.run()
