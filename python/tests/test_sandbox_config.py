"""iVisor config rendering and fail-closed allowlist validation."""
import pytest

from agentauth.capabilities.sandbox.config import (
    KNOWN_KEYS,
    AllowEntryError,
    IVisorConfig,
    validate_allow_entry,
)


def test_renders_the_documented_grammar():
    cfg = IVisorConfig(rootfs="/rf", workspace="/ws", ram_mb=2048,
                       allow=("api.internal.com", "1.2.3.4:443"),
                       comment="test")
    assert cfg.render() == (
        "# test\n"
        "ram_mb = 2048\n"
        "rootfs = /rf\n"
        "workspace = /ws\n"
        "sandbox = on\n"
        "allow = 1.2.3.4:443,api.internal.com\n"
    )


def test_empty_allow_omits_the_key_entirely():
    # iVisor's default is deny-all; an empty `allow =` line is not the same
    # thing as no line, so we omit it rather than emit an empty value.
    assert "allow" not in IVisorConfig(rootfs="/rf", workspace="/ws").render()


def test_sandbox_off_is_rendered_explicitly():
    text = IVisorConfig(rootfs="/rf", workspace="/ws", sandbox=False).render()
    assert "sandbox = off" in text


def test_listen_is_emitted_when_set():
    cfg = IVisorConfig(rootfs="/rf", workspace="/ws", listen="8000")
    assert "listen = 8000" in cfg.render()


def test_allow_order_does_not_change_the_digest():
    a = IVisorConfig(rootfs="/rf", workspace="/ws", allow=("a.com", "b.com"))
    b = IVisorConfig(rootfs="/rf", workspace="/ws", allow=("b.com", "a.com"))
    assert a.digest() == b.digest()


def test_comment_is_excluded_from_the_digest():
    a = IVisorConfig(rootfs="/rf", workspace="/ws", comment="run one")
    b = IVisorConfig(rootfs="/rf", workspace="/ws", comment="run two")
    assert a.digest() == b.digest()


def test_policy_change_changes_the_digest():
    base = IVisorConfig(rootfs="/rf", workspace="/ws")
    wider = IVisorConfig(rootfs="/rf", workspace="/ws", allow=("evil.com",))
    assert base.digest() != wider.digest()


@pytest.mark.parametrize("ram", [0, 512, 767, 1000])
def test_ram_below_floor_or_off_granularity_is_rejected(ram):
    with pytest.raises(ValueError, match="ram_mb"):
        IVisorConfig(rootfs="/rf", workspace="/ws", ram_mb=ram)


def test_ram_at_the_floor_is_accepted():
    assert IVisorConfig(rootfs="/rf", workspace="/ws", ram_mb=768).ram_mb == 768


def test_unknown_config_keys_are_refused():
    # iVisor aborts the run on an unknown key; catching it here gives a better
    # error than a failed spawn.
    with pytest.raises(ValueError, match="unknown iVisor config key"):
        IVisorConfig(rootfs="/rf", workspace="/ws", extra={"nope": "1"})


def test_extra_known_keys_are_rendered():
    cfg = IVisorConfig(rootfs="/rf", workspace="/ws", extra={"compute": "on"})
    assert "compute = on" in cfg.render()


def test_render_only_ever_emits_known_keys():
    text = IVisorConfig(rootfs="/rf", workspace="/ws", ram_mb=1024,
                        allow=("a.com",), listen="8000").render()
    for line in text.splitlines():
        if line.startswith("#"):
            continue
        assert line.split(" = ")[0] in KNOWN_KEYS


@pytest.mark.parametrize("entry", [
    "example.com", "api.example.com:443", "1.2.3.4", "8.8.8.8:53",
    "[2606::1]:443", "sub.domain.co.uk",
])
def test_valid_allow_entries(entry):
    validate_allow_entry(entry)


@pytest.mark.parametrize("entry", [
    "*.example.com",     # no wildcard rules in iVisor: this would be dropped
    "not a host",
    "localhost",         # no dot: iVisor cannot parse it as a domain
    "",
    "   ",
    "http://example.com",
    ":443",
])
def test_invalid_allow_entries_raise_rather_than_degrade(entry):
    with pytest.raises(AllowEntryError):
        validate_allow_entry(entry)


def test_invalid_entry_is_caught_at_config_construction():
    with pytest.raises(AllowEntryError):
        IVisorConfig(rootfs="/rf", workspace="/ws", allow=("*.evil.com",))
