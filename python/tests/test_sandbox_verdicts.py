"""Verdict-parser tests, ported from iVisor-demo's policy.rs test module so the
two implementations stay in step (iVisor ADR-0021)."""
from clayseal.capabilities.sandbox.verdicts import (
    POLICY_PREFIX,
    PolicyEvent,
    Verdict,
    parse_policy_line,
)


def test_parses_a_network_denial():
    e = parse_policy_line(
        "ivisor: policy net.connect verdict=deny dst=203.0.113.10:443 "
        "reason=not-allowlisted errno=ECONNREFUSED", verified=True)
    assert e is not None
    assert e.event == "net.connect"
    assert e.subsystem == "net"
    assert e.verdict is Verdict.DENY
    assert e.get("dst") == "203.0.113.10:443"
    assert e.get("reason") == "not-allowlisted"
    assert e.verified


def test_distinguishes_a_miss_from_a_denial():
    # The distinction every containment number rests on: an absent path is not
    # something the sandbox refused.
    miss = parse_policy_line(
        "ivisor: policy fs.open verdict=miss root=rootfs "
        "path=/Users/y/.ssh/id_ed25519 flags=0o0 errno=ENOENT", verified=True)
    assert miss is not None
    assert miss.verdict is Verdict.MISS
    assert miss.matches_watch(["/.ssh/"])

    deny = parse_policy_line(
        "ivisor: policy fs.open verdict=deny root=rootfs path=/etc/x errno=EROFS",
        verified=True)
    assert deny is not None
    assert deny.verdict is Verdict.DENY


def test_handles_quoted_values_and_json_arrays():
    e = parse_policy_line(
        'ivisor: policy proc.exec verdict=allow path=/bin/sh '
        'argv=["sh","-c","echo a b"]', verified=True)
    assert e is not None
    assert e.get("argv") == '["sh","-c","echo a b"]'
    assert e.get("path") == "/bin/sh"

    q = parse_policy_line(
        'ivisor: policy fs.open verdict=allow root=workspace '
        'path="/work/a file.txt"', verified=True)
    assert q is not None
    assert q.get("path") == "/work/a file.txt"


def test_unescapes_json_string_escapes():
    e = parse_policy_line(
        r'ivisor: policy fs.open verdict=allow path="/work/a\tb\nc\"d\\e"',
        verified=True)
    assert e is not None
    assert e.get("path") == '/work/a\tb\nc"d\\e'


def test_ignores_everything_that_is_not_a_policy_line():
    assert parse_policy_line("ivisor: syscall 64 (write) args=[1] -> 0xe",
                             verified=True) is None
    assert parse_policy_line("Traceback (most recent call last):",
                             verified=True) is None
    assert parse_policy_line("", verified=True) is None
    # Well-formed prefix but no verdict: not classifiable, so not accepted
    # an unclassifiable line must never become a silent allow.
    assert parse_policy_line("ivisor: policy net.connect dst=1.2.3.4:443",
                             verified=True) is None
    # An unknown verdict word is likewise rejected rather than coerced.
    assert parse_policy_line("ivisor: policy net.connect verdict=maybe",
                             verified=True) is None
    # Prefix with no event name.
    assert parse_policy_line(POLICY_PREFIX + " verdict=allow",
                             verified=True) is None


def test_survives_a_truncated_line_without_raising():
    # Values are truncated at 256 bytes upstream, and a pipe can tear anywhere.
    full = 'ivisor: policy fs.open verdict=deny path="/a/b" errno=EROFS'
    for cut in range(len(full) + 1):
        parse_policy_line(full[:cut], verified=True)  # must not raise


def test_unterminated_quote_and_bracket_do_not_hang():
    e = parse_policy_line('ivisor: policy fs.open verdict=deny path="/a/b',
                          verified=True)
    assert e is not None and e.get("path") == "/a/b"
    a = parse_policy_line('ivisor: policy proc.exec verdict=allow argv=["sh",',
                          verified=True)
    assert a is not None and a.get("argv") == '["sh",'


def test_unknown_keys_are_kept_not_rejected():
    # The format is allowed to gain keys; a consumer that rejects them breaks
    # on the next iVisor release.
    e = parse_policy_line(
        "ivisor: policy net.connect verdict=allow dst=1.2.3.4:443 "
        "status=ok epoch=7 future_key=xyz", verified=True)
    assert e is not None
    assert e.get("future_key") == "xyz"
    assert e.get("status") == "ok"


def test_verified_flag_is_carried_through():
    line = "ivisor: policy fs.open verdict=allow path=/work/x"
    assert parse_policy_line(line, verified=True).verified is True
    assert parse_policy_line(line, verified=False).verified is False


def test_subject_and_summary():
    e = parse_policy_line(
        "ivisor: policy net.connect verdict=deny dst=203.0.113.10:443 "
        "reason=not-allowlisted", verified=True)
    assert e.subject() == "203.0.113.10:443"
    assert "not-allowlisted" in e.summary()
    # No identifying field -> empty subject, not a crash.
    bare = PolicyEvent(event="net.udp", verdict=Verdict.DENY)
    assert bare.subject() == ""
