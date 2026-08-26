"""Attacks on the proxy itself, and the defects each one found.

The proxy is an enforcement point, so the interesting question is not whether it
decides correctly but whether an attacker can arrange for it to decide about a
different message than the one the server runs. Everything here got past the
suite that existed before it was written.

Three classes, and they are worth naming separately because the fixes differ:

1. PARSER DIFFERENTIAL. The proxy authorized its own parse and forwarded the
   original bytes, so it was only as correct as the agreement between two JSON
   parsers. Fixed by refusing ambiguity and re-serialising what was authorized.
2. ONE-OF-MANY. The gateway checks one path per action, and a call can name
   several. Fixed by screening the whole set before the action reaches it.
3. REPRESENTATION. A path that has to be decoded or truncated before it means
   anything cannot be compared against a scope, because the gateway and whatever
   opens the file would be comparing different strings.
"""
from __future__ import annotations

import json
import threading
import time

from agentauth.capabilities.mcp_proxy import MAX_BATCH, McpProxy
from agentauth.capabilities.policy import compile_policy


def _proxy(doc_over=None, **kw):
    doc = {
        "version": 1,
        "goal": {"id": "q", "summary": "patch the staging web tier"},
        "profile": "supervised",
        "tools": {"allow": ["tf_apply", "read_ticket"],
                  "harmless": ["tf_apply", "read_ticket"],
                  "effects": {"tf_apply": "write", "read_ticket": "read"}},
        "paths": {"allow": ["infra/staging/**"], "deny": ["infra/prod/**"],
                  "arg_names": {"tf_apply": "target_dir"},
                  "pathless": ["read_ticket"]},
    }
    if doc_over:
        doc.update(doc_over)
    pol = compile_policy(doc)
    kw.setdefault("log", lambda _m: None)
    return McpProxy(gateway=pol.build(), allowed_tools=pol.allowed_tools,
                    tool_verbs=dict(pol.tool_verbs), path_args=dict(pol.path_args),
                    pathless_tools=pol.pathless_tools, **kw)


def _apply(args, id_=1):
    return json.dumps({"jsonrpc": "2.0", "id": id_, "method": "tools/call",
                       "params": {"name": "tf_apply", "arguments": args}})


def _forwarded(proxy, raw) -> bool:
    return proxy.handle_client_message(raw)[0] is not None


# --------------------------------------------------------------------------- #
# 1. Parser differential
# --------------------------------------------------------------------------- #
def test_a_duplicate_key_is_refused_rather_than_resolved():
    """`{"name": "wire_transfer", "name": "read_ticket"}` means two things.

    Python keeps the last duplicate. A parser that keeps the first runs the
    transfer this proxy believed it had cleared. There is no correct key to pick,
    so the message is refused instead of guessed at.
    """
    proxy = _proxy()
    raw = ('{"jsonrpc":"2.0","id":1,"method":"tools/call",'
           '"params":{"name":"wire_transfer","name":"read_ticket"}}')
    to_server, to_client = proxy.handle_client_message(raw)
    assert to_server is None
    assert "duplicate JSON key" in json.loads(to_client)["error"]["message"]
    assert proxy.stats.malformed == 1


def test_a_duplicate_key_anywhere_in_the_message_is_refused():
    proxy = _proxy()
    for raw in (
        '{"jsonrpc":"2.0","id":1,"method":"tools/list","method":"tools/call"}',
        '{"jsonrpc":"2.0","id":1,"method":"tools/call",'
        '"params":{"name":"wire_transfer"},"params":{"name":"read_ticket"}}',
    ):
        assert not _forwarded(proxy, raw), raw


def test_what_is_forwarded_is_what_was_authorized():
    """Re-serialised, not echoed. Byte passthrough is the vulnerability."""
    proxy = _proxy()
    raw = ('{"jsonrpc":"2.0",   "id":1,\t"method":"tools/call",'
           '"params":{"name":"read_ticket"}}')
    to_server, _ = proxy.handle_client_message(raw)
    assert to_server != raw
    assert json.loads(to_server) == json.loads(raw)


def test_a_method_that_only_almost_matches_is_refused():
    """Forwarding it bets that the server is exactly as strict about the string."""
    proxy = _proxy()
    for method in ("tools/call ", " tools/call", "Tools/Call", "TOOLS/CALL"):
        raw = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                          "params": {"name": "wire_transfer"}})
        assert not _forwarded(proxy, raw), method


def test_a_genuinely_unknown_method_is_still_passed_through():
    """Refusing everything unfamiliar turns a protocol extension into a hang."""
    proxy = _proxy()
    assert _forwarded(proxy, json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "resources/list"}))
    assert _forwarded(proxy, "not json at all")


# --------------------------------------------------------------------------- #
# 2. One of many
# --------------------------------------------------------------------------- #
def test_a_second_path_argument_cannot_smuggle_a_write():
    """The regression that declaring `arg_names` introduced.

    The declared argument replaced the default ones instead of joining them, so
    a benign `target_dir` alongside a hostile `path` was checked on the benign
    one and the hostile one was never looked at.
    """
    proxy = _proxy()
    assert not _forwarded(proxy, _apply(
        {"target_dir": "infra/staging/ok.tf", "path": "infra/prod/web.tf"}))


def test_every_path_in_a_list_is_checked_not_the_first():
    proxy = _proxy()
    assert not _forwarded(proxy, _apply(
        {"target_dir": ["infra/staging/a.tf", "infra/prod/b.tf"]}))
    assert _forwarded(proxy, _apply(
        {"target_dir": ["infra/staging/a.tf", "infra/staging/b.tf"]}))


def test_paths_nested_one_level_down_are_still_checked():
    proxy = _proxy()
    assert not _forwarded(proxy, _apply(
        {"target_dir": "infra/staging/a.tf", "file": ["infra/prod/b.tf"]}))


def test_traversal_and_absolute_paths_are_refused():
    proxy = _proxy()
    for value in ("infra/staging/../prod/web.tf",
                  "infra/staging/./../prod/web.tf",
                  "/etc/passwd",
                  "~/.ssh/id_rsa",
                  "/infra/prod/web.tf"):
        assert not _forwarded(proxy, _apply({"target_dir": value})), value


# --------------------------------------------------------------------------- #
# 3. Representation
# --------------------------------------------------------------------------- #
def test_an_encoded_or_truncatable_path_is_refused_before_the_scope():
    """A path that means one thing here and another to whatever opens the file.

    `%2e%2e` is a traversal to anything that URL-decodes, and a NUL truncates in
    anything backed by C. Neither can be compared against a scope, because the
    two ends would be comparing different strings.
    """
    proxy = _proxy()
    for value in ("infra/staging/%2e%2e/prod/web.tf",
                  "infra/staging/x\x00../prod/web.tf",
                  "infra%2fstaging%2f..%2fprod"):
        to_server, to_client = proxy.handle_client_message(
            _apply({"target_dir": value}))
        assert to_server is None, value
        assert "cannot be checked against a scope" in \
            json.loads(to_client)["error"]["message"]


def test_a_poisoned_path_is_refused_even_with_no_scope_configured():
    """It is a property of the path, not of the policy."""
    proxy = _proxy({"paths": {"arg_names": {"tf_apply": "target_dir"}}})
    assert not _forwarded(proxy, _apply({"target_dir": "a/b\x00c"}))


# --------------------------------------------------------------------------- #
# Resource bounds
# --------------------------------------------------------------------------- #
def test_an_oversized_batch_is_refused_rather_than_authorized_one_by_one():
    """Each element takes the session lock and may reach a remote judge."""
    proxy = _proxy()
    batch = json.dumps([
        {"jsonrpc": "2.0", "id": i, "method": "tools/call",
         "params": {"name": "read_ticket", "arguments": {}}}
        for i in range(MAX_BATCH + 1)
    ])
    to_server, to_client = proxy.handle_client_message(batch)
    assert to_server is None
    assert "exceeds" in json.loads(to_client)["error"]["message"]


def test_a_batch_at_the_limit_is_still_served():
    proxy = _proxy()
    batch = json.dumps([
        {"jsonrpc": "2.0", "id": i, "method": "tools/call",
         "params": {"name": "read_ticket", "arguments": {}}}
        for i in range(MAX_BATCH)
    ])
    to_server, _ = proxy.handle_client_message(batch)
    assert len(json.loads(to_server)) == MAX_BATCH


# --------------------------------------------------------------------------- #
# Ordering, which is what makes the content tiers mean anything
# --------------------------------------------------------------------------- #
def test_an_effectful_call_waits_for_the_results_it_might_depend_on():
    """MCP clients pipeline. Without this the provenance tier is asked about a
    destination before it has been told where that destination came from."""
    proxy = _proxy({"tools": {"allow": ["read_ticket", "send_email"],
                              "harmless": ["read_ticket"],
                              "effects": {"read_ticket": "read",
                                          "send_email": "send"}},
                    "paths": {"pathless": ["read_ticket", "send_email"]},
                    "egress": {"domains": ["acme-internal.com"]}},
                   settle_timeout=5.0)
    proxy._results_channel_live = True
    proxy.handle_client_message(json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
         "params": {"name": "read_ticket", "arguments": {"id": "T-1"}}}))

    released = threading.Event()

    def send():
        proxy.handle_client_message(json.dumps(
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
             "params": {"name": "send_email",
                        "arguments": {"to": "ops@acme-internal.com"}}}))
        released.set()

    thread = threading.Thread(target=send)
    thread.start()
    time.sleep(0.2)
    assert not released.is_set(), "the send did not wait for the read"

    proxy.handle_server_message(json.dumps(
        {"jsonrpc": "2.0", "id": 1, "result": {"content": [
            {"type": "text", "text": "contact billing@acme-internal.com"}]}}))
    thread.join(timeout=5)
    assert released.is_set()
    assert "billing@acme-internal.com" in proxy.gateway.broker.provenance._origins


def test_a_server_that_never_answers_does_not_deadlock_the_proxy():
    """Expiry forfeits the ORDERING advisory, never the floor, and says so."""
    notes: list[str] = []
    proxy = _proxy({"tools": {"allow": ["read_ticket", "send_email"],
                              "harmless": ["read_ticket"],
                              "effects": {"read_ticket": "read",
                                          "send_email": "send"}},
                    "paths": {"pathless": ["read_ticket", "send_email"]},
                    "egress": {"domains": ["acme-internal.com"]}},
                   settle_timeout=0.5, log=notes.append)
    proxy._results_channel_live = True
    proxy.handle_client_message(json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
         "params": {"name": "read_ticket", "arguments": {}}}))

    started = time.monotonic()
    to_server, _ = proxy.handle_client_message(json.dumps(
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": "send_email",
                    "arguments": {"to": "ops@acme-internal.com"}}}))
    elapsed = time.monotonic() - started
    assert to_server is not None
    assert 0.4 < elapsed < 5.0
    assert any("proceeded without the results" in n for n in notes), notes


def test_a_caller_that_never_feeds_results_is_never_made_to_wait():
    """The trap this default nearly became.

    A caller driving `handle_client_message` with no server behind it has nothing
    to wait for. Waiting anyway turned every effectful call into a stall, which
    it did to this repository's own suite before the guard existed.
    """
    proxy = _proxy(settle_timeout=30.0)
    proxy.handle_client_message(_apply({"target_dir": "infra/staging/a.tf"}, id_=1))
    started = time.monotonic()
    proxy.handle_client_message(_apply({"target_dir": "infra/staging/b.tf"}, id_=2))
    assert time.monotonic() - started < 2.0


def test_a_read_is_never_held():
    proxy = _proxy(settle_timeout=30.0)
    proxy._results_channel_live = True
    proxy.handle_client_message(json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
         "params": {"name": "read_ticket", "arguments": {}}}))
    started = time.monotonic()
    proxy.handle_client_message(json.dumps(
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": "read_ticket", "arguments": {}}}))
    assert time.monotonic() - started < 2.0


# --------------------------------------------------------------------------- #
# Concurrency
# --------------------------------------------------------------------------- #
def test_a_ceiling_holds_under_concurrent_calls():
    proxy = _proxy({"tools": {"allow": ["send_email"], "harmless": [],
                              "effects": {"send_email": "send"}},
                    "paths": {"pathless": ["send_email"]},
                    "egress": {"domains": ["acme-internal.com"]},
                    "budgets": {"calls": {"ceilings": {"emails": 3},
                                          "tracked": {"send_email": "emails"}}}})
    results: list[bool] = []
    lock = threading.Lock()
    barrier = threading.Barrier(20)

    def worker(i: int) -> None:
        barrier.wait()
        allowed = _forwarded(proxy, json.dumps(
            {"jsonrpc": "2.0", "id": i, "method": "tools/call",
             "params": {"name": "send_email",
                        "arguments": {"to": "ops@acme-internal.com"}}}))
        with lock:
            results.append(allowed)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(True) == 3, results


def test_concurrent_calls_get_distinct_step_numbers():
    proxy = _proxy()
    steps: set[int] = set()
    lock = threading.Lock()

    def worker() -> None:
        action = proxy._action_for({"name": "read_ticket", "arguments": {}})
        with lock:
            steps.add(action.step)

    threads = [threading.Thread(target=worker) for _ in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(steps) == 50


# --------------------------------------------------------------------------- #
# The allow-list that allows more than it looks like
# --------------------------------------------------------------------------- #
def test_a_public_suffix_in_the_egress_list_is_an_error():
    """`domains` matches a name and everything under it."""
    for domain in ("com", "amazonaws.com", "vercel.app", "ngrok-free.app"):
        policy = compile_policy({
            "version": 1, "goal": {"id": "q", "summary": "s"},
            "egress": {"domains": [domain]},
        })
        assert any(f.code == "egress-public-suffix" and f.level == "error"
                   for f in policy.lint()), domain


def test_an_organisation_domain_is_not_flagged():
    policy = compile_policy({
        "version": 1, "goal": {"id": "q", "summary": "s"},
        "egress": {"domains": ["acme-internal.com", "slack.com"]},
    })
    assert not any(f.code == "egress-public-suffix" for f in policy.lint())
