"""The proxy has to refuse in a way the server never learns about.

The library's own `authorize()` is a call the agent's harness chooses to make.
These tests cover the version that does not depend on that choice: a process
between the agent and the MCP server, where a denied `tools/call` is answered
with a JSON-RPC error and the server's subprocess never receives the frame.

The end-to-end test spawns a real MCP-shaped server over stdio and asserts on
what that server RECORDED, because "the client got an error" and "the effect did
not happen" are different claims, and only the second one is the product.
"""
from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path

from clayseal.capabilities.broker import SessionBroker
from clayseal.capabilities.hardening.egress_policy import EgressPolicy
from clayseal.capabilities.mcp_proxy import POLICY_DENIED, McpProxy
from clayseal.capabilities.policy import compile_policy
from clayseal.capabilities.scoping.goal import GoalSpec


def _call(tool: str, args: dict | None = None, *, id_: int = 1) -> str:
    return json.dumps({
        "jsonrpc": "2.0", "id": id_, "method": "tools/call",
        "params": {"name": tool, "arguments": args or {}},
    })


def _proxy(**kw) -> McpProxy:
    broker = SessionBroker(
        goal=GoalSpec(query_id="q", summary="summarise the open billing tickets"),
        egress=EgressPolicy(allowed_domains={"acme-internal.com"}),
    )
    kw.setdefault("log", lambda _m: None)
    return McpProxy(gateway=broker, **kw)


# --------------------------------------------------------------------------- #
# The decision
# --------------------------------------------------------------------------- #
def test_a_tool_outside_the_policy_never_reaches_the_server():
    proxy = _proxy(allowed_tools={"read_ticket"})
    to_server, to_client = proxy.handle_client_message(_call("delete_everything"))
    assert to_server is None
    assert to_client is not None
    reply = json.loads(to_client)
    assert reply["id"] == 1
    assert reply["error"]["code"] == POLICY_DENIED
    assert "not in this session's policy" in reply["error"]["message"]


def test_an_allowed_tool_is_forwarded_verbatim():
    proxy = _proxy(allowed_tools={"read_ticket"})
    raw = _call("read_ticket", {"id": "T-1001"})
    to_server, to_client = proxy.handle_client_message(raw)
    assert to_server == raw
    assert to_client is None


def test_a_step_up_is_reported_as_a_refusal_not_a_pass():
    """Nothing in a stdio proxy can hold a call open while a human is asked.

    So a STEP_UP has to reach the agent as a refusal that names the reason. The
    alternative, forwarding it because it was not a hard deny, would turn the
    supervised profile into the autonomous one at the transport layer.
    """
    class StepsUp:
        def authorize(self, action):
            from clayseal.capabilities.broker import BrokerDecision, Outcome

            return BrokerDecision(
                outcome=Outcome.STEP_UP, layer="floor",
                reasons=("destination not on the allow-list",),
            )

    proxy = McpProxy(gateway=StepsUp(), log=lambda _m: None)
    _, to_client = proxy.handle_client_message(_call("send_email"))
    reply = json.loads(to_client)
    assert "held for human approval" in reply["error"]["message"]
    assert proxy.stats.stepped_up == 1
    assert proxy.stats.forwarded == 0


def test_a_frame_the_proxy_does_not_understand_is_forwarded_not_dropped():
    """A proxy that eats what it cannot parse turns an extension into a hang."""
    proxy = _proxy()
    for raw in ("not json at all", json.dumps({"jsonrpc": "2.0", "method": "ping"})):
        to_server, to_client = proxy.handle_client_message(raw)
        assert to_server == raw
        assert to_client is None


# --------------------------------------------------------------------------- #
# The catalog
# --------------------------------------------------------------------------- #
def test_tools_outside_the_policy_are_not_advertised():
    proxy = _proxy(allowed_tools={"read_ticket"})
    listing = json.dumps({
        "jsonrpc": "2.0", "id": 2,
        "result": {"tools": [{"name": "read_ticket"}, {"name": "wire_transfer"}]},
    })
    out = json.loads(proxy.handle_server_message(listing))
    assert [t["name"] for t in out["result"]["tools"]] == ["read_ticket"]
    assert proxy.stats.hidden_tools == {"wire_transfer"}


def test_an_unfiltered_proxy_leaves_the_catalog_alone():
    proxy = _proxy(allowed_tools=None)
    listing = json.dumps({"jsonrpc": "2.0", "id": 2,
                          "result": {"tools": [{"name": "anything"}]}})
    assert proxy.handle_server_message(listing) == listing


# --------------------------------------------------------------------------- #
# End to end, against a real subprocess
# --------------------------------------------------------------------------- #
_SERVER = textwrap.dedent('''
    import json, sys, pathlib
    log = pathlib.Path(sys.argv[1])
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        msg = json.loads(line)
        # Record every call that actually arrived. This file is the evidence.
        with log.open("a") as fh:
            fh.write(msg["params"]["name"] + "\\n")
        print(json.dumps({"jsonrpc": "2.0", "id": msg.get("id"),
                          "result": {"content": [{"type": "text", "text": "done"}]}}),
              flush=True)
''')


def test_the_denied_call_does_not_reach_the_server_process(tmp_path: Path):
    """The claim that matters: the effect did not happen.

    A client-visible error proves the agent was told no. It does not prove the
    tool was not run. This asserts on the server's own record of what it
    received.
    """
    from clayseal.capabilities.mcp_proxy import run_stdio_proxy

    server_py = tmp_path / "server.py"
    server_py.write_text(_SERVER)
    received = tmp_path / "received.txt"

    class Pipe:
        def __init__(self, lines): self._lines = list(lines)
        def __iter__(self): return iter(self._lines)

    class Sink:
        def __init__(self): self.out = []
        def write(self, s): self.out.append(s)
        def flush(self): pass

    proxy = _proxy(allowed_tools={"read_ticket"})
    sink = Sink()
    run_stdio_proxy(
        proxy,
        [sys.executable, str(server_py), str(received)],
        stdin=Pipe([_call("read_ticket", {"id": "T-1"}, id_=1),
                    _call("wire_transfer", {"to": "attacker"}, id_=2)]),
        stdout=sink,
    )

    arrived = received.read_text().split() if received.exists() else []
    assert arrived == ["read_ticket"], f"server received {arrived}"

    replies = [json.loads(line) for line in "".join(sink.out).splitlines() if line]
    by_id = {r["id"]: r for r in replies}
    assert "result" in by_id[1]
    assert by_id[2]["error"]["code"] == POLICY_DENIED


def test_the_policy_document_drives_the_proxy():
    """The two halves join: a reviewed file becomes the tool allow-list."""
    policy = compile_policy({
        "version": 1,
        "goal": {"id": "q", "summary": "read tickets"},
        "tools": {"allow": ["read_ticket"], "harmless": ["read_ticket"]},
    })
    proxy = McpProxy(gateway=policy.build(), allowed_tools=policy.allowed_tools,
                     log=lambda _m: None)
    assert proxy.handle_client_message(_call("wire_transfer"))[0] is None
    assert proxy.handle_client_message(_call("read_ticket"))[1] is None


def test_the_subprocess_is_not_started_by_the_shell():
    """argv is a list, so a server path with a space is not two arguments."""
    import inspect

    from clayseal.capabilities import mcp_proxy

    source = inspect.getsource(mcp_proxy.run_stdio_proxy)
    assert "shell=True" not in source
    assert "subprocess.Popen(" in source
