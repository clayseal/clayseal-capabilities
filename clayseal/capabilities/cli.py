"""`clayseal`: read a policy, review it, and enforce it.

In the order someone actually uses them.

    clayseal try --fast                    see it work before reading anything
    clayseal howto                         how to write a policy and enforce it
    clayseal policy new  > policy.yaml     a starter policy to edit
    clayseal policy lint   policy.yaml     errors until TODOs are gone
    clayseal proxy --policy policy.yaml -- <mcp-server>
    clayseal skill --write                 drop a Cursor/Claude skill here
"""
from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from clayseal.capabilities.policy import PolicyError, load_policy


def _cmd_policy_index(args: argparse.Namespace) -> int:
    """`clayseal policy` with no subcommand: say how to start, not argparse's error."""
    parser = getattr(args, "_policy_parser", None)
    if parser is not None:
        parser.print_help()
    print("\nStart with:  clayseal policy new > policy.yaml", file=sys.stderr)
    return 2


def _cmd_try(args: argparse.Namespace) -> int:
    from clayseal.capabilities.onboarding import run

    return run(fast=args.fast, explain=args.explain)


def _cmd_howto(args: argparse.Namespace) -> int:
    from clayseal.capabilities.agent_guide import howto_text

    print(howto_text(), end="")
    return 0


def _cmd_skill(args: argparse.Namespace) -> int:
    """Print the skill, or write it where Cursor and Claude Code will find it."""
    from clayseal.capabilities.agent_guide import (
        consumer_agents_markdown,
        skill_markdown,
    )

    text = skill_markdown()
    if not args.write:
        print(text, end="")
        return 0

    targets = (
        Path(".cursor/skills/clayseal/SKILL.md"),
        Path(".claude/skills/clayseal/SKILL.md"),
    )
    wrote = 0
    for path in targets:
        if path.exists() and not args.force:
            print(f"{path} exists; pass --force to overwrite", file=sys.stderr)
            continue
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        except OSError as exc:
            print(f"clayseal: cannot write {path}: {exc}", file=sys.stderr)
            continue
        print(f"wrote {path}", file=sys.stderr)
        wrote += 1

    agents = Path("AGENTS.md")
    if not agents.exists():
        try:
            agents.write_text(consumer_agents_markdown())
        except OSError as exc:
            print(f"clayseal: cannot write {agents}: {exc}", file=sys.stderr)
        else:
            print("wrote AGENTS.md", file=sys.stderr)
            wrote += 1

    if wrote == 0:
        return 1
    if Path("policy.yaml").exists():
        print("next: clayseal policy lint policy.yaml", file=sys.stderr)
    else:
        print("next: clayseal policy new > policy.yaml", file=sys.stderr)
    return 0


def _cmd_show(args: argparse.Namespace) -> int:
    policy = load_policy(args.policy)
    print(policy.describe())
    return 0


def _cmd_lint(args: argparse.Namespace) -> int:
    policy = load_policy(args.policy)
    findings = policy.lint()
    if not findings:
        print(f"{args.policy}: clean")
        return 0
    for finding in findings:
        print(finding)
    errors = sum(1 for f in findings if f.level == "error")
    warnings = len(findings) - errors
    print(f"\n{errors} error(s), {warnings} warning(s)", file=sys.stderr)
    if errors and not args.warnings_as_errors:
        return 1
    return 1 if (errors or (warnings and args.warnings_as_errors)) else 0


def _cmd_new(args: argparse.Namespace) -> int:
    from clayseal.capabilities.starter import starter_policy

    name = args.out or "policy.yaml"
    text = starter_policy(goal_id=args.goal_id, days=args.days, name=name)
    if args.out:
        path = Path(args.out)
        if path.exists() and not args.force:
            print(f"{path} exists; pass --force to overwrite", file=sys.stderr)
            return 1
        path.write_text(text)
        print(f"wrote {path}", file=sys.stderr)
    else:
        print(text, end="")
    # Hints stay on stderr so `> policy.yaml` still shows them.
    print(f"now edit the TODOs, then: clayseal policy lint {name}",
          file=sys.stderr)
    print("rename the your_* tools; put real mailboxes in egress.recipients",
          file=sys.stderr)
    return 0


def _cmd_init(args: argparse.Namespace) -> int:
    """Scaffold a policy from a live MCP server's own tool catalog.

    The first question an operator hits is "what do I write here", and most of
    the answer is sitting in the server they already run. This asks it for
    `tools/list` and writes the skeleton out. What it writes is a file for a
    person to finish rather than a grant: the server describing the tools is the
    server being constrained, so the catalog is read as a suggestion that may
    raise a tool's effect and never lower it.
    """
    import json
    import subprocess

    from clayseal.capabilities.policy_draft import Draft, extract, to_yaml
    from clayseal.capabilities.policy_scaffold import read_catalog

    command = [c for c in (args.command or []) if c != "--"]
    if not command:
        print("clayseal policy init needs the server to run, after `--`:\n"
              "  clayseal policy init -- npx @acme/mcp-server", file=sys.stderr)
        return 2

    if args.rules and not Path(args.rules).exists():
        print(f"clayseal: no such document: {args.rules}", file=sys.stderr)
        return 2

    request = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    try:
        # argv comes from the operator's own command line, not from a document.
        run = subprocess.run(
            command, input=request + "\n", capture_output=True, text=True,
            timeout=args.timeout, check=False)
    except (subprocess.TimeoutExpired, OSError) as exc:
        print(f"clayseal: could not run the server: {exc}", file=sys.stderr)
        return 2

    catalog = None
    for line in run.stdout.splitlines():
        try:
            message = json.loads(line)
        except ValueError:
            continue
        if not isinstance(message, dict) or "result" not in message:
            continue
        read = read_catalog(message["result"])
        if read.tools or read.unreadable:
            catalog = read
            break

    if catalog is None:
        print("clayseal: the server returned no tool catalog. Run it by hand "
              "and\n          check it answers tools/list on stdio.",
              file=sys.stderr)
        if run.stderr.strip():
            print(f"clayseal: the server said: {run.stderr.strip()[:400]}",
                  file=sys.stderr)
        return 1

    draft, document = Draft(), None
    if args.rules:
        # The catalog goes IN, not just out. `extract` binds ordering and
        # state-conditional rules to a tool, and with no catalog it has nothing
        # to bind to and files the sentence as a TODO instead. This command has
        # had both halves in hand all along and was passing only one.
        draft = extract(Path(args.rules).read_text(),
                        [t.name for t in catalog.tools])
        document = str(args.rules)

    rendered = to_yaml(
        draft,
        goal_id=args.goal_id or "REPLACE-ME",
        goal_summary=args.goal or "REPLACE ME with the task this grant is for",
        catalog=catalog,
        document=document,
        server=" ".join(command))

    if args.out:
        Path(args.out).write_text(rendered)
        print(f"clayseal: wrote {args.out}", file=sys.stderr)
    else:
        print(rendered)

    print(f"clayseal: {len(catalog.tools)} tool(s) from the server's own "
          "catalog", file=sys.stderr)
    if args.rules:
        print(f"clayseal: {draft.summary()}", file=sys.stderr)
    if catalog.unreadable:
        print(f"clayseal: {catalog.unreadable} catalog entry/entries could not "
              "be read as a tool and were left out", file=sys.stderr)
    unsure = catalog.unsure()
    if unsure:
        print(f"clayseal: no effect could be worked out for "
              f"{', '.join(unsure)}. Set them.", file=sys.stderr)
    for tool in catalog.disagreements():
        print(f"clayseal: {tool.name}: {tool.disagreement}", file=sys.stderr)
    print("clayseal: every effect above is a GUESS and the catalog is written "
          "by the\n          server this would constrain. Check them, fill the "
          "TODOs, then\n          `clayseal policy lint`.", file=sys.stderr)
    return 0


def _cmd_draft(args: argparse.Namespace) -> int:
    from clayseal.capabilities.policy_draft import extract, to_yaml

    try:
        document = Path(args.document).read_text()
    except OSError as exc:
        print(f"clayseal: cannot read {args.document}: {exc}", file=sys.stderr)
        return 2

    tools = [t.strip() for t in (args.tools or "").split(",") if t.strip()]
    draft = extract(document, tools)
    rendered = to_yaml(draft, goal_id=args.goal_id or "REPLACE-ME",
                       goal_summary=args.goal or
                       "REPLACE ME with the task this grant is for",
                       tools=tools)

    if args.out:
        Path(args.out).write_text(rendered)
        print(f"clayseal: wrote {args.out}", file=sys.stderr)
    else:
        print(rendered)

    print(f"clayseal: {draft.summary()}", file=sys.stderr)
    if draft.unmapped:
        print("clayseal: these read as rules and did NOT become policy:",
              file=sys.stderr)
        for rule in draft.unmapped:
            print(f"  {rule.cite()}", file=sys.stderr)
    print("clayseal: this is a DRAFT and not a grant. Read it against the source,"
          "\n          fill the TODOs, then run `clayseal policy lint` on it.",
          file=sys.stderr)
    return 0


def _cmd_proxy(args: argparse.Namespace) -> int:
    from clayseal.capabilities.mcp_proxy import McpProxy, run_stdio_proxy

    if not args.command:
        print(
            "clayseal proxy needs the server to run, after `--`:\n"
            "  clayseal proxy --policy policy.yaml -- npx @acme/mcp-server",
            file=sys.stderr,
        )
        return 2

    if _looks_like_a_python_module(list(args.command)):
        print(
            "clayseal: that command ends in a .py file. If it is ordinary "
            "Python functions and not an MCP server (JSON-RPC on stdio), wrap "
            "them with Guardrail instead — see `clayseal howto`.",
            file=sys.stderr,
        )

    policy = load_policy(args.policy)
    findings = policy.lint()
    errors = [f for f in findings if f.level == "error"]
    if errors:
        # Refusing here rather than warning. An error finding means the document
        # grants something its author did not intend, and starting anyway would
        # enforce that intent.
        print(f"clayseal: refusing to start on {len(errors)} policy error(s):",
              file=sys.stderr)
        for f in errors:
            print(f"  {f}", file=sys.stderr)
        print("  Fix them, or run `clayseal policy lint` to see the whole list.",
              file=sys.stderr)
        return 2
    for f in findings:
        print(f"clayseal: {f}", file=sys.stderr)

    gateway = policy.build()
    print(f"clayseal: enforcing {policy.source} ({policy.digest()[:19]}) "
          f"under profile {policy.profile}", file=sys.stderr)
    proxy = McpProxy.from_policy(policy, gateway)
    return run_stdio_proxy(proxy, list(args.command))


def _looks_like_a_python_module(command: list[str]) -> bool:
    """`python tools.py`, not `python -m some.mcp` and not `npx @org/server`."""
    if not command or "-m" in command:
        return False
    return Path(command[-1]).suffix == ".py"


def _is_loopback(host: str) -> bool:
    """Is this bind address reachable only from the same host?

    An empty host and `0.0.0.0` / `::` mean every interface. Anything that does
    not parse as an address is a name, and a name is not assumed to be local.
    """
    import ipaddress

    host = (host or "").strip().strip("[]")
    if not host:
        return False
    if host in {"localhost", "localhost.localdomain"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _cmd_serve(args: argparse.Namespace) -> int:
    """Run the policy in front of a Streamable HTTP MCP server.

    `proxy` is the stdio form, where the process boundary is the session
    boundary. This is the remote form, where MCP 2026-07-28 has removed the
    session entirely, so what survives a request is whatever the policy binds to
    a principal. `readiness` reports which tiers are live and which cannot be,
    because an operator reading a quiet log cannot tell a tier that found
    nothing from one that never ran.
    """
    from clayseal.capabilities.http_gateway import (
        HttpGateway,
        serve,
        urllib_upstream,
    )
    from clayseal.capabilities.mcp_proxy import McpProxy

    try:
        policy = load_policy(args.policy)
    except PolicyError as exc:
        print(f"clayseal: {exc}", file=sys.stderr)
        return 2

    gateway = HttpGateway(
        proxy=McpProxy.from_policy(policy),
        upstream=urllib_upstream(args.upstream) if args.upstream else None,
        require_headers=not args.allow_missing_headers,
    )
    # The gateway carries no authentication of its own: it authorizes the CALLS
    # it is handed, and trusts whoever hands them over. On loopback that is the
    # agent process on the same host. Bound anywhere else, anyone who can reach
    # the port can push tool calls through it under this policy's authority, so
    # a non-loopback bind needs an authenticating proxy in front of it.
    if not _is_loopback(args.host):
        print(f"clayseal: WARNING {args.host} is not a loopback address. This "
              f"gateway does not authenticate its callers; put an "
              f"authenticating proxy in front of it or bind 127.0.0.1.",
              file=sys.stderr)
    server = serve(gateway, host=args.host, port=args.port, path=args.path,
                   log=lambda line: print(f"clayseal: {line}", file=sys.stderr))
    print(f"clayseal: enforcing {policy.source} ({policy.digest()[:19]}) on "
          f"http://{args.host}:{args.port}{args.path}", file=sys.stderr)
    for key, value in gateway.readiness().items():
        print(f"clayseal:   {key}: {value}", file=sys.stderr)
    if args.upstream:
        print(f"clayseal: forwarding allowed calls to {args.upstream}",
              file=sys.stderr)
    else:
        print("clayseal: no --upstream, so this decides and does not forward",
              file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="clayseal",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Authorize each agent tool call against a reviewable policy file.",
        epilog=(
            "Start here:\n"
            "  clayseal try --fast\n"
            "  clayseal howto\n"
            "  clayseal policy new > policy.yaml\n"
            "  clayseal policy lint policy.yaml\n"
            "  # Python tools: wrap them — see `clayseal howto`\n"
            "  clayseal proxy --policy policy.yaml -- <mcp-server>\n"
        ),
    )
    sub = parser.add_subparsers(dest="group", required=False)

    try_cmd = sub.add_parser(
        "try", help="watch the gateway stop two attacks, no setup")
    try_cmd.add_argument("--fast", action="store_true",
                         help="no pauses; also the default when piped")
    try_cmd.add_argument("--explain", action="store_true",
                         help="name the layer that answered each call")
    try_cmd.set_defaults(func=_cmd_try)

    howto_cmd = sub.add_parser(
        "howto",
        help="print how to write a policy and put it in front of an agent",
        description=(
            "The deploy runbook, from the installed package. An agent that ran "
            "`pip install clayseal` does not have the git docs; run this instead."
        ),
    )
    howto_cmd.set_defaults(func=_cmd_howto)

    skill_cmd = sub.add_parser(
        "skill",
        help="print a Cursor/Claude skill; --write installs it in this project",
        description=(
            "The same runbook as `clayseal howto`, as a SKILL.md Cursor and "
            "Claude Code will pick up. Without --write it prints to stdout. "
            "With --write it lands in .cursor/skills/clayseal/ and "
            ".claude/skills/clayseal/, and writes AGENTS.md if that file is "
            "missing."
        ),
    )
    skill_cmd.add_argument(
        "--write", action="store_true",
        help="write the skill into this directory",
    )
    skill_cmd.add_argument(
        "--force", action="store_true",
        help="overwrite an existing skill file",
    )
    skill_cmd.set_defaults(func=_cmd_skill)

    serve_cmd = sub.add_parser(
        "serve", help="HTTP MCP gateway (not Claude Desktop; use proxy for that)",
        description=(
            "Streamable HTTP. Claude Desktop and Cursor speak stdio — that is "
            "`clayseal proxy`. Use this when the client is already HTTP. MCP "
            "2026-07-28 removes the session handshake, so a per-session ceiling "
            "counts over nothing: bind one to a principal with "
            "`deployment.principal` and a durable ledger, which `policy lint` "
            "will insist on."))
    serve_cmd.add_argument("--policy", required=True)
    serve_cmd.add_argument("--upstream", default=None,
                           help="URL of the MCP server to forward allowed calls to")
    serve_cmd.add_argument("--host", default="127.0.0.1")
    serve_cmd.add_argument("--port", type=int, default=8900)
    serve_cmd.add_argument("--path", default="/mcp")
    serve_cmd.add_argument(
        "--allow-missing-headers", action="store_true",
        help=("accept a request with no Mcp-Method. The spec requires it and a "
              "gateway that cannot see what it is routing is not routing it, so "
              "this is for talking to a pre-2026 client and nothing else."))
    serve_cmd.set_defaults(func=_cmd_serve)

    policy = sub.add_parser(
        "policy",
        help="write, lint, or inspect a policy (start with: new)",
    )
    policy_sub = policy.add_subparsers(dest="action", required=False)
    policy.set_defaults(func=_cmd_policy_index, _policy_parser=policy)

    new_cmd = policy_sub.add_parser(
        "new",
        help="write a commented starter policy you edit",
        description=(
            "Writes a policy with every section present and every line "
            "explained. It is the answer to 'what do I do after the demo' when "
            "you have no MCP server for `policy init` to read and no written "
            "policy for `policy draft` to translate. It lints with errors until "
            "you replace the TODOs, so an unedited file cannot reach production "
            "quietly. Tools that do not take a file path must go under "
            "paths.pathless or `clayseal proxy` will refuse them."
        ),
    )
    new_cmd.add_argument("--out", default=None,
                         help="write here instead of stdout")
    new_cmd.add_argument("--goal-id", default="TODO-name-this-run")
    new_cmd.add_argument("--days", type=int, default=30,
                         help="how long the grant lives (default 30)")
    new_cmd.add_argument("--force", action="store_true",
                         help="overwrite an existing file")
    new_cmd.set_defaults(func=_cmd_new)

    lint = policy_sub.add_parser(
        "lint", help="errors until TODOs are gone; then warnings to read")
    lint.add_argument("policy")
    lint.add_argument(
        "--warnings-as-errors", action="store_true",
        help="exit non-zero on warnings too, for a stricter pre-merge gate",
    )
    lint.set_defaults(func=_cmd_lint)

    show = policy_sub.add_parser("show", help="print what this file actually grants")
    show.add_argument("policy")
    show.set_defaults(func=_cmd_show)

    draft = policy_sub.add_parser(
        "draft",
        help="turn a written business rule into a policy draft",
        description=(
            "Reads a delegation-of-authority matrix, AP policy, SOP or similar "
            "and drafts the policy document it implies. Every rule cites the "
            "line it came from, and a sentence that reads as a rule and did not "
            "translate is emitted as a TODO rather than dropped. The output is a "
            "file for a person to review; it is never a grant on its own."
        ),
    )
    draft.add_argument("document", help="the business document to read")
    draft.add_argument("--out", default=None, help="write here instead of stdout")
    draft.add_argument("--goal-id", default=None)
    draft.add_argument("--goal", default=None, help="the sealed goal summary")
    draft.add_argument("--tools", default=None,
                       help="comma-separated tool names the agent may reach")
    draft.set_defaults(func=_cmd_draft)

    init = policy_sub.add_parser(
        "init",
        help="scaffold a policy from a live MCP server's tool catalog",
        description=(
            "Asks the server for tools/list and writes a policy naming every "
            "tool it advertises, with each effect guessed from the name or the "
            "server's own description and the guesses marked. Pass --rules to "
            "read the ceilings out of a written policy at the same time, and "
            "the two halves land in one file: what the organisation permits, "
            "and what the tools are called."
        ),
    )
    init.add_argument("--out", default=None)
    init.add_argument(
        "--rules", default=None, metavar="DOCUMENT",
        help="a written policy to read the rules from, as `policy draft` does")
    init.add_argument("--goal-id", default=None)
    init.add_argument("--goal", default=None)
    init.add_argument("--timeout", type=float, default=30.0)
    init.add_argument("command", nargs=argparse.REMAINDER,
                      help="the MCP server to ask, after `--`")
    init.set_defaults(func=_cmd_init)

    proxy = sub.add_parser(
        "proxy",
        help="stdio MCP gateway for Claude Desktop / Cursor",
        description=(
            "The agent connects to this process; this process runs the real "
            "MCP server. Use this for Claude Desktop, Cursor, and any stdio "
            "client. Every tools/call is authorized before it is forwarded, "
            "and tools outside the policy are removed from the advertised "
            "catalog. For HTTP clients, see `clayseal serve`."
        ),
    )
    proxy.add_argument("--policy", required=True)
    proxy.add_argument(
        "command", nargs=argparse.REMAINDER,
        help="the MCP server to run, after `--`",
    )
    proxy.set_defaults(func=_cmd_proxy)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "group", None) is None:
        parser.print_help()
        print("\nStart here:  clayseal try", file=sys.stderr)
        print("Next:        clayseal howto", file=sys.stderr)
        return 0
    if getattr(args, "command", None) and args.command and args.command[0] == "--":
        args.command = args.command[1:]
    try:
        return args.func(args)
    except PolicyError as exc:
        print(f"clayseal: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
