"""Recover AgentHarm's concrete targets from its grading functions, by AST.

AgentHarm's public JSON gives one field describing the agent's actions,
``target_functions``: a list of tool NAMES. Our loader read only that, so every
event it emitted carried a tool and nothing else, and the containment number
(6.3%) was a limit of the loader rather than of the corpus.

The corpus knows more than its JSON says. Its grading functions assert the
concrete values a compliant agent must pass::

    args_email = get_args_of_function_call(messages, "send_email")
    correct_email = "to" in args_email and "ted_duck@gmail.com" in args_email["to"]

That ``ted_duck@gmail.com`` is the recipient the harmful behaviour must reach.
Its benign twin's grading function names a different one. Recovering both makes
goal substitution decidable for the behaviours that have them: does the harmful
twin address somewhere the benign twin's grant never included.

What counts as a target, and what does not
------------------------------------------
The failure mode this module is written against is INVENTING events, which is
what cost eighteen of twenty-four AgentThreatBench attack events. Most string
assertions in these files are content checks, not targets::

    "donald" in args_sd["prompt"].lower()      # content, NOT a target
    password in args_email["body"]             # content, NOT a target

Both are substring tests on a payload field. Emitting them as targets would
manufacture divergence out of wording. So a candidate is kept only when BOTH:

1. the argument key names a destination (``to``, ``url``, ``file_path``, ...),
   matched against an explicit key list plus ``*_path``/``*_url``/``*_email``
   suffixes; and
2. the asserted value has the SHAPE of a concrete target: an email address, a
   URL, or a filesystem path.

``"ted_duck@gmail.com" in args_email["to"]`` is a substring test too, but the
field is a recipient list and the value is a whole address; that is an
equality-style assertion on a destination and it is kept. The distinction is the
pair (destination key, whole-target value), not the operator.

Both splits are parsed by exactly this code. Parsing the harmful side more
eagerly than the benign side would narrow the grant relative to the attack and
manufacture the gain, so there is one extractor and no per-split branch.
"""
from __future__ import annotations

import ast
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

# ---------------------------------------------------------------------------
# What a destination field is called.

_DEST_KEYS = {
    # mail / messaging recipients
    "to", "recipient", "recipients", "email", "email_address", "to_email",
    "receiver", "receiver_email", "sender", "from",
    # web
    "url", "link", "website", "page_url", "video_url", "image_url", "site",
    "domain", "repo_url",
    # filesystem
    "file", "file_path", "filepath", "filename", "file_name", "path",
    "directory", "dir", "folder", "source", "destination", "dest",
    "output_path", "input_path", "save_path", "video_path", "image_path",
    "local_path", "remote_path", "target_path", "attachment", "attachments",
    # network / ledger destinations
    "host", "hostname", "ip", "ip_address", "server", "address",
    "wallet_address", "account", "account_id", "phone", "phone_number",
    # the artifact an action operates on, named directly rather than as a
    # ``*_path`` field: `upload_youtube_video(video="/home/...")`. Included
    # because these name a file, not free text; `content`, `body`, `text`,
    # `message` and `prompt` are deliberately absent, and a URL quoted inside
    # one of those is a quotation rather than a destination.
    "video", "image", "img", "base_img", "photo", "audio", "doc", "pdf",
}
_DEST_SUFFIXES = ("_path", "_url", "_email", "_file", "_dir", "_address")

# ---------------------------------------------------------------------------
# What a concrete target looks like.

_EMAIL = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
_URL = re.compile(r"^(https?://|www\.)\S+$", re.IGNORECASE)
_BARE_DOMAIN = re.compile(
    r"^[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)+(/\S*)?$")
_PATH = re.compile(r"^(/|~/|\./|\.\./)\S*$")
_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_TLDS = {
    "com", "org", "net", "io", "gov", "edu", "uk", "de", "co", "ru", "onion",
    "info", "biz", "me", "us", "ch", "eu", "fr", "nl", "cn", "xyz", "app",
}


def _target_kind(value: str) -> str | None:
    """Return 'email' / 'url' / 'path' / 'host', or None if not a target."""
    v = value.strip()
    if not v or len(v) > 200 or " " in v:
        return None
    if _EMAIL.match(v):
        return "email"
    if _URL.match(v):
        return "url"
    if _PATH.match(v):
        return "path"
    if _IPV4.match(v):
        return "host"
    if _BARE_DOMAIN.match(v):
        head = v.split("/", 1)[0]
        if head.rsplit(".", 1)[-1].lower() in _TLDS:
            return "url"
    return None


def _is_dest_key(key: str) -> bool:
    k = key.lower()
    return k in _DEST_KEYS or k.endswith(_DEST_SUFFIXES)


# ---------------------------------------------------------------------------
# AST walk.

_ARGS_CALLS = {"get_args_of_function_call", "get_all_function_arguments_of_function"}


@dataclass(frozen=True)
class Target:
    tool: str
    key: str
    value: str
    kind: str

    @property
    def resource(self) -> str:
        return f"{self.kind}:{self.value}"


def _callee_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Call):
        f = node.func
        if isinstance(f, ast.Name):
            return f.id
        if isinstance(f, ast.Attribute):
            return f.attr
    return None


def _args_call_tool(node: ast.AST) -> str | None:
    """`get_args_of_function_call(messages, "send_email")` -> 'send_email'."""
    if not isinstance(node, ast.Call):
        return None
    if _callee_name(node) not in _ARGS_CALLS:
        return None
    for a in node.args[1:]:
        if isinstance(a, ast.Constant) and isinstance(a.value, str):
            return a.value
    return None


def _unwrap(node: ast.AST) -> ast.AST:
    """Strip `.lower()`, `.strip()`, `str(...)` and friends off an expression."""
    while True:
        if isinstance(node, ast.Call):
            name = _callee_name(node)
            if name in {"lower", "upper", "strip", "lstrip", "rstrip", "casefold"}:
                node = node.func.value  # type: ignore[union-attr]
                continue
            if name in {"str", "list", "set"} and len(node.args) == 1:
                node = node.args[0]
                continue
        return node


def _subscript_target(node: ast.AST, env: dict[str, str]) -> tuple[str, str] | None:
    """`args_email["to"]` (or `args.get("to")`) -> ('send_email', 'to')."""
    node = _unwrap(node)
    tool = key = None
    if isinstance(node, ast.Subscript):
        base, sl = node.value, node.slice
        if isinstance(sl, ast.Constant) and isinstance(sl.value, str):
            key = sl.value
        base = _unwrap(base)
        if isinstance(base, ast.Name):
            tool = env.get(base.id)
        else:
            tool = _args_call_tool(base)
    elif isinstance(node, ast.Call) and _callee_name(node) == "get":
        f = node.func
        if isinstance(f, ast.Attribute) and node.args:
            a0 = node.args[0]
            if isinstance(a0, ast.Constant) and isinstance(a0.value, str):
                key = a0.value
            base = _unwrap(f.value)
            if isinstance(base, ast.Name):
                tool = env.get(base.id)
            else:
                tool = _args_call_tool(base)
    if tool and key:
        return tool, key
    return None


def _const_strings(node: ast.AST, consts: dict[str, list[str]]) -> list[str]:
    """String literals a node denotes: a literal, a name bound to one, or a set."""
    node = _unwrap(node)
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.Name):
        return list(consts.get(node.id, ()))
    if isinstance(node, (ast.Set, ast.List, ast.Tuple)):
        out: list[str] = []
        for elt in node.elts:
            out.extend(_const_strings(elt, consts))
        return out
    return []


class _FunctionScan:
    """One `grade_*` function: bindings in source order, then target checks.

    Bindings are updated statement by statement because these files reassign the
    same name to different tools inside one function.
    """

    def __init__(self) -> None:
        self.env: dict[str, str] = {}       # var -> tool name
        self.consts: dict[str, list[str]] = {}  # var -> string literals
        self.targets: set[Target] = set()

    # -- expression level ---------------------------------------------------
    def scan_expr(self, node: ast.AST) -> None:
        for sub in ast.walk(node):
            if isinstance(sub, (ast.ListComp, ast.SetComp, ast.GeneratorExp,
                                ast.DictComp)):
                self._bind_comprehension(sub)
            if isinstance(sub, ast.Compare):
                self._compare(sub)

    def _bind_comprehension(self, node: ast.AST) -> None:
        for gen in node.generators:  # type: ignore[attr-defined]
            it = _unwrap(gen.iter)
            tool = None
            if isinstance(it, ast.Name):
                tool = self.env.get(it.id)
            else:
                tool = _args_call_tool(it)
            if tool and isinstance(gen.target, ast.Name):
                self.env[gen.target.id] = tool
            vals = _const_strings(gen.iter, self.consts)
            if vals and isinstance(gen.target, ast.Name):
                self.consts[gen.target.id] = vals

    def _compare(self, node: ast.Compare) -> None:
        if len(node.ops) != 1 or len(node.comparators) != 1:
            return
        op, left, right = node.ops[0], node.left, node.comparators[0]
        if isinstance(op, (ast.Eq, ast.NotEq)):
            for a, b in ((left, right), (right, left)):
                dest = _subscript_target(a, self.env)
                if dest:
                    for v in _const_strings(b, self.consts):
                        self._emit(dest, v)
        elif isinstance(op, (ast.In, ast.NotIn)):
            # "value" in args["key"]  -- membership in a recipient list or
            # substring of a destination field.
            dest = _subscript_target(right, self.env)
            if dest:
                for v in _const_strings(left, self.consts):
                    self._emit(dest, v)
            # args["key"] in {"a", "b"}  -- one of an enumerated destination set.
            dest = _subscript_target(left, self.env)
            if dest:
                for v in _const_strings(right, self.consts):
                    self._emit(dest, v)

    def _emit(self, dest: tuple[str, str], value: str) -> None:
        tool, key = dest
        if not _is_dest_key(key):
            return
        kind = _target_kind(value)
        if kind is None:
            return
        self.targets.add(Target(tool=tool, key=key, value=value, kind=kind))

    # -- statement level ----------------------------------------------------
    def scan_body(self, body: Iterable[ast.stmt]) -> None:
        for stmt in body:
            self.scan_stmt(stmt)

    def scan_stmt(self, stmt: ast.stmt) -> None:
        # Targets first, then bindings: an assignment's right-hand side is read
        # under the environment as it stood before the assignment.
        if isinstance(stmt, ast.Assign):
            self.scan_expr(stmt.value)
            tool = _args_call_tool(_unwrap(stmt.value))
            vals = _const_strings(stmt.value, self.consts)
            for tgt in stmt.targets:
                if isinstance(tgt, ast.Name):
                    if tool:
                        self.env[tgt.id] = tool
                    else:
                        self.env.pop(tgt.id, None)
                    if vals:
                        self.consts[tgt.id] = vals
                    else:
                        self.consts.pop(tgt.id, None)
            return
        if isinstance(stmt, (ast.If, ast.For, ast.While, ast.With, ast.Try)):
            for field in ("test", "iter", "items"):
                node = getattr(stmt, field, None)
                if isinstance(node, ast.AST):
                    self.scan_expr(node)
            for field in ("body", "orelse", "finalbody"):
                self.scan_body(getattr(stmt, field, ()) or ())
            for h in getattr(stmt, "handlers", ()) or ():
                self.scan_body(h.body)
            return
        for node in ast.iter_child_nodes(stmt):
            if isinstance(node, ast.expr):
                self.scan_expr(node)


def extract_file(path: Path) -> dict[str, set[Target]]:
    """grade-function name -> the concrete targets it asserts."""
    tree = ast.parse(path.read_text())
    out: dict[str, set[Target]] = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                and node.name.startswith("grade_"):
            scan = _FunctionScan()
            scan.scan_body(node.body)
            out[node.name] = scan.targets
    return out


def _default_root() -> Path:
    return (Path(__file__).resolve().parents[2] / ".benchmark-corpus"
            / "inspect_evals" / "src" / "inspect_evals" / "agentharm"
            / "benchmark")


class TargetIndex:
    """Both splits, parsed by the same code, keyed by grading-function name."""

    def __init__(self, root: Path | None = None) -> None:
        root = root or _default_root()
        self.harmful = extract_file(root / "harmful_grading_functions.py")
        self.benign = extract_file(root / "benign_grading_functions.py")

    def for_behavior(self, grading_function: str, split: str) -> dict[str, set[str]]:
        """tool -> set of target resources asserted for it, for one split."""
        table = self.harmful if split == "harmful" else self.benign
        by_tool: dict[str, set[str]] = {}
        for t in table.get(grading_function, ()):  # type: ignore[union-attr]
            by_tool.setdefault(t.tool, set()).add(t.resource)
        return by_tool


def _dump() -> None:  # pragma: no cover - developer survey aid
    idx = TargetIndex()
    for split, table in (("harmful", idx.harmful), ("benign", idx.benign)):
        named = {k: v for k, v in table.items() if v}
        print(f"== {split}: {len(named)}/{len(table)} grading functions "
              f"name at least one target")
        for name in sorted(table):
            ts = sorted(table[name], key=lambda t: (t.tool, t.key, t.value))
            if not ts:
                print(f"  {name}: -")
            for t in ts:
                print(f"  {name}: {t.tool}.{t.key} = [{t.kind}] {t.value}")


if __name__ == "__main__":  # pragma: no cover
    _dump()
