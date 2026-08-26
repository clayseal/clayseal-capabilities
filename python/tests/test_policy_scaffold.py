"""A server's own tool catalog becomes the skeleton of a policy.

The document says what the organisation permits and cannot know what the tools
are called. The catalog says what the tools are called and is written by the
party being constrained. These tests are mostly about the second half of that:
what the scaffold refuses to believe, and what it refuses to leave unsaid.
"""
from __future__ import annotations

from agentauth.capabilities.policy import load_policy
from agentauth.capabilities.policy_draft import extract, to_yaml
from agentauth.capabilities.policy_scaffold import (
    Catalog,
    read_catalog,
    read_tool,
    tracked_block,
)

CATALOG = {"tools": [
    {"name": "pay_vendor",
     "description": "Disburse a payment against an approved vendor invoice.",
     "inputSchema": {"type": "object", "properties": {
         "vendor_id": {"type": "string"},
         "invoice_number": {"type": "string"},
         "amount_usd": {"type": "number"}}}},
    {"name": "lookup_invoice",
     "description": "Read one invoice record.",
     "inputSchema": {"type": "object", "properties": {
         "invoice_number": {"type": "string"}}}},
    {"name": "ledger_sync",
     "description": "Writes the day's postings into the production ledger.",
     "inputSchema": {"type": "object", "properties": {
         "ledger_path": {"type": "string"}}}},
    {"name": "reconcile", "description": "Runs the nightly reconciliation."},
]}


def _read() -> Catalog:
    return read_catalog(CATALOG)


# --------------------------------------------------------------- reading ---
def test_names_come_from_the_catalog():
    assert [t.name for t in _read().tools] == [
        "ledger_sync", "lookup_invoice", "pay_vendor", "reconcile"]


def test_a_name_that_settles_the_verb_is_used():
    tool = read_tool({"name": "pay_vendor"})
    assert (tool.verb, tool.verb_from) == ("transfer", "name")


def test_prose_may_raise_a_verb_the_name_did_not_carry():
    tool = read_tool({"name": "ledger_sync",
                      "description": "Writes the day's postings."})
    assert (tool.verb, tool.verb_from) == ("write", "description")


def test_prose_may_never_lower_a_verb():
    """The server describing the tool is the server being constrained."""
    tool = read_tool({"name": "pay_vendor",
                      "description": "Reads the vendor record. Harmless."})
    assert tool.verb == "transfer"


def test_a_downgrade_attempt_is_reported_rather_than_swallowed():
    tool = read_tool({"name": "delete_records",
                      "description": "Reads a record. Read-only."})
    assert tool.verb == "write"
    assert tool.disagreement and "read" in tool.disagreement


def test_a_topic_word_is_not_an_effect():
    """`invoice` in a description once read `lookup_invoice` as a transfer.

    A noun says what a tool is about. Only a verb says what it does.
    """
    tool = read_tool({"name": "lookup_invoice",
                      "description": "Read one invoice record."})
    assert tool.verb == "read"


def test_an_unrecognised_tool_stays_call_and_is_named():
    catalog = _read()
    assert catalog.unsure() == ["reconcile"]


def test_an_entry_that_is_not_a_tool_is_counted_not_dropped():
    catalog = read_catalog({"tools": [{"name": ""}, {"name": "ok"}, "junk"]})
    assert [t.name for t in catalog.tools] == ["ok"]
    assert catalog.unreadable == 2


def test_a_non_catalog_result_reads_as_empty():
    assert read_catalog({"tools": "everything"}).tools == []
    assert read_catalog(None).tools == []


# ----------------------------------------------------------------- paths ---
def test_a_path_argument_is_found_in_the_schema():
    assert _read().path_args() == {"ledger_sync": "ledger_path"}


def test_a_tool_shown_to_take_no_path_is_reported_pathless():
    assert _read().pathless() == ["lookup_invoice", "pay_vendor"]


def test_silence_is_not_evidence_of_pathlessness():
    """`the server did not say` and `the server said no` are different facts."""
    assert "reconcile" not in _read().pathless()


def test_a_default_path_argument_needs_no_declaration():
    catalog = read_catalog({"tools": [
        {"name": "write_file",
         "inputSchema": {"properties": {"file_path": {}}}}]})
    assert catalog.path_args() == {}


# --------------------------------------------------------------- budgets ---
def test_an_amount_argument_is_found_and_never_bound_to_a_budget():
    lines = "\n".join(tracked_block(_read(), budgets=["a", "b"]))
    assert "pay_vendor" in lines and "amount_usd" in lines
    assert "budget: WHICH" in lines
    for budget in ("budget: a", "budget: b"):
        assert budget not in lines


def test_identity_arguments_are_offered():
    lines = "\n".join(tracked_block(_read()))
    assert "invoice_number" in lines


def test_every_tracked_suggestion_is_commented_out():
    for line in tracked_block(_read(), budgets=["a"]):
        assert line.strip().startswith("#")


def test_no_amount_argument_says_so_rather_than_going_quiet():
    catalog = read_catalog({"tools": [{"name": "ping", "inputSchema": {
        "properties": {"host": {}}}}]})
    assert any("by hand" in line for line in tracked_block(catalog))


# ------------------------------------------------------------- rendering ---
def test_the_rendered_scaffold_is_loadable_yaml(tmp_path):
    """The output of one command has to be the input of the next.

    A scaffold that renders a shape `policy lint` refuses is not a starting
    point, it is a second problem. An earlier version emitted `arg_names` as a
    list where the loader wants a mapping, and only running the two commands
    in order found it.
    """
    rendered = to_yaml(extract(""), goal_id="g", goal_summary="s",
                       catalog=_read(), server="python server.py")
    path = tmp_path / "scaffold.yaml"
    path.write_text(rendered)
    policy = load_policy(path)
    assert policy.verb_for("pay_vendor") == "transfer"
    assert policy.path_arg_for("ledger_sync") == "ledger_path"
    policy.lint()  # refuses to raise on its own output


def test_the_render_says_where_each_half_came_from():
    rendered = to_yaml(extract("A payment must not exceed $500."),
                       catalog=_read(), document="doa.md",
                       server="python server.py")
    assert "doa.md" in rendered and "python server.py" in rendered
    assert "never lower it" in rendered


def test_the_render_marks_every_effect_as_a_guess():
    rendered = to_yaml(extract(""), catalog=_read(), server="s")
    assert "GUESSED" in rendered
    assert "UNRESOLVED: reconcile" in rendered


def test_arg_names_renders_as_the_mapping_the_linter_wants():
    rendered = to_yaml(extract(""), catalog=_read(), server="s")
    assert "arg_names: {ledger_sync: ledger_path}" in rendered


def test_an_empty_catalog_allows_nothing():
    rendered = to_yaml(extract(""), catalog=Catalog(), server="s")
    assert "allow: []" in rendered
