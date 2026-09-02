"""The one field in a grant nobody could generate, and the rules it must obey."""

from clayseal.capabilities.budget_binding import (
    Binding,
    Ceiling,
    derive_tracked,
    merge_tracked,
    refute,
)


def tool(name, description="", **args):
    return {"type": "function", "function": {
        "name": name, "description": description,
        "parameters": {"type": "object",
                       "properties": {k: {"type": v} for k, v in args.items()}}}}


def test_sole_ceiling_binds_every_spending_tool():
    got = derive_tracked(
        ["usd_daily"],
        [tool("pay_vendor", vendor="string", amount="number"),
         tool("issue_refund", order="string", amount="number"),
         tool("list_open_items")])
    assert {b.tool: b.budget_id for b in got} == {
        "pay_vendor": "usd_daily", "issue_refund": "usd_daily"}
    assert all(b.tier == "sole" for b in got)


def test_a_read_never_debits_however_its_arguments_look():
    # `get_quote(amount=...)` prices a thing and moves nothing. Charging it
    # refuses honest work mid-task, which is the expensive direction.
    got = derive_tracked(["usd"], [tool("get_quote", amount="number")])
    assert got == []


def test_quantity_is_read_from_the_type_not_only_the_name():
    # The named list missed `fee`, `delta` and `tons`, and two of those are
    # ordinary names for an amount of money.
    for arg in ("fee", "delta", "tons"):
        got = derive_tracked(["usd"], [tool("charge_thing", **{arg: "number",
                                                               "item": "string"})])
        assert [b.amount_arg for b in got] == [arg], arg


def test_a_duration_is_not_a_quantity():
    # `advance_clock(hours=24)` is a number and is not a read. Against a money
    # ceiling it debited 24 dollars for moving the clock a day.
    assert derive_tracked(["usd"], [tool("advance_clock", hours="number")]) == []


def test_named_argument_wins_over_a_second_number():
    got = derive_tracked(["usd"], [tool("pay_vendor", amount="number",
                                        priority="number")])
    assert [b.amount_arg for b in got] == ["amount"]


def test_strict_demands_evidence_and_permissive_does_not():
    # `record_ops_adjustment` is described as "looks like bookkeeping"; that is
    # the point of it. No word list reaches it.
    hidden = [tool("record_ops_adjustment", "Record an operations adjustment.",
                   delta="number", label="string")]
    assert derive_tracked(["usd"], hidden, strict=True) == []
    assert [b.tool for b in derive_tracked(["usd"], hidden)] == \
        ["record_ops_adjustment"]


def test_several_ceilings_use_wording_and_refuse_to_break_a_tie():
    tools = [tool("pay_vendor", vendor="string", amount="number")]
    ceilings = [Ceiling("usd_vendor", "Vendor payments are capped at $5,000"),
                Ceiling("usd_travel", "Travel spend is capped at $2,000")]
    assert [b.budget_id for b in derive_tracked(ceilings, tools)] == ["usd_vendor"]
    # Two ceilings a tool matches equally well is the case where naming the
    # wrong one splits a shared limit and still reads as working policy.
    tie = [Ceiling("a", "Payments are capped"), Ceiling("b", "Payments are capped")]
    assert derive_tracked(tie, tools) == []


def test_a_proposal_naming_a_ceiling_that_does_not_exist_is_discarded():
    tools = [tool("settle_thing", "Settles a thing.", qty="number")]
    ceilings = [Ceiling("a", "cap one"), Ceiling("b", "cap two")]
    assert derive_tracked(ceilings, tools,
                          propose=lambda t, c: {"settle_thing": "invented"}) == []
    got = derive_tracked(ceilings, tools,
                         propose=lambda t, c: {"settle_thing": "b"})
    assert [(b.tool, b.budget_id, b.tier) for b in got] == \
        [("settle_thing", "b", "proposed")]


def test_merge_never_overwrites_what_an_operator_wrote():
    # The catalogue is written by the party being constrained, and this is the
    # field it would most want to move.
    declared = {"pay_vendor": ("amount", "usd_strict")}
    derived = [Binding("pay_vendor", "amount", "usd_loose", "sole", ""),
               Binding("wire_transfer", "amount", "usd_loose", "sole", "")]
    assert merge_tracked(declared, derived) == {
        "pay_vendor": ("amount", "usd_strict"),
        "wire_transfer": ("amount", "usd_loose")}


def test_refutation_drops_the_binding_legitimate_work_contradicts():
    bindings = [Binding("pay_external", "amount", "usd", "sole", ""),
                Binding("transfer", "amount", "usd", "sole", "")]
    good = [[("pay_external", {"amount": 2000.0}),
             ("transfer", {"amount": 500.0}),
             ("transfer", {"amount": 500.0}),
             ("pay_external", {"amount": 1000.0})]]
    kept, notes = refute(bindings, {"usd": 3000.0}, good)
    # Minimal repair: the internal book transfer is what pushed it over, and
    # the payment binding, which was right, survives.
    assert [b.tool for b in kept] == ["pay_external"]
    assert notes and "transfer" in notes[0]


def test_a_running_total_is_not_evidence_against_a_windowed_ceiling():
    bindings = [Binding("pay_vendor", "amount", "usd_roll", "sole", "")]
    good = [[("pay_vendor", {"amount": 2000.0}), ("pay_vendor", {"amount": 2000.0})]]
    assert refute(bindings, {"usd_roll": 3000.0}, good)[0] == []
    kept, notes = refute(bindings, {"usd_roll": 3000.0}, good,
                         windowed={"usd_roll"})
    assert [b.tool for b in kept] == ["pay_vendor"] and notes == []


def test_refutation_drops_an_identity_legitimate_work_repeats():
    bindings = [Binding("pay_vendor", "amount", "usd", "sole", "",
                        identity_args=("vendor",))]
    good = [[("pay_vendor", {"vendor": "Acme", "amount": 10.0}),
             ("pay_vendor", {"vendor": "Acme", "amount": 10.0})]]
    kept, notes = refute(bindings, {"usd": 1000.0}, good)
    # The ceiling survives; only the once-per-object dedup is given up.
    assert [(b.tool, b.identity_args) for b in kept] == [("pay_vendor", ())]
    assert notes and "identity" in notes[0]


def test_refutation_terminates_when_no_binding_can_explain_the_breach():
    bindings = [Binding("pay_vendor", "amount", "usd", "sole", "")]
    good = [[("pay_vendor", {"amount": 9999.0})]]
    assert refute(bindings, {"usd": 10.0}, good)[0] == []


def test_no_ceiling_means_no_binding():
    assert derive_tracked([], [tool("pay_vendor", amount="number")]) == []
