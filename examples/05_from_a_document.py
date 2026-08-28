"""A written business rule and a tool catalog become an enforced grant.

The rung that matters is inert when nobody declares a ceiling, and across
eleven independently-authored corpora, 0 of 520 tasks do. Organisations DO
write their ceilings down. This is the whole path from the sentence to the
denial, in one file, with no network and no server subprocess.

Run it:

    python examples/05_from_a_document.py

The command-line version of the same thing, against a server you actually run:

    clayseal policy init --rules delegation_of_authority.md \
        -- npx @your-org/mcp-server > draft.yaml
    clayseal policy lint draft.yaml
"""
from __future__ import annotations

from clayseal.capabilities.monitor.action import Action
from clayseal.capabilities.policy import load_policy_text
from clayseal.capabilities.policy_draft import extract, to_yaml
from clayseal.capabilities.policy_scaffold import read_catalog

# What the organisation permits. Nobody wrote this for an agent.
DOCUMENT = """\
# Accounts Payable, delegation of authority

3.1 A single vendor payment must not exceed $10,000.
3.2 Total disbursements must not exceed $50,000 in any rolling 24 hours.
3.4 Each invoice may be paid once only.
4.2 No more than 20 refunds may be issued per day.
5.1 Payment confirmations may only be sent to addresses at acme-internal.com.
6.1 The service account may read and write only under /finance/ap/.
6.2 Production ledger files (*.ledger) must never be modified.
7.1 The person who prepares a payment may not approve it.
"""

# What the tools are called. This is a `tools/list` reply, verbatim.
CATALOG = {"tools": [
    {"name": "pay_vendor",
     "description": "Disburse a payment against an approved vendor invoice.",
     "inputSchema": {"properties": {"vendor_id": {}, "invoice_number": {},
                                    "amount_usd": {}, "period": {}}}},
    {"name": "issue_refund",
     "description": "Refund a customer against an original transaction.",
     "inputSchema": {"properties": {"transaction_id": {}, "amount_usd": {}}}},
    {"name": "ledger_sync",
     "description": "Writes the day's postings into the production ledger.",
     "inputSchema": {"properties": {"ledger_path": {}, "as_of": {}}}},
    {"name": "notify_vendor",
     "description": "Sends an email confirmation to the vendor contact.",
     "inputSchema": {"properties": {"to": {}, "body": {}}}},
]}


def main() -> None:
    catalog = read_catalog(CATALOG)
    draft = extract(DOCUMENT)

    print("== step 1, the draft ==")
    print(draft.summary())
    for rule in draft.unmapped:
        print(f"  left for a person: {rule.cite()}")
    print("  effects read from the catalog: "
          + ", ".join(f"{t.name}={t.verb}" for t in catalog.tools))
    print("  path argument found: " + str(catalog.path_args()))
    to_yaml(draft, goal_id="ap-2026-08", catalog=catalog, document="the memo",
            server="the AP server")   # this is what `policy init` writes out

    # == step 2, the review ==
    # A person read that draft and made three decisions the machine cannot.
    # Which tool debits which ceiling, that 3.1 is a per-call threshold rather
    # than a cumulative one, and that a refund is a disbursement so it debits
    # the same total. Splitting it into its own budget would let $55,000 out
    # against a rule that says $50,000.
    reviewed = """
version: 1
goal: {id: ap-2026-08, summary: Pay approved vendor invoices for August}
profile: supervised
tools:
  allow: [pay_vendor, issue_refund, ledger_sync, notify_vendor]
  effects: {pay_vendor: transfer, issue_refund: transfer,
            ledger_sync: write, notify_vendor: send}
paths:
  allow: ["/finance/ap/**"]
  deny:  ["*.ledger"]
  arg_names: {ledger_sync: ledger_path}
  pathless: [pay_vendor, issue_refund, notify_vendor]
egress:
  domains: [acme-internal.com]
  bind_recipients: true
budgets:
  value:
    ceilings: {payments: "50000"}
    windows:  {payments: 86400}
    tracked:
      pay_vendor:   {arg: amount_usd, budget: payments,
                     identity: [invoice_number, period]}
      issue_refund: {arg: amount_usd, budget: payments,
                     identity: [transaction_id]}
  calls:
    ceilings: {refund_count: 20}
    windows:  {refund_count: 86400}
    tracked:  {issue_refund: refund_count}
"""
    policy = load_policy_text(reviewed, source="the reviewed draft")
    print("\n== step 2, what a reviewer must still decide ==")
    for finding in policy.lint():
        print(f"  {finding.level.upper():8} {finding.code}")

    stack = policy.build()
    print("\n== step 3, enforced ==")
    step = 0

    def call(label: str, tool: str, **args: object) -> None:
        nonlocal step
        step += 1
        arg = policy.path_arg_for(tool)
        meta = {"path": args[arg]} if arg and arg in args else {}
        decision = stack.authorize(Action(
            step=step, tool=tool, resource=f"mcp:tool:{tool}",
            verb=policy.verb_for(tool), args=dict(args), meta=meta))
        print(f"  {label:36} {decision.outcome:8} "
              f"{', '.join(decision.reasons)}")

    call("3.2 $30k of the $50k total", "pay_vendor", vendor_id="v1",
         invoice_number="INV-1", amount_usd=30000, period="2026-08")
    call("a refund debits the same total", "issue_refund",
         transaction_id="T-9", amount_usd=4000)
    call("3.2 this one would make $51k", "pay_vendor", vendor_id="v2",
         invoice_number="INV-2", amount_usd=17000, period="2026-08")
    call("3.4 INV-1 a second time", "pay_vendor", vendor_id="v1",
         invoice_number="INV-1", amount_usd=1000, period="2026-08")
    call("6.1 inside /finance/ap", "ledger_sync",
         ledger_path="/finance/ap/postings.json", as_of="2026-08-24")
    call("6.2 a .ledger file", "ledger_sync",
         ledger_path="/finance/ap/2026-08.ledger", as_of="2026-08-24")
    call("5.1 an acme-internal address", "notify_vendor",
         to="ap@acme-internal.com", body="paid")
    call("5.1 a personal address", "notify_vendor",
         to="someone@gmail.com", body="paid")

    print("\n  7.1 is not enforced anywhere above. Segregation of duties is a")
    print("  rule about WHO acts, and this layer authorizes actions rather")
    print("  than people. The draft says so in a TODO instead of going quiet.")


if __name__ == "__main__":
    main()
