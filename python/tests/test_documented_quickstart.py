"""Execute the code blocks the docs tell a new integrator to run.

Both `README.md` and `docs/DEV_GUIDE.md` shipped a quickstart ending in

    assert verify_commit_token(token, key=key.public_key()).valid

which is wrong three ways: there is no `key=` parameter, `public_key` is an
Ed25519 object rather than the hex string `trusted_minting_keys` matches on, and
the function returns `(ok, reason)` rather than something with `.valid`. The
first thing a new user ran failed on its last line.

Prose drifts from an API silently; a test does not. These extract the fenced
python blocks from the docs and execute them, so the documented path is checked
by the same suite as the code it documents.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]

#: Blocks that need the identity layer or the receipts layer, neither of which is
#: a hard dependency here, plus the shell/config blocks. Keyed by a substring
#: that appears in the block itself so the skip cannot silently drift onto a
#: different block when the docs are reordered.
_NEEDS_OPTIONAL_LAYER = (
    "from agentauth.identity import",
    "from agentauth.receipts",
    "class MyProvider",
    "register_identity_provider",
)


def _python_blocks(doc: Path) -> list[str]:
    return re.findall(r"```python\n(.*?)```", doc.read_text(), re.DOTALL)


def _runnable(block: str) -> bool:
    return not any(marker in block for marker in _NEEDS_OPTIONAL_LAYER)


def _blocks_for(name: str) -> list[tuple[str, str]]:
    doc = REPO / name
    return [
        (f"{name}#{i}", b)
        for i, b in enumerate(_python_blocks(doc))
        if _runnable(b)
    ]


DOC_BLOCKS = _blocks_for("README.md") + _blocks_for("docs/DEV_GUIDE.md")


def test_the_docs_actually_contain_runnable_blocks():
    """Guard the guard: a regex that stops matching would pass every test below."""
    assert len(DOC_BLOCKS) >= 2, DOC_BLOCKS


@pytest.mark.parametrize("label,source", DOC_BLOCKS, ids=[b[0] for b in DOC_BLOCKS])
def test_documented_block_executes(label: str, source: str):
    """Run each block; a block that is an illustrative FRAGMENT is only compiled.

    Some doc blocks deliberately show a call in context (`decision =
    broker.authorize(action)`) without constructing the world around it. Those
    raise `NameError` on a name they never bind, and demanding they run would
    push the docs toward unreadably long examples.

    Every other failure is a real defect and fails the test — including the
    `TypeError: unexpected keyword argument` that the old quickstart's
    `verify_commit_token(token, key=...)` produced, which is the bug class this
    file exists for. A fragment is still compiled, so syntax rot is caught
    everywhere.
    """
    namespace: dict = {"__name__": "__doc_block__"}
    code = compile(source, label, "exec")
    try:
        exec(code, namespace)  # noqa: S102 - that is the point
    except NameError as exc:
        pytest.skip(f"{label} is an illustrative fragment ({exc})")
    except Exception as exc:  # noqa: BLE001 - report which block and why
        pytest.fail(f"{label} does not run: {type(exc).__name__}: {exc}\n\n{source}")


#: Blocks a new integrator is told to run verbatim. These must EXECUTE, not
#: merely compile, and may not degrade into "fragment" and silently skip.
_MUST_RUN = ("issue_commit_token(", "get_identity_provider(")


def test_the_onboarding_blocks_are_complete_programs():
    complete = [
        label for label, src in DOC_BLOCKS
        if all(marker in src for marker in _MUST_RUN)
    ]
    assert complete, "no doc block issues a commit token from an identity session"
    for label, src in DOC_BLOCKS:
        if label not in complete:
            continue
        namespace: dict = {"__name__": "__doc_block__"}
        exec(compile(src, label, "exec"), namespace)  # noqa: S102


def test_quickstart_verification_is_bound_to_the_arguments():
    """The claim the quickstart makes about itself: mutate an argument, lose the token.

    The snippet asserts `ok`; what makes that interesting is that it stops being
    true when the tool call changes. Without this, a quickstart that passed a
    context with no binding at all would still be green.
    """
    from agentauth.capabilities.commit import (
        InMemoryUsedTokenStore,
        issue_commit_token,
        verify_commit_token,
    )
    from agentauth.core.runtime import (
        ActionDescriptor,
        AuthorityContext,
        ExecutionContext,
    )
    from agentauth.core.signing import generate_keypair

    def ctx_for(amount: int) -> ExecutionContext:
        return ExecutionContext(
            action=ActionDescriptor(
                action_name="mcp.tools/call/payroll_bonus",
                resource_ref="rippling:bonus",
            ),
            input={"employee_id": "emp_123", "amount": amount},
            authority=AuthorityContext(authority_id="payroll-agent"),
            query_id="q-1",
        )

    key = generate_keypair()
    authorized = ctx_for(100)
    signed = issue_commit_token(authorized, key=key, ttl_seconds=300)

    ok, reason = verify_commit_token(
        signed,
        ctx=authorized,
        trusted_minting_keys={key.public_key_hex},
        used_token_store=InMemoryUsedTokenStore(),
    )
    assert ok, reason

    mutated_ok, mutated_reason = verify_commit_token(
        signed,
        ctx=ctx_for(1_000_000),
        trusted_minting_keys={key.public_key_hex},
        used_token_store=InMemoryUsedTokenStore(),
    )
    assert not mutated_ok
    assert "arguments_hash" in (mutated_reason or "")


def test_minting_raises_and_verifying_returns_a_verdict():
    """The two boundaries have deliberately opposite contracts.

    `issue_commit_token` used to carry a guard copy-pasted from the verifier and
    returned `(False, reason)` from a function annotated `-> SignedCommitToken`,
    so the caller failed with an `AttributeError` one frame out — the exact
    failure the guard exists to prevent.
    """
    from agentauth.capabilities.commit import issue_commit_token, verify_commit_token
    from agentauth.core.runtime import (
        ActionDescriptor,
        AuthorityContext,
        ExecutionContext,
    )
    from agentauth.core.signing import generate_keypair

    bad = ExecutionContext(
        action=ActionDescriptor(action_name=123, resource_ref="r"),  # type: ignore[arg-type]
        input={},
        authority=AuthorityContext(authority_id="a"),
        query_id="q",
    )

    with pytest.raises(ValueError, match="action_name must be a string"):
        issue_commit_token(bad, key=generate_keypair(), ttl_seconds=300)

    # The verifier, given the same malformed context, answers rather than throws.
    good = ExecutionContext(
        action=ActionDescriptor(action_name="t/call/x", resource_ref="r"),
        input={},
        authority=AuthorityContext(authority_id="a"),
        query_id="q",
    )
    key = generate_keypair()
    signed = issue_commit_token(good, key=key, ttl_seconds=300)
    ok, reason = verify_commit_token(
        signed, ctx=bad, trusted_minting_keys={key.public_key_hex}
    )
    assert not ok
    assert "action_name must be a string" in (reason or "")
