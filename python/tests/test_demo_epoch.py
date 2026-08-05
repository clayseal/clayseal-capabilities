"""Policy epochs: the digest is the policy's identity, and migration is policy."""
import pytest

from demo.epoch import open_epoch, spec_for
from demo.escalation import Level, policy_for
from demo.scenario import INTERNAL, ticket_triage

ROOTFS = "/nonexistent/rootfs"      # never executed here; only rendered into config


@pytest.fixture
def scen():
    return ticket_triage()


def _epoch(scen, level, tmp_path, index=0, prev=None):
    caps = policy_for(level, scen.seal())
    return open_epoch(caps, level=level, index=index, run_root=tmp_path,
                      rootfs=ROOTFS, scenario=scen, prev=prev)


def test_baseline_allows_only_the_sealed_domain(scen, tmp_path):
    epoch = _epoch(scen, Level.BASELINE, tmp_path)
    assert epoch.allow == (INTERNAL,)
    assert f"allow = {INTERNAL}" in epoch.config_text


def test_suspect_is_byte_identical_to_baseline(scen, tmp_path):
    """`digest unchanged` on the rail is a real claim, not a caption."""
    base = _epoch(scen, Level.BASELINE, tmp_path, index=0)
    suspect = _epoch(scen, Level.SUSPECT, tmp_path, index=0)
    assert suspect.digest == base.digest


def test_containment_changes_the_digest_and_empties_the_allow_list(scen, tmp_path):
    base = _epoch(scen, Level.BASELINE, tmp_path, index=0)
    contained = _epoch(scen, Level.CONTAINED, tmp_path, index=1)
    assert contained.digest != base.digest
    assert contained.allow == ()
    # No allow-list at all, which is iVisor's deny-by-default, rather than an
    # empty `allow =` line that would mean something else.
    assert "allow =" not in contained.config_text


def test_quarantine_changes_the_digest_again(scen, tmp_path):
    contained = _epoch(scen, Level.CONTAINED, tmp_path, index=1)
    quarantined = _epoch(scen, Level.QUARANTINED, tmp_path, index=2)
    assert quarantined.digest != contained.digest


def test_each_epoch_gets_its_own_run_directory(scen, tmp_path):
    first = _epoch(scen, Level.BASELINE, tmp_path, index=0)
    second = _epoch(scen, Level.CONTAINED, tmp_path, index=1)
    assert first.run_dir != second.run_dir
    assert first.run_dir.name == "epoch-0"
    assert second.run_dir.name == "epoch-1"


# --------------------------------------------------------------------------- #
# Staging and migration — where quarantine is actually enforced
# --------------------------------------------------------------------------- #

def test_tickets_are_staged_below_quarantine(scen, tmp_path):
    for level in (Level.BASELINE, Level.SUSPECT, Level.CONTAINED):
        epoch = _epoch(scen, level, tmp_path)
        staged = set(epoch.base_files)
        assert "data/tickets/T-1006.txt" in staged, level
        assert "tools/send_email.py" in staged, level


def test_quarantine_unstages_the_ticket_corpus(scen, tmp_path):
    epoch = _epoch(scen, Level.QUARANTINED, tmp_path)
    assert not any(k.startswith("data/tickets/") for k in epoch.base_files)
    # The tools remain: the agent can still run, it just has nothing to read.
    # Absence, not refusal — the guest sees ENOENT.
    assert "tools/read_ticket.py" in epoch.base_files


def test_the_summary_is_carried_forward_into_containment(scen, tmp_path):
    base = _epoch(scen, Level.BASELINE, tmp_path, index=0)
    (base.workspace / "out").mkdir(parents=True)
    (base.workspace / "out" / "summary.md").write_text("6 tickets triaged\n")

    contained = _epoch(scen, Level.CONTAINED, tmp_path, index=1, prev=base)
    assert "out/summary.md" in contained.base_files
    assert contained.base_files["out/summary.md"].read_text() == "6 tickets triaged\n"


def test_quarantine_migrates_nothing(scen, tmp_path):
    base = _epoch(scen, Level.BASELINE, tmp_path, index=0)
    (base.workspace / "out").mkdir(parents=True)
    (base.workspace / "out" / "summary.md").write_text("6 tickets triaged\n")

    quarantined = _epoch(scen, Level.QUARANTINED, tmp_path, index=1, prev=base)
    assert "out/summary.md" not in quarantined.base_files


def test_migration_tolerates_a_file_the_agent_never_wrote(scen, tmp_path):
    base = _epoch(scen, Level.BASELINE, tmp_path, index=0)
    contained = _epoch(scen, Level.CONTAINED, tmp_path, index=1, prev=base)
    assert "out/summary.md" not in contained.base_files   # nothing to carry


# --------------------------------------------------------------------------- #
# Run specs
# --------------------------------------------------------------------------- #

def test_spec_carries_the_epoch_policy_and_timeout(scen, tmp_path):
    epoch = _epoch(scen, Level.QUARANTINED, tmp_path)
    spec = spec_for(epoch, "read_ticket", {"id": "T-1001"}, scenario=scen,
                    rootfs=ROOTFS, ivisor_bin="/bin/true")
    assert spec.guest_args == ("-u", "/work/tools/read_ticket.py", "T-1001")
    assert spec.timeout_s == epoch.caps.timeout_s == 30.0
    assert spec.egress is None                       # deny-all under quarantine
    assert "fsmiss" in spec.trace                    # so absence is observable


def test_first_call_creates_the_run_dir_and_later_calls_reuse_it(scen, tmp_path):
    epoch = _epoch(scen, Level.BASELINE, tmp_path)
    first = spec_for(epoch, "list_tickets", {}, scenario=scen, rootfs=ROOTFS,
                     ivisor_bin="/bin/true")
    assert first.reuse_run_dir is None

    class _Staged:
        run_dir = epoch.run_dir

    class _Outcome:
        staged = _Staged()

    epoch.adopt(_Outcome())
    second = spec_for(epoch, "read_ticket", {"id": "T-1"}, scenario=scen,
                      rootfs=ROOTFS, ivisor_bin="/bin/true")
    assert second.reuse_run_dir == epoch.run_dir     # workspace state persists


def test_per_call_files_are_merged_over_the_epoch_baseline(scen, tmp_path):
    epoch = _epoch(scen, Level.BASELINE, tmp_path)
    summary = tmp_path / "summary_input.txt"
    summary.write_text("themes: billing, shipping\n")
    spec = spec_for(epoch, "write_summary", {"text": "..."}, scenario=scen,
                    rootfs=ROOTFS, ivisor_bin="/bin/true",
                    extra_files={"task/summary_input.txt": summary})
    assert "task/summary_input.txt" in spec.extra_files
    assert "tools/write_summary.py" in spec.extra_files
