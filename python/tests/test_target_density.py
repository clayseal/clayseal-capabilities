"""The target-identity channel: what it must and must not do.

These are mechanism tests. The corpus result lives in
``benchmarks/results/opeval.md``; what is pinned here is the behaviour that
result depends on, so a refactor that quietly breaks the estimator fails in CI
rather than in a re-measurement six weeks later.
"""
from __future__ import annotations

from agentauth.capabilities.monitor.action import Action, Trajectory
from agentauth.capabilities.monitor.scoring.target import (
    TargetDensityScorer,
    action_target,
    segments,
)
from agentauth.capabilities.scoping.goal import GoalSpec


def _goal(kind: str = "goal:summarize-app") -> GoalSpec:
    return GoalSpec(query_id="q", summary="summarize the app",
                    allow_resources=[], structured_intent={"kind": kind})


def _traj(paths: list[str], verb: str = "read", kind: str = "goal:summarize-app"):
    return Trajectory(
        goal=_goal(kind),
        actions=[Action(step=i, tool="Read", resource="workspace", verb=verb,
                        meta={"path": p}) for i, p in enumerate(paths)],
    )


def _fit(paths: list[str], repeats: int = 40, **kw) -> TargetDensityScorer:
    return TargetDensityScorer(**kw).fit([_traj(paths) for _ in range(repeats)])


# --------------------------------------------------------------------------- #
# The property the whole design rests on.
# --------------------------------------------------------------------------- #
def test_a_novel_branch_scores_far_above_an_observed_one():
    """The generalization cliff in miniature.

    Both paths sit inside a grant of ``repo/**``. A syntactic pattern admits them
    equally; the density must not.
    """
    scorer = _fit(["repo/app/summary.txt", "repo/app/notes.txt",
                   "repo/app/data.csv"])
    observed = scorer.surprise(_traj(["repo/app/summary.txt"]))[0].surprise
    novel = scorer.surprise(_traj(["repo/.ssh/id_rsa"]))[0].surprise
    assert novel > observed + 4, (observed, novel)


def test_escape_mass_shrinks_as_a_node_concentrates():
    """A node seen often with few children must reserve little mass for a new
    one; a diffuse node must reserve a lot. This is the property that keeps the
    channel from becoming a false-positive generator on sparse buckets."""
    concentrated = _fit(["repo/app/a.txt", "repo/app/b.txt"], repeats=200)
    diffuse = _fit([f"repo/d{i}/f{i}.txt" for i in range(20)], repeats=3)
    novel = _traj(["repo/zzz/new.txt"])
    assert (concentrated.surprise(novel)[0].surprise
            > diffuse.surprise(novel)[0].surprise)


def test_a_parent_traversal_is_not_normalized_away():
    """``..`` is the escape this channel exists to notice; resolving the path
    before scoring would erase the signal."""
    assert ".." in segments("repo/app/../../etc/shadow")
    scorer = _fit(["repo/app/summary.txt", "repo/app/notes.txt"])
    escape = scorer.surprise(_traj(["repo/app/../../etc/shadow"]))[0].surprise
    inside = scorer.surprise(_traj(["repo/app/summary.txt"]))[0].surprise
    assert escape > inside + 4


# --------------------------------------------------------------------------- #
# Abstention: no evidence is not evidence of anomaly.
# --------------------------------------------------------------------------- #
def test_an_unseen_goal_bucket_abstains_rather_than_flagging():
    """Cold start must degrade to the per-action floor, never to blocking.

    A UEBA layer that scores every brand-new goal type as maximally anomalous is
    an outage generator on the day a customer ships a new agent.
    """
    scorer = _fit(["repo/app/summary.txt"], repeats=40)
    unseen = _traj(["totally/elsewhere/x.txt"], kind="goal:never-seen")
    assert scorer.surprise(unseen)[0].surprise == 0.0


def test_a_thin_bucket_backs_off_to_the_peer_group_before_abstaining():
    """Entity -> cohort -> prior. A bucket below ``min_observations`` on its own
    must still be scored from the pooled trie rather than dropped."""
    scorer = TargetDensityScorer(min_observations=12)
    scorer.fit([_traj(["repo/app/a.txt"], kind="goal:common") for _ in range(40)]
               + [_traj(["repo/app/b.txt"], kind="goal:rare")])
    rare_novel = _traj(["repo/.ssh/id_rsa"], kind="goal:rare")
    assert scorer.surprise(rare_novel)[0].surprise > 0.0


def test_an_unfitted_scorer_scores_zero_rather_than_infinity():
    assert TargetDensityScorer().surprise(_traj(["a/b/c"]))[0].surprise == 0.0


# --------------------------------------------------------------------------- #
# Target extraction has to work on both corpus shapes.
# --------------------------------------------------------------------------- #
def test_target_prefers_the_path_but_falls_back_to_the_resource():
    """RedCode/SLEIGHT put identity in ``meta['path']`` and hold ``resource``
    constant; tau2/ATIF put it in ``resource`` with no path at all."""
    with_path = Action(step=0, tool="Read", resource="workspace", verb="read",
                       meta={"path": "repo/app/x.txt"})
    without = Action(step=0, tool="t", resource="mcp:tool:send_money", verb="call")
    assert action_target(with_path) == "repo/app/x.txt"
    assert action_target(without) == "mcp:tool:send_money"
    assert segments("mcp:tool:send_money") == ("tool", "send_money")


def test_verb_conditioning_gives_read_and_write_separate_baselines():
    """Reading a config and writing a config are different events.

    The channel keeps a trie per ``(bucket, verb)``, so a path the cohort only
    ever *reads* is surprising as a *write* target. Note what this test does not
    claim: when a verb has no observations at all the scorer backs off to the
    bucket rather than inventing a penalty, because verb novelty is already in
    ``action_token`` and the sequence channel's job. Double-counting it here
    would make the two channels correlated, which defeats factorizing them.
    """
    scorer = TargetDensityScorer(min_observations=1)
    scorer.fit(
        [_traj(["repo/config/app.yaml"], verb="read") for _ in range(40)]
        + [_traj(["repo/out/report.txt"], verb="write") for _ in range(40)]
    )
    read_known = scorer.surprise(
        _traj(["repo/config/app.yaml"], verb="read"))[0].surprise
    write_readonly = scorer.surprise(
        _traj(["repo/config/app.yaml"], verb="write"))[0].surprise
    assert write_readonly > read_known + 2, (read_known, write_readonly)


def test_explain_names_the_offending_segment():
    """An alert an analyst cannot read is shelfware."""
    scorer = _fit(["repo/app/summary.txt", "repo/app/notes.txt"])
    traj = _traj(["repo/.ssh/id_rsa"])
    assert ".ssh" in scorer.explain(traj, traj.actions[0])


def test_depth_alone_does_not_rank_a_path_as_anomalous():
    """``reduce='max'`` is chosen so a long in-corridor path does not outrank a
    short excursion. A sum would make depth the signal."""
    scorer = _fit(["repo/app/a/b/c/d/e.txt", "repo/app/a/b/c/d/f.txt"])
    deep_ok = scorer.surprise(_traj(["repo/app/a/b/c/d/e.txt"]))[0].surprise
    shallow_bad = scorer.surprise(_traj(["etc/shadow"]))[0].surprise
    assert shallow_bad > deep_ok


# --------------------------------------------------------------------------- #
# Readiness as a DEPTH: the channel declaring what it does and does not know.
# --------------------------------------------------------------------------- #
def test_ready_depth_grows_with_observations_per_target():
    """The governing variable, pinned.

    `benchmarks/concentration.py --curve` finds depth-1 novel-child surprise
    tracking observations per distinct target across three corpora regardless of
    synthetic-vs-real or tool-vs-filesystem: 1.7 obs/target gives 1.8 bits, 196
    gives 6.1. So readiness is not a property of the mechanism, it is a position
    on a curve, and it has to move when the traffic does.
    """
    from agentauth.capabilities.monitor.scoring.ngram import goal_bucket

    sparse = TargetDensityScorer().fit(
        [_traj([f"repo/d{i}/f{i}.txt"]) for i in range(60)])
    dense = TargetDensityScorer().fit(
        [_traj(["repo/app/a.txt", "repo/app/b.txt"]) for _ in range(60)])
    bucket = goal_bucket(_traj(["x"]))
    assert sparse.ready_depth(bucket, "read") < dense.ready_depth(bucket, "read")


def test_a_baseline_that_only_knows_the_root_scores_only_the_root():
    """RedCode's actual shape, and the reason L1 mimicry reads exactly 0.

    123 observations over 2 roots is a sharp boundary worth enforcing; 68
    distinct targets over the same traffic is 1.8 apiece and cannot separate
    anything. The scorer must enforce the first and stay silent on the second,
    rather than emitting noise below the depth it has evidence for.
    """
    from agentauth.capabilities.monitor.scoring.ngram import goal_bucket

    scorer = TargetDensityScorer().fit(
        [_traj([f"repo/unique{i}/file{i}.txt"]) for i in range(60)])
    bucket = goal_bucket(_traj(["x"]))
    assert scorer.ready_depth(bucket, "read") == 0

    novel_root = scorer.surprise(_traj(["etc/shadow"]))[0].surprise
    assert novel_root > 3.0, novel_root

    # The precise invariant: below ``ready_depth`` the scorer is *indifferent*.
    # A novel leaf and a known leaf under the same known root must score
    # identically, because all the surprise either earns comes from the root
    # segment. Asserting the novel leaf scores exactly 0 would be wrong, the
    # known root still contributes its own (near-zero) term.
    novel_leaf = scorer.surprise(_traj(["repo/unique0/stolen.txt"]))[0].surprise
    known_leaf = scorer.surprise(_traj(["repo/unique0/file0.txt"]))[0].surprise
    assert novel_leaf == known_leaf, (
        "the scorer discriminated below the depth it has evidence for: "
        f"{novel_leaf} vs {known_leaf}")
    assert novel_leaf < 1.0, novel_leaf


def test_readiness_reports_what_is_missing_rather_than_just_refusing():
    """An operator has to be able to act on a not-ready verdict."""
    scorer = _fit(["repo/app/a.txt"], repeats=3)
    report = scorer.readiness()
    key = next(iter(report))
    assert report[key]["ready"] is False
    assert "more clean actions" in report[key]["reason"]
    assert report[key]["obs_per_target"] > 0
