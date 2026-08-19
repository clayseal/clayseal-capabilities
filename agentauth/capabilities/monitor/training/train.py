"""Train the goal-conditioned transformer scorer on benign trajectories.

    python -m agentauth.capabilities.monitor.training.train \
        --corpus benign.jsonl --out models/traj-lm --epochs 10 --device cuda

Trains a next-action language model on benign trajectories only (the detector is
a one-class model: it learns "normal for this goal" and flags departures), then
writes the checkpoint plus a benign calibration file so
``TrajectoryDetector`` can attach the conformal layer without recomputation.
Run on a GPU VM; the n-gram scorer covers CPU/offline use.
"""
from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

from agentauth.capabilities.monitor.scoring.ngram import goal_bucket
from agentauth.capabilities.monitor.scoring.transformer import (
    TransformerConfig,
    TransformerScorer,
    build_model,
)
from agentauth.capabilities.monitor.training.data import Vocab, load_corpus


def _pad_batch(seqs: list[list[int]], pad_id: int):
    import torch

    width = max(len(s) for s in seqs)
    padded = [s + [pad_id] * (width - len(s)) for s in seqs]
    return torch.tensor(padded)


def train(args: argparse.Namespace) -> None:
    import torch
    from torch import nn

    torch.manual_seed(args.seed)
    random.seed(args.seed)

    corpus = load_corpus(args.corpus)
    if not corpus:
        raise SystemExit(f"no trajectories in {args.corpus}")
    random.shuffle(corpus)
    vocab = Vocab.build(corpus, min_count=args.min_count)
    encoded = [vocab.encode(t)[0] for t in corpus]

    config = TransformerConfig(
        vocab_size=len(vocab), d_model=args.d_model, n_head=args.n_head,
        n_layer=args.n_layer, dim_feedforward=args.dim_feedforward, max_len=args.max_len,
    )
    device = args.device
    model = build_model(config).to(device)
    opt = torch.optim.AdamW(model.parameters(), lr=args.lr)
    loss_fn = nn.CrossEntropyLoss(ignore_index=vocab.pad_id)

    seqs = [s[: config.max_len] for s in encoded if len(s) >= 2]
    for epoch in range(args.epochs):
        random.shuffle(seqs)
        model.train()
        total, n = 0.0, 0
        for i in range(0, len(seqs), args.batch_size):
            batch = _pad_batch(seqs[i : i + args.batch_size], vocab.pad_id).to(device)
            logits = model(batch[:, :-1])
            loss = loss_fn(logits.reshape(-1, logits.size(-1)), batch[:, 1:].reshape(-1))
            opt.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            total += float(loss.detach()) * batch.size(0)
            n += batch.size(0)
        print(f"epoch {epoch + 1}/{args.epochs}  loss={total / max(1, n):.4f}", flush=True)

    scorer = TransformerScorer(model, vocab, config, device=device)
    scorer.save(args.out)
    _dump_calibration(scorer, corpus, Path(args.out) / "calibration.jsonl")
    print(f"saved model + calibration to {args.out}", flush=True)


def _dump_calibration(scorer: TransformerScorer, corpus, path: Path) -> None:
    with path.open("w") as handle:
        for traj in corpus:
            bucket = goal_bucket(traj)
            for scored in scorer.surprise(traj):
                handle.write(json.dumps({"bucket": bucket, "surprise": scored.surprise}) + "\n")


def _parse(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Train goal-conditioned trajectory scorer")
    p.add_argument("--corpus", required=True, help="jsonl of benign trajectories")
    p.add_argument("--out", required=True, help="output model directory")
    p.add_argument("--epochs", type=int, default=10)
    p.add_argument("--batch-size", type=int, default=64)
    p.add_argument("--lr", type=float, default=3e-4)
    p.add_argument("--d-model", type=int, default=128)
    p.add_argument("--n-head", type=int, default=4)
    p.add_argument("--n-layer", type=int, default=3)
    p.add_argument("--dim-feedforward", type=int, default=256)
    p.add_argument("--max-len", type=int, default=256)
    p.add_argument("--min-count", type=int, default=1)
    p.add_argument("--device", default="cpu")
    p.add_argument("--seed", type=int, default=0)
    return p.parse_args(argv)


if __name__ == "__main__":
    train(_parse())
