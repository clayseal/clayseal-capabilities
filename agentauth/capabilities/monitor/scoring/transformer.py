"""Goal-conditioned transformer scorer (the high-ceiling learned model).

A small decoder-only language model over the shared action-token vocabulary,
conditioned on the sealed goal by prepending the goal tokens. Surprise for an
action is the model's negative log-probability of that action token given the
goal and every prior action, so a step that is unlikely under how this goal is
usually pursued scores high. The conformal layer then turns those scores into
calibrated decisions, exactly as it does for the n-gram baseline: the scorer is
swapped, the guarantee is unchanged.

torch is imported lazily and is an optional extra (``[monitor]``). The package,
its tests, and the whole detector pipeline run without it via the n-gram scorer;
this class is the model trained on a GPU VM and loaded for inference.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from agentauth.capabilities.monitor.action import Trajectory
from agentauth.capabilities.monitor.scoring.base import ScoredStep
from agentauth.capabilities.monitor.training.data import Vocab


def _require_torch():
    try:
        import torch
    except ImportError as exc:  # pragma: no cover - exercised only without torch
        raise ImportError(
            "The transformer scorer needs torch. Install the extra: "
            "pip install 'agentauth-capabilities[monitor]' (train on a GPU VM; "
            "the n-gram scorer covers CPU/offline use)."
        ) from exc
    import torch

    return torch


@dataclass
class TransformerConfig:
    vocab_size: int
    d_model: int = 128
    n_head: int = 4
    n_layer: int = 3
    dim_feedforward: int = 256
    max_len: int = 256
    dropout: float = 0.1


def build_model(config: TransformerConfig):
    """Construct the decoder-only LM (returns an ``nn.Module``)."""
    torch = _require_torch()
    from torch import nn

    class GoalConditionedLM(nn.Module):
        def __init__(self, cfg: TransformerConfig) -> None:
            super().__init__()
            self.cfg = cfg
            self.tok = nn.Embedding(cfg.vocab_size, cfg.d_model)
            self.pos = nn.Embedding(cfg.max_len, cfg.d_model)
            layer = nn.TransformerEncoderLayer(
                d_model=cfg.d_model, nhead=cfg.n_head,
                dim_feedforward=cfg.dim_feedforward, dropout=cfg.dropout,
                batch_first=True, activation="gelu",
            )
            self.blocks = nn.TransformerEncoder(layer, num_layers=cfg.n_layer)
            self.norm = nn.LayerNorm(cfg.d_model)
            self.head = nn.Linear(cfg.d_model, cfg.vocab_size)

        def forward(self, ids):  # ids: (B, T)
            b, t = ids.shape
            positions = torch.arange(t, device=ids.device).unsqueeze(0).expand(b, t)
            x = self.tok(ids) + self.pos(positions)
            mask = torch.triu(torch.ones(t, t, device=ids.device), diagonal=1).bool()
            x = self.blocks(x, mask=mask)
            return self.head(self.norm(x))  # (B, T, V)

    return GoalConditionedLM(config)


class TransformerScorer:
    """SequenceScorer backed by a trained ``GoalConditionedLM`` checkpoint."""

    name = "transformer"

    def __init__(self, model, vocab: Vocab, config: TransformerConfig, *, device: str = "cpu") -> None:
        self._torch = _require_torch()
        self.model = model.to(device).eval()
        self.vocab = vocab
        self.config = config
        self.device = device

    def surprise(self, traj: Trajectory) -> list[ScoredStep]:
        torch = self._torch
        ids, action_positions = self.vocab.encode(traj)
        if not action_positions:
            return []
        ids = ids[: self.config.max_len]
        with torch.no_grad():
            logits = self.model(torch.tensor([ids], device=self.device))  # (1, T, V)
            log_probs = torch.log_softmax(logits[0], dim=-1)  # (T, V)
        out: list[ScoredStep] = []
        for pos, action in zip(action_positions, traj.actions, strict=False):
            if pos >= len(ids) or pos == 0:
                out.append(ScoredStep(action.step, 0.0))
                continue
            # P(token at pos | tokens < pos) comes from logits at pos-1.
            token_id = ids[pos]
            out.append(ScoredStep(action.step, float(-log_probs[pos - 1, token_id])))
        return out

    # ---- persistence -------------------------------------------------------
    def save(self, out_dir: str | Path) -> None:
        torch = self._torch
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        torch.save(self.model.state_dict(), out / "model.pt")
        self.vocab.save(out / "vocab.json")
        (out / "config.json").write_text(json.dumps(asdict(self.config)))

    @classmethod
    def load(cls, out_dir: str | Path, *, device: str = "cpu") -> TransformerScorer:
        torch = _require_torch()
        out = Path(out_dir)
        config = TransformerConfig(**json.loads((out / "config.json").read_text()))
        vocab = Vocab.load(out / "vocab.json")
        model = build_model(config)
        model.load_state_dict(torch.load(out / "model.pt", map_location=device))
        return cls(model, vocab, config, device=device)
