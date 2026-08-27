#!/usr/bin/env bash
# GPU-VM workload: train the goal-conditioned trajectory scorer and evaluate the
# behavioral detector on external data.
#
# This is the one GPU-bound step (transformer training); route it to a GPU VM
# (e.g. the T4), not the laptop. The enforcement ladder and the n-gram detector
# stay CPU-only. Nothing here launches a VM, run it ON the VM after syncing the
# repo, same delivery path as run_benchmark.sh.
#
#   DATASET=agentdojo LIMIT=3000 EPOCHS=20 benchmarks/azure/train_detector.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

DATASET="${DATASET:-agentdojo}"
LIMIT="${LIMIT:-3000}"
EPOCHS="${EPOCHS:-20}"
ALPHA="${ALPHA:-0.05}"
OUT_DIR="${OUT_DIR:-$REPO_ROOT/benchmarks/results/detector/$(date -u +%Y%m%dT%H%M%SZ)}"
# agentdojo needs Python 3.10-3.12; prefer 3.12.
PYTHON="${PYTHON:-$(command -v python3.12 || command -v python3)}"

log() { printf '[%s] [train] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
mkdir -p "$OUT_DIR"

if [[ ! -d .venv ]]; then "$PYTHON" -m venv .venv; fi
# shellcheck disable=SC1091
source .venv/bin/activate
pip install --quiet --upgrade pip
[[ -d ../agentauth-core ]] && pip install --quiet -e "../agentauth-core"
pip install --quiet -e ".[benchmarks,monitor]"

# Detect CUDA; fall back to CPU so the script still completes on a CPU VM.
DEVICE=$(python -c "import torch; print('cuda' if torch.cuda.is_available() else 'cpu')")
log "device=$DEVICE dataset=$DATASET limit=$LIMIT epochs=$EPOCHS"

CORPUS="$OUT_DIR/benign.jsonl"
MODEL="$OUT_DIR/traj-lm"

log "building benign corpus"
python -m benchmarks.build_corpus --dataset "$DATASET" --limit "$LIMIT" --out "$CORPUS"

log "training transformer scorer"
python -m agentauth.capabilities.monitor.training.train \
    --corpus "$CORPUS" --out "$MODEL" --epochs "$EPOCHS" --device "$DEVICE" \
    | tee "$OUT_DIR/train.log"

log "evaluating detector: n-gram baseline vs trained transformer"
python -m benchmarks.cli --dataset "$DATASET" --limit "$LIMIT" --mode detector \
    --scorer ngram --alpha "$ALPHA" --json "$OUT_DIR/detector_ngram.json" \
    | tee "$OUT_DIR/detector_ngram.md"
python -m benchmarks.cli --dataset "$DATASET" --limit "$LIMIT" --mode detector \
    --scorer transformer --model-dir "$MODEL" --alpha "$ALPHA" \
    --json "$OUT_DIR/detector_transformer.json" | tee "$OUT_DIR/detector_transformer.md"

log "artifacts in $OUT_DIR"
