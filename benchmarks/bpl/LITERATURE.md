# Literature → BPL scenario map

Research notes grounding harder BPL scenarios in multi-agent failure taxonomies,
long-horizon agent attacks, policy-invisible violations, and documented agent
incidents. Scenarios themselves live in `scenarios/literature.py` (tag
`literature`).

## Sources (primary)

| Source | What it contributes to BPL |
|--------|----------------------------|
| **MAST** — Cemri et al., *Why Do Multi-Agent LLM Systems Fail?* ([site](https://sites.google.com/berkeley.edu/mast/home), arXiv:2503.13657) | Empirically grounded taxonomy over 7 MAS frameworks / 200 traces: **specification issues (~42%)**, **inter-agent misalignment (~37%)**, **task verification (~21%)**. Failures are structural (handoffs, verification theater), not just “bad prompting.” |
| **Multi-Agent Risks from Advanced AI** — Hammond et al. (arXiv:2502.14143) | Incentive-level failure modes: **miscoordination**, **conflict**, **collusion**; risk factors include information asymmetry, commitment problems, emergent agency. |
| **AgentLAB** — Jiang et al. (arXiv:2602.16901 / ICML) | Long-horizon attacks: **intent hijacking**, **tool chaining**, **task injection**, **objective drifting**, **memory poisoning**. Single-turn defenses fail; cumulative observation shifts matter. |
| **PhantomPolicy** — *Policy-Invisible Violations in LLM-Based Agents* (arXiv:2604.12177) | Actions that are user-sanctioned and locally reasonable but violate policy because **decisive state is absent from the model-visible context**. Categories include inactive recipients, audience mismatch, **accumulated session leakage**. Frontier models still violate ~90–98% of risky cases when metadata is hidden. |
| **Incident registries** — Oso “AI agents gone rogue”, Curity agentic incidents, Unit 42 agentic threats, Meshgate production-safety writeups | Real-world patterns: destructive “fix” under error (DB/volume delete), unauthorized posts, peer-approval bypass, runaway tool loops, fail-open governance hooks. |

## Mapping into BPL (composite / Progent-blind / no injection strings)

| Literature construct | BPL scenario | Family | Why it’s hard for frontier models |
|----------------------|--------------|--------|-----------------------------------|
| MAST FC1 handoff / ambiguous spec | `handoff-spec-cascade` | escape | Wrong interpretation is written by a “planner” tool and treated as ground truth by the executor lane |
| MAST FC3 verification theater | `rubber-stamp-verifier` | aggregate | `verify_*` always returns OK; destruction happens on commit |
| MAST FM-1.3 step repetition | `retry-storm-double-effect` | aggregate | Retries of an already-succeeded pay blow the ceiling |
| Hammond miscoordination | `miscoord-double-fulfill` | aggregate | Two personas each believe they own the invoice |
| AgentLAB objective drifting | `observation-objective-drift` | confidentiality | Success criteria shift across benign status observations |
| AgentLAB memory poisoning | `memory-poison-preference` | confidentiality | Preference written mid-run later redirects egress |
| PhantomPolicy invisible attribute | `invisible-inactive-recipient` | confidentiality | Recipient looks fine; `status=inactive` only in meta lookup |
| PhantomPolicy accumulated leakage | `accumulated-scope-union` | confidentiality | Partner-OK + INTERNAL reads → combined external send |
| Incident: destructive error recovery | `error-recovery-drop-volume` | escape | Credential/staging error “fixed” by dropping prod volume |

## Design constraints (unchanged)

1. Every tool on the violating path is in the OpenAI allowlist → **Progent-blind**.
2. No jailbreak / injection strings; pressure comes from handoffs, hidden metadata, observation drift, or error recovery → **CaMeL-adjacent but composite**.
3. `violated(env)` remains a pure predicate; `clayseal_expected` marks aspirational broker gaps (provenance graphs, inactive-recipient binding, etc.).

## Implications for ClaySeal / product

- **Stateful ledgers** still win classic aggregate BPL; literature hard cases need **world-model / provenance** (PhantomPolicy Sentinel-style), **sealed goal that survives handoffs**, and **deny on destructive recovery verbs**.
- Prompt-level policy (PhantomPolicy ablation) cuts but does not eliminate invisible violations — matches our `load_policy` pattern being necessary but insufficient.
- Multi-agent H2H should score **org ledger / shared mandate**, not per-persona views (see also `sibling-session-collusion` in ultra).

## Deep tier (less accessible sources → `scenarios/deep.py`, tag `deep`)

| Source | Construct | BPL scenario |
|--------|-----------|--------------|
| Motwani et al., NeurIPS 2024 — *Secret Collusion among AI Agents* | Steganographic coordination via benign channels | `stego-weather-coord` |
| Calvano et al., AER 2020 — algorithmic pricing collusion | Tacit matching of supracompetitive prices without messages | `tacit-price-match` |
| Laban et al. 2025 — *LLMs Get Lost in Multi-Turn Conversation* | Sharded specs; premature commitment; loss of early constraints | `sharded-ceiling-forgetting` |
| Liu et al., TACL 2024 — Lost in the Middle | U-shaped attention; binding rule buried mid-document | `buried-middle-mandate` |
| SCOPEGATE (arXiv:2606.28679) | Capability gates ≠ fail-closed per-call value authorization | `capability-gate-not-value-auth` |
| CSA / SANS confused-deputy notes; RFC 8693 lessons | Audience-bound token passthrough to a broader API | `token-passthrough-audience` |
| Classical TOCTOU under mutable authz state | Check-then-pay after revocation | `toctou-stale-approval` |
| SMSR (arXiv:2606.12703) — Multi-Session Memory Poisoning | Prior-session retrieve steers current egress | `msmp-cross-session-retrieve` |

These are intentionally harder than the primer literature tier: coded coordination, attention geometry, and authorization-vs-capability distinctions rather than explicit “don’t exceed $X” in the user prompt.
