# AML analytics on real financial-crime data

STATUS: current

Two real-data validations of the anomaly layer's AML-derived analytics, one
per-transaction and one per-entity-sequence.

## Peer-deviation sensor, per-transaction (ULB credit-card fraud)

`benchmarks/fraud_validation.py`. Fit peer statistics on legitimate transactions,
score held-out transactions with `aml.peer_z_score`, measure separation of fraud.

- ROC-AUC: **0.914**
- recall at 1% false-positive rate: **0.32**

This grounds the learned peer-deviation component the detector uses.

## Fan-out typology, per-entity-sequence (IBM AML HI-Small)

`benchmarks/aml_sequence_validation.py`. Stream the transaction file, group by
originating account, build the per-account features the AML tier scores (velocity
= transaction count, fan-out = distinct destinations), label an account laundering
if any of its transactions is labeled laundering.

- Legitimate accounts never exceed a fan-out of **36**.
- Laundering hub accounts reach **500 to 14,000**.
- Every account exhibiting the fan-out typology (fan-out beyond the entire
  legitimate range) is separated: **15 of 15 at a 1% false-alarm rate**.

Honest scope: the dataset's laundering is partly a multi-account graph pattern, so
it also labels peripheral mule accounts (median fan-out 3) that carry no
per-account signal. Those are a graph-detection problem, not a per-entity sequence
one, so a naive AUC over every labeled account looks weak (~0.55). What this
validates is the typology the sequence detector is built for: an entity that
itself fans out or moves at high velocity. Structuring is not validated on this
dataset because the amounts span currencies and do not cluster at round
thresholds; structuring is validated in the agent domain (fragmented-overspend)
and enforced deterministically by the budget rung.

## Standing

The AML-derived analytics separate real fraud per-transaction (0.914 AUC) and the
real fan-out laundering typology per-entity (clean separation, 15/15 at 1% FPR),
which grounds the agent-domain detector on real financial-crime data. The data
files are external (ULB in the sibling receipts corpus; IBM AML via `AML_DATA`).
