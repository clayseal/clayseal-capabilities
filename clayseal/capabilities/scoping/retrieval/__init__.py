"""Ranking chunks against a goal, several ways.

BM25 for lexical overlap, an ANN index for embedding similarity, reciprocal-rank
fusion to combine rankings without tuning a weight between incomparable scores,
MMR to stop the top of the list being five copies of one file, and a reranker.

None of this decides authority. It decides what a lease is built FROM, and
`capability_scope.py` decides what the lease says. Retrieval that ranks badly
costs utility, by leaving something out that the session then cannot reach; it
cannot widen a grant.
"""
