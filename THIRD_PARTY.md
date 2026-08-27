# Third-party material

Clay Seal itself is MIT (see [LICENSE](LICENSE)). Nothing below is redistributed
in this repository. The benchmark corpora are **fetched** by
[`benchmarks/fetch_corpora.sh`](benchmarks/fetch_corpora.sh) into
`.benchmark-corpus/`, which is gitignored, so cloning this repository does not
copy any of it. Each remains under its own licence and its own terms of use.

If you use the benchmark suites in published work, cite the corpora, not this
repository's replay of them.

## Corpora fetched by `benchmarks/fetch_corpora.sh`

| corpus | source | licence |
| --- | --- | --- |
| RedCode-Exec | [AI-secure/RedCode](https://github.com/AI-secure/RedCode) | Apache-2.0 |
| AgentHarm | [ai-safety-institute/AgentHarm](https://huggingface.co/datasets/ai-safety-institute/AgentHarm) (UK AI Safety Institute) | MIT |
| Agent Security Bench (ASB) | [agiresearch/ASB](https://github.com/agiresearch/ASB) | see upstream repository |
| Gorilla BFCL (multi-turn) | [ShishirPatil/gorilla](https://github.com/ShishirPatil/gorilla) | Apache-2.0 |
| InjecAgent | [uiuc-kang-lab/InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent) | see upstream repository |
| ToolEmu | [ryoungj/ToolEmu](https://github.com/ryoungj/ToolEmu) | see upstream repository |
| SLEIGHT-Bench | arXiv:2605.16626 | see upstream; canary-protected, read the note below |
| AgentDojo | [ethz-spylab/agentdojo](https://github.com/ethz-spylab/agentdojo) | MIT |
| τ²-bench | [sierra-research/tau2-bench](https://github.com/sierra-research/tau2-bench) | see upstream repository |

Where a licence is listed as "see upstream repository", check it yourself before
redistributing that corpus or its derivatives. This project does not
redistribute any of them and takes no position on terms it is not party to.

### SLEIGHT-Bench canary

SLEIGHT-Bench transcripts carry an explicit training opt-out string and ship
encrypted so they stay out of scraped training corpora. The decryption key is
published in the upstream README deliberately: the encryption is there to stop
automated collection, not human access. Do not commit decrypted transcripts, and
do not include them in anything that could be crawled. `.gitignore` covers
`.benchmark-corpus/`, which is where they land.

## Synthetic material in this repository

The personas and addresses under `benchmarks/` and `demo/` are synthetic.
`bluesparrowtech.com` personas come from AgentDojo, targets from AgentHarm, and
the rest are `example.com` / `example.test` / `corp.example` reserved names.
Credential-shaped strings in tests are vendor documentation examples
(`AKIAIOSFODNN7EXAMPLE`) or placeholders; no credential is committed anywhere in
the working tree or in any reachable history.

## Runtime dependencies

The library itself depends on two packages, both permissively licensed:

| package | licence |
| --- | --- |
| [cryptography](https://github.com/pyca/cryptography) | Apache-2.0 OR BSD-3-Clause |
| [PyYAML](https://github.com/yaml/pyyaml) | MIT |

Optional extras pull further packages; see `[project.optional-dependencies]` in
[pyproject.toml](pyproject.toml). None is required to use the gateway.
