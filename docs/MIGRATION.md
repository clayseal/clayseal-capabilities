# Migrating to Clay Seal 0.6

The package was renamed. If you installed from the private design-partner feed
as `agentauth-capabilities`, this is what changes and what does not.

Nothing here changes a decision the gateway makes. It is a rename, and the
sections below say exactly where the rename stops.

## The short version

```bash
pip uninstall agentauth-capabilities
pip install clayseal
```

```bash
# in your own source
grep -rl 'agentauth\.' . | xargs sed -i '' \
  -e 's/agentauth\.capabilities/clayseal.capabilities/g' \
  -e 's/agentauth\.core/clayseal.core/g'

# and in your deployment config
CLAYSEAL_ENV=...          # was AGENTAUTH_ENV
CLAYSEAL_COMMIT_TOKEN_*   # was AGENTAUTH_COMMIT_TOKEN_*
```

`agentauth.identity` and `agentauth.receipts` are **separate distributions** and
keep their names. Do not rewrite those.

## You do not have to do it today

The old import paths still work for one release:

```python
from agentauth.capabilities import Guardrail   # works in 0.6, warns, gone in 0.7
```

The alias is an import hook, not a copy. `agentauth.capabilities.session_rules`
and `clayseal.capabilities.session_rules` are the *same module object*, so a
plugin registered through the old path is visible to a lookup through the new
one, and the used-token store is one store rather than two. Mixing the spellings
during a migration is safe.

To find every old import in your codebase, turn the warning into an error:

```bash
python -W error::DeprecationWarning -m yourapp
```

## Environment variables

Every `AGENTAUTH_*` variable is now `CLAYSEAL_*`. The old names are still read
for one release and log a warning naming the replacement, once per variable.

The current name wins if both are set, so you can roll the rename out one
service at a time.

Nothing mutates `os.environ`. If you spawn subprocesses that read these
variables themselves, rename them in the environment you pass to the child; the
library will not do it behind your back.

`AGENT_RECEIPTS_*` belongs to the receipts distribution and is unchanged.

## Entry points

If you publish a plugin, move its entry-point group from `agentauth.<group>` to
`clayseal.<group>`:

```toml
[project.entry-points."clayseal.sandbox_backends"]
my_backend = "my_package.backend:MyBackend"
```

Both prefixes are read in 0.6, and the `clayseal.` one wins if you declare both.
A plugin you have already published keeps loading without a release.

## What was deliberately NOT renamed

These are wire and storage identifiers, not module paths. Renaming them would
change the meaning of data already on disk or already in flight:

| identifier | why it stays |
| --- | --- |
| `agentauth:commit:` | the replay store's key prefix. Rename it and every commit token the gateway has already spent becomes unseen, which reopens the replay window the store exists to close. |
| `agentauth:ledger`, `agentauth:decisions` | existing ledger entries and decision streams stay addressable. Both are already overridable by configuration. |
| `agentauth:authorize` | the DPoP HTU binding string. Changing it invalidates bindings held by clients that have not upgraded. |
| `"agentauth"` identity provider | the name in `get_identity_provider("agentauth")` and the default SPIFFE audience, both of which appear in credentials already issued. |

If you want the storage prefixes renamed in your own deployment, set them
explicitly (`CLAYSEAL_LEDGER_REDIS_PREFIX`, `CLAYSEAL_COMMIT_TOKEN_STORE` and
friends) and migrate the keys yourself. The library will not move them for you,
because it cannot tell an empty store from one it failed to read.

## Version

`clayseal` starts at 0.6.0. The `clayseal` name on PyPI previously held a small
partner installer that routed pip at a private feed; 0.6.0 supersedes it, and
that installer is no longer the way in. There is no private feed any more.
