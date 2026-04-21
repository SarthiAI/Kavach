# Kavach Python SDK, learn by example

Twenty-one standalone scripts. Each one tells a small business
story end to end: the policy, the actions, the attacks, and why
Kavach refuses what it refuses. Every script runs on its own,
prints a readable trace, and exits 0 if every check passes.

Copy any script out, edit the policy dict or the ActionContext,
run it. No shared helpers, no framework, no magic. The whole API
surface you need is imported at the top of each file.

```bash
cd business-tests-python

# Absolute quick start. The smallest useful Kavach program you can
# write. Reading it top to bottom takes about 60 seconds.
./venv/bin/python tier1/01_quickstart.py

# Run every scenario.
./venv/bin/python run_all.py
```

## What makes Kavach worth a look

The scenarios cluster around six capabilities that are hard to
stitch together from off the shelf libraries:

| Capability | Demonstrated in |
|---|---|
| PQ signed permits across service boundaries | [05](tier2/05_signed_permit.py), [06](tier2/06_ephemeral_permits.py), [08](tier2/08_loan_approval.py), [09](tier2/09_api_key_rotation.py), [10](tier2/10_break_glass.py) |
| Signed audit chains with entry-level tamper detection | [16](tier3/16_healthcare_phi.py), [17](tier3/17_pq_audit_rotation.py), [20](tier3/20_ai_underwriter_evidence.py) |
| SecureChannel with replay / recipient / context binding | [13](tier3/13_secure_channel_fleet.py), [15](tier3/15_agent_marketplace.py) |
| Cross-replica invalidation broadcast | [03](tier1/03_reset_geo_drift.py), [14](tier3/14_invalidation_fanout.py) |
| Drift detectors at authorization time (fail closed, not alert) | [03](tier1/03_reset_geo_drift.py), [04](tier1/04_session_hygiene.py), [11](tier2/11_ecommerce_fraud.py) |
| PQ-hybrid mode with downgrade defence | [07](tier2/07_pq_hybrid_downgrade.py), [17](tier3/17_pq_audit_rotation.py) |

The same scenarios also cover the hottest AI-agent security topic
of 2025-26: **prompt injection defence**. Kavach signs the user's
click and refuses every tool call that drifts from that signed
scope. These are the cases where OAuth scopes, DB row security,
and hand-coded `if` statements do not fit:

| AI / prompt-injection angle | Demonstrated in |
|---|---|
| Kavach signs the user click; agent can only act inside that signed scope | [18](tier3/18_ai_agent_attestation.py) |
| One Kavach-signed intent covers a whole flow across four SaaS systems | [19](tier3/19_cross_saas_finance_agent.py) |
| Kavach-anchored evidence chain the regulator can re-verify independently | [20](tier3/20_ai_underwriter_evidence.py) |
| Agent in customer's VPC; signing keys on user's device; Kavach in the middle | [21](tier3/21_customer_deployed_agent.py) |

## Setup

The folder ships with a local virtual environment so nothing
touches your system Python.

```bash
cd business-tests-python

# Create a venv if one does not exist yet.
python -m venv venv

# Install the published SDK from PyPI.
./venv/bin/pip install --upgrade pip
./venv/bin/pip install kavach-sdk
```

You can also activate the venv if you prefer (`source
venv/bin/activate`) but every script runs fine with the full venv
path.

## Running

```bash
# One scenario. Read the output top to bottom, that IS the doc.
./venv/bin/python tier1/01_quickstart.py

# Every scenario.
./venv/bin/python run_all.py

# Just one tier.
./venv/bin/python run_all.py --tier 2

# Filter by filename.
./venv/bin/python run_all.py --only ai_underwriter
```

Every script exits 0 on all pass, 1 on any fail. `run_all.py`
prints a summary table at the end.

## Where to start

If you are new to Kavach, read in the natural order 01 → 21. Each
step builds on the last. If you only have 20 minutes, read these
six files in order:

1. [tier1/01_quickstart.py](tier1/01_quickstart.py) (one policy,
   one gate, three verdicts in under 60 lines).
2. [tier1/03_reset_geo_drift.py](tier1/03_reset_geo_drift.py)
   (drift detectors block at authorization time plus invalidation
   broadcast).
3. [tier2/05_signed_permit.py](tier2/05_signed_permit.py) (auth
   signs a permit, payments verifies, four attack shapes caught
   by the signature or the trusted directory).
4. [tier3/13_secure_channel_fleet.py](tier3/13_secure_channel_fleet.py)
   (the SecureChannel primitive: replay + recipient + context
   binding, four attacks caught).
5. [tier3/18_ai_agent_attestation.py](tier3/18_ai_agent_attestation.py)
   (prompt injection defence in 200 lines, including narrative).
6. [tier3/21_customer_deployed_agent.py](tier3/21_customer_deployed_agent.py)
   (user held signing keys, container holds only short lived
   permits, a clean fit for VPC deployed agents).

After that, pick whatever matches the domain you are building in.
The full set covers healthcare PHI, a fintech checkout, a
consulting firm's document service, a banking underwriter, a
cross-SaaS finance bot, an agent marketplace, and a PQ-safe
7-year audit archive.

## Folder layout

```
business-tests-python/
|- README.md       (this file)
|- run_all.py      (driver that runs every scenario)
|- venv/           (local virtual env, not committed)
|
|- tier1/          foundations, read these first
|   |- 01_quickstart.py              one gate, 60 seconds of reading
|   |- 02_document_access.py         classification, rate, app side scope
|   |- 03_reset_geo_drift.py         geo drift + invalidation broadcast
|   `- 04_session_hygiene.py         all four drift detectors
|
|- tier2/          signed permits and single-service use cases
|   |- 05_signed_permit.py           PQ signed permit across services
|   |- 06_ephemeral_permits.py       short-lived permits vs static API keys
|   |- 07_pq_hybrid_downgrade.py     hybrid mode and downgrade defence
|   |- 08_loan_approval.py           tiered ceilings + regulator invariant
|   |- 09_api_key_rotation.py        two-person rule for key rotation
|   |- 10_break_glass.py             SRE emergency access with audit
|   |- 11_ecommerce_fraud.py         multi-layer fraud + observe-only rollout
|   `- 12_http_mcp.py                HTTP and MCP middleware (preview)
|
`- tier3/          multi-service, advanced, AI prompt injection
    |- 13_secure_channel_fleet.py     SecureChannel, four adversarial tests
    |- 14_invalidation_fanout.py      cross-replica session fan out
    |- 15_agent_marketplace.py        vendor orchestrator, kill switch, rotation
    |- 16_healthcare_phi.py           PHI access with signed audit chain
    |- 17_pq_audit_rotation.py        7 year archive across key rotations
    |- 18_ai_agent_attestation.py     AI prompt injection, base pattern
    |- 19_cross_saas_finance_agent.py one signed intent across four SaaS
    |- 20_ai_underwriter_evidence.py  AI loan officer, regulator grade audit
    `- 21_customer_deployed_agent.py  agent in customer VPC, user held keys
```

## Style

Every file is one self-contained script. No shared helpers, no
coloured output, no surprise magic. Every name in `kavach.*` that
a scenario uses is imported at the top so you can see the API
surface at a glance. Copy a script out, edit it, run it.
