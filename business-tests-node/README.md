# Kavach Node SDK, learn by example

Twenty-one standalone scripts. Each one tells a small business story end to end: the policy, the actions, the attacks, and why Kavach refuses what it refuses. Every script runs on its own, prints a readable trace, and exits 0 if every check passes.

Copy any script out, edit the policy or the action context, run it. No shared helpers, no framework, no magic. The whole API surface you need is imported at the top of each file.

This folder is a one-to-one Node port of `business-tests-python/`. Same scenarios, same setup, same sub-cases, same assertions. A green run here means the Node SDK delivers the same end-to-end contract that the Python SDK validates.

```bash
cd business-tests-node

# Install the local SDK build, compile, run.
npm install
npm run build

# Absolute quick start. The smallest useful Kavach program you can
# write. Reading it top to bottom takes about 60 seconds.
node dist/tier1/01_quickstart.js

# Run every scenario.
node dist/run_all.js
```

## Setup

The Node SDK is not yet published to npm. The local install points at the workspace SDK build at `../kavach-node/npm`, so build that first.

```bash
# From the Kavach workspace root:
(cd kavach-node && npx napi build --platform --release)
(cd kavach-node/npm && npm install && npm run build)

# Then from business-tests-node/:
npm install
npm run build
```

## Running

```bash
# Compile and run every scenario.
npm run run:all

# One scenario.
node dist/tier1/01_quickstart.js

# One tier.
node dist/run_all.js --tier 2

# Filter by filename substring.
node dist/run_all.js --only ai_underwriter
```

Every script exits 0 on all pass, 1 on any fail. `run_all.js` prints a summary table at the end.

## Folder layout

```
business-tests-node/
|- README.md
|- package.json, tsconfig.json
|- run_all.ts                (tier-aware driver)
|
|- tier1/    foundations, read these first
|   |- 01_quickstart.ts                one gate, 60 seconds of reading
|   |- 02_document_access.ts           classification, rate, app side scope
|   |- 03_reset_geo_drift.ts           geo drift + invalidation broadcast
|   `- 04_session_hygiene.ts           all four drift detectors
|
|- tier2/    signed permits and single-service use cases
|   |- 05_signed_permit.ts             PQ signed permit across services
|   |- 06_ephemeral_permits.ts         short-lived permits vs static API keys
|   |- 07_pq_hybrid_downgrade.ts       hybrid mode and downgrade defence
|   |- 08_loan_approval.ts             tiered ceilings + regulator invariant
|   |- 09_api_key_rotation.ts          two-person rule for key rotation
|   |- 10_break_glass.ts               SRE emergency access with audit
|   |- 11_ecommerce_fraud.ts           multi-layer fraud + observe-only rollout
|   `- 12_http_mcp.ts                  HTTP and MCP middleware (preview)
|
`- tier3/    multi-service, advanced, AI prompt injection
    |- 13_secure_channel_fleet.ts      SecureChannel, four adversarial tests
    |- 14_invalidation_fanout.ts       cross-replica session fan out
    |- 15_agent_marketplace.ts         vendor orchestrator, kill switch, rotation
    |- 16_healthcare_phi.ts            PHI access with signed audit chain
    |- 17_pq_audit_rotation.ts         7 year archive across key rotations
    |- 18_ai_agent_attestation.ts      AI prompt injection, base pattern
    |- 19_cross_saas_finance_agent.ts  one signed intent across four SaaS
    |- 20_ai_underwriter_evidence.ts   AI loan officer, regulator grade audit
    `- 21_customer_deployed_agent.ts   agent in customer VPC, user held keys
```

## Style

Every file is one self-contained script. No shared helpers, no coloured output, no surprise magic. Every name in `kavach-sdk` that a scenario uses is imported at the top so you can see the API surface at a glance. Copy a script out, edit it, run it.
