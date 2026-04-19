# Kavach end-to-end scenario: AI support-agent refunds

A working mini-deployment that exercises Kavach's two capabilities against a realistic business problem.

- **Capability 1, the gate**: the support-agent uses Kavach to decide whether each refund is allowed.
- **Capability 2, the PQ crypto envelope**: the payment service will *only* act on a refund request that carries a valid PQ-signed permit produced by the gate.

## What's in here

```
bootstrap.py           generates keys + signed directory manifest
kavach_policies.toml   the actual policy rules the gate enforces
support_agent.py       FastAPI app on :8001 (agent + Kavach gate)
payment_service.py     FastAPI app on :8002 (permit verifier + "refund processor")
runner.py              orchestrates both services + runs 15 scenarios
```

## Run it

From the `e2e-tests/` directory:

```bash
source ../kavach-py/.venv/bin/activate
python runner.py
```

The venv already has `kavach` installed via `maturin develop --release`. The E2E deps (`fastapi`, `uvicorn`, `httpx`, `rich`) were added when you ran `pip install -r requirements.txt`.

## What you'll see

Both services are started in-process on localhost (ports 8001/8002/8003). Every line on stdout is tagged with the service name so you can read the flow top to bottom:

```
15:00:00.123 | runner  | INFO  | ━━━ Scenario 1: ₹500 refund within policy ━━━
15:00:00.124 | agent   | INFO  | tool call: caller=agent-bot action=issue_refund params={'amount': 500.0}
15:00:00.125 | agent   | INFO  | gate verdict: PERMIT
15:00:00.125 | agent   | INFO  | signed permit issued: key_id=a4f… alg=hybrid expires_at=…
15:00:00.126 | agent   | INFO  | appended audit entry #1 (permit)
15:00:00.126 | runner  | INFO  | ✓ PASS scenario 1: small refund permitted, status=200 verdict=permit
```

At the end of the run a rich-formatted table summarises pass/fail for every scenario.

## The 15 scenarios

### Capability 1: the gate

| # | What | Why it matters |
|---|------|---------------|
| 1 | ₹500 refund | Baseline: a normal refund permits |
| 2 | ₹6000 refund | Policy `param_max = 5000` refuses |
| 3 | 51st refund in 24h | `rate_limit = 50/24h` refuses once the window fills |
| 4 | Reload policy to allow ₹100000, attempt ₹60000 | In-code `Invariant` hard-caps at ₹50000; policies can't override it |
| 5 | Agent session origin=IN, current=US | Geo drift triggers `Invalidate` (not just Refuse) |
| 6 | Action `delete_order` | No policy permits it, so default-deny |
| 7 | Policy `time_window` excluding now | Time-window condition refuses outside the allowed hours |

### Capability 2: the crypto envelope

| # | What | Why it matters |
|---|------|---------------|
| 8 | POST /refund without a permit | Payment service rejects; you can't move money without signed proof |
| 9 | POST with random-bytes "signature" | `DirectoryTokenVerifier` rejects at verify |
| 10 | Permit signed by a key **not** in the directory | Directory miss rejected by `key_id` lookup |
| 11 | Permit with `expires_at` in the past | Payment service's explicit TTL check rejects replay |
| 12 | Permit bound to `read_order`, replayed on `/refund` | Signature covers `action_name`, so reuse across actions fails |
| 13 | PQ-only payment instance receives a hybrid permit | Algorithm-downgrade guard fires (strict both directions) |
| 14 | Tamper one byte in the exported audit JSONL | `verify_jsonl` detects the break |
| 15 | Claim a hybrid chain is PQ-only (`hybrid=False`) | Mode-assertion rejected **before** any crypto runs, which prevents silent downgrade |

## What the audit chain looks like

After the run, `state/audit.jsonl` contains one JSON object per line: the signed audit of every decision the gate made during the run. You can open it in any text editor to see what the library persists. The scenario 14/15 assertions show how a later auditor would re-verify that file cryptographically.

## Known scope notes

- **The "amount" field is not bound to the permit signature.** `PermitToken` covers `token_id + evaluation_id + issued_at + expires_at + action_name`. Binding the full action params (including `amount`) to the signed permit is the job of `SecureChannel::send_signed` plus the integrator's own payload schema; that is one layer up from the permit token. We test action-name binding here (scenario 12) because that's what the token itself enforces.
- **Geo drift uses countries + lat/lon**, not IP ranges. IP-change drift is a different detector that requires persistent session state across evaluate calls; the Python SDK deliberately builds a fresh `SessionState` on every call, so this demo models drift as "origin country not equal to current country" (same concept, SDK-supported).

## Cleaning up

```bash
rm -rf state/   # removes keys, directory manifest, audit JSONL
```

Nothing else to tear down. The services only exist while `runner.py` is running.
