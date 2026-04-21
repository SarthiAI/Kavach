"""
Scenario 15: zero-trust agent marketplace with vendor rotation.

The story
---------
A platform coordinates three vendor agents from different
suppliers. Each has its own Kavach keypair. A root keypair signs
a manifest listing the three vendor bundles; the orchestrator
pins that manifest at startup.

    agent-alpha  : billing automation, capped at $250 per call.
    agent-beta   : data enrichment, only for US or CA callers.
    agent-gamma  : maintenance, only during Pacific day shift.

For each vendor call:
    1. Central Kavach gate evaluates the request. If it refuses,
       no network traffic happens.
    2. Orchestrator opens a SecureChannel to the vendor and sends
       a signed request.
    3. Vendor signs its own PermitToken and returns it.
    4. Orchestrator verifies the returned permit against the root
       signed directory.

We also exercise two ops levers that come built in: an
empty-policy kill switch (reload the central gate with ""), and
directory rotation (rebuild the manifest without one vendor;
their permits stop verifying instantly).

Seven cases: A/B/C happy paths per vendor, D/E policy refuses
that never reach the channel, F kill switch across all vendors,
G directory rotation that kicks beta out.

Run this file directly:

    python tier3/15_agent_marketplace.py
"""

import base64
import json
import tempfile
import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

from kavach import (
    ActionContext,
    DirectoryTokenVerifier,
    Gate,
    KavachKeyPair,
    PermitToken,
    PqTokenSigner,
    PublicKeyDirectory,
    SecureChannel,
)


LA = ZoneInfo("America/Los_Angeles")
ALPHA, BETA, GAMMA = "agent-alpha", "agent-beta", "agent-gamma"


def shift_window_now():
    now = datetime.now(tz=LA)
    start = (now - timedelta(minutes=15)).replace(second=0, microsecond=0)
    end = (now + timedelta(minutes=15)).replace(second=0, microsecond=0)
    return f"{start.strftime('%H:%M')}-{end.strftime('%H:%M')} America/Los_Angeles"


def build_policies(shift_window):
    return {
        "policies": [
            {
                "name": "alpha_billing",
                "effect": "permit", "priority": 10,
                "conditions": [
                    {"identity_id": ALPHA},
                    {"action": "agent.run_task"},
                    {"param_max": {"field": "amount_usd", "max": 250.0}},
                ],
            },
            {
                "name": "beta_us_fence",
                "effect": "permit", "priority": 10,
                "conditions": [
                    {"identity_id": BETA},
                    {"action": "agent.run_task"},
                    {"param_in": {"field": "country_code", "values": ["US", "CA"]}},
                ],
            },
            {
                "name": "gamma_day_shift",
                "effect": "permit", "priority": 10,
                "conditions": [
                    {"identity_id": GAMMA},
                    {"action": "agent.run_task"},
                    {"time_window": shift_window},
                ],
            },
        ],
    }


# Vendor signs its own PermitToken to return to the orchestrator.
def vendor_sign_permit(signer, ttl_s=3600):
    now = int(time.time())
    base = PermitToken(
        token_id=str(uuid.uuid4()), evaluation_id=str(uuid.uuid4()),
        issued_at=now, expires_at=now + ttl_s,
        action_name="agent.run_task", signature=b"\x00",
    )
    return PermitToken(
        token_id=base.token_id, evaluation_id=base.evaluation_id,
        issued_at=base.issued_at, expires_at=base.expires_at,
        action_name=base.action_name, signature=bytes(signer.sign(base)),
    )


def pack(permit):
    return json.dumps({
        "token_id": permit.token_id, "evaluation_id": permit.evaluation_id,
        "issued_at": permit.issued_at, "expires_at": permit.expires_at,
        "action_name": permit.action_name,
        "signature_b64": base64.b64encode(bytes(permit.signature)).decode("ascii"),
    }).encode("utf-8")


def unpack(raw):
    obj = json.loads(raw.decode("utf-8"))
    return PermitToken(
        token_id=obj["token_id"], evaluation_id=obj["evaluation_id"],
        issued_at=obj["issued_at"], expires_at=obj["expires_at"],
        action_name=obj["action_name"],
        signature=base64.b64decode(obj["signature_b64"]),
    )


def vendor_round_trip(label, oc_channel, vendor_channel, vendor_signer, verifier, request):
    """Orchestrator -> vendor -> orchestrator, one round trip. Returns
    the verified permit."""
    context_id = f"orch-{label}-{uuid.uuid4()}"
    correlation_id = str(uuid.uuid4())
    sealed_req = oc_channel.send_signed(
        json.dumps(request).encode("utf-8"), context_id, correlation_id)
    vendor_channel.receive_signed(sealed_req, context_id)
    permit = vendor_sign_permit(vendor_signer)
    sealed_permit = vendor_channel.send_signed(
        pack(permit), context_id, correlation_id + ":resp")
    returned = unpack(oc_channel.receive_signed(sealed_permit, context_id))
    verifier.verify(returned, returned.signature)
    print(f"  {label}: round trip ok, returned permit {returned.token_id}")
    return returned


def main():
    print("=" * 70)
    print("Scenario 15: zero-trust agent marketplace with vendor rotation")
    print("=" * 70)
    print()

    # Keypairs.
    root_kp = KavachKeyPair.generate()
    orchestrator_kp = KavachKeyPair.generate()
    alpha_kp, beta_kp, gamma_kp = [KavachKeyPair.generate() for _ in range(3)]
    alpha_bundle = alpha_kp.public_keys()
    beta_bundle = beta_kp.public_keys()
    gamma_bundle = gamma_kp.public_keys()
    orchestrator_bundle = orchestrator_kp.public_keys()
    print(f"  root={root_kp.id}")
    print(f"  orchestrator={orchestrator_kp.id}")
    for name, kp in [("alpha", alpha_kp), ("beta", beta_kp), ("gamma", gamma_kp)]:
        print(f"  {name}={kp.id}")
    print()

    # Root signs a v1 manifest with all three vendors.
    manifest_v1 = bytes(root_kp.build_signed_manifest([alpha_bundle, beta_bundle, gamma_bundle]))
    tmpdir = Path(tempfile.mkdtemp(prefix="kavach-10-"))
    manifest_path = tmpdir / "trusted_vendors.json"
    manifest_path.write_bytes(manifest_v1)
    directory = PublicKeyDirectory.from_signed_file(
        str(manifest_path), root_kp.public_keys().ml_dsa_verifying_key)
    verifier = DirectoryTokenVerifier(directory, hybrid=False)
    print(f"  manifest_v1: {len(manifest_v1)} bytes, directory.length={directory.length}")
    print()

    # SecureChannels per vendor, both sides.
    channels = {
        ALPHA: (SecureChannel(orchestrator_kp, alpha_bundle), SecureChannel(alpha_kp, orchestrator_bundle)),
        BETA: (SecureChannel(orchestrator_kp, beta_bundle), SecureChannel(beta_kp, orchestrator_bundle)),
        GAMMA: (SecureChannel(orchestrator_kp, gamma_bundle), SecureChannel(gamma_kp, orchestrator_bundle)),
    }
    signers = {
        ALPHA: PqTokenSigner.from_keypair_pq_only(alpha_kp),
        BETA: PqTokenSigner.from_keypair_pq_only(beta_kp),
        GAMMA: PqTokenSigner.from_keypair_pq_only(gamma_kp),
    }

    gate = Gate.from_dict(build_policies(shift_window_now()))
    print(f"  gate.evaluator_count={gate.evaluator_count}")
    print()

    def ctx(agent, **params):
        c = ActionContext(
            principal_id=agent, principal_kind="agent",
            action_name="agent.run_task", roles=["agent"],
            params={k: v for k, v in params.items() if isinstance(v, (int, float))},
        )
        for k, v in params.items():
            if isinstance(v, str):
                c.with_param(k, v)
        return c

    results = []
    permits = {}

    # --- Cases A/B/C: three vendor happy paths.
    print("Cases A/B/C: one happy round trip per vendor.")
    call_specs = [
        ("A", ALPHA, ctx(ALPHA, amount_usd=100.0), {"action": "agent.run_task", "amount_usd": 100.0}),
        ("B", BETA, ctx(BETA, country_code="US"), {"action": "agent.run_task", "country_code": "US"}),
        ("C", GAMMA, ctx(GAMMA), {"action": "agent.run_task", "worker_id": "gamma-07"}),
    ]
    for case_id, agent, c, req in call_specs:
        v = gate.evaluate(c)
        print(f"  Case {case_id}: gate.{v.kind} for {agent}")
        results.append((f"Case {case_id}: gate permits {agent}", v.is_permit))
        if v.is_permit:
            oc, ac = channels[agent]
            permits[agent] = vendor_round_trip(
                f"Case {case_id}/{agent}", oc, ac, signers[agent], verifier, req,
            )
            results.append((f"Case {case_id}: permit round trips with correct action_name",
                            permits[agent].action_name == "agent.run_task"))
    print()

    # --- Cases D/E: policy refuses, no channel.
    print("Case D: alpha $500 (over $250 cap).")
    v = gate.evaluate(ctx(ALPHA, amount_usd=500.0))
    print(f"  {v.kind}  evaluator={v.evaluator}  code={v.code}")
    results.append(("Case D: alpha $500 refuses on policy",
                    v.is_refuse and v.evaluator == "policy"))
    print()

    print("Case E: beta country_code=RU (not in US/CA allow list).")
    v = gate.evaluate(ctx(BETA, country_code="RU"))
    print(f"  {v.kind}  evaluator={v.evaluator}  code={v.code}")
    results.append(("Case E: beta RU refuses on policy",
                    v.is_refuse and v.evaluator == "policy"))
    print()

    # --- Case F: kill switch.
    print("Case F: kill switch. Reload gate with empty string.")
    gate.reload("")
    budget_ms = 200.0
    for name, c in [("alpha", ctx(ALPHA, amount_usd=100.0)),
                    ("beta", ctx(BETA, country_code="US")),
                    ("gamma", ctx(GAMMA))]:
        t0 = time.perf_counter()
        v = gate.evaluate(c)
        elapsed = (time.perf_counter() - t0) * 1000.0
        print(f"  {name}: {v.kind}  code={v.code}  elapsed={elapsed:.3f}ms")
        results.append((f"Case F: {name} refuses after empty reload", v.is_refuse))
        results.append((f"Case F: {name} under {int(budget_ms)}ms", elapsed < budget_ms))
    print()

    # --- Case G: directory rotation, beta removed.
    print("Case G: operator removes beta, rebuilds manifest, reloads directory.")
    manifest_v2 = bytes(root_kp.build_signed_manifest([alpha_bundle, gamma_bundle]))
    manifest_path.write_bytes(manifest_v2)
    directory.reload()
    print(f"  directory.length now {directory.length}")
    results.append(("Case G: directory length 2 after rotation", directory.length == 2))

    refused = False
    try:
        verifier.verify(permits[BETA], permits[BETA].signature)
    except ValueError as e:
        refused = "public key not found" in str(e)
        print(f"  beta verify raised: {str(e)[:140]}")
    results.append(("Case G: beta permit refused after rotation", refused))

    for name, key in [("alpha", ALPHA), ("gamma", GAMMA)]:
        ok = True
        try:
            verifier.verify(permits[key], permits[key].signature)
        except Exception:
            ok = False
        print(f"  {name} permit still verifies: {ok}")
        results.append((f"Case G: {name} permit still verifies", ok))
    print()

    # --- Summary.
    print("=" * 70)
    print("Summary")
    print("=" * 70)
    passed = sum(1 for _, ok in results if ok)
    for label, ok in results:
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    print()
    print(f"{passed}/{len(results)} checks passed.")
    print()
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
