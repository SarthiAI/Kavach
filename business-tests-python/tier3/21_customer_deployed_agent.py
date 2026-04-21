"""
Scenario 21: AI agent in the customer's VPC, user-held keys, Kavach in the middle.

The business story
------------------
A B2B SaaS vendor ships an AI agent as a container the customer
runs in their own VPC. Law firm, insurer, healthcare group, all
of them cannot hand their data to the vendor cloud (data
residency, HIPAA, GDPR, contracts). The agent still calls the
vendor's central API to log activity, fetch model updates, and
reconcile billing.

Two facts change the threat model:

    The agent runs ON THE CUSTOMER'S SIDE. The vendor cannot
    assume the host is clean. Customer admins have root. A
    compromise inside the customer VPC is plausible.

    The only actor the vendor trusts for that user's data is
    the user at their laptop. Not the VPC. Not the container
    image. Not the 3am SSH session.

Why OAuth breaks here. The typical answer is a long-lived
OAuth token in the container. That tells the vendor 'this
container is allowed' but not 'the user clicked this right
now'. A compromised VPC (or a prompt injection from a document
the agent reads) can drive the agent to exfiltrate, modify
records, or call the vendor API in ways the user never
intended.

What Kavach does
----------------
The signing keypair stays on the user's device (laptop, phone,
hardware key). The container holds only a verifying bundle and
the short-lived permits the user has signed in the last few
seconds. Every user click produces a fresh Kavach permit with
the scope bound in via an ML-DSA-65 signature. The vendor API
verifies Kavach's signature and refuses anything outside the
signed scope.

The vendor gets three concrete wins:

    A VPC compromise harvests only the permits in memory at
    that moment, each seconds from expiring. No long-lived
    bearer material was ever in the container.

    A prompt injection cannot widen scope, any mutation breaks
    Kavach's signature binding.

    Kavach verifies offline. No round trip to an auth service.
    Permit plus pinned bundle is enough.

Short timescales in this demo
-----------------------------
The signing keypair in this scenario expires in 2 seconds to
keep the script fast. In production this tracks the user's
active session, typically seconds to minutes.

Five cases:

    A. User signs an intent on the laptop, agent carries
       (permit, scope) to the vendor API, vendor permits.
    B. VPC attacker signs a rogue permit with their own
       keypair. Vendor's directory does not trust them.
       Refused.
    C. Prompt injection widens allowed_actions to include
       send_email. Refused.
    D. Past TTL, any captured permit stops working.
    E. User re-signs. Fresh bundle pinned, next action runs.

Run this file directly:

    python tier3/21_customer_deployed_agent.py
"""

import hashlib
import json
import time

from kavach import (
    ActionContext,
    DirectoryTokenVerifier,
    Gate,
    KavachKeyPair,
    PqTokenSigner,
    PublicKeyDirectory,
)


USER_TTL_SECONDS = 2
INTENT_ACTION = "agent.intent"


# ---------------------------------------------------------------------
# The user's device (laptop, phone, hardware token) holds the signing
# keypair. The VPC agent container never sees it. Every click signs a
# fresh short lived permit with the scope hash bound into action_name.
# ---------------------------------------------------------------------

USER_INTENT_POLICIES = {
    "policies": [
        {
            "name": "user_signs_agent_intent",
            "description": "Customer user signs a short lived agent action intent",
            "effect": "permit",
            "priority": 10,
            "conditions": [
                {"identity_role": "customer_user"},
                {"param_max": {"field": "max_tokens", "max": 4000.0}},
            ],
        },
    ],
}


def canonical_scope_bytes(scope):
    return json.dumps(scope, sort_keys=True, separators=(",", ":")).encode()


def scope_hash(scope):
    return hashlib.sha256(canonical_scope_bytes(scope)).hexdigest()


def bind_action(base, scope):
    return f"{base}:{scope_hash(scope)}"


class UserDevice:
    """Stands in for the user's laptop / phone / hardware key.

    Holds the signing keypair. Signs intent permits in response to
    explicit user clicks. The rest of the customer VPC never has
    direct access to this object's inner keypair, only the permits
    it emits.
    """

    def __init__(self, user_id: str, ttl_seconds: int):
        self.user_id = user_id
        self._keypair = KavachKeyPair.generate_with_expiry(ttl_seconds)
        self._signer = PqTokenSigner.from_keypair_pq_only(self._keypair)
        self._gate = Gate.from_dict(USER_INTENT_POLICIES, token_signer=self._signer)

    def bundle(self):
        return self._keypair.public_keys()

    def key_id(self):
        return self._keypair.id

    def sign_intent(self, action_scope):
        """User clicks a button; device canonicalises the scope, binds
        its hash into the action_name, and signs."""
        scope = {
            "user_id": self.user_id,
            "resource": action_scope.get("resource", ""),
            "allowed_actions": list(action_scope.get("allowed_actions", [])),
            "max_tokens": int(action_scope.get("max_tokens", 4000)),
        }
        ctx = ActionContext(
            principal_id=self.user_id,
            principal_kind="user",
            action_name=bind_action(INTENT_ACTION, scope),
            roles=["customer_user"],
            params={"max_tokens": float(scope["max_tokens"])},
        )
        verdict = self._gate.evaluate(ctx)
        return verdict.permit_token, scope


def vendor_api_call(*, tool_call, permit, scope, verifier):
    """The SaaS vendor's central API. Kavach verifies the signature and
    the scope binding; then this function enforces tool-call fields
    against a scope Kavach just confirmed the user signed."""

    try:
        verifier.verify(permit, permit.signature)
    except ValueError as e:
        return {"kind": "refuse",
                "reason": "permit expired or tampered",
                "error": str(e)[:180]}

    base, _, _ = permit.action_name.partition(":")
    if base != INTENT_ACTION:
        return {"kind": "refuse",
                "reason": "permit is not an agent intent",
                "got_action": base}
    if permit.action_name != bind_action(INTENT_ACTION, scope):
        return {"kind": "refuse",
                "reason": "scope does not match the signed intent (hash mismatch)"}

    if tool_call.get("on_behalf_of") != scope["user_id"]:
        return {"kind": "refuse",
                "reason": "tool call principal does not match the scope principal"}
    if tool_call["action"] not in scope["allowed_actions"]:
        return {"kind": "refuse",
                "reason": "action not in user's signed scope",
                "requested": tool_call["action"],
                "allowed": scope["allowed_actions"]}
    if tool_call.get("resource") != scope.get("resource"):
        return {"kind": "refuse",
                "reason": "resource not in user's signed scope",
                "requested_resource": tool_call.get("resource"),
                "allowed_resource": scope.get("resource")}

    return {"kind": "permit",
            "reason": "ran under user signed intent",
            "permit_token_id": permit.token_id}


def main():
    print("=" * 70)
    print("Scenario 21: agent in the customer's VPC, user-held keys, Kavach in between")
    print("=" * 70)
    print()
    print("The user's laptop holds the signing key. The VPC agent container")
    print("holds no long-lived credentials, just whatever permits the user")
    print("has signed in the last few seconds. The vendor API verifies every")
    print("call against Kavach's signature and refuses anything outside the")
    print("user's signed scope. Below we walk the happy path, a VPC attacker,")
    print("a prompt injection, the TTL expiring, and the user re-signing.")
    print()

    results = []

    # -----------------------------------------------------------------
    # On the user's device.
    # -----------------------------------------------------------------
    print(f"User's device generates a signing keypair (TTL = {USER_TTL_SECONDS}s).")
    print("(2 seconds keeps this script fast; in production this tracks the")
    print(" user's active session, typically seconds to minutes.)")
    device = UserDevice("user-ava", USER_TTL_SECONDS)
    user_bundle = device.bundle()
    print(f"  user.key_id: {device.key_id()}")
    print()

    # -----------------------------------------------------------------
    # On the vendor side: pinned directory + verifier.
    # -----------------------------------------------------------------
    print("Vendor API bootstraps a directory pinned to the user's bundle.")
    directory = PublicKeyDirectory.in_memory([user_bundle])
    verifier = DirectoryTokenVerifier(directory, hybrid=False)
    print(f"  directory.length: {directory.length}")
    print()

    # -----------------------------------------------------------------
    # Case A: user clicks, permit flows through VPC agent, vendor runs.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case A: user clicks 'summarise contract contract-2026-042'.")
    print("-" * 70)
    print("User's device signs an intent, with the scope hash bound into")
    print("the permit's action_name. The permit plus the scope bytes travel")
    print("through the VPC agent container to the vendor API. Vendor")
    print("verifies the signature, recomputes the hash, and runs the action.")
    print("The container never saw the signing key.")
    print()
    action_scope = {
        "resource": "contract-2026-042",
        "allowed_actions": ["summarise", "draft_reply"],
        "max_tokens": 4000,
    }
    permit, scope = device.sign_intent(action_scope)
    print(f"  permit token_id:   {permit.token_id}")
    print(f"  action_name:       {permit.action_name}")
    print(f"  issued/expires at: {permit.issued_at} / {permit.expires_at}")

    r = vendor_api_call(
        tool_call={"action": "summarise", "resource": "contract-2026-042",
                   "on_behalf_of": "user-ava"},
        permit=permit, scope=scope, verifier=verifier,
    )
    print(f"  vendor API: {r['kind']} ({r['reason']})")
    print()
    results.append(("Case A: in TTL summarise permits", r["kind"] == "permit"))

    # -----------------------------------------------------------------
    # Case B: VPC compromise tries to mint its own permit.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case B: attacker inside the VPC tries to mint a new permit.")
    print("-" * 70)
    print("The attacker is inside the customer's VPC and has root on the")
    print("agent container. They generate their own Kavach keypair and")
    print("sign a fresh permit locally, impersonating user-ava. They")
    print("present this rogue permit to the vendor API. The vendor")
    print("resolves the permit's embedded key_id against its pinned")
    print("directory and finds nothing (the rogue key is not trusted).")
    print()
    rogue_kp = KavachKeyPair.generate()
    rogue_signer = PqTokenSigner.from_keypair_pq_only(rogue_kp)
    rogue_gate = Gate.from_dict(USER_INTENT_POLICIES, token_signer=rogue_signer)
    rogue_scope = {
        "user_id": "user-ava",
        "resource": "contract-2026-042",
        "allowed_actions": ["summarise", "draft_reply"],
        "max_tokens": 4000,
    }
    rogue_ctx = ActionContext(
        principal_id="user-ava",
        principal_kind="user",
        action_name=bind_action(INTENT_ACTION, rogue_scope),
        roles=["customer_user"],
        params={"max_tokens": 4000.0},
    )
    rogue_permit = rogue_gate.evaluate(rogue_ctx).permit_token
    print(f"  rogue key_id:          {rogue_kp.id}")
    print(f"  rogue permit.token_id: {rogue_permit.token_id}")

    r = vendor_api_call(
        tool_call={"action": "summarise", "resource": "contract-2026-042",
                   "on_behalf_of": "user-ava"},
        permit=rogue_permit, scope=rogue_scope, verifier=verifier,
    )
    print(f"  vendor API: {r['kind']} ({r['reason']})")
    print(f"  error:      {r.get('error', '')[:180]}")
    print()
    results.append(("Case B: rogue keypair from VPC refused", r["kind"] == "refuse"))

    # -----------------------------------------------------------------
    # Case C: prompt injection tries to widen the scope.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case C: prompt injection widens the in-memory scope.")
    print("-" * 70)
    print("User signed a fresh permit for {summarise, draft_reply} on")
    print("contract-2026-042. An injection in the contract body tells")
    print("the agent to email a third party. The agent mutates its own")
    print("scope.allowed_actions to include 'send_email' and emits the")
    print("tool call. The vendor API recomputes the scope hash and finds")
    print("it no longer matches the one bound into the permit; refuse.")
    print()
    fresh_permit, fresh_scope = device.sign_intent(action_scope)
    tampered_scope = dict(fresh_scope)
    tampered_scope["allowed_actions"] = list(fresh_scope["allowed_actions"]) + ["send_email"]
    r = vendor_api_call(
        tool_call={"action": "send_email", "resource": "contract-2026-042",
                   "on_behalf_of": "user-ava"},
        permit=fresh_permit, scope=tampered_scope, verifier=verifier,
    )
    print(f"  vendor API: {r['kind']} ({r['reason']})")
    print()
    ok = r["kind"] == "refuse" and "hash mismatch" in r["reason"]
    results.append(("Case C: scope widening refused via hash mismatch", ok))

    # -----------------------------------------------------------------
    # Case D: past the TTL, reuse attempt refused.
    # -----------------------------------------------------------------
    print("-" * 70)
    print(f"Case D: wait {USER_TTL_SECONDS + 1}s past TTL, try any permit.")
    print("-" * 70)
    print("A VPC admin with transient access copies the permit out of")
    print("the container's memory. Nothing to do with it; the signing")
    print("bundle has expired. Vendor API refuses on expiry. No long")
    print("lived bearer material was available to capture in the first")
    print("place. This is why the short TTL matters: captured state")
    print("ages out before it can be reused.")
    print()
    print(f"  sleeping {USER_TTL_SECONDS + 1}s...")
    time.sleep(USER_TTL_SECONDS + 1)
    r = vendor_api_call(
        tool_call={"action": "summarise", "resource": "contract-2026-042",
                   "on_behalf_of": "user-ava"},
        permit=permit, scope=scope, verifier=verifier,
    )
    print(f"  vendor API: {r['kind']} ({r['reason']})")
    print()
    ok = r["kind"] == "refuse" and "expired" in r.get("error", "").lower()
    results.append(("Case D: past TTL captured permit refused", ok))

    # -----------------------------------------------------------------
    # Case E: user re-signs; fresh permit goes through.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case E: after TTL expiry, user re-signs and the vendor accepts.")
    print("-" * 70)
    print("Case D showed that an expired permit stops working. Case E")
    print("completes the picture: the user clicks again, the device mints")
    print("a fresh keypair with a new TTL, the vendor's directory pins")
    print("the new bundle, and the next action goes through. There is no")
    print("offline window where 'the old key still works and the new one")
    print("does not'. Each action is anchored to a click that was")
    print("actually made.")
    print()
    fresh_device = UserDevice("user-ava", USER_TTL_SECONDS)
    fresh_directory = PublicKeyDirectory.in_memory([fresh_device.bundle()])
    fresh_verifier = DirectoryTokenVerifier(fresh_directory, hybrid=False)
    fresh_permit_e, fresh_scope_e = fresh_device.sign_intent(action_scope)
    r = vendor_api_call(
        tool_call={"action": "summarise", "resource": "contract-2026-042",
                   "on_behalf_of": "user-ava"},
        permit=fresh_permit_e, scope=fresh_scope_e, verifier=fresh_verifier,
    )
    print(f"  new device key_id: {fresh_device.key_id()}")
    print(f"  vendor API:        {r['kind']} ({r['reason']})")
    print()
    results.append(("Case E: re-signed permit after expiry permits",
                    r["kind"] == "permit"))

    # -----------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------
    print("=" * 70)
    print("Summary")
    print("=" * 70)
    passed = sum(1 for _, ok in results if ok)
    for label, ok in results:
        mark = "PASS" if ok else "FAIL"
        print(f"  [{mark}] {label}")
    print()
    print(f"{passed}/{len(results)} checks passed.")
    print()

    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
