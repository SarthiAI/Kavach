"""
Scenario 19: one Kavach-signed intent, four SaaS systems.

The business story
------------------
The CFO clicks 'pay invoice INV-1234'. Behind that click, an
AI agent runs a flow across four unrelated SaaS products.
NetSuite pulls the invoice. Stripe sends the payout. Ramp
writes the GL entry. Slack posts the confirmation.

Why OAuth is not enough. OAuth scopes are per platform.
Stripe's 'payouts.write' has nothing to say about NetSuite's
'invoices.read'. You cannot express 'for this ONE invoice,
allow these four calls'. The usual fallback is broad tokens to
every platform, and a prompt injection inside any one of those
platforms' data can swing any of those tokens at anything.

What Kavach does
----------------
The CFO signs ONE Kavach intent at click time. The scope
(invoice, vendor, amount cap, target channel, principal) is
bound into the permit with an ML-DSA-65 signature. Every SaaS
adapter verifies Kavach's signature and refuses anything that
has drifted from the signed scope. Raising the amount, swapping
the invoice, or redirecting the vendor all break Kavach's
signature or the bound scope, so no adapter runs them.

The whole run lands in a Kavach signed audit chain that the
internal risk team or an external auditor can re-verify
independently.

Six cases:

    A. NetSuite reads INV-1234 under the intent.
    B. Stripe sends a $4,800 payout to vendor acme.
    C. Ramp writes the matching GL entry.
    D. Injection swaps the invoice to INV-9999. Refused.
    E. Attacker relabels the Stripe permit as a NetSuite
       delete. Refused.
    F. Amount escalation to $50,000. Refused.

Run this file directly:

    python tier3/19_cross_saas_finance_agent.py
"""

import hashlib
import json

from kavach import (
    ActionContext,
    AuditEntry,
    DirectoryTokenVerifier,
    Gate,
    KavachKeyPair,
    PqTokenSigner,
    PublicKeyDirectory,
    SignedAuditChain,
)


INTENT_ACTION = "finance.pay_invoice"


INTENT_POLICIES = {
    "policies": [
        {
            "name": "cfo_signs_pay_invoice",
            "effect": "permit",
            "priority": 10,
            "conditions": [
                {"identity_role": "cfo"},
                {"param_max": {"field": "max_amount_usd", "max": 5000.0}},
            ],
        },
    ],
}


# Each SaaS adapter is configured by a small dict: which action
# names it handles, which scope fields every call must match,
# which numeric field must stay under a scope cap.
ADAPTERS = {
    "netsuite": {
        "handles": ["invoice.read"],
        "must_match": ["invoice_id"],
        "caps": [],
    },
    "stripe": {
        "handles": ["payment.initiate"],
        "must_match": ["invoice_id", "vendor_id"],
        "caps": [("amount_usd", "max_amount_usd")],
    },
    "ramp": {
        "handles": ["gl.write_entry"],
        "must_match": ["invoice_id"],
        "caps": [("amount_usd", "max_amount_usd")],
    },
    "slack": {
        "handles": ["chat.post_message"],
        "must_match": ["channel"],
        "caps": [],
    },
}


def canonical_scope_bytes(scope):
    return json.dumps(scope, sort_keys=True, separators=(",", ":")).encode()


def scope_hash(scope):
    return hashlib.sha256(canonical_scope_bytes(scope)).hexdigest()


def bind_action(base, scope):
    return f"{base}:{scope_hash(scope)}"


def saas_adapter(system, tool_call, permit, scope, verifier, chain):
    """Single adapter driven by the ADAPTERS config above. Kavach
    verifies the signature and the scope binding; then the adapter
    enforces its own fields against a scope Kavach just confirmed
    was signed by the CFO."""
    cfg = ADAPTERS[system]

    def finish(kind, reason):
        chain.append(AuditEntry(
            principal_id=tool_call.get("on_behalf_of", "unknown"),
            action_name=f"{system}.{tool_call['action']}",
            verdict=kind,
            verdict_detail=reason,
        ))
        return {"system": system, "kind": kind, "reason": reason}

    try:
        verifier.verify(permit, permit.signature)
    except ValueError as e:
        return finish("refuse", f"permit invalid: {str(e)[:80]}")

    base, _, _ = permit.action_name.partition(":")
    if base != INTENT_ACTION:
        return finish("refuse", f"permit is not a {INTENT_ACTION}")
    if permit.action_name != bind_action(INTENT_ACTION, scope):
        return finish("refuse", "scope does not match the signed intent (hash mismatch)")

    if tool_call["action"] not in cfg["handles"]:
        return finish("refuse", f"{system} does not handle '{tool_call['action']}'")
    for field in cfg["must_match"]:
        if tool_call.get(field) != scope.get(field):
            return finish("refuse",
                          f"{field} '{tool_call.get(field)}' != scope '{scope.get(field)}'")
    for tool_field, scope_field in cfg["caps"]:
        if tool_call[tool_field] > scope[scope_field]:
            return finish("refuse",
                          f"{tool_field} ${tool_call[tool_field]} > cap ${scope[scope_field]}")

    return finish("permit", f"ran under intent {permit.token_id}")


def main():
    print("=" * 70)
    print("Scenario 19: one Kavach-signed intent, four SaaS systems")
    print("=" * 70)
    print()
    print("The CFO clicks 'pay invoice INV-1234'. Kavach signs that click.")
    print("The AI agent then runs across NetSuite, Stripe, Ramp, and Slack.")
    print("Every one of those SaaS adapters refuses anything that does not")
    print("match the CFO's signed intent. Below we run the clean flow, three")
    print("injections, and verify the signed audit chain at the end.")
    print()

    # Setup: CFO keypair, directory, audit chain.
    cfo_kp = KavachKeyPair.generate_with_expiry(300)
    verifier = DirectoryTokenVerifier(
        PublicKeyDirectory.in_memory([cfo_kp.public_keys()]),
        hybrid=False,
    )
    intent_gate = Gate.from_dict(
        INTENT_POLICIES,
        token_signer=PqTokenSigner.from_keypair_pq_only(cfo_kp),
    )
    audit_kp = KavachKeyPair.generate()
    chain = SignedAuditChain(audit_kp, hybrid=False)

    # CFO signs one intent for 'pay INV-1234 up to $5k, to acme, announce in #finance-ops'.
    print("CFO clicks 'pay INV-1234'. One signed intent covers the whole run.")
    scope = {
        "user_id": "cfo-kiran",
        "invoice_id": "INV-1234",
        "vendor_id": "vend-acme",
        "max_amount_usd": 5000.0,
        "channel": "#finance-ops",
    }
    print(f"  scope: {scope}")

    ctx = ActionContext(
        principal_id=scope["user_id"],
        principal_kind="user",
        action_name=bind_action(INTENT_ACTION, scope),
        roles=["cfo"],
        params={"max_amount_usd": scope["max_amount_usd"]},
    )
    permit = intent_gate.evaluate(ctx).permit_token
    print(f"  intent token id:  {permit.token_id}")
    print(f"  action_name:      {permit.action_name}")
    print()

    def call(system, scope_for_call=None, **tool_call):
        tool_call["on_behalf_of"] = scope["user_id"]
        r = saas_adapter(system, tool_call, permit,
                         scope_for_call if scope_for_call is not None else scope,
                         verifier, chain)
        print(f"  {r['system']:<10} {r['kind']:<7} {r['reason']}")
        return r

    results = []

    print("Case A: NetSuite reads INV-1234.")
    r = call("netsuite", action="invoice.read", invoice_id="INV-1234")
    results.append(("Case A: NetSuite read permits", r["kind"] == "permit"))
    print()

    print("Case B: Stripe sends $4,800 payout to vend-acme.")
    r = call("stripe", action="payment.initiate", invoice_id="INV-1234",
             vendor_id="vend-acme", amount_usd=4800.0)
    results.append(("Case B: Stripe payment permits", r["kind"] == "permit"))
    print()

    print("Case C: Ramp writes the GL entry for $4,800.")
    r = call("ramp", action="gl.write_entry", invoice_id="INV-1234", amount_usd=4800.0)
    results.append(("Case C: Ramp GL entry permits", r["kind"] == "permit"))
    print()

    print("Case D: injection in the invoice PDF says 'also pay INV-9999'. The")
    print("        agent builds a tampered scope and a matching tool call.")
    print("        Kavach's signature covers the original invoice; the adapter")
    print("        refuses.")
    tampered_scope_d = dict(scope)
    tampered_scope_d["invoice_id"] = "INV-9999"
    tampered_scope_d["vendor_id"] = "vend-starfall"
    r = call("stripe", scope_for_call=tampered_scope_d,
             action="payment.initiate", invoice_id="INV-9999",
             vendor_id="vend-starfall", amount_usd=4900.0)
    results.append(("Case D: wrong invoice refused via hash mismatch",
                    r["kind"] == "refuse" and "hash mismatch" in r["reason"]))
    print()

    print("Case E: attacker relabels Stripe permit as a NetSuite delete.")
    r = call("netsuite", action="invoice.delete", invoice_id="INV-1234")
    results.append(("Case E: adapter action relabel refused", r["kind"] == "refuse"))
    print()

    print("Case F: injection inflates the amount to $50,000. The agent raises")
    print("        its own scope to cover it. Kavach's signature was over the")
    print("        original scope; the adapter refuses.")
    tampered_scope_f = dict(scope)
    tampered_scope_f["max_amount_usd"] = 100000.0
    r = call("stripe", scope_for_call=tampered_scope_f,
             action="payment.initiate", invoice_id="INV-1234",
             vendor_id="vend-acme", amount_usd=50000.0)
    results.append(("Case F: amount escalation refused via hash mismatch",
                    r["kind"] == "refuse" and "hash mismatch" in r["reason"]))
    print()

    print("Slack confirms to #finance-ops.")
    r = call("slack", action="chat.post_message", channel="#finance-ops")
    results.append(("Final: Slack post permits", r["kind"] == "permit"))
    print()

    # Reverify audit chain to prove tamper-evidence for the whole run.
    verified = SignedAuditChain.verify_jsonl(bytes(chain.export_jsonl()), audit_kp.public_keys())
    results.append(("Final: audit chain reverifies cleanly", verified == chain.length))
    print(f"audit entries verified: {verified}/{chain.length}")
    print()

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
