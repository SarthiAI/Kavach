"""FastAPI support-agent service, hosts the Kavach gate + signs permits.

Runs on 127.0.0.1:8001. Exposes two endpoints:

    POST /agent/tool        , simulates the LLM calling a tool; gates it
    POST /agent/reload      , hot-reloads the policy TOML (test hook)

The "LLM" is simulated by the test runner passing action_name + params
directly. Every real agent integration looks like this internally, an LLM
decides to call `tool_name(args)`, the tool handler runs Kavach first.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from fastapi import FastAPI, HTTPException
from kavach import (
    ActionContext,
    AuditEntry,
    Gate,
    GeoLocation,
    KavachKeyPair,
    PermitToken,
    PqTokenSigner,
    SignedAuditChain,
)
from pydantic import BaseModel

# A module-level logger gives the runner's single stream a clear "agent" tag.
log = logging.getLogger("agent")


class ToolCall(BaseModel):
    """Shape of the payload the runner (or an LLM) posts to /agent/tool."""

    caller_id: str
    action_name: str
    # Params are untyped, body-dependent invariants (e.g. `amount`) inspect
    # these. Using dict[str, float] keeps it obvious.
    params: dict[str, float] = {}
    # Principal identity, defaults to an AI agent, but humans / services /
    # schedulers hit the same gate with different kinds + roles.
    principal_kind: str = "agent"
    roles: list[str] = []
    current_ip: str | None = None
    origin_ip: str | None = None
    origin_country: str | None = None
    current_country: str | None = None


class ToolResponse(BaseModel):
    """Shape of a successful tool invocation."""

    verdict: str
    permit_token: dict | None = None
    signature_hex: str | None = None
    detail: str | None = None


@dataclass
class AgentState:
    """Shared state built at startup and read on every request."""

    gate: Gate
    signer: PqTokenSigner
    key_id: str
    audit_chain: SignedAuditChain
    audit_path: Path


def build_app(
    keypair: KavachKeyPair,
    policy_path: Path,
    audit_path: Path,
) -> FastAPI:
    """Wire the FastAPI app.

    Invariants are enforced in code (not TOML): hard refund cap of ₹50k
    regardless of what the policy set says. This is the "no policy change
    can override me" guarantee, the same kind of thing you'd hard-wire
    for KYC limits, regulatory caps, etc.
    """
    signer = PqTokenSigner.from_keypair_hybrid(keypair)
    log.info("token signer: hybrid (ML-DSA-65 + Ed25519), key_id=%s", signer.key_id)

    # The gate. Policies are loaded from TOML; invariants live in code.
    # geo_drift_max_km=500 switches the GeoLocationDrift detector to tolerant
    # mode, a mid-session jump between cities farther than 500 km apart is
    # treated as a Violation (i.e. Invalidate the session).
    gate = Gate.from_file(
        str(policy_path),
        invariants=[("hard_refund_cap", "amount", 50_000.0)],
        token_signer=signer,
        geo_drift_max_km=500.0,
    )
    log.info("gate built: %d evaluators (geo drift threshold = 500 km)", gate.evaluator_count)

    # Audit chain lives on disk so the test runner can tamper with it
    # between scenarios and re-verify.
    audit_chain = SignedAuditChain(keypair, hybrid=True)
    state = AgentState(
        gate=gate,
        signer=signer,
        key_id=signer.key_id,
        audit_chain=audit_chain,
        audit_path=audit_path,
    )

    app = FastAPI(title="Kavach Support Agent", version="0.1.0")

    @app.post("/agent/tool", response_model=ToolResponse)
    async def invoke_tool(call: ToolCall) -> ToolResponse:
        """The hot path: every tool call goes through Kavach first."""
        log.info(
            "tool call: caller=%s action=%s params=%s",
            call.caller_id,
            call.action_name,
            call.params,
        )

        ctx = _build_context(call)
        verdict = state.gate.evaluate(ctx)
        log.info(
            "gate verdict: %s%s",
            _verdict_label(verdict),
            f" ({verdict.evaluator}: {verdict.reason})" if not verdict.is_permit else "",
        )

        # Append to the signed audit chain regardless of verdict, that's
        # the whole point of audit. Even refusals are durable.
        _append_audit(state, call, verdict)

        if verdict.is_permit:
            token = verdict.permit_token
            assert token is not None, "permit must carry a token (signer was wired)"
            log.info(
                "signed permit issued: key_id=%s alg=hybrid expires_at=%d",
                state.key_id,
                token.expires_at,
            )
            return ToolResponse(
                verdict="permit",
                permit_token={
                    "token_id": token.token_id,
                    "evaluation_id": token.evaluation_id,
                    "issued_at": token.issued_at,
                    "expires_at": token.expires_at,
                    "action_name": token.action_name,
                    "key_id": state.key_id,
                },
                signature_hex=token.signature.hex() if token.signature else None,
            )

        if verdict.is_invalidate:
            raise HTTPException(status_code=401, detail=f"invalidated: {verdict.reason}")

        # Refuse, the caller gets enough info to understand what broke.
        raise HTTPException(
            status_code=403,
            detail=f"[{verdict.code}] {verdict.evaluator}: {verdict.reason}",
        )

    @app.post("/agent/reload")
    async def reload_policy(body: dict) -> dict:
        """Hot-reload the policy TOML. Used in test case 4 to prove the
        invariant refuses a refund even when policy says otherwise."""
        new_toml = body.get("policy_toml", "")
        try:
            state.gate.reload(new_toml)
        except Exception as err:
            log.warning("policy reload failed: %s", err)
            raise HTTPException(status_code=400, detail=str(err))
        log.info("policy reloaded (%d bytes)", len(new_toml))
        return {"ok": True}

    @app.post("/agent/audit/export")
    async def export_audit() -> dict:
        """Dump the current audit chain to the configured JSONL path and
        return the path + entry count. Used by the runner to verify the
        chain later."""
        data = state.audit_chain.export_jsonl()
        state.audit_path.write_bytes(data)
        log.info(
            "audit chain exported: %d entries → %s (%d bytes)",
            state.audit_chain.length,
            state.audit_path,
            len(data),
        )
        return {
            "path": str(state.audit_path),
            "length": state.audit_chain.length,
            "bytes": len(data),
        }

    return app


def _build_context(call: ToolCall) -> ActionContext:
    """Translate the HTTP body into a Kavach ActionContext.

    `origin_country` + `current_country` model geo drift: when they differ
    (and both carry lat/lon) the GeoLocationDrift detector compares them via
    Haversine and either Warns or Invalidates depending on the gate's
    `geo_drift_max_km` config. The detector only enters the geo-distance
    branch when `origin_ip != current_ip`, so we pass both explicitly.
    """
    origin_geo = _geo(call.origin_country) if call.origin_country else None
    current_geo = _geo(call.current_country) if call.current_country else None

    return ActionContext(
        principal_id=call.caller_id,
        principal_kind=call.principal_kind,
        action_name=call.action_name,
        roles=call.roles,
        params=call.params,
        ip=call.current_ip,
        origin_ip=call.origin_ip,
        origin_geo=origin_geo,
        current_geo=current_geo,
    )


# A tiny gazetteer, enough to drive the geo-drift test without pulling
# in a real GeoIP database. Matches the cities Kavach's P2.7 smoke test
# uses so the distances the library computes are predictable.
_CITIES = {
    "IN": GeoLocation("IN", city="Bangalore", latitude=12.9716, longitude=77.5946),
    "US": GeoLocation("US", city="New York", latitude=40.7128, longitude=-74.0060),
    "SG": GeoLocation("SG", city="Singapore", latitude=1.3521, longitude=103.8198),
}


def _geo(country: str) -> GeoLocation | None:
    return _CITIES.get(country.upper())


def _verdict_label(v) -> str:
    if v.is_permit:
        return "PERMIT"
    if v.is_refuse:
        return "REFUSE"
    if v.is_invalidate:
        return "INVALIDATE"
    return "UNKNOWN"


def _append_audit(state: AgentState, call: ToolCall, verdict) -> None:
    entry = AuditEntry(
        principal_id=call.caller_id,
        action_name=call.action_name,
        verdict=_verdict_label(verdict).lower(),
        verdict_detail=(
            verdict.reason if not verdict.is_permit else "permit within policy"
        ),
    )
    state.audit_chain.append(entry)
    log.info(
        "appended audit entry #%d (%s)",
        state.audit_chain.length,
        _verdict_label(verdict).lower(),
    )
