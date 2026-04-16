"""FastAPI payment-service — verifies signed permits, then "processes" refunds.

Runs on 127.0.0.1:8002. One endpoint:

    POST /payments/refund

The important bit: this service has **no trust relationship with the agent**
other than the signed directory. Anyone POSTing here has to carry a
PermitToken signed by a key the directory knows about. No token, forged
token, expired token, wrong-algorithm token → 401.

Without this step, any compromised caller could POST `{order_id, amount}`
directly and the payment would go through. Kavach's post-quantum crypto
envelope is what closes that gap.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException
from kavach import DirectoryTokenVerifier, PermitToken, PublicKeyDirectory
from pydantic import BaseModel

log = logging.getLogger("payment")


class PermitIn(BaseModel):
    """The caller reconstructs a PermitToken here from the bytes they got
    from the agent. This field-level shape is exactly what the agent's
    /agent/tool response carries."""

    token_id: str
    evaluation_id: str
    issued_at: int
    expires_at: int
    action_name: str
    key_id: str


class RefundRequest(BaseModel):
    order_id: str
    amount: float
    permit: PermitIn | None = None
    signature_hex: str | None = None


class RefundResponse(BaseModel):
    ok: bool
    order_id: str
    amount: float
    detail: str


def build_app(directory_path: Path, root_vk_path: Path, hybrid: bool = True) -> FastAPI:
    """Load the signed directory + build the verifier. One-time setup —
    everything after is per-request."""
    root_vk = root_vk_path.read_bytes()
    directory = PublicKeyDirectory.from_signed_file(str(directory_path), root_vk)
    log.info(
        "signed directory loaded: path=%s entries=%d",
        directory_path,
        directory.length,
    )

    verifier = DirectoryTokenVerifier(directory, hybrid=hybrid)
    log.info("token verifier: hybrid=%s", hybrid)

    # Mutable slot so /admin/reload_directory can swap in a rebuilt verifier.
    # We can't reassign a local inside the handler closure; a 1-element list
    # is the idiomatic Python workaround that stays clear.
    state = {"directory": directory, "verifier": verifier}

    app = FastAPI(title="Kavach Payment Service", version="0.1.0")

    @app.post("/payments/refund", response_model=RefundResponse)
    async def process_refund(req: RefundRequest) -> RefundResponse:
        log.info(
            "refund request: order_id=%s amount=%.2f has_permit=%s",
            req.order_id,
            req.amount,
            req.permit is not None,
        )

        # (1) No permit → 401. This is the ground-level policy: we don't
        # move money without proof the gate said OK.
        if req.permit is None or req.signature_hex is None:
            log.warning("refund rejected: missing permit / signature")
            raise HTTPException(status_code=401, detail="permit token required")

        # (2) Token expiry. Signature verification alone won't catch this —
        # an attacker can replay a legitimately-signed token from last week.
        # Every downstream service *must* check expires_at itself.
        now = int(time.time())
        if req.permit.expires_at < now:
            log.warning(
                "refund rejected: permit expired (%ds ago)",
                now - req.permit.expires_at,
            )
            raise HTTPException(status_code=401, detail="permit expired")

        # (3) Action binding. The signature covers `action_name` among
        # other fields — so a token for `read_order` can't be replayed on
        # a `issue_refund` endpoint. Belt-and-braces check before the
        # crypto verify confirms it.
        if req.permit.action_name != "issue_refund":
            log.warning(
                "refund rejected: permit bound to wrong action '%s'",
                req.permit.action_name,
            )
            raise HTTPException(status_code=401, detail="permit not for this action")

        # (4) Crypto verify via the directory. If the signing key isn't in
        # the directory, the signature is forged, or the envelope algorithm
        # mismatches our verifier mode, this raises — we fail closed.
        token = PermitToken(
            token_id=req.permit.token_id,
            evaluation_id=req.permit.evaluation_id,
            issued_at=req.permit.issued_at,
            expires_at=req.permit.expires_at,
            action_name=req.permit.action_name,
        )
        try:
            signature = bytes.fromhex(req.signature_hex)
            state["verifier"].verify(token, signature)
        except Exception as err:
            log.warning("refund rejected: signature verify failed: %s", err)
            raise HTTPException(status_code=401, detail=f"invalid permit: {err}")

        log.info("✓ permit verified (key_id=%s)", req.permit.key_id)

        # (5) Process the refund. In a real service this is where Stripe
        # or whoever gets called — we just log and return.
        log.info("✓ refund processed: %.2f → order %s", req.amount, req.order_id)
        return RefundResponse(
            ok=True,
            order_id=req.order_id,
            amount=req.amount,
            detail=f"refund of {req.amount} credited to {req.order_id}",
        )

    @app.post("/payments/admin/reload_directory")
    async def reload_directory() -> dict:
        """Re-read the signed directory file from disk and rebuild the
        verifier. Use this after the ops team rotates / revokes keys and
        writes a new directory.json. Old in-flight verifications already
        in progress finish against the previous verifier — new calls pick
        up the fresh one immediately.
        """
        try:
            new_directory = PublicKeyDirectory.from_signed_file(
                str(directory_path), root_vk
            )
        except Exception as err:
            log.error("directory reload failed: %s", err)
            raise HTTPException(status_code=500, detail=f"reload failed: {err}")
        new_verifier = DirectoryTokenVerifier(new_directory, hybrid=hybrid)
        state["directory"] = new_directory
        state["verifier"] = new_verifier
        log.info(
            "✓ directory reloaded: entries=%d (was %d)",
            new_directory.length,
            directory.length,
        )
        return {"ok": True, "entries": new_directory.length}

    return app
