"""End-to-end runner for the Kavach refund scenario.

Spins both services up as in-process uvicorn servers, runs 15 scenarios,
reports a pass/fail table at the end. Every step, agent, payment, audit,
logs to the same stream with a per-service tag so you can read the flow
top to bottom.

Run:

    python runner.py
"""

from __future__ import annotations

import asyncio
import logging
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import uvicorn
from kavach import (
    DirectoryTokenVerifier,
    KavachKeyPair,
    PermitToken,
    PqTokenSigner,
    PublicKeyDirectory,
    SignedAuditChain,
)
from rich.console import Console
from rich.table import Table

from bootstrap import setup
import payment_service
import support_agent

# ─── Logging setup ───────────────────────────────────────────────────

FORMAT = "%(asctime)s.%(msecs)03d | %(name)-7s | %(levelname)-5s | %(message)s"
logging.basicConfig(
    level=logging.INFO,
    format=FORMAT,
    datefmt="%H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)
# Uvicorn is noisy by default, tone its access logs down since we do our
# own per-request logging inside the services.
for noisy in ("uvicorn", "uvicorn.access", "uvicorn.error"):
    logging.getLogger(noisy).setLevel(logging.WARNING)

log = logging.getLogger("runner")
console = Console()

# ─── Service config ──────────────────────────────────────────────────

AGENT_HOST, AGENT_PORT = "127.0.0.1", 8001
PAY_HOST, PAY_PORT = "127.0.0.1", 8002
PAY_PQ_ONLY_PORT = 8003  # Second payment instance, PQ-only verifier, for test 13

STATE_DIR = Path(__file__).parent / "state"
POLICY_PATH = Path(__file__).parent / "kavach_policies.toml"
AUDIT_PATH = STATE_DIR / "audit.jsonl"

# ─── Scenario infrastructure ─────────────────────────────────────────


@dataclass
class ScenarioResult:
    num: int
    name: str
    passed: bool
    detail: str
    exercises: str  # "gate" or "crypto"


@dataclass
class RunCtx:
    """Resources shared across scenarios."""

    agent_kp: KavachKeyPair
    root_kp: KavachKeyPair  # Used to re-sign directory if we need to evolve it
    results: list[ScenarioResult] = field(default_factory=list)


async def start_server(app, host: str, port: int, label: str) -> uvicorn.Server:
    """Spin uvicorn on a background task. Waits until the socket is up."""
    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    server = uvicorn.Server(config)
    asyncio.create_task(server.serve())
    # Poll until the server binds.
    for _ in range(200):  # up to 10s
        if server.started:
            log.info("service up: %s → http://%s:%d", label, host, port)
            return server
        await asyncio.sleep(0.05)
    raise RuntimeError(f"server '{label}' failed to start")


async def call_agent(
    client: httpx.AsyncClient,
    caller_id: str = "agent-bot",
    action_name: str = "issue_refund",
    params: dict[str, float] | None = None,
    origin_country: str | None = None,
    current_country: str | None = None,
    origin_ip: str | None = None,
    current_ip: str | None = None,
) -> httpx.Response:
    return await client.post(
        f"http://{AGENT_HOST}:{AGENT_PORT}/agent/tool",
        json={
            "caller_id": caller_id,
            "action_name": action_name,
            "params": params or {},
            "origin_country": origin_country,
            "current_country": current_country,
            "origin_ip": origin_ip,
            "current_ip": current_ip,
        },
    )


async def post_refund(
    client: httpx.AsyncClient,
    port: int,
    order_id: str,
    amount: float,
    permit: dict | None = None,
    signature_hex: str | None = None,
) -> httpx.Response:
    return await client.post(
        f"http://{PAY_HOST}:{port}/payments/refund",
        json={
            "order_id": order_id,
            "amount": amount,
            "permit": permit,
            "signature_hex": signature_hex,
        },
    )


def record(ctx: RunCtx, num: int, name: str, exercises: str, passed: bool, detail: str) -> None:
    ctx.results.append(ScenarioResult(num, name, passed, detail, exercises))
    log.info(
        "%s scenario %d: %s, %s",
        "✓ PASS" if passed else "✗ FAIL",
        num,
        name,
        detail,
    )
    log.info("")  # blank line for readability between scenarios


# ─── Scenarios 1–7: the gate ─────────────────────────────────────────


async def s01_small_refund_permits(client: httpx.AsyncClient, ctx: RunCtx) -> None:
    log.info("━━━ Scenario 1: ₹500 refund within policy ━━━")
    resp = await call_agent(
        client, params={"amount": 500.0}, origin_country="IN", current_country="IN"
    )
    ok = resp.status_code == 200 and resp.json()["verdict"] == "permit"
    record(
        ctx, 1, "small refund permitted", "gate",
        ok, f"status={resp.status_code} verdict={resp.json().get('verdict', '?')}",
    )


async def s02_large_refund_refused(client: httpx.AsyncClient, ctx: RunCtx) -> None:
    log.info("━━━ Scenario 2: ₹6000 refund exceeds policy param_max ━━━")
    resp = await call_agent(
        client, params={"amount": 6000.0}, origin_country="IN", current_country="IN"
    )
    # 403 because the gate refused.
    ok = resp.status_code == 403
    record(
        ctx, 2, "refund over ₹5000 refused by policy", "gate",
        ok, f"status={resp.status_code} detail={(resp.json().get('detail') or '')[:80]}",
    )


async def s03_rate_limit_refuses_51st(client: httpx.AsyncClient, ctx: RunCtx) -> None:
    log.info("━━━ Scenario 3: 51st refund in 24h exceeds rate_limit ━━━")
    # Fire 50 permits in quick succession under a different caller id so the
    # other scenarios' rate-limit counter stays clean.
    caller = f"ratelimit-bot-{uuid.uuid4().hex[:6]}"
    for i in range(50):
        r = await call_agent(
            client, caller_id=caller, params={"amount": 100.0},
            origin_country="IN", current_country="IN",
        )
        assert r.status_code == 200, f"attempt {i + 1} should permit, got {r.status_code}"
    log.info("50 refunds accepted, attempting 51st (should refuse)")
    resp = await call_agent(
        client, caller_id=caller, params={"amount": 100.0},
        origin_country="IN", current_country="IN",
    )
    ok = resp.status_code == 403
    record(
        ctx, 3, "51st refund refused by rate_limit", "gate",
        ok, f"status={resp.status_code}",
    )


async def s04_invariant_beats_policy(client: httpx.AsyncClient, ctx: RunCtx) -> None:
    log.info("━━━ Scenario 4: reload policy to allow ₹100000, invariant still refuses ₹60000 ━━━")
    # Hot-reload policies that permit up to ₹1 lakh. The in-code invariant
    # (₹50k hard cap) must still refuse.
    permissive_toml = """
[[policy]]
name = "reckless_policy"
effect = "permit"
priority = 5
conditions = [
    { identity_kind = "agent" },
    { action = "issue_refund" },
    { param_max = { field = "amount", max = 100000.0 } },
]
"""
    r = await client.post(
        f"http://{AGENT_HOST}:{AGENT_PORT}/agent/reload",
        json={"policy_toml": permissive_toml},
    )
    assert r.status_code == 200
    resp = await call_agent(
        client, params={"amount": 60000.0}, origin_country="IN", current_country="IN"
    )
    ok = resp.status_code == 403
    record(
        ctx, 4, "invariant hard-cap overrides permissive policy", "gate",
        ok, f"status={resp.status_code} detail={(resp.json().get('detail') or '')[:80]}",
    )

    # Restore the original policy so scenarios 5+ have their expected rules.
    r = await client.post(
        f"http://{AGENT_HOST}:{AGENT_PORT}/agent/reload",
        json={"policy_toml": POLICY_PATH.read_text()},
    )
    assert r.status_code == 200


async def s05_geo_drift_invalidates(client: httpx.AsyncClient, ctx: RunCtx) -> None:
    log.info("━━━ Scenario 5: session origin=Bangalore, current=New York → Invalidate ━━━")
    # Drift detector only enters the geo branch when origin_ip != current_ip.
    # Pass both explicitly to model "session started from IP A, request
    # coming from IP B (and countries differ)".
    resp = await call_agent(
        client, params={"amount": 500.0},
        origin_country="IN", current_country="US",
        origin_ip="1.2.3.4", current_ip="5.6.7.8",
    )
    # 401 because the agent raised Invalidate (distance >> 500 km threshold).
    ok = resp.status_code == 401
    detail = resp.json().get("detail") or ""
    record(
        ctx, 5, "geo drift invalidates session", "gate",
        ok, f"status={resp.status_code} detail={detail[:80]}",
    )


async def s06_unknown_action_default_deny(client: httpx.AsyncClient, ctx: RunCtx) -> None:
    log.info("━━━ Scenario 6: action 'delete_order' matches no permit policy ━━━")
    resp = await call_agent(
        client, action_name="delete_order", params={"order_id_hash": 12345.0},
        origin_country="IN", current_country="IN",
    )
    ok = resp.status_code == 403
    record(
        ctx, 6, "unknown action default-denied", "gate",
        ok, f"status={resp.status_code}",
    )


async def s07_time_window_refuses(client: httpx.AsyncClient, ctx: RunCtx) -> None:
    log.info("━━━ Scenario 7: time_window outside business hours ━━━")
    # Pick a 1-hour window guaranteed to NOT include now (UTC). Offset by
    # 12 hours so it's always on the other side of the clock.
    now = datetime.now(timezone.utc)
    start_hour = (now.hour + 12) % 24
    end_hour = (start_hour + 1) % 24
    window = f"{start_hour:02d}:00-{end_hour:02d}:00"
    log.info("installing policy with time_window=%s (current UTC=%02d:%02d)",
             window, now.hour, now.minute)
    nights_only = f"""
[[policy]]
name = "nights_only"
effect = "permit"
priority = 10
conditions = [
    {{ identity_kind = "agent" }},
    {{ action = "issue_refund" }},
    {{ param_max = {{ field = "amount", max = 5000.0 }} }},
    {{ time_window = "{window}" }},
]
"""
    await client.post(
        f"http://{AGENT_HOST}:{AGENT_PORT}/agent/reload",
        json={"policy_toml": nights_only},
    )
    resp = await call_agent(
        client, params={"amount": 500.0}, origin_country="IN", current_country="IN"
    )
    ok = resp.status_code == 403
    record(
        ctx, 7, "refund refused outside time_window", "gate",
        ok, f"status={resp.status_code}",
    )

    # Restore original policy for crypto scenarios
    await client.post(
        f"http://{AGENT_HOST}:{AGENT_PORT}/agent/reload",
        json={"policy_toml": POLICY_PATH.read_text()},
    )


# ─── Scenarios 8–15: the crypto envelope ─────────────────────────────


async def obtain_valid_permit(client: httpx.AsyncClient) -> dict:
    """Helper used by several crypto scenarios. Returns a fresh valid
    {permit, signature_hex} pair for action=issue_refund, amount=500."""
    r = await call_agent(
        client, params={"amount": 500.0}, origin_country="IN", current_country="IN"
    )
    assert r.status_code == 200, f"expected Permit, got {r.status_code}: {r.text}"
    data = r.json()
    return {"permit": data["permit_token"], "signature_hex": data["signature_hex"]}


async def s08_unsigned_refund_rejected(client: httpx.AsyncClient, ctx: RunCtx) -> None:
    log.info("━━━ Scenario 8: POST /payments/refund with no permit → 401 ━━━")
    resp = await post_refund(client, PAY_PORT, "O-001", 500.0)
    ok = resp.status_code == 401
    record(
        ctx, 8, "unsigned request rejected", "crypto",
        ok, f"status={resp.status_code}",
    )


async def s09_forged_signature_rejected(client: httpx.AsyncClient, ctx: RunCtx) -> None:
    log.info("━━━ Scenario 9: POST with random-bytes signature → 401 ━━━")
    bundle = await obtain_valid_permit(client)
    # Replace the signature with random bytes of the same length.
    forged = "aa" * (len(bundle["signature_hex"]) // 2)
    resp = await post_refund(
        client, PAY_PORT, "O-009", 500.0, permit=bundle["permit"], signature_hex=forged,
    )
    ok = resp.status_code == 401
    record(
        ctx, 9, "forged signature rejected", "crypto",
        ok, f"status={resp.status_code}",
    )


async def s10_wrong_key_rejected(client: httpx.AsyncClient, ctx: RunCtx) -> None:
    log.info("━━━ Scenario 10: permit signed by a key NOT in the directory → 401 ━━━")
    # Spin up a fresh keypair completely outside the signed directory.
    imposter = KavachKeyPair.generate()
    imposter_signer = PqTokenSigner.from_keypair_hybrid(imposter)
    tok = PermitToken(
        token_id=str(uuid.uuid4()),
        evaluation_id=str(uuid.uuid4()),
        issued_at=int(time.time()),
        expires_at=int(time.time()) + 30,
        action_name="issue_refund",
    )
    sig = imposter_signer.sign(tok)
    permit = {
        "token_id": tok.token_id,
        "evaluation_id": tok.evaluation_id,
        "issued_at": tok.issued_at,
        "expires_at": tok.expires_at,
        "action_name": tok.action_name,
        "key_id": imposter_signer.key_id,
    }
    resp = await post_refund(
        client, PAY_PORT, "O-010", 500.0, permit=permit, signature_hex=sig.hex(),
    )
    ok = resp.status_code == 401
    record(
        ctx, 10, "permit from unknown key rejected (directory miss)", "crypto",
        ok, f"status={resp.status_code}",
    )


async def s11_expired_permit_rejected(client: httpx.AsyncClient, ctx: RunCtx) -> None:
    log.info("━━━ Scenario 11: permit with expires_at in the past → 401 ━━━")
    # Craft a token with expires_at = 10s ago. Sign it with the agent's
    # real signer so the signature is valid, but the payment service's
    # explicit expires_at check must still refuse.
    agent_signer = PqTokenSigner.from_keypair_hybrid(ctx.agent_kp)
    tok = PermitToken(
        token_id=str(uuid.uuid4()),
        evaluation_id=str(uuid.uuid4()),
        issued_at=int(time.time()) - 40,
        expires_at=int(time.time()) - 10,
        action_name="issue_refund",
    )
    sig = agent_signer.sign(tok)
    permit = {
        "token_id": tok.token_id,
        "evaluation_id": tok.evaluation_id,
        "issued_at": tok.issued_at,
        "expires_at": tok.expires_at,
        "action_name": tok.action_name,
        "key_id": agent_signer.key_id,
    }
    resp = await post_refund(
        client, PAY_PORT, "O-011", 500.0, permit=permit, signature_hex=sig.hex(),
    )
    ok = resp.status_code == 401
    record(
        ctx, 11, "expired permit rejected", "crypto",
        ok, f"status={resp.status_code}",
    )


async def s12_wrong_action_rejected(client: httpx.AsyncClient, ctx: RunCtx) -> None:
    log.info("━━━ Scenario 12: permit bound to 'read_order' replayed on /refund → 401 ━━━")
    # Get a permit for `read_order` and replay it against the refund endpoint.
    r = await call_agent(
        client, action_name="read_order",
        origin_country="IN", current_country="IN",
    )
    assert r.status_code == 200, "read_order should permit"
    data = r.json()
    resp = await post_refund(
        client, PAY_PORT, "O-012", 500.0,
        permit=data["permit_token"], signature_hex=data["signature_hex"],
    )
    ok = resp.status_code == 401
    record(
        ctx, 12, "permit bound to different action rejected", "crypto",
        ok, f"status={resp.status_code}",
    )


async def s13_pq_only_verifier_rejects_hybrid(client: httpx.AsyncClient, ctx: RunCtx) -> None:
    log.info("━━━ Scenario 13: PQ-only payment service receives hybrid permit → 401 ━━━")
    bundle = await obtain_valid_permit(client)
    # Post to the alternate payment instance wired with hybrid=False.
    resp = await post_refund(
        client, PAY_PQ_ONLY_PORT, "O-013", 500.0,
        permit=bundle["permit"], signature_hex=bundle["signature_hex"],
    )
    ok = resp.status_code == 401
    record(
        ctx, 13, "algorithm downgrade guard blocks hybrid→PQ-only", "crypto",
        ok, f"status={resp.status_code}",
    )


async def s14_audit_chain_detects_tamper(client: httpx.AsyncClient, ctx: RunCtx) -> None:
    log.info("━━━ Scenario 14: tamper audit JSONL → verify fails ━━━")
    # Export the agent's audit chain to disk.
    export = await client.post(f"http://{AGENT_HOST}:{AGENT_PORT}/agent/audit/export")
    assert export.status_code == 200
    audit_path = Path(export.json()["path"])
    raw = audit_path.read_bytes()
    log.info("audit exported: %d entries, %d bytes", export.json()["length"], len(raw))

    # Verify it's genuinely clean first.
    try:
        SignedAuditChain.verify_jsonl(
            raw, ctx.agent_kp.public_keys(), hybrid=True,
        )
    except Exception as err:
        record(
            ctx, 14, "audit chain verifies clean before tamper", "crypto",
            False, f"clean verify failed: {err}",
        )
        return

    # Tamper: flip a byte in the middle of the first entry.
    tampered = bytearray(raw)
    tampered[100] ^= 0x01  # small but signature-breaking
    log.info("tampered byte at offset 100")

    verified = False
    err_msg = "no error"
    try:
        SignedAuditChain.verify_jsonl(
            bytes(tampered), ctx.agent_kp.public_keys(), hybrid=True,
        )
        verified = True
    except Exception as err:
        err_msg = str(err)
    ok = not verified
    record(
        ctx, 14, "signed audit chain detects tamper", "crypto",
        ok, f"verify_jsonl raised: {err_msg[:60]}" if ok else "verification incorrectly succeeded",
    )


async def s15_audit_chain_mode_mismatch(client: httpx.AsyncClient, ctx: RunCtx) -> None:
    log.info("━━━ Scenario 15: caller asserts hybrid=False on a hybrid chain → rejected ━━━")
    export = await client.post(f"http://{AGENT_HOST}:{AGENT_PORT}/agent/audit/export")
    assert export.status_code == 200
    raw = Path(export.json()["path"]).read_bytes()
    bundle = ctx.agent_kp.public_keys()

    # Hybrid=False on a hybrid chain must raise before any crypto runs.
    verified = False
    err_msg = "no error"
    try:
        SignedAuditChain.verify_jsonl(raw, bundle, hybrid=False)
        verified = True
    except Exception as err:
        err_msg = str(err)
    ok = not verified and "mode mismatch" in err_msg.lower()
    record(
        ctx, 15, "mode-downgrade assertion rejected", "crypto",
        ok, f"verify_jsonl raised: {err_msg[:80]}",
    )


# ─── Orchestration + reporting ───────────────────────────────────────


async def main() -> int:
    console.rule("[bold cyan]Kavach E2E, refund scenario")
    log.info("setting up keys + signed directory")
    bs = setup()

    log.info("agent key_id    = %s", bs.agent_kp.public_keys().id)
    log.info("root VK bytes   = %d", bs.root_vk_path.stat().st_size)
    log.info("directory bytes = %d", bs.directory_path.stat().st_size)

    # Agent: holds its keypair + Kavach gate. Signs permits and audit.
    agent_app = support_agent.build_app(
        keypair=bs.agent_kp,
        policy_path=POLICY_PATH,
        audit_path=AUDIT_PATH,
    )
    agent_server = await start_server(agent_app, AGENT_HOST, AGENT_PORT, "agent")

    # Main payment instance: hybrid verifier (this is how real deployments
    # should run, accept hybrid, reject PQ-only, full defence in depth).
    pay_app = payment_service.build_app(
        directory_path=bs.directory_path,
        root_vk_path=bs.root_vk_path,
        hybrid=True,
    )
    pay_server = await start_server(pay_app, PAY_HOST, PAY_PORT, "payment")

    # A SECOND payment instance, PQ-only, so scenario 13 can demonstrate
    # algorithm-downgrade guarding. Same directory, different verifier mode.
    pay_pq_app = payment_service.build_app(
        directory_path=bs.directory_path,
        root_vk_path=bs.root_vk_path,
        hybrid=False,
    )
    pay_pq_server = await start_server(pay_pq_app, PAY_HOST, PAY_PQ_ONLY_PORT, "payment-pq")

    ctx = RunCtx(agent_kp=bs.agent_kp, root_kp=bs.root_kp)
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            # Capability 1, the gate
            await s01_small_refund_permits(client, ctx)
            await s02_large_refund_refused(client, ctx)
            await s03_rate_limit_refuses_51st(client, ctx)
            await s04_invariant_beats_policy(client, ctx)
            await s05_geo_drift_invalidates(client, ctx)
            await s06_unknown_action_default_deny(client, ctx)
            await s07_time_window_refuses(client, ctx)

            # Capability 2, the crypto envelope
            await s08_unsigned_refund_rejected(client, ctx)
            await s09_forged_signature_rejected(client, ctx)
            await s10_wrong_key_rejected(client, ctx)
            await s11_expired_permit_rejected(client, ctx)
            await s12_wrong_action_rejected(client, ctx)
            await s13_pq_only_verifier_rejects_hybrid(client, ctx)
            await s14_audit_chain_detects_tamper(client, ctx)
            await s15_audit_chain_mode_mismatch(client, ctx)
    finally:
        agent_server.should_exit = True
        pay_server.should_exit = True
        pay_pq_server.should_exit = True

    # ── Summary table ────────────────────────────────────────────
    print()
    console.rule("[bold cyan]Results")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("#", justify="right", style="dim", width=3)
    table.add_column("Scenario", min_width=45)
    table.add_column("Exercises", style="cyan", width=11)
    table.add_column("Result", width=8)
    table.add_column("Detail", overflow="fold")
    for r in ctx.results:
        table.add_row(
            str(r.num),
            r.name,
            r.exercises,
            "[green]PASS[/green]" if r.passed else "[red]FAIL[/red]",
            r.detail,
        )
    console.print(table)

    passed = sum(1 for r in ctx.results if r.passed)
    total = len(ctx.results)
    style = "green" if passed == total else "red"
    console.print(
        f"\n[bold {style}]{passed}/{total} scenarios passed[/bold {style}]"
    )
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
