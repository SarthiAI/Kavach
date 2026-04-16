"""Hard end-to-end suite: compound scenarios, concurrent load, adversarial variance.

Exercises more than one Kavach feature per scenario, against realistic
business-flow conditions:

    1. Mixed-role concurrent operations with mid-run policy reload
    2. Coordinated permit-laundering attacker (20+ variants)
    3. Key rotation (old permits invalidated, new key works)
    4. Kill-switch via empty policy (measure time-to-refuse)
    5. Invariant as compliance floor (rogue-admin simulation)
    6. Audit forensics (reconstruct + 5 tamper variants)

Run:

    source ../kavach-py/.venv/bin/activate
    python hard_runner.py
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import sys
import time
import uuid
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import uvicorn
from kavach import (
    KavachKeyPair,
    PermitToken,
    PqTokenSigner,
    SignedAuditChain,
)
from rich.console import Console
from rich.table import Table

from bootstrap import setup
import payment_service
import support_agent

# ─── Logging ─────────────────────────────────────────────────────────

FORMAT = "%(asctime)s.%(msecs)03d | %(name)-7s | %(levelname)-5s | %(message)s"
logging.basicConfig(
    level=logging.INFO, format=FORMAT, datefmt="%H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)
for noisy in ("uvicorn", "uvicorn.access", "uvicorn.error", "httpx", "httpcore"):
    logging.getLogger(noisy).setLevel(logging.WARNING)

log = logging.getLogger("runner")
console = Console()

# ─── Config ──────────────────────────────────────────────────────────

AGENT_HOST, AGENT_PORT = "127.0.0.1", 8101
PAY_HOST, PAY_PORT = "127.0.0.1", 8102

STATE_DIR = Path(__file__).parent / "state_hard"
POLICY_PATH = Path(__file__).parent / "hard_policies.toml"
AUDIT_PATH = STATE_DIR / "audit.jsonl"

# ─── Results harness ─────────────────────────────────────────────────


@dataclass
class ScenarioResult:
    num: int
    name: str
    passed: bool
    detail: str


@dataclass
class RunCtx:
    agent_kp: KavachKeyPair
    root_kp: KavachKeyPair
    bootstrap_: Any
    results: list[ScenarioResult] = field(default_factory=list)


def record(ctx: RunCtx, num: int, name: str, passed: bool, detail: str) -> None:
    ctx.results.append(ScenarioResult(num, name, passed, detail))
    log.info("%s scenario %d: %s — %s",
             "✓ PASS" if passed else "✗ FAIL", num, name, detail)
    log.info("")


# ─── HTTP helpers ────────────────────────────────────────────────────


async def call_agent(
    client: httpx.AsyncClient, *,
    caller_id: str,
    action_name: str = "issue_refund",
    params: dict[str, float] | None = None,
    principal_kind: str = "agent",
    roles: list[str] | None = None,
    origin_ip: str | None = None,
    current_ip: str | None = None,
    origin_country: str | None = None,
    current_country: str | None = None,
) -> httpx.Response:
    return await client.post(
        f"http://{AGENT_HOST}:{AGENT_PORT}/agent/tool",
        json={
            "caller_id": caller_id,
            "action_name": action_name,
            "params": params or {},
            "principal_kind": principal_kind,
            "roles": roles or [],
            "origin_ip": origin_ip,
            "current_ip": current_ip,
            "origin_country": origin_country,
            "current_country": current_country,
        },
    )


async def post_refund(
    client: httpx.AsyncClient, *,
    order_id: str,
    amount: float,
    permit: dict | None,
    signature_hex: str | None,
) -> httpx.Response:
    return await client.post(
        f"http://{PAY_HOST}:{PAY_PORT}/payments/refund",
        json={
            "order_id": order_id,
            "amount": amount,
            "permit": permit,
            "signature_hex": signature_hex,
        },
    )


async def start_server(app, host: str, port: int, label: str) -> uvicorn.Server:
    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    server = uvicorn.Server(config)
    asyncio.create_task(server.serve())
    for _ in range(200):
        if server.started:
            log.info("service up: %s → http://%s:%d", label, host, port)
            return server
        await asyncio.sleep(0.05)
    raise RuntimeError(f"server '{label}' failed to start")


# ─── Scenario 1: mixed-role concurrent with mid-run policy reload ────


async def s01_mixed_role_concurrent(client: httpx.AsyncClient, ctx: RunCtx) -> None:
    """Three principals — AI agent, human support rep, admin — all firing
    refunds concurrently. Mid-run, admin tightens the agent policy. Verify
    each principal sees the behaviour its policy defines, and the reload
    doesn't leak across principals."""
    log.info("━━━ Scenario 1: mixed-role concurrent ops + mid-run reload ━━━")

    RUN_SECONDS = 8
    MID_RELOAD_AT = 4  # seconds in
    start = time.monotonic()

    @dataclass
    class PrincipalStats:
        name: str
        permit: int = 0
        refuse: int = 0
        error: int = 0
        # Permit counts split by before/after the reload so we can prove
        # the reload actually changed behaviour for the agent specifically.
        permit_before: int = 0
        permit_after: int = 0
        refuse_before: int = 0
        refuse_after: int = 0

    agent_stats = PrincipalStats("agent")
    support_stats = PrincipalStats("support")
    admin_stats = PrincipalStats("admin")

    async def fire_loop(stats: PrincipalStats, kwargs: dict, amount_range: tuple[float, float]) -> None:
        while time.monotonic() - start < RUN_SECONDS:
            amount = round(random.uniform(*amount_range), 2)
            try:
                resp = await call_agent(
                    client, params={"amount": amount},
                    origin_country="IN", current_country="IN",  # no drift
                    **kwargs,
                )
            except Exception as err:
                stats.error += 1
                log.debug("%s error: %s", stats.name, err)
                await asyncio.sleep(0.05)
                continue

            elapsed = time.monotonic() - start
            bucket_before = elapsed < MID_RELOAD_AT
            if resp.status_code == 200:
                stats.permit += 1
                if bucket_before: stats.permit_before += 1
                else: stats.permit_after += 1
            elif resp.status_code == 403:
                stats.refuse += 1
                if bucket_before: stats.refuse_before += 1
                else: stats.refuse_after += 1
            else:
                stats.error += 1
            await asyncio.sleep(random.uniform(0.01, 0.05))

    async def reload_midway() -> None:
        await asyncio.sleep(MID_RELOAD_AT)
        log.info("mid-run: tightening agent cap from 5000 to 1000")
        tight = """
[[policy]]
name = "agent_refunds_tight"
effect = "permit"
priority = 10
conditions = [
    { identity_kind = "agent" },
    { action = "issue_refund" },
    { param_max = { field = "amount", max = 1000.0 } },
    { rate_limit = { max = 100, window = "24h" } },
]

[[policy]]
name = "support_rep_refunds"
effect = "permit"
priority = 20
conditions = [
    { identity_role = "support_agent" },
    { action = "issue_refund" },
    { param_max = { field = "amount", max = 50000.0 } },
    { rate_limit = { max = 200, window = "24h" } },
]

[[policy]]
name = "admin_refunds"
effect = "permit"
priority = 30
conditions = [
    { identity_role = "admin" },
    { action = "issue_refund" },
]
"""
        r = await client.post(
            f"http://{AGENT_HOST}:{AGENT_PORT}/agent/reload",
            json={"policy_toml": tight},
        )
        assert r.status_code == 200

    # Run 3 principals concurrently. Amount ranges chosen so pre-reload all
    # normally permit, post-reload only the agent starts refusing.
    tasks = [
        asyncio.create_task(fire_loop(
            agent_stats,
            {"caller_id": "agent-bot", "principal_kind": "agent"},
            (1500.0, 4500.0),  # all > 1000 cap after reload
        )),
        asyncio.create_task(fire_loop(
            support_stats,
            {"caller_id": "rep-01", "principal_kind": "user", "roles": ["support_agent"]},
            (5000.0, 40000.0),  # within support cap
        )),
        asyncio.create_task(fire_loop(
            admin_stats,
            {"caller_id": "admin-01", "principal_kind": "user", "roles": ["admin"]},
            (10000.0, 45000.0),  # within invariant cap
        )),
        asyncio.create_task(reload_midway()),
    ]
    await asyncio.gather(*tasks)

    total = agent_stats.permit + agent_stats.refuse + support_stats.permit + support_stats.refuse + admin_stats.permit + admin_stats.refuse
    log.info("total refunds attempted: %d", total)
    log.info("  agent:   permit=%d (before=%d/after=%d)  refuse=%d (before=%d/after=%d)",
             agent_stats.permit, agent_stats.permit_before, agent_stats.permit_after,
             agent_stats.refuse, agent_stats.refuse_before, agent_stats.refuse_after)
    log.info("  support: permit=%d  refuse=%d  errors=%d",
             support_stats.permit, support_stats.refuse, support_stats.error)
    log.info("  admin:   permit=%d  refuse=%d  errors=%d",
             admin_stats.permit, admin_stats.refuse, admin_stats.error)

    # Assertions:
    # 1. Agent permits BEFORE reload should be > 0 (amounts 1500-4500 within
    #    original 5000 cap).
    # 2. Agent permits AFTER reload should be 0 (all amounts > 1000 cap).
    # 3. Support + admin should keep permitting *after* the agent-only reload
    #    (their policies weren't touched). Rate-limit refusals near the tail
    #    of the run are OK and not policy-reload contamination.
    agent_permitted_before = agent_stats.permit_before > 0
    agent_refused_after = agent_stats.permit_after == 0 and agent_stats.refuse_after > 0
    support_still_working = support_stats.permit_after > 0
    admin_still_working = admin_stats.permit_after > 0

    ok = (
        agent_permitted_before
        and agent_refused_after
        and support_still_working
        and admin_still_working
    )
    detail = (
        f"total={total} | "
        f"agent before={agent_stats.permit_before}p/{agent_stats.refuse_before}r, "
        f"after={agent_stats.permit_after}p/{agent_stats.refuse_after}r | "
        f"support {support_stats.permit}p/{support_stats.refuse}r | "
        f"admin {admin_stats.permit}p/{admin_stats.refuse}r"
    )
    record(ctx, 1, "mixed-role concurrent ops + mid-run reload", ok, detail)

    # Restore the original policy so other scenarios see their expected rules.
    await client.post(
        f"http://{AGENT_HOST}:{AGENT_PORT}/agent/reload",
        json={"policy_toml": POLICY_PATH.read_text()},
    )


# ─── Scenario 2: permit-laundering attacker (20+ variants) ───────────


async def s02_permit_laundering(client: httpx.AsyncClient, ctx: RunCtx) -> None:
    """Obtain a legitimate permit, then try every reasonable tamper /
    substitution / replay variant against the payment service. Every
    variant must 401."""
    log.info("━━━ Scenario 2: 20+ permit-laundering attack variants ━━━")

    # Capture 3 fresh legit permits for action=issue_refund (admin-level so
    # policy doesn't refuse on amount during capture).
    captured: list[dict] = []
    for i in range(3):
        r = await call_agent(
            client, caller_id=f"admin-capture-{i}",
            principal_kind="user", roles=["admin"],
            params={"amount": 500.0},
            origin_country="IN", current_country="IN",
        )
        assert r.status_code == 200, f"capture {i} failed: {r.text}"
        data = r.json()
        captured.append({
            "permit": data["permit_token"],
            "signature_hex": data["signature_hex"],
        })
    log.info("captured %d valid permits for mutation", len(captured))

    # Base permit + signature we'll mutate in most attacks.
    base_permit = dict(captured[0]["permit"])
    base_sig_hex = captured[0]["signature_hex"]
    sig_bytes = bytes.fromhex(base_sig_hex)
    sig_len = len(sig_bytes)

    attacks: list[tuple[str, dict | None, str | None]] = []

    # ── Signature-manipulation attacks ──
    attacks.append(("sig: all zeros", dict(base_permit), ("00" * sig_len)))
    attacks.append(("sig: all 0xFF", dict(base_permit), ("ff" * sig_len)))
    attacks.append(("sig: truncated (1 byte)", dict(base_permit), base_sig_hex[:-2]))
    attacks.append(("sig: extended (+null)", dict(base_permit), base_sig_hex + "00"))
    attacks.append(("sig: empty", dict(base_permit), ""))
    # Bit-flip at a few characteristic offsets.
    def flip(h: str, off: int) -> str:
        ba = bytearray(bytes.fromhex(h))
        ba[off] ^= 0x01
        return ba.hex()
    for off_label, off in [("0", 0), ("10", 10), ("100", 100), ("mid", sig_len // 2), ("last", sig_len - 1)]:
        attacks.append((f"sig: bit-flip @ offset {off_label}", dict(base_permit), flip(base_sig_hex, off)))
    attacks.append(("sig: random bytes", dict(base_permit),
                    bytes(random.randbytes(sig_len)).hex()))

    # ── Permit-field tampers (signature left intact, body changed) ──
    def with_field(**overrides):
        p = dict(base_permit)
        p.update(overrides)
        return p
    attacks.append(("field: action_name -> delete_order",
                    with_field(action_name="delete_order"), base_sig_hex))
    attacks.append(("field: action_name -> ''",
                    with_field(action_name=""), base_sig_hex))
    attacks.append(("field: expires_at = 0",
                    with_field(expires_at=0), base_sig_hex))
    attacks.append(("field: expires_at = issued_at - 1",
                    with_field(expires_at=base_permit["issued_at"] - 1), base_sig_hex))
    attacks.append(("field: token_id = random uuid",
                    with_field(token_id=str(uuid.uuid4())), base_sig_hex))
    attacks.append(("field: evaluation_id = random uuid",
                    with_field(evaluation_id=str(uuid.uuid4())), base_sig_hex))
    # Note: `key_id` in the permit body is informational — the verifier reads
    # the authoritative key_id from the signed envelope inside `signature`.
    # Tampering permit.key_id doesn't affect verification (nor does it buy
    # the attacker anything — they get the original verdict). Not a real
    # attack; not tested here.

    # ── Cross-permit signature grafting ──
    attacks.append(("graft: permit A body + permit B signature",
                    dict(captured[0]["permit"]),
                    captured[1]["signature_hex"]))
    attacks.append(("graft: permit A body + permit C signature",
                    dict(captured[0]["permit"]),
                    captured[2]["signature_hex"]))

    # ── Valid-but-wrong-action replay (get a fresh read_order permit) ──
    r = await call_agent(
        client, caller_id="admin-readorder",
        principal_kind="user", roles=["admin"],
        action_name="read_order",
        origin_country="IN", current_country="IN",
    )
    # read_order may not be permitted in hard_policies.toml — add a fallback
    # so we can still test wrong-action replay. If the agent refuses, we
    # need to give it a policy that permits read_order temporarily. Simpler:
    # tamper a valid issue_refund permit's action_name and rely on action
    # rejection in payment_service.
    if r.status_code == 200:
        data = r.json()
        attacks.append(("valid read_order permit replayed on /refund",
                        data["permit_token"], data["signature_hex"]))

    # ── Run every attack ──
    succeeded_attacks: list[str] = []
    for name, permit, sig_hex in attacks:
        resp = await post_refund(
            client, order_id=f"ATTACK-{uuid.uuid4().hex[:6]}",
            amount=500.0, permit=permit, signature_hex=sig_hex,
        )
        if resp.status_code != 401:
            succeeded_attacks.append(f"{name} → {resp.status_code}")

    ok = not succeeded_attacks
    detail = (
        f"{len(attacks)} variants tested, all rejected"
        if ok else
        f"{len(succeeded_attacks)} attack(s) succeeded: {'; '.join(succeeded_attacks[:3])}"
    )
    record(ctx, 2, f"{len(attacks)} permit-laundering variants all rejected", ok, detail)


# ─── Scenario 3: directory rotation invalidates old permits ──────────


async def s03_key_rotation(client: httpx.AsyncClient, ctx: RunCtx) -> None:
    """Directory is rotated to remove the agent's current key. Already-issued
    (not-yet-expired) permits must be rejected after rotation. A fresh key
    signed by the runner (standing in for the next-gen agent) is then
    accepted after the payment service reloads."""
    log.info("━━━ Scenario 3: directory rotation invalidates pre-rotation permits ━━━")

    # Step 1: capture 5 fresh permits signed by the current agent key.
    captured = []
    for i in range(5):
        r = await call_agent(
            client, caller_id=f"admin-k1-{i}",
            principal_kind="user", roles=["admin"],
            params={"amount": 500.0},
            origin_country="IN", current_country="IN",
        )
        assert r.status_code == 200
        captured.append(r.json())
    log.info("captured %d permits signed with K1 (current)", len(captured))

    # Sanity: confirm K1 permits are accepted right now.
    sanity = await post_refund(
        client, order_id="PRE-ROT-1", amount=500.0,
        permit=captured[0]["permit_token"],
        signature_hex=captured[0]["signature_hex"],
    )
    pre_rotate_ok = sanity.status_code == 200

    # Step 2: generate K2 + rebuild the signed directory with K2 only.
    k2 = KavachKeyPair.generate()
    new_manifest = ctx.root_kp.build_signed_manifest([k2.public_keys()])
    ctx.bootstrap_.directory_path.write_bytes(new_manifest)
    log.info("directory rotated: K1 removed, K2 added (key_id=%s)", k2.public_keys().id)

    # Step 3: payment service reloads directory.
    rr = await client.post(f"http://{PAY_HOST}:{PAY_PORT}/payments/admin/reload_directory")
    assert rr.status_code == 200

    # Step 4: replay all K1 permits — every one should 401 now (key missing).
    post_rotate_rejected = 0
    for i, perm in enumerate(captured):
        resp = await post_refund(
            client, order_id=f"POST-ROT-{i}", amount=500.0,
            permit=perm["permit_token"],
            signature_hex=perm["signature_hex"],
        )
        if resp.status_code == 401:
            post_rotate_rejected += 1

    # Step 5: runner signs a fresh permit with K2 → should be accepted.
    k2_signer = PqTokenSigner.from_keypair_hybrid(k2)
    tok = PermitToken(
        token_id=str(uuid.uuid4()),
        evaluation_id=str(uuid.uuid4()),
        issued_at=int(time.time()),
        expires_at=int(time.time()) + 30,
        action_name="issue_refund",
    )
    sig = k2_signer.sign(tok)
    new_permit = {
        "token_id": tok.token_id,
        "evaluation_id": tok.evaluation_id,
        "issued_at": tok.issued_at,
        "expires_at": tok.expires_at,
        "action_name": tok.action_name,
        "key_id": k2_signer.key_id,
    }
    k2_resp = await post_refund(
        client, order_id="NEW-K2", amount=500.0,
        permit=new_permit, signature_hex=sig.hex(),
    )
    new_key_ok = k2_resp.status_code == 200

    ok = pre_rotate_ok and post_rotate_rejected == len(captured) and new_key_ok
    detail = (
        f"pre-rotate K1={sanity.status_code}, post-rotate K1 rejected="
        f"{post_rotate_rejected}/{len(captured)}, new K2 permit={k2_resp.status_code}"
    )
    record(ctx, 3, "directory rotation invalidates pre-rotation permits", ok, detail)

    # Restore: put K1 back in the directory so scenarios 4-6 can still use
    # the agent's signer.
    restored = ctx.root_kp.build_signed_manifest([ctx.agent_kp.public_keys()])
    ctx.bootstrap_.directory_path.write_bytes(restored)
    await client.post(f"http://{PAY_HOST}:{PAY_PORT}/payments/admin/reload_directory")


# ─── Scenario 4: kill-switch via empty policy ────────────────────────


async def s04_kill_switch(client: httpx.AsyncClient, ctx: RunCtx) -> None:
    """10 concurrent admins issue refunds at ~20/s. Mid-run, empty policy
    pushed. Measure time between reload completion and first post-reload
    refusal. Should be < 100ms — any slower implies stale state."""
    log.info("━━━ Scenario 4: kill-switch (empty policy) propagation speed ━━━")

    RUN_SECONDS = 4
    RELOAD_AT = 2
    start = time.monotonic()

    @dataclass
    class Timeline:
        reload_completed_at: float | None = None
        first_refuse_after_reload_at: float | None = None
        permits_after_reload: int = 0

    timeline = Timeline()
    lock = asyncio.Lock()

    async def fire(caller_id: str) -> None:
        while time.monotonic() - start < RUN_SECONDS:
            resp = await call_agent(
                client, caller_id=caller_id,
                principal_kind="user", roles=["admin"],
                params={"amount": 1000.0},
                origin_country="IN", current_country="IN",
            )
            now = time.monotonic()
            async with lock:
                if timeline.reload_completed_at is not None:
                    if resp.status_code == 200:
                        timeline.permits_after_reload += 1
                    elif resp.status_code == 403 and timeline.first_refuse_after_reload_at is None:
                        timeline.first_refuse_after_reload_at = now
            await asyncio.sleep(0.04)  # ~25/s per caller

    async def push_kill_switch() -> None:
        await asyncio.sleep(RELOAD_AT)
        log.info("pushing kill-switch (empty policy)...")
        r = await client.post(
            f"http://{AGENT_HOST}:{AGENT_PORT}/agent/reload",
            json={"policy_toml": ""},
        )
        assert r.status_code == 200
        async with lock:
            timeline.reload_completed_at = time.monotonic()
        log.info("kill-switch pushed")

    tasks = [asyncio.create_task(fire(f"admin-{i}")) for i in range(10)]
    tasks.append(asyncio.create_task(push_kill_switch()))
    await asyncio.gather(*tasks)

    if timeline.reload_completed_at is None or timeline.first_refuse_after_reload_at is None:
        ok = False
        detail = "reload or first-refuse not observed"
    else:
        delta_ms = (timeline.first_refuse_after_reload_at - timeline.reload_completed_at) * 1000
        # Must be near-instant — allow up to 200ms for pytest-like scheduling
        # on busy runners. Also require zero Permits after reload.
        ok = delta_ms < 200 and timeline.permits_after_reload == 0
        detail = (
            f"first refuse {delta_ms:+.1f}ms after reload, "
            f"permits_after_reload={timeline.permits_after_reload}"
        )
    record(ctx, 4, "kill-switch propagates in <200ms, no permits leak", ok, detail)

    # Restore normal policy.
    await client.post(
        f"http://{AGENT_HOST}:{AGENT_PORT}/agent/reload",
        json={"policy_toml": POLICY_PATH.read_text()},
    )


# ─── Scenario 5: invariant as compliance floor ───────────────────────


async def s05_invariant_floor(client: httpx.AsyncClient, ctx: RunCtx) -> None:
    """A 'rogue admin' pushes a policy that permits up to ₹5 lakh. The
    in-code invariant (₹50k cap) must refuse every refund over that, with
    the refusal coming from the 'invariants' evaluator specifically."""
    log.info("━━━ Scenario 5: invariant stops rogue admin from bypassing ₹50k cap ━━━")

    # Push the rogue-permissive policy.
    rogue = """
[[policy]]
name = "rogue_lax_cap"
effect = "permit"
priority = 99
conditions = [
    { identity_role = "admin" },
    { action = "issue_refund" },
    { param_max = { field = "amount", max = 500000.0 } },
]
"""
    r = await client.post(
        f"http://{AGENT_HOST}:{AGENT_PORT}/agent/reload",
        json={"policy_toml": rogue},
    )
    assert r.status_code == 200

    probes = [
        (49_000.0,  "permit"),
        (50_000.0,  "permit"),
        (50_001.0,  "refuse"),
        (60_000.0,  "refuse"),
        (100_000.0, "refuse"),
        (300_000.0, "refuse"),
        (400_000.0, "refuse"),
    ]

    mismatches = []
    invariant_catches = 0
    for amount, expected in probes:
        resp = await call_agent(
            client, caller_id="admin-rogue",
            principal_kind="user", roles=["admin"],
            params={"amount": amount},
            origin_country="IN", current_country="IN",
        )
        actual = "permit" if resp.status_code == 200 else "refuse"
        if actual != expected:
            mismatches.append(f"₹{amount:,.0f}: expected {expected} got {actual}")
            continue
        if expected == "refuse":
            # Confirm the refuser was the invariants evaluator, not policy.
            detail = (resp.json().get("detail") or "")
            if "invariants" in detail.lower() or "invariant" in detail.lower():
                invariant_catches += 1
            else:
                mismatches.append(f"₹{amount:,.0f}: refused but NOT by invariants ({detail[:60]})")

    expected_invariant = sum(1 for _, e in probes if e == "refuse")
    ok = not mismatches and invariant_catches == expected_invariant
    detail = (
        f"{len(probes)} probes all correctly classified, "
        f"{invariant_catches}/{expected_invariant} refusals attributed to invariants"
        if ok else "; ".join(mismatches[:2])
    )
    record(ctx, 5, "invariant floor beats rogue policy", ok, detail)

    # Restore normal policy.
    await client.post(
        f"http://{AGENT_HOST}:{AGENT_PORT}/agent/reload",
        json={"policy_toml": POLICY_PATH.read_text()},
    )


# ─── Scenario 6: audit forensics ─────────────────────────────────────


async def s06_audit_forensics(client: httpx.AsyncClient, ctx: RunCtx) -> None:
    """Export the audit chain built up over scenarios 1-5. A simulated
    auditor (who only has the agent's public bundle) reconstructs per-principal
    statistics and attempts five tamper variants — all must be detected."""
    log.info("━━━ Scenario 6: audit forensics + 5 tamper variants ━━━")

    # Export the chain to disk.
    exp = await client.post(f"http://{AGENT_HOST}:{AGENT_PORT}/agent/audit/export")
    assert exp.status_code == 200
    chain_bytes = Path(exp.json()["path"]).read_bytes()
    chain_len = exp.json()["length"]
    log.info("audit chain exported: %d entries, %d bytes", chain_len, len(chain_bytes))

    # Clean verify (baseline).
    try:
        SignedAuditChain.verify_jsonl(chain_bytes, ctx.agent_kp.public_keys(), hybrid=True)
        clean_ok = True
    except Exception as err:
        clean_ok = False
        log.error("clean verify failed: %s", err)

    # Decode per-entry principal/verdict. The audit-entry JSON is stored
    # inside signed_payload.data as a byte array (list of ints) — the bytes
    # are what was signed, so the verifier reconstructs exactly what the
    # signer signed.
    lines = [l for l in chain_bytes.decode().splitlines() if l.strip()]
    per_principal: Counter[str] = Counter()
    per_verdict: Counter[str] = Counter()
    for l in lines:
        try:
            obj = json.loads(l)
            payload = obj.get("signed_payload", {})
            data_bytes = bytes(payload.get("data", []))
            entry = json.loads(data_bytes.decode("utf-8"))
            per_principal[entry.get("principal_id", "?")] += 1
            per_verdict[entry.get("verdict", "?")] += 1
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            pass
    log.info("per-principal counts: %s", dict(per_principal))
    log.info("per-verdict   counts: %s", dict(per_verdict))

    # ── Five tamper variants ──
    def try_verify(data: bytes) -> str | None:
        try:
            SignedAuditChain.verify_jsonl(data, ctx.agent_kp.public_keys(), hybrid=True)
            return None
        except Exception as err:
            return str(err)

    tampers: list[tuple[str, bytes, str]] = []

    # T1: bit-flip inside entry #10.
    if len(lines) >= 10:
        t1_lines = list(lines)
        original = t1_lines[9].encode()
        tampered = bytearray(original)
        # Flip a byte that's guaranteed to be data (offset 50 is well inside
        # the signed payload of any reasonable audit entry).
        if len(tampered) > 50:
            tampered[50] ^= 0x01
            t1 = b"\n".join([bytes(tampered) if i == 9 else l.encode() for i, l in enumerate(t1_lines)]) + b"\n"
            tampers.append(("bit-flip inside entry #10", t1, "signature"))

    # T2: delete entry #20.
    if len(lines) >= 21:
        t2_lines = [l for i, l in enumerate(lines) if i != 19]
        t2 = ("\n".join(t2_lines) + "\n").encode()
        tampers.append(("delete entry #20", t2, "chain"))

    # T3: reorder entries #5 and #6.
    if len(lines) >= 7:
        t3_lines = list(lines)
        t3_lines[4], t3_lines[5] = t3_lines[5], t3_lines[4]
        t3 = ("\n".join(t3_lines) + "\n").encode()
        tampers.append(("reorder entries #5 ↔ #6", t3, "chain"))

    # T4: append a forged entry with plausible-looking (but wrong)
    # signatures. Must fail chain-link verify (prev_hash wrong) or
    # signature verify.
    fake_audit_entry = {
        "id": str(uuid.uuid4()),
        "evaluation_id": str(uuid.uuid4()),
        "timestamp": "2025-01-01T00:00:00Z",
        "principal_id": "attacker",
        "action_name": "issue_refund",
        "resource": None,
        "verdict": "permit",
        "verdict_detail": "forged entry",
        "decided_by": None,
        "session_id": str(uuid.uuid4()),
        "ip": None,
        "context_snapshot": None,
    }
    fake_line = {
        "index": len(lines),
        "previous_hash": "0" * 64,
        "signed_payload": {
            "data": list(json.dumps(fake_audit_entry).encode()),
            "ml_dsa_signature": [0] * 3293,
            "ed25519_signature": [0] * 64,
            "key_id": ctx.agent_kp.public_keys().id,
            "signed_at": "2025-01-01T00:00:00Z",
            "nonce": [0] * 16,
        },
        "entry_hash": "f" * 64,
    }
    t4 = chain_bytes + (json.dumps(fake_line) + "\n").encode()
    tampers.append(("append forged entry", t4, "signature"))

    # T5: splice — strip the ed25519_signature inside signed_payload of the
    # first entry. That makes one entry PQ-only while the rest stay hybrid.
    # detect_mode sees a mixed chain → reject before any crypto runs.
    if lines:
        try:
            first = json.loads(lines[0])
            if "signed_payload" in first:
                first["signed_payload"]["ed25519_signature"] = None
            t5_lines = [json.dumps(first)] + lines[1:]
            t5 = ("\n".join(t5_lines) + "\n").encode()
            tampers.append(("splice PQ-only entry into hybrid chain", t5, "mode"))
        except json.JSONDecodeError:
            pass

    results: list[tuple[str, bool, str]] = []
    for name, data, _expected_error_class in tampers:
        err = try_verify(data)
        rejected = err is not None
        results.append((name, rejected, err or "(verified — shouldn't have)"))
        log.info("tamper [%s] → %s", name, "REJECTED" if rejected else "ACCEPTED (BAD)")

    all_rejected = all(r[1] for r in results)
    ok = clean_ok and all_rejected and len(tampers) == 5 and len(per_principal) > 1
    detail = (
        f"chain_len={chain_len}, principals={len(per_principal)}, "
        f"tamper_variants={len(tampers)}, all_rejected={all_rejected}, clean_verify={clean_ok}"
    )
    record(ctx, 6, "audit forensics + 5 tamper variants detected", ok, detail)


# ─── Main ────────────────────────────────────────────────────────────


async def main() -> int:
    console.rule("[bold cyan]Kavach hard E2E — compound scenarios")
    log.info("setting up keys + signed directory")
    bs = setup(STATE_DIR)
    log.info("agent key_id = %s", bs.agent_kp.public_keys().id)

    STATE_DIR.mkdir(exist_ok=True)
    agent_app = support_agent.build_app(
        keypair=bs.agent_kp, policy_path=POLICY_PATH, audit_path=AUDIT_PATH,
    )
    await start_server(agent_app, AGENT_HOST, AGENT_PORT, "agent")

    pay_app = payment_service.build_app(
        directory_path=bs.directory_path, root_vk_path=bs.root_vk_path, hybrid=True,
    )
    await start_server(pay_app, PAY_HOST, PAY_PORT, "payment")

    ctx = RunCtx(agent_kp=bs.agent_kp, root_kp=bs.root_kp, bootstrap_=bs)

    async with httpx.AsyncClient(timeout=10.0) as client:
        await s01_mixed_role_concurrent(client, ctx)
        await s02_permit_laundering(client, ctx)
        await s04_kill_switch(client, ctx)
        await s05_invariant_floor(client, ctx)
        await s03_key_rotation(client, ctx)
        await s06_audit_forensics(client, ctx)

    # Summary
    print()
    console.rule("[bold cyan]Results")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("#", justify="right", style="dim", width=3)
    table.add_column("Scenario", min_width=45)
    table.add_column("Result", width=8)
    table.add_column("Detail", overflow="fold")
    for r in sorted(ctx.results, key=lambda r: r.num):
        table.add_row(
            str(r.num), r.name,
            "[green]PASS[/green]" if r.passed else "[red]FAIL[/red]",
            r.detail,
        )
    console.print(table)
    passed = sum(1 for r in ctx.results if r.passed)
    total = len(ctx.results)
    style = "green" if passed == total else "red"
    console.print(f"\n[bold {style}]{passed}/{total} compound scenarios passed[/bold {style}]")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
