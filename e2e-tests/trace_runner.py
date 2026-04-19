"""Trace runner: walk through 4 key Kavach flows showing every byte of data.

This isn't a test suite, it's a narrated tour. It runs a small number of
end-to-end operations and dumps every HTTP body, every PermitToken, every
audit entry, every directory blob to stdout so you can read exactly what
Kavach moves on the wire.

Flows walked:

    FLOW 1: happy-path refund (agent → gate → permit → payment → audit)
    FLOW 2: rejected attack   (forged signature, shown byte-for-byte)
    FLOW 3: directory rotation (old manifest bytes, new manifest bytes,
                                old permit that now fails)
    FLOW 4: audit-entry anatomy (hash linkage, signed_payload structure,
                                 verify + tamper visible at byte level)

Run:

    source ../kavach-py/.venv/bin/activate
    python trace_runner.py
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
import time
import uuid
from pathlib import Path
from typing import Any

import httpx
import uvicorn
from kavach import KavachKeyPair, PermitToken, PqTokenSigner, SignedAuditChain
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax

from bootstrap import setup
import payment_service
import support_agent

# ─── Setup ───────────────────────────────────────────────────────────

logging.basicConfig(level=logging.WARNING)  # tame the service logs, trace output is the focus

console = Console(width=120)

AGENT_HOST, AGENT_PORT = "127.0.0.1", 8201
PAY_HOST, PAY_PORT = "127.0.0.1", 8202
STATE_DIR = Path(__file__).parent / "state_trace"
POLICY_PATH = Path(__file__).parent / "kavach_policies.toml"
AUDIT_PATH = STATE_DIR / "audit.jsonl"

# ─── Formatting helpers ──────────────────────────────────────────────


def hex_preview(b: bytes | list[int], max_show: int = 16) -> str:
    """Short hex summary, first N bytes + total length."""
    if isinstance(b, list):
        b = bytes(b)
    head = b[:max_show].hex()
    if len(b) > max_show:
        return f"{head}… ({len(b)} bytes)"
    return f"{head} ({len(b)} bytes)"


def pretty_json(obj: Any, *, title: str | None = None, truncate_bytes_at: int = 32) -> None:
    """Pretty-print a JSON object with long byte arrays truncated.

    Kavach payloads contain 3.3 KB ML-DSA signatures and 1.9 KB verifying
    keys, dumping them raw swamps the screen. This helper renders them as
    `<3293 bytes: a1b2c3...>` strings so the surrounding structure stays
    readable while the presence + size of the data is obvious.
    """
    rendered = _render(obj, truncate_bytes_at)
    text = json.dumps(rendered, indent=2)
    syntax = Syntax(text, "json", theme="monokai", background_color="default", word_wrap=True)
    console.print(Panel(syntax, title=title, border_style="cyan", expand=False))


def _render(obj: Any, thresh: int) -> Any:
    if isinstance(obj, list) and obj and all(isinstance(x, int) and 0 <= x <= 255 for x in obj):
        if len(obj) > thresh:
            return f"<{len(obj)} bytes: {bytes(obj[:8]).hex()}…>"
        return bytes(obj).hex()
    if isinstance(obj, dict):
        return {k: _render(v, thresh) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_render(x, thresh) for x in obj]
    if isinstance(obj, str) and len(obj) > 200 and all(c in "0123456789abcdef" for c in obj):
        return f"<{len(obj) // 2} bytes hex: {obj[:40]}…>"
    return obj


def heading(title: str) -> None:
    console.print()
    console.rule(f"[bold cyan]{title}[/bold cyan]")
    console.print()


def step(num: float, what: str) -> None:
    console.print(f"[yellow bold]Step {num}:[/yellow bold] {what}")


# ─── Instrumented HTTP client: dumps every request + response ────────


class TracingClient:
    """Thin wrapper around httpx.AsyncClient that prints every POST body
    (request and response) so the wire-level flow is visible."""

    def __init__(self, inner: httpx.AsyncClient):
        self.inner = inner

    async def post(self, url: str, json_body: dict, *, label: str) -> httpx.Response:
        pretty_json(json_body, title=f"▶ POST {url}   ({label})", truncate_bytes_at=32)
        resp = await self.inner.post(url, json=json_body)
        try:
            body = resp.json()
        except Exception:
            body = {"_raw_text": resp.text}
        pretty_json(
            {"status": resp.status_code, "body": body},
            title=f"◀ response   ({label})",
            truncate_bytes_at=32,
        )
        return resp


# ─── Server bring-up ─────────────────────────────────────────────────


async def start_server(app, host: str, port: int) -> uvicorn.Server:
    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    server = uvicorn.Server(config)
    asyncio.create_task(server.serve())
    for _ in range(200):
        if server.started:
            return server
        await asyncio.sleep(0.05)
    raise RuntimeError(f"server on :{port} didn't start")


# ─── FLOW 1: happy-path refund end-to-end ────────────────────────────


async def flow_1_happy_path(tc: TracingClient) -> None:
    heading("FLOW 1, Happy-path refund")
    console.print(
        "Follow a single legitimate refund from the 'agent decides to issue' "
        "step all the way to the 'payment service processes it' step. Every "
        "payload on the wire is printed.\n"
    )

    step(1.1, "Runner → Agent: POST /agent/tool with the tool-call args")
    resp = await tc.post(
        f"http://{AGENT_HOST}:{AGENT_PORT}/agent/tool",
        {
            "caller_id": "agent-bot",
            "action_name": "issue_refund",
            "params": {"amount": 500.0},
            "principal_kind": "agent",
            "origin_country": "IN",
            "current_country": "IN",
        },
        label="tool call",
    )
    data = resp.json()

    step(1.2, "Agent response → Runner: PermitToken + signature envelope")
    console.print(
        "The `permit_token` dict is the exact fields the payment service will "
        "need to reconstruct a `PermitToken` and verify it. `signature_hex` is "
        "the JSON-encoded SignedTokenEnvelope (algorithm + ml_dsa_signature + "
        "ed25519_signature + key_id), the cryptographic proof."
    )

    sig_hex = data["signature_hex"]
    sig_bytes = bytes.fromhex(sig_hex)
    envelope = json.loads(sig_bytes.decode())
    pretty_json(envelope, title="⤷ signature envelope (decoded from signature_hex)")

    step(1.3, "Runner → Payment: POST /payments/refund with permit + signature")
    resp2 = await tc.post(
        f"http://{PAY_HOST}:{PAY_PORT}/payments/refund",
        {
            "order_id": "O-001",
            "amount": 500.0,
            "permit": data["permit_token"],
            "signature_hex": sig_hex,
        },
        label="refund request",
    )

    step(1.4, "Payment response → Runner")
    console.print(
        "Under the hood the payment service did four checks:\n"
        "  (a) permit + signature present\n"
        "  (b) expires_at > now  (replay guard, application-level)\n"
        "  (c) action_name == 'issue_refund'  (reuse guard, application-level)\n"
        "  (d) DirectoryTokenVerifier.verify, looks up the key_id in the signed\n"
        "      directory, verifies BOTH ML-DSA-65 and Ed25519 signatures against\n"
        "      the PermitToken's canonical_bytes.\n"
        "Any of these failing would short-circuit to 401 with a specific reason."
    )
    assert resp2.status_code == 200


# ─── FLOW 2: forged signature rejected ───────────────────────────────


async def flow_2_forged_signature(tc: TracingClient) -> None:
    heading("FLOW 2, Attacker submits a forged signature")
    console.print(
        "Attacker captures a legit permit, replaces the signature bytes with "
        "zeros, POSTs to payment. Payment rejects at the signature verify step.\n"
    )

    step(2.1, "Capture a legit permit (happens the same way as flow 1)")
    resp = await tc.post(
        f"http://{AGENT_HOST}:{AGENT_PORT}/agent/tool",
        {
            "caller_id": "agent-bot",
            "action_name": "issue_refund",
            "params": {"amount": 500.0},
            "principal_kind": "agent",
            "origin_country": "IN",
            "current_country": "IN",
        },
        label="capture permit",
    )
    legit = resp.json()
    sig_len = len(bytes.fromhex(legit["signature_hex"]))

    step(2.2, "Forge: same permit body, zero out the signature bytes")
    forged_sig = "00" * sig_len
    console.print(
        f"legit signature_hex  = {legit['signature_hex'][:40]}… ({sig_len} bytes)\n"
        f"forged signature_hex = {forged_sig[:40]}… ({sig_len} bytes, all zero)"
    )

    step(2.3, "Runner → Payment: POST with forged signature")
    resp2 = await tc.post(
        f"http://{PAY_HOST}:{PAY_PORT}/payments/refund",
        {
            "order_id": "O-FORGE",
            "amount": 500.0,
            "permit": legit["permit_token"],
            "signature_hex": forged_sig,
        },
        label="forged attack",
    )
    assert resp2.status_code == 401

    step(2.4, "Result: 401 with 'invalid permit: verify failed: …' in detail")
    console.print(
        "The DirectoryTokenVerifier tried to JSON-decode the signature bytes "
        "into a SignedTokenEnvelope, and failed, because `\\x00\\x00\\x00…` "
        "isn't valid JSON. Different byte mutations would fail at different "
        "stages (envelope parse, algorithm mismatch, signature verify); every "
        "path fails closed."
    )


# ─── FLOW 3: directory rotation (with actual bytes shown) ────────────


async def flow_3_directory_rotation(
    tc: TracingClient, *, directory_path: Path, root_kp: KavachKeyPair, agent_kp: KavachKeyPair
) -> None:
    heading("FLOW 3, Directory rotation")
    console.print(
        "Ops team rotates the agent's signing key. The on-disk signed "
        "directory is rewritten with the new key's bundle; the payment "
        "service reloads; already-issued permits (signed by the old key) "
        "no longer verify because their key_id is gone from the directory.\n"
    )

    step(3.1, "Capture a permit signed by the current agent key (K1)")
    resp = await tc.post(
        f"http://{AGENT_HOST}:{AGENT_PORT}/agent/tool",
        {
            "caller_id": "agent-bot",
            "action_name": "issue_refund",
            "params": {"amount": 500.0},
            "principal_kind": "agent",
            "origin_country": "IN",
            "current_country": "IN",
        },
        label="capture K1 permit",
    )
    k1_permit = resp.json()

    step(3.2, "Directory on disk BEFORE rotation, entry is K1's bundle")
    before = json.loads(directory_path.read_bytes())
    # The signed manifest stores bundles_json as a raw JSON string, parse it
    # to show what's actually in there.
    before_bundles = json.loads(before["bundles_json"])
    pretty_json(
        {
            "bundles_json (parsed)": before_bundles,
            "manifest signature (ML-DSA-65 over bundles_json)": before["signature"],
        },
        title=f"directory.json   ({len(directory_path.read_bytes())} bytes on disk)",
    )

    step(3.3, "Runner generates K2, re-signs a fresh directory, overwrites the file")
    k2 = KavachKeyPair.generate()
    new_manifest_bytes = root_kp.build_signed_manifest([k2.public_keys()])
    directory_path.write_bytes(new_manifest_bytes)

    after = json.loads(directory_path.read_bytes())
    after_bundles = json.loads(after["bundles_json"])
    pretty_json(
        {
            "bundles_json (parsed)": after_bundles,
            "manifest signature": after["signature"],
        },
        title=f"directory.json AFTER rotation   ({len(new_manifest_bytes)} bytes)",
    )
    console.print(
        f"[dim]K1 key_id = {agent_kp.public_keys().id}\n"
        f"K2 key_id = {k2.public_keys().id}[/dim]"
    )

    step(3.4, "Payment reloads its DirectoryTokenVerifier from the new file")
    await tc.post(
        f"http://{PAY_HOST}:{PAY_PORT}/payments/admin/reload_directory",
        {},
        label="reload directory",
    )

    step(3.5, "Replay the K1 permit, verification fails (K1 not in directory)")
    r = await tc.post(
        f"http://{PAY_HOST}:{PAY_PORT}/payments/refund",
        {
            "order_id": "K1-REPLAY",
            "amount": 500.0,
            "permit": k1_permit["permit_token"],
            "signature_hex": k1_permit["signature_hex"],
        },
        label="K1 replay after rotation",
    )
    assert r.status_code == 401

    step(3.6, "Fresh permit signed with K2, accepted because K2 is in the new directory")
    signer_k2 = PqTokenSigner.from_keypair_hybrid(k2)
    tok = PermitToken(
        token_id=str(uuid.uuid4()),
        evaluation_id=str(uuid.uuid4()),
        issued_at=int(time.time()),
        expires_at=int(time.time()) + 30,
        action_name="issue_refund",
    )
    sig = signer_k2.sign(tok)
    r2 = await tc.post(
        f"http://{PAY_HOST}:{PAY_PORT}/payments/refund",
        {
            "order_id": "K2-FRESH",
            "amount": 500.0,
            "permit": {
                "token_id": tok.token_id,
                "evaluation_id": tok.evaluation_id,
                "issued_at": tok.issued_at,
                "expires_at": tok.expires_at,
                "action_name": tok.action_name,
                "key_id": signer_k2.key_id,
            },
            "signature_hex": sig.hex(),
        },
        label="K2 fresh permit",
    )
    assert r2.status_code == 200

    # Restore K1 so flow 4 can still export audit from this agent.
    restored = root_kp.build_signed_manifest([agent_kp.public_keys()])
    directory_path.write_bytes(restored)
    await tc.post(
        f"http://{PAY_HOST}:{PAY_PORT}/payments/admin/reload_directory",
        {},
        label="restore K1 directory",
    )


# ─── FLOW 4: audit chain anatomy ─────────────────────────────────────


async def flow_4_audit_anatomy(tc: TracingClient, *, agent_kp: KavachKeyPair) -> None:
    heading("FLOW 4, Audit chain anatomy")
    console.print(
        "Every gate decision (Permit AND Refuse) lands in a hash-chained, "
        "signature-bound JSONL log. We export it, show the entry structure, "
        "demonstrate the hash linkage, then tamper one byte and watch the "
        "chain-verify fail at a specific entry.\n"
    )

    step(4.1, "Export the audit chain to disk (produces signed JSONL)")
    resp = await tc.post(
        f"http://{AGENT_HOST}:{AGENT_PORT}/agent/audit/export", {},
        label="export audit",
    )
    chain_path = Path(resp.json()["path"])
    chain_bytes = chain_path.read_bytes()
    lines = [l for l in chain_bytes.decode().splitlines() if l.strip()]
    console.print(f"[dim]audit.jsonl: {len(lines)} entries, {len(chain_bytes)} bytes[/dim]")

    step(4.2, "Decode entry #0, show all layers: envelope, signed_payload, inner audit record")
    entry0 = json.loads(lines[0])
    pretty_json(entry0, title="entry #0, wire format")

    # The signed_payload.data is a byte array; decoding it reveals the human
    # audit record that was signed.
    inner = json.loads(bytes(entry0["signed_payload"]["data"]).decode())
    pretty_json(inner, title="entry #0, decoded signed_payload.data (the signed audit record)")

    step(4.3, "Show the hash chain linkage: entry #1.previous_hash == entry #0.entry_hash")
    if len(lines) >= 2:
        entry1 = json.loads(lines[1])
        prev = entry0["entry_hash"]
        seen = entry1["previous_hash"]
        linked = prev == seen
        console.print(
            f"  entry #0 entry_hash   = {prev}\n"
            f"  entry #1 previous_hash = {seen}\n"
            f"  chain linked: [{'green' if linked else 'red'}]{linked}[/]"
        )
        # Show a few more for pattern recognition
        for i in range(2, min(6, len(lines))):
            entry = json.loads(lines[i])
            console.print(
                f"  entry #{i}: previous_hash={entry['previous_hash'][:16]}…  "
                f"entry_hash={entry['entry_hash'][:16]}…"
            )

    step(4.4, "Clean verify, should succeed")
    try:
        SignedAuditChain.verify_jsonl(chain_bytes, agent_kp.public_keys(), hybrid=True)
        console.print("[green]  ✓ verify_jsonl clean, every entry signature checks out, every hash links[/green]")
    except Exception as err:
        console.print(f"[red]  ✗ clean verify unexpectedly failed: {err}[/red]")

    step(4.5, "Tamper: flip one byte in the MIDDLE of entry #0's signed_payload data. Verify again.")
    # Modify a byte inside signed_payload.data (the audit-record bytes).
    entry0_tamper = json.loads(lines[0])
    data_list = list(entry0_tamper["signed_payload"]["data"])
    flip_offset = len(data_list) // 2
    original_byte = data_list[flip_offset]
    data_list[flip_offset] = original_byte ^ 0x01
    entry0_tamper["signed_payload"]["data"] = data_list
    tampered = (json.dumps(entry0_tamper) + "\n" + "\n".join(lines[1:])).encode() + b"\n"

    console.print(
        f"  flipped byte at offset {flip_offset} inside signed_payload.data "
        f"(0x{original_byte:02x} → 0x{original_byte ^ 0x01:02x})"
    )
    try:
        SignedAuditChain.verify_jsonl(tampered, agent_kp.public_keys(), hybrid=True)
        console.print("[red]  ✗ verify UNEXPECTEDLY SUCCEEDED (bad)[/red]")
    except Exception as err:
        console.print(
            f"[green]  ✓ verify_jsonl rejected the tamper[/green]\n"
            f"    → error: [italic]{err}[/italic]"
        )


# ─── Main ────────────────────────────────────────────────────────────


async def main() -> int:
    console.rule("[bold magenta]Kavach data-flow trace[/bold magenta]")
    console.print(
        "Bringing up an in-process agent + payment service on ports 8201/8202. "
        "All HTTP traffic is printed request-and-response below.\n"
    )

    STATE_DIR.mkdir(exist_ok=True)
    bs = setup(STATE_DIR)

    agent_app = support_agent.build_app(
        keypair=bs.agent_kp, policy_path=POLICY_PATH, audit_path=AUDIT_PATH
    )
    await start_server(agent_app, AGENT_HOST, AGENT_PORT)
    pay_app = payment_service.build_app(
        directory_path=bs.directory_path, root_vk_path=bs.root_vk_path, hybrid=True
    )
    await start_server(pay_app, PAY_HOST, PAY_PORT)

    async with httpx.AsyncClient(timeout=10.0) as client:
        tc = TracingClient(client)
        await flow_1_happy_path(tc)
        await flow_2_forged_signature(tc)
        await flow_3_directory_rotation(
            tc,
            directory_path=bs.directory_path,
            root_kp=bs.root_kp,
            agent_kp=bs.agent_kp,
        )
        await flow_4_audit_anatomy(tc, agent_kp=bs.agent_kp)

    console.rule("[bold magenta]Trace complete[/bold magenta]")
    console.print(
        "\nEvery HTTP body above is exactly what crossed the wire. Every "
        "JSON object shown is the real in-memory representation. No "
        "post-processing or summarization.\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
