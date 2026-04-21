"""
Scenario 13: SecureChannel for fleet telemetry, with replay and
recipient binding defence.

The story
---------
A telematics platform collects signed status packets from a fleet
of industrial IoT devices ("edge"). The packets travel over a
message bus (Kafka, NATS, RabbitMQ, S3 drop, doesn't matter) back
to a control plane service ("control"). The operator needs three
guarantees on every packet:

    1. Integrity and authenticity. The packet came from the device
       that signed it, nothing was changed in transit.
    2. Confidentiality. A nosey cloud operator with bus read access
       cannot read the payload.
    3. No replay, no cross talk. An attacker who captures one packet
       cannot inject it back on the bus to trigger a re-processing,
       and cannot re-use a packet addressed to control against a
       different recipient service.

TLS (or mTLS) would cover 1 and 2 on a point to point link. But the
bus here is a message queue, not a socket. The sender and receiver
are decoupled. Any signed blob the bus holds can be picked up,
copied, replayed, or forwarded to a different recipient unless the
signing and encryption layer above the bus binds every message to
a specific sender-recipient pair plus a monotonic context and
tracks nonces.

Kavach's SecureChannel does exactly this. You hand it your own
KavachKeyPair and the remote party's PublicKeyBundle and you get
`send_signed(data, context_id, correlation_id)` and
`receive_signed(sealed, expected_context_id)`. Under the hood:

    ML-KEM-768 + X25519 for the key exchange (hybrid post quantum
        and classical, so breaking either alone does not break the
        confidentiality),
    ChaCha20-Poly1305 for the AEAD body (with the recipient key id
        bound into the AAD),
    ML-DSA-65 for the sender's signature (post quantum),
    and a nonce cache on each side to catch replays.

TLS and JWT each solve pieces of this, but neither binds a
message to a specific sender + recipient + context across a
decoupled bus. Kavach's SecureChannel does, which is the gap
this scenario fills.

Five cases:

    A. Happy path. Edge signs a packet, control receives it, the
       inner payload matches what was sent.
    B. Replay. The operator captures the sealed bytes off the bus
       and hands them to control a second time. receive_signed()
       refuses with replay detected.
    C. Wrong recipient. An attacker forwards a packet that edge
       signed for control to a separate 'relay' service instead.
       The relay has its own keypair and opens its own SecureChannel
       with edge, but the sealed payload was addressed to control.
       relay.receive_signed() refuses because the recipient key id
       inside the AEAD does not match its own.
    D. Wrong context. The operator captures a packet that was
       signed with context_id='fleet.telemetry' and tries to pass
       it into a handler that expects context_id='fleet.command'.
       Kavach rejects before returning bytes.
    E. Tamper. An attacker flips one byte inside the sealed blob.
       The AEAD tag fails, receive_signed refuses.

Run this file directly:

    python tier3/13_secure_channel_fleet.py
"""

from kavach import KavachKeyPair, SecureChannel


def main():
    print("=" * 70)
    print("Scenario 13: SecureChannel for fleet telemetry, adversarial")
    print("=" * 70)
    print()
    print("We are going to build three keypairs (edge, control, relay),")
    print("wire SecureChannels between them, send a signed telemetry")
    print("packet, and then try four different attacks on the bus. The")
    print("channel's replay cache, recipient binding, context binding,")
    print("and AEAD tag each catch a different shape of attack.")
    print()

    results = []

    # -----------------------------------------------------------------
    # Three keypairs, one per node.
    # -----------------------------------------------------------------
    print("Generating keypairs for edge, control, and a rogue relay.")
    edge_kp = KavachKeyPair.generate()
    control_kp = KavachKeyPair.generate()
    relay_kp = KavachKeyPair.generate()
    edge_bundle = edge_kp.public_keys()
    control_bundle = control_kp.public_keys()
    relay_bundle = relay_kp.public_keys()
    print(f"  edge.key_id:    {edge_kp.id}")
    print(f"  control.key_id: {control_kp.id}")
    print(f"  relay.key_id:   {relay_kp.id}")
    print()

    # -----------------------------------------------------------------
    # Channels. edge has one view of the conversation, control has
    # another. Each side constructs its own SecureChannel from its own
    # keypair plus the remote party's bundle. The two channels share
    # nothing (no "server" in the middle). relay does the same to
    # pretend it was the intended recipient.
    # -----------------------------------------------------------------
    print("Building SecureChannel endpoints.")
    edge_to_control = SecureChannel(edge_kp, control_bundle)
    control_to_edge = SecureChannel(control_kp, edge_bundle)
    relay_to_edge = SecureChannel(relay_kp, edge_bundle)
    print(f"  edge_to_control.local_key_id:  {edge_to_control.local_key_id}")
    print(f"  edge_to_control.remote_key_id: {edge_to_control.remote_key_id}")
    print(f"  control_to_edge.local_key_id:  {control_to_edge.local_key_id}")
    print(f"  control_to_edge.remote_key_id: {control_to_edge.remote_key_id}")
    print()

    telemetry_payload = b'{"device":"pump-03","temp_c":72.4,"pressure_bar":4.1,"ts":1776000000}'
    context_id = "fleet.telemetry"
    correlation_id = "msg-0001"

    # -----------------------------------------------------------------
    # Case A: happy path.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case A: edge signs + encrypts a telemetry packet, control reads it.")
    print("-" * 70)
    print("edge calls send_signed(payload, context_id, correlation_id).")
    print("It returns sealed bytes we can drop onto the bus verbatim.")
    print("control calls receive_signed(sealed, expected_context_id)")
    print("and gets the original payload back. No extra crypto plumbing")
    print("in the scenario code; it is all inside the channel.")
    print()

    sealed = bytes(edge_to_control.send_signed(telemetry_payload, context_id, correlation_id))
    print(f"  sealed length: {len(sealed)} bytes")
    print(f"  plaintext length: {len(telemetry_payload)} bytes")
    received = bytes(control_to_edge.receive_signed(sealed, context_id))
    print(f"  received: {received.decode('utf-8')}")
    print()

    results.append(("Case A: control receives the original bytes",
                    received == telemetry_payload))

    # -----------------------------------------------------------------
    # Case B: replay.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case B: operator captures sealed bytes and replays them.")
    print("-" * 70)
    print("The exact same sealed blob is handed to control a second")
    print("time, unchanged. The channel's nonce cache remembers the")
    print("correlation id and the signature; the second call refuses")
    print("with a replay error. This protects against a Kafka partition")
    print("re-read, a malicious bus admin, or an at-least-once delivery")
    print("quirk turning into a duplicate side effect.")
    print()

    refused = False
    msg = ""
    try:
        control_to_edge.receive_signed(sealed, context_id)
    except ValueError as e:
        refused = True
        msg = str(e)
    print(f"  receive_signed raised: {refused}")
    print(f"  message (first 180 chars): {msg[:180]}")
    print()

    ok = refused and ("replay" in msg.lower() or "nonce" in msg.lower())
    results.append(("Case B: replay detected", ok))

    # -----------------------------------------------------------------
    # Case C: wrong recipient.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case C: attacker forwards the sealed packet to a rogue relay.")
    print("-" * 70)
    print("Imagine the bus has a public mirror topic and a rogue relay")
    print("service is reading it. Relay opens its own SecureChannel")
    print("with edge and tries to receive_signed(sealed, context_id).")
    print("But the sealed payload's AEAD had control's key id bound")
    print("into the AAD. Relay's channel sees a recipient mismatch and")
    print("refuses. Even if relay has the exact same ML-KEM public key")
    print("length, the binding does not line up.")
    print()

    # Fresh sealed blob (not the replayed one) to isolate the failure
    # to the recipient mismatch, not the replay cache.
    sealed_for_control = bytes(edge_to_control.send_signed(
        telemetry_payload,
        context_id,
        "msg-0002",
    ))
    refused = False
    msg = ""
    try:
        relay_to_edge.receive_signed(sealed_for_control, context_id)
    except ValueError as e:
        refused = True
        msg = str(e)
    print(f"  relay.receive_signed raised: {refused}")
    print(f"  message (first 180 chars): {msg[:180]}")
    print()

    ok = refused
    results.append(("Case C: wrong recipient refused", ok))

    # -----------------------------------------------------------------
    # Case D: wrong context.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case D: attacker replays a telemetry packet into a command handler.")
    print("-" * 70)
    print("A legitimate control plane handler for 'fleet.command' tries")
    print("to receive_signed on a packet that edge signed with the")
    print("context_id 'fleet.telemetry'. The signature covers the")
    print("context binding, so the handler sees a context mismatch and")
    print("refuses. This is the defence against 'this packet was real,")
    print("I am just going to feed it into a different code path'.")
    print()

    sealed_telemetry = bytes(edge_to_control.send_signed(
        telemetry_payload,
        "fleet.telemetry",
        "msg-0003",
    ))
    refused = False
    msg = ""
    try:
        control_to_edge.receive_signed(sealed_telemetry, "fleet.command")
    except ValueError as e:
        refused = True
        msg = str(e)
    print(f"  receive_signed(expected='fleet.command') raised: {refused}")
    print(f"  message (first 180 chars): {msg[:180]}")
    print()

    ok = refused and ("context" in msg.lower() or "mismatch" in msg.lower())
    results.append(("Case D: context mismatch refused", ok))

    # -----------------------------------------------------------------
    # Case E: tamper.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case E: attacker flips one byte inside the sealed blob.")
    print("-" * 70)
    print("A bus admin edits one byte somewhere in the sealed bytes.")
    print("The AEAD's Poly1305 tag no longer matches the ciphertext +")
    print("AAD. receive_signed refuses with a decrypt / authenticity")
    print("error, without ever producing a plaintext.")
    print()

    sealed_clean = bytes(edge_to_control.send_signed(
        telemetry_payload,
        context_id,
        "msg-0004",
    ))
    # Flip a byte roughly in the middle of the envelope so we hit
    # ciphertext rather than the outer JSON wrapper.
    mid = len(sealed_clean) // 2
    tampered = sealed_clean[:mid] + bytes([sealed_clean[mid] ^ 0x20]) + sealed_clean[mid + 1:]

    refused = False
    msg = ""
    try:
        control_to_edge.receive_signed(tampered, context_id)
    except ValueError as e:
        refused = True
        msg = str(e)
    print(f"  receive_signed raised: {refused}")
    print(f"  message (first 180 chars): {msg[:180]}")
    print()

    results.append(("Case E: tampered sealed bytes refused", refused))

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
