/**
 * Scenario 13: SecureChannel for fleet telemetry, with replay and
 * recipient binding defence.
 *
 * The story
 * ---------
 * A telematics platform collects signed status packets from a fleet
 * of industrial IoT devices ("edge"). The packets travel over a
 * message bus (Kafka, NATS, RabbitMQ, S3 drop, doesn't matter) back
 * to a control plane service ("control"). The operator needs three
 * guarantees on every packet:
 *
 *     1. Integrity and authenticity. The packet came from the device
 *        that signed it, nothing was changed in transit.
 *     2. Confidentiality. A nosey cloud operator with bus read access
 *        cannot read the payload.
 *     3. No replay, no cross talk. An attacker who captures one packet
 *        cannot inject it back on the bus to trigger a re-processing,
 *        and cannot re-use a packet addressed to control against a
 *        different recipient service.
 *
 * TLS (or mTLS) would cover 1 and 2 on a point to point link. But the
 * bus here is a message queue, not a socket. The sender and receiver
 * are decoupled. Any signed blob the bus holds can be picked up,
 * copied, replayed, or forwarded to a different recipient unless the
 * signing and encryption layer above the bus binds every message to
 * a specific sender-recipient pair plus a monotonic context and
 * tracks nonces.
 *
 * Kavach's SecureChannel does exactly this. You hand it your own
 * KavachKeyPair and the remote party's PublicKeyBundle and you get
 * `sendSigned(data, contextId, correlationId)` and
 * `receiveSigned(sealed, expectedContextId)`. Under the hood:
 *
 *     ML-KEM-768 + X25519 for the key exchange (hybrid post quantum
 *         and classical, so breaking either alone does not break the
 *         confidentiality),
 *     ChaCha20-Poly1305 for the AEAD body (with the recipient key id
 *         bound into the AAD),
 *     ML-DSA-65 for the sender's signature (post quantum),
 *     and a nonce cache on each side to catch replays.
 *
 * TLS and JWT each solve pieces of this, but neither binds a
 * message to a specific sender + recipient + context across a
 * decoupled bus. Kavach's SecureChannel does, which is the gap
 * this scenario fills.
 *
 * Five cases:
 *
 *     A. Happy path. Edge signs a packet, control receives it, the
 *        inner payload matches what was sent.
 *     B. Replay. The operator captures the sealed bytes off the bus
 *        and hands them to control a second time. receiveSigned()
 *        refuses with replay detected.
 *     C. Wrong recipient. An attacker forwards a packet that edge
 *        signed for control to a separate 'relay' service instead.
 *        The relay has its own keypair and opens its own SecureChannel
 *        with edge, but the sealed payload was addressed to control.
 *        relay.receiveSigned() refuses because the recipient key id
 *        inside the AEAD does not match its own.
 *     D. Wrong context. The operator captures a packet that was
 *        signed with contextId='fleet.telemetry' and tries to pass
 *        it into a handler that expects contextId='fleet.command'.
 *        Kavach rejects before returning bytes.
 *     E. Tamper. An attacker flips one byte inside the sealed blob.
 *        The AEAD tag fails, receiveSigned refuses.
 *
 * Run this file directly:
 *
 *   node dist/tier3/13_secure_channel_fleet.js
 */

import { KavachKeyPair, SecureChannel } from 'kavach-sdk';

function main(): number {
  console.log('='.repeat(70));
  console.log('Scenario 13: SecureChannel for fleet telemetry, adversarial');
  console.log('='.repeat(70));
  console.log();
  console.log('We are going to build three keypairs (edge, control, relay),');
  console.log('wire SecureChannels between them, send a signed telemetry');
  console.log('packet, and then try four different attacks on the bus. The');
  console.log("channel's replay cache, recipient binding, context binding,");
  console.log('and AEAD tag each catch a different shape of attack.');
  console.log();

  const results: [string, boolean][] = [];

  // -----------------------------------------------------------------
  // Three keypairs, one per node.
  // -----------------------------------------------------------------
  console.log('Generating keypairs for edge, control, and a rogue relay.');
  const edgeKp = KavachKeyPair.generate();
  const controlKp = KavachKeyPair.generate();
  const relayKp = KavachKeyPair.generate();
  const edgeBundle = edgeKp.publicKeys();
  const controlBundle = controlKp.publicKeys();
  // relayBundle would be needed if anyone wanted to send to relay; here
  // relay only receives, so we do not pull its bundle out separately.
  console.log(`  edge.key_id:    ${edgeKp.id}`);
  console.log(`  control.key_id: ${controlKp.id}`);
  console.log(`  relay.key_id:   ${relayKp.id}`);
  console.log();

  // -----------------------------------------------------------------
  // Channels. edge has one view of the conversation, control has
  // another. Each side constructs its own SecureChannel from its own
  // keypair plus the remote party's bundle. The two channels share
  // nothing (no "server" in the middle). relay does the same to
  // pretend it was the intended recipient.
  // -----------------------------------------------------------------
  console.log('Building SecureChannel endpoints.');
  const edgeToControl = new SecureChannel(edgeKp, controlBundle);
  const controlToEdge = new SecureChannel(controlKp, edgeBundle);
  const relayToEdge = new SecureChannel(relayKp, edgeBundle);
  console.log(`  edgeToControl.localKeyId:  ${edgeToControl.localKeyId}`);
  console.log(`  edgeToControl.remoteKeyId: ${edgeToControl.remoteKeyId}`);
  console.log(`  controlToEdge.localKeyId:  ${controlToEdge.localKeyId}`);
  console.log(`  controlToEdge.remoteKeyId: ${controlToEdge.remoteKeyId}`);
  console.log();

  const telemetryPayload = Buffer.from(
    '{"device":"pump-03","temp_c":72.4,"pressure_bar":4.1,"ts":1776000000}',
    'utf-8',
  );
  const contextId = 'fleet.telemetry';
  const correlationId = 'msg-0001';

  // -----------------------------------------------------------------
  // Case A: happy path.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case A: edge signs + encrypts a telemetry packet, control reads it.');
  console.log('-'.repeat(70));
  console.log('edge calls sendSigned(payload, contextId, correlationId).');
  console.log('It returns sealed bytes we can drop onto the bus verbatim.');
  console.log('control calls receiveSigned(sealed, expectedContextId)');
  console.log('and gets the original payload back. No extra crypto plumbing');
  console.log('in the scenario code; it is all inside the channel.');
  console.log();

  const sealed = edgeToControl.sendSigned(telemetryPayload, contextId, correlationId);
  console.log(`  sealed length: ${sealed.length} bytes`);
  console.log(`  plaintext length: ${telemetryPayload.length} bytes`);
  const received = controlToEdge.receiveSigned(sealed, contextId);
  console.log(`  received: ${received.toString('utf-8')}`);
  console.log();

  results.push([
    'Case A: control receives the original bytes',
    Buffer.compare(received, telemetryPayload) === 0,
  ]);

  // -----------------------------------------------------------------
  // Case B: replay.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case B: operator captures sealed bytes and replays them.');
  console.log('-'.repeat(70));
  console.log('The exact same sealed blob is handed to control a second');
  console.log("time, unchanged. The channel's nonce cache remembers the");
  console.log('correlation id and the signature; the second call refuses');
  console.log('with a replay error. This protects against a Kafka partition');
  console.log('re-read, a malicious bus admin, or an at-least-once delivery');
  console.log('quirk turning into a duplicate side effect.');
  console.log();

  let refused = false;
  let msg = '';
  try {
    controlToEdge.receiveSigned(sealed, contextId);
  } catch (e) {
    refused = true;
    msg = (e as Error).message;
  }
  console.log(`  receiveSigned raised: ${refused}`);
  console.log(`  message (first 180 chars): ${msg.slice(0, 180)}`);
  console.log();

  {
    const lower = msg.toLowerCase();
    const ok = refused && (lower.includes('replay') || lower.includes('nonce'));
    results.push(['Case B: replay detected', ok]);
  }

  // -----------------------------------------------------------------
  // Case C: wrong recipient.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case C: attacker forwards the sealed packet to a rogue relay.');
  console.log('-'.repeat(70));
  console.log('Imagine the bus has a public mirror topic and a rogue relay');
  console.log('service is reading it. Relay opens its own SecureChannel');
  console.log('with edge and tries to receiveSigned(sealed, contextId).');
  console.log("But the sealed payload's AEAD had control's key id bound");
  console.log("into the AAD. Relay's channel sees a recipient mismatch and");
  console.log('refuses. Even if relay has the exact same ML-KEM public key');
  console.log('length, the binding does not line up.');
  console.log();

  // Fresh sealed blob (not the replayed one) to isolate the failure
  // to the recipient mismatch, not the replay cache.
  const sealedForControl = edgeToControl.sendSigned(
    telemetryPayload,
    contextId,
    'msg-0002',
  );
  refused = false;
  msg = '';
  try {
    relayToEdge.receiveSigned(sealedForControl, contextId);
  } catch (e) {
    refused = true;
    msg = (e as Error).message;
  }
  console.log(`  relay.receiveSigned raised: ${refused}`);
  console.log(`  message (first 180 chars): ${msg.slice(0, 180)}`);
  console.log();

  results.push(['Case C: wrong recipient refused', refused]);

  // -----------------------------------------------------------------
  // Case D: wrong context.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case D: attacker replays a telemetry packet into a command handler.');
  console.log('-'.repeat(70));
  console.log("A legitimate control plane handler for 'fleet.command' tries");
  console.log('to receiveSigned on a packet that edge signed with the');
  console.log("contextId 'fleet.telemetry'. The signature covers the");
  console.log('context binding, so the handler sees a context mismatch and');
  console.log("refuses. This is the defence against 'this packet was real,");
  console.log("I am just going to feed it into a different code path'.");
  console.log();

  const sealedTelemetry = edgeToControl.sendSigned(
    telemetryPayload,
    'fleet.telemetry',
    'msg-0003',
  );
  refused = false;
  msg = '';
  try {
    controlToEdge.receiveSigned(sealedTelemetry, 'fleet.command');
  } catch (e) {
    refused = true;
    msg = (e as Error).message;
  }
  console.log(`  receiveSigned(expected='fleet.command') raised: ${refused}`);
  console.log(`  message (first 180 chars): ${msg.slice(0, 180)}`);
  console.log();

  {
    const lower = msg.toLowerCase();
    const ok = refused && (lower.includes('context') || lower.includes('mismatch'));
    results.push(['Case D: context mismatch refused', ok]);
  }

  // -----------------------------------------------------------------
  // Case E: tamper.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case E: attacker flips one byte inside the sealed blob.');
  console.log('-'.repeat(70));
  console.log('A bus admin edits one byte somewhere in the sealed bytes.');
  console.log("The AEAD's Poly1305 tag no longer matches the ciphertext +");
  console.log('AAD. receiveSigned refuses with a decrypt / authenticity');
  console.log('error, without ever producing a plaintext.');
  console.log();

  const sealedClean = edgeToControl.sendSigned(
    telemetryPayload,
    contextId,
    'msg-0004',
  );
  // Flip a byte roughly in the middle of the envelope so we hit
  // ciphertext rather than the outer JSON wrapper.
  const tampered = Buffer.from(sealedClean);
  const mid = Math.floor(tampered.length / 2);
  tampered[mid] = tampered[mid]! ^ 0x20;

  refused = false;
  msg = '';
  try {
    controlToEdge.receiveSigned(tampered, contextId);
  } catch (e) {
    refused = true;
    msg = (e as Error).message;
  }
  console.log(`  receiveSigned raised: ${refused}`);
  console.log(`  message (first 180 chars): ${msg.slice(0, 180)}`);
  console.log();

  results.push(['Case E: tampered sealed bytes refused', refused]);

  // -----------------------------------------------------------------
  // Summary
  // -----------------------------------------------------------------
  console.log('='.repeat(70));
  console.log('Summary');
  console.log('='.repeat(70));
  const passed = results.filter(([, ok]) => ok).length;
  for (const [label, ok] of results) {
    const mark = ok ? 'PASS' : 'FAIL';
    console.log(`  [${mark}] ${label}`);
  }
  console.log();
  console.log(`${passed}/${results.length} checks passed.`);
  console.log();

  return passed === results.length ? 0 : 1;
}

process.exit(main());
