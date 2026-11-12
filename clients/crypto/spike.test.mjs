import test from 'node:test';
import assert from 'node:assert/strict';
import { Device, Relay, fixturePins, offlineExchange } from './spike.mjs';
import { decodeGroupState, decodeMlsMessage, encodeMlsMessage } from 'ts-mls';

async function pair() {
  const alice = await Device.enroll('tenant-a/alice');
  const bob = await Device.enroll('tenant-b/bob');
  const pins = fixturePins(alice.publicPackage, bob.publicPackage);
  const session = crypto.randomUUID();
  const welcome = await alice.start(bob.publicPackage, session, pins);
  await bob.join(welcome, alice.identity, session, pins);
  return { alice, bob, pins, session, welcome };
}

test('offline initiation, delayed decrypt after private state restoration, and reply', async () => {
  assert.equal((await offlineExchange()).reply, 'pass');
});

test('ciphertext tamper rejects without consuming the valid message', async () => {
  const { alice, bob } = await pair();
  const original = await alice.send('synthetic tamper probe');
  const altered = structuredClone(original);
  altered.wire[altered.wire.length - 1] ^= 1;
  await assert.rejects(bob.receive(altered));
  assert.equal(await bob.receive(original), 'synthetic tamper probe');
});

test('routing identity, recipient, session and message ID mutation rejects', async () => {
  const { alice, bob } = await pair();
  const packet = await alice.send('synthetic metadata probe');
  for (const key of ['from', 'to', 'session', 'id']) {
    await assert.rejects(bob.receive({ ...packet, [key]: 'other' }));
  }
  assert.equal(await bob.receive(packet), 'synthetic metadata probe');
});

test('rewriting both visible AAD and routing metadata still fails cryptographic authentication', async () => {
  const { alice, bob } = await pair();
  const original = await alice.send('authenticated metadata');
  const packet = { ...original, id: 'attacker-replacement' };
  const [message] = decodeMlsMessage(original.wire, 0);
  message.privateMessage.authenticatedData = new TextEncoder().encode(JSON.stringify(
    ['amdn-f0-spike-v1', packet.session, packet.from, packet.to, packet.id],
  ));
  packet.wire = encodeMlsMessage(message);
  await assert.rejects(bob.receive(packet));
  assert.equal(await bob.receive(original), 'authenticated metadata');
});

test('public key package signature mutation rejects despite matching identity pins', async () => {
  const alice = await Device.enroll('alice');
  const bob = await Device.enroll('bob');
  const pins = fixturePins(alice.publicPackage, bob.publicPackage);
  const corrupted = bob.publicPackage;
  corrupted[corrupted.length - 1] ^= 1;
  await assert.rejects(alice.start(corrupted, 'tampered-key-package', pins));
});

test('reordered messages decrypt once; committed restored state rejects duplicates', async () => {
  const { alice, bob } = await pair();
  const first = await alice.send('first');
  const second = await alice.send('second');
  assert.equal(await bob.receive(second), 'second');
  assert.equal(await bob.receive(first), 'first');
  await assert.rejects(bob.receive(first));
  const restored = Device.restore(bob.checkpoint());
  await assert.rejects(restored.receive(second));
  assert.equal(await restored.receive(await alice.send('after restart')), 'after restart');
});

test('stale private checkpoint permits replay: durable anti-rollback remains a release blocker', async () => {
  const { alice, bob } = await pair();
  const stale = bob.checkpoint();
  const packet = await alice.send('rollback demonstration');
  assert.equal(await bob.receive(packet), 'rollback demonstration');
  await assert.rejects(bob.receive(packet));
  assert.equal(await Device.restore(stale).receive(packet), 'rollback demonstration');
});

test('new device key is refused under old pins; explicit verification starts a fresh session', async () => {
  const { alice, bob, pins, session, welcome } = await pair();
  const replacement = await Device.enroll(bob.identity);
  const newAlice = await Device.enroll(alice.identity);
  await assert.rejects(newAlice.start(replacement.publicPackage, 'replacement', pins), /key changed|unverified/);
  await assert.rejects(replacement.join(welcome, alice.identity, session, pins));
  const approvedPins = fixturePins(newAlice.publicPackage, replacement.publicPackage);
  const newWelcome = await newAlice.start(replacement.publicPackage, 'verified-replacement', approvedPins);
  await replacement.join(newWelcome, newAlice.identity, 'verified-replacement', approvedPins);
  assert.equal(await replacement.receive(await newAlice.send('new session')), 'new session');
  await assert.rejects(bob.receive(await newAlice.send('old device excluded')));
});

test('different group cannot decrypt even after routing metadata is transplanted', async () => {
  const one = await pair();
  const two = await pair();
  const packet = await one.alice.send('wrong group');
  await assert.rejects(two.bob.receive({ ...packet, session: two.session }));
});

test('provider records contain only wire bytes, public routing and no private checkpoint', async () => {
  const { alice, bob, welcome } = await pair();
  const relay = new Relay();
  const plaintext = 'SYNTHETIC-PLAINTEXT-CANARY-DO-NOT-LOG';
  const packet = await alice.send(plaintext);
  relay.store('key-package', alice.identity, bob.publicPackage);
  relay.store('welcome', bob.identity, welcome);
  relay.store('application', bob.identity, packet.wire);
  const [receiverState] = decodeGroupState(bob.checkpoint().state, 0);
  for (const record of relay.inspect()) {
    assert.deepEqual(Object.keys(record).sort(), ['bytes', 'kind', 'to']);
    assert.equal(new TextDecoder().decode(Uint8Array.from(record.bytes)).includes(plaintext), false);
    assert.equal(Buffer.from(record.bytes).includes(Buffer.from(bob.checkpoint().state)), false);
    assert.equal(Buffer.from(record.bytes).includes(Buffer.from(receiverState.signaturePrivateKey)), false);
  }
  assert.equal(await bob.receive({ ...packet, wire: relay.read(2) }), plaintext);
});

test('truncated, trailing, oversized and non-MLS records reject', async () => {
  const { alice, bob } = await pair();
  const packet = await alice.send('valid');
  for (const bytes of [new Uint8Array(), packet.wire.slice(0, 10),
    Uint8Array.from([...packet.wire, 0]), new Uint8Array(128 * 1024 + 1), alice.publicPackage]) {
    await assert.rejects(bob.receive({ ...packet, wire: bytes }));
  }
  assert.equal(await bob.receive(packet), 'valid');
});

test('overlapping operations on one device fail instead of reusing send state', async () => {
  const { alice, bob } = await pair();
  const first = alice.send('serialized');
  await assert.rejects(alice.send('overlap'), /Concurrent/);
  assert.equal(await bob.receive(await first), 'serialized');
});
