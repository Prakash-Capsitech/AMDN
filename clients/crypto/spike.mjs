// F0 experiment only: never import this module into the application.
import {
  createApplicationMessage, createCommit, createGroup, defaultCapabilities,
  defaultLifetime, decodeGroupState, decodeMlsMessage, emptyPskIndex,
  encodeGroupState, encodeMlsMessage, generateKeyPackage, getCiphersuiteFromName,
  getCiphersuiteImpl, joinGroup, makePskIndex, processPrivateMessage, zeroOutUint8Array,
} from 'ts-mls';
import { defaultClientConfig } from 'ts-mls/clientConfig.js';

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
export const suite = 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519';
const implementation = getCiphersuiteImpl(getCiphersuiteFromName(suite));
const MAX_WIRE = 128 * 1024;
const equal = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);

function decodeExact(decode, bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length > MAX_WIRE) throw new Error('Invalid wire size');
  const result = decode(bytes, 0);
  if (!result || result[1] !== bytes.length) throw new Error('Invalid or trailing wire data');
  return result[0];
}

function wire(kind, value) {
  return encodeMlsMessage({ version: 'mls10', wireformat: kind, ...value });
}

function publicPackage(bytes) {
  const message = decodeExact(decodeMlsMessage, bytes);
  if (message.wireformat !== 'mls_key_package') throw new Error('Expected public key package');
  return message.keyPackage;
}

// The harness supplies these pins out of band. A delivery-provider response is
// never sufficient to create/replace a pin. Real enrollment remains F0.4 work.
export function fixturePins(...packages) {
  return packages.map(bytes => {
    const keyPackage = publicPackage(bytes);
    return [decoder.decode(keyPackage.leafNode.credential.identity),
      Array.from(keyPackage.leafNode.signaturePublicKey)];
  });
}

function configFor(pins) {
  const trusted = new Map(structuredClone(pins));
  return {
    ...defaultClientConfig,
    keyRetentionConfig: { retainKeysForGenerations: 10, retainKeysForEpochs: 0, maximumForwardRatchetSteps: 100 },
    authService: {
      async validateCredential(credential, signatureKey) {
        if (credential.credentialType !== 'basic') return false;
        const expected = trusted.get(decoder.decode(credential.identity));
        return expected !== undefined && equal(signatureKey, expected);
      },
    },
  };
}

function label(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 128) throw new Error('Invalid routing label');
  return value;
}

function aad({ session, from, to, id }) {
  return encoder.encode(JSON.stringify(['amdn-f0-spike-v1', label(session), label(from), label(to), label(id)]));
}

export class Device {
  #identity;
  #keys;
  #state;
  #config;
  #pins;
  #peer;
  #session;
  #busy = false;

  static async enroll(identity) {
    const device = new Device();
    device.#identity = label(identity);
    device.#keys = await generateKeyPackage(
      { credentialType: 'basic', identity: encoder.encode(identity) },
      defaultCapabilities(), defaultLifetime, [], await implementation,
    );
    return device;
  }

  get identity() { return this.#identity; }
  get publicPackage() { return wire('mls_key_package', { keyPackage: this.#keys.publicPackage }); }

  // Serialize operations within one device; this is not a cross-tab storage lock.
  async #exclusive(operation) {
    if (this.#busy) throw new Error('Concurrent device operation');
    this.#busy = true;
    try { return await operation(); } finally { this.#busy = false; }
  }

  #configure(peer, session, pins) {
    if (this.#state) throw new Error('Use a new device/session for explicit replacement');
    this.#peer = label(peer);
    this.#session = label(session);
    this.#pins = structuredClone(pins);
    this.#config = configFor(pins);
  }

  async start(peerPackage, session, pins) {
    return this.#exclusive(async () => {
      const peer = publicPackage(peerPackage);
      this.#configure(decoder.decode(peer.leafNode.credential.identity), session, pins);
      if (!await this.#config.authService.validateCredential(peer.leafNode.credential, peer.leafNode.signaturePublicKey)) {
        throw new Error('Identity key changed or unverified; explicit verification required');
      }
      const impl = await implementation;
      const initial = await createGroup(encoder.encode(session), this.#keys.publicPackage,
        this.#keys.privatePackage, [], impl, this.#config);
      const result = await createCommit({ state: initial, cipherSuite: impl }, {
        extraProposals: [{ proposalType: 'add', add: { keyPackage: peer } }],
        ratchetTreeExtension: true,
      });
      this.#state = result.newState;
      result.consumed.forEach(zeroOutUint8Array);
      return wire('mls_welcome', { welcome: result.welcome });
    });
  }

  async join(welcomeBytes, peer, session, pins) {
    return this.#exclusive(async () => {
      this.#configure(peer, session, pins);
      const welcome = decodeExact(decodeMlsMessage, welcomeBytes);
      if (welcome.wireformat !== 'mls_welcome') throw new Error('Expected Welcome');
      const next = await joinGroup(welcome.welcome, this.#keys.publicPackage, this.#keys.privatePackage,
        emptyPskIndex, await implementation, undefined, undefined, this.#config);
      if (!equal(next.groupContext.groupId, encoder.encode(session))) throw new Error('Wrong session');
      const members = next.ratchetTree.filter(n => n?.nodeType === 'leaf');
      const identities = members.map(n => decoder.decode(n.leaf.credential.identity)).sort();
      if (JSON.stringify(identities) !== JSON.stringify([this.#identity, peer].sort())) throw new Error('Wrong participants');
      this.#state = next;
    });
  }

  async send(text, id = crypto.randomUUID()) {
    return this.#exclusive(async () => {
      if (!this.#state) throw new Error('Not joined');
      if (typeof text !== 'string' || encoder.encode(text).length > 16384) throw new Error('Invalid plaintext size');
      const packet = { session: this.#session, from: this.#identity, to: this.#peer, id: label(id) };
      const result = await createApplicationMessage(this.#state, encoder.encode(text), await implementation, aad(packet));
      this.#state = result.newState;
      result.consumed.forEach(zeroOutUint8Array);
      return { ...packet, wire: wire('mls_private_message', { privateMessage: result.privateMessage }) };
    });
  }

  async receive(packet) {
    return this.#exclusive(async () => {
      if (!this.#state) throw new Error('Not joined');
      if (packet.session !== this.#session || packet.to !== this.#identity || packet.from !== this.#peer) {
        throw new Error('Wrong routing binding');
      }
      const message = decodeExact(decodeMlsMessage, packet.wire);
      if (message.wireformat !== 'mls_private_message' || message.privateMessage.contentType !== 'application') {
        throw new Error('Expected application message');
      }
      if (!equal(message.privateMessage.authenticatedData, aad(packet))) throw new Error('Wrong authenticated routing data');
      const result = await processPrivateMessage(this.#state, message.privateMessage,
        makePskIndex(this.#state, {}), await implementation);
      if (result.kind !== 'applicationMessage') throw new Error('Expected application result');
      const plaintext = decoder.decode(result.message);
      this.#state = result.newState;
      result.consumed.forEach(zeroOutUint8Array);
      return plaintext;
    });
  }

  // PRIVATE, unencrypted, synthetic in-memory checkpoint. Never send to Relay,
  // disk, logs or a provider. This is a codec experiment, not secure storage.
  checkpoint() {
    if (!this.#state || this.#busy) throw new Error('No stable state to checkpoint');
    return { identity: this.#identity, peer: this.#peer, session: this.#session,
      pins: structuredClone(this.#pins), state: encodeGroupState(this.#state) };
  }

  static restore(checkpoint) {
    const device = new Device();
    device.#identity = label(checkpoint.identity);
    device.#configure(checkpoint.peer, checkpoint.session, checkpoint.pins);
    device.#state = { ...decodeExact(decodeGroupState, checkpoint.state), clientConfig: device.#config };
    if (!equal(device.#state.groupContext.groupId, encoder.encode(device.#session))) throw new Error('Wrong checkpoint session');
    return device;
  }
}

// Only explicit wire records cross the simulated provider boundary. Device
// objects, plaintext and checkpoints are never arguments to this class.
export class Relay {
  #records = [];
  store(kind, to, bytes) {
    if (!['key-package', 'welcome', 'application'].includes(kind)) throw new Error('Invalid record kind');
    if (!(bytes instanceof Uint8Array) || bytes.length > MAX_WIRE) throw new Error('Invalid relay bytes');
    this.#records.push({ kind, to: label(to), bytes: Array.from(bytes) });
  }
  read(index) { return Uint8Array.from(this.#records[index].bytes); }
  inspect() { return structuredClone(this.#records); }
}

export async function offlineExchange() {
  const alice = await Device.enroll('tenant-a/alice');
  let bob = await Device.enroll('tenant-b/bob');
  const pins = fixturePins(alice.publicPackage, bob.publicPackage);
  const relay = new Relay();
  relay.store('key-package', alice.identity, bob.publicPackage);
  // Bob performs no operation between publication and delayed Welcome receipt.
  const welcome = await alice.start(relay.read(0), crypto.randomUUID(), pins);
  relay.store('welcome', bob.identity, welcome);
  const message = await alice.send('Synthetic offline message for F0');
  relay.store('application', bob.identity, message.wire);
  await bob.join(relay.read(1), alice.identity, message.session, pins);
  // Throw away the live receiver and reconstruct from a private serialized state.
  bob = Device.restore(bob.checkpoint());
  const received = await bob.receive({ ...message, wire: relay.read(2) });
  if (received !== 'Synthetic offline message for F0') throw new Error('Offline decryption mismatch');
  const reply = await bob.send('Synthetic reply');
  if (await alice.receive(reply) !== 'Synthetic reply') throw new Error('Reply mismatch');
  return { offlineExchange: 'pass', restoredReceiver: 'pass', reply: 'pass',
    providerRecords: relay.inspect().length, protocol: 'MLS 1.0', library: 'ts-mls 1.6.4',
    productionApproved: false };
}
