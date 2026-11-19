import { test, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { EnrollmentClient } from './enrollment.mjs'

const TENANT = '10000000-0000-0000-0000-000000000001'
const config = () => ({ tenantId: TENANT, rpId: 'amdn.invalid', getAccessToken: async () => 'synthetic-token' })
const requests = []; const prompts = []
let answer; let credential; let failure
function fixture(name) {
  const value = JSON.parse(readFileSync(new URL(`../../docs/protocols/examples/enrollment/${name}.json`, import.meta.url)))
  if (value.expires_at) {
    value.expires_at = new Date(Date.now() + 300000).toISOString()
    value.challenge_expires_at = new Date(Date.now() + 120000).toISOString()
  }
  return value
}
function browserCredential(registration) {
  const value = fixture(registration ? 'WebAuthnRegistration' : 'WebAuthnAssertion')
  const buffer = text => Uint8Array.from(Buffer.from(text, 'base64url')).buffer
  return { id: value.id, rawId: buffer(value.rawId), type: value.type,
    getClientExtensionResults: () => ({}), response: Object.fromEntries(Object.entries(value.response).map(([key, data]) => [key, data === null ? null : buffer(data)])),
    authenticatorAttachment: 'ignored', toJSON() { throw Error('Native toJSON must not be used') } }
}
beforeEach(() => {
  requests.length = 0; prompts.length = 0; failure = null; answer = fixture('EnrollmentRegistrationOptions'); credential = browserCredential(true)
  Object.defineProperty(globalThis, 'navigator', { configurable: true, value: { credentials: {
    create: async options => { prompts.push(options); return credential },
    get: async options => { prompts.push(options); return credential }
  } } })
  globalThis.isSecureContext = true; globalThis.location = new URL('https://amdn.invalid'); globalThis.top = globalThis; globalThis.self = globalThis
  globalThis.PublicKeyCredential = class {}
  globalThis.fetch = async (url, options) => {
    requests.push({ url, options: { ...options, headers: { ...options.headers } } })
    if (failure) throw failure
    return new Response(JSON.stringify(answer), { status: 200, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } })
  }
})

test('same-origin transport omits cookies, disallows redirects and obtains tokens per command', async () => {
  let tokens = 0
  const client = new EnrollmentClient({ ...config(), getAccessToken: async () => `synthetic-${++tokens}` })
  await client.beginEnrollment({ expectedIdentityVersion: 1 })
  const request = requests[0]
  assert.equal(request.url, `https://amdn.invalid/v1/device-enrollments?tenant_id=${TENANT}`)
  for (const [key, value] of Object.entries({ mode: 'cors', credentials: 'omit', redirect: 'error', cache: 'no-store', referrerPolicy: 'no-referrer' })) assert.equal(request.options[key], value)
  assert.equal(request.options.headers.Authorization, 'Bearer synthetic-1')
  assert.equal(request.options.headers.Origin, undefined)
  answer = fixture('EnrollmentCandidateOptions')
  await client.prove()
  assert.equal(tokens, 2)
  assert.equal(requests[1].options.headers.Authorization, 'Bearer synthetic-2')
})

test('create converts binary options, preserves signed bytes and omits browser extras', async () => {
  const client = new EnrollmentClient(config()); await client.beginEnrollment({ expectedIdentityVersion: 1 })
  answer = fixture('EnrollmentCandidateOptions'); await client.prove()
  const options = prompts[0].publicKey
  assert.equal(options.challenge.byteLength, 32); assert.equal(options.user.id.byteLength, 32)
  assert.equal(options.attestation, 'none'); assert.equal(options.authenticatorSelection.userVerification, 'required')
  assert.deepEqual(JSON.parse(requests[1].options.body), fixture('WebAuthnRegistration'))
  assert.equal(client.state.snapshot.state, 'awaiting_candidate_proof')
})

test('assertion uses one credential and never parses or reserializes signed client data', async () => {
  const client = new EnrollmentClient(config()); await client.beginEnrollment({ expectedIdentityVersion: 1 })
  answer = fixture('EnrollmentCandidateOptions'); await client.prove()
  credential = browserCredential(false); answer = fixture('EnrollmentCompleted')
  answer.committed_identity_version = 2; answer.current_lifecycle.identity_version = 2
  await client.prove()
  assert.equal(prompts[1].publicKey.allowCredentials.length, 1)
  const expected = fixture('WebAuthnAssertion'); delete expected.response.userHandle
  assert.deepEqual(JSON.parse(requests[2].options.body), expected)
  assert.equal(client.state.status, 'completed'); assert.equal(client.state.snapshot.messaging_ready, false)
})

test('lost begin response retains byte-identical request and key; retry never prompts', async () => {
  failure = Error('sensitive transport details')
  const client = new EnrollmentClient(config())
  await assert.rejects(client.beginEnrollment({ expectedIdentityVersion: 1 }), { code: 'unavailable', message: 'Enrollment: unavailable' })
  assert.equal(client.state.status, 'uncertain')
  await assert.rejects(client.beginEnrollment({ expectedIdentityVersion: 1 }), { code: 'invalid_state' })
  failure = null; await client.retry()
  assert.equal(requests[0].options.body, requests[1].options.body)
  assert.equal(requests[0].options.headers['Idempotency-Key'], requests[1].options.headers['Idempotency-Key'])
  assert.equal(prompts.length, 0)
})

test('lost proof response retries stored proof instead of generating another signature', async () => {
  const client = new EnrollmentClient(config()); await client.beginEnrollment({ expectedIdentityVersion: 1 })
  failure = Error('lost after commit'); await assert.rejects(client.prove(), { code: 'unavailable' })
  await assert.rejects(client.prove(), { code: 'invalid_state' })
  failure = null; answer = fixture('EnrollmentCandidateOptions'); await client.retry()
  assert.equal(prompts.length, 1)
  assert.equal(requests[1].options.body, requests[2].options.body)
  assert.equal(requests[1].options.headers['Idempotency-Key'], requests[2].options.headers['Idempotency-Key'])
})

test('cancellation before credential selection preserves state without sending proof', async () => {
  navigator.credentials.create = async () => { throw new DOMException('private diagnostic', 'NotAllowedError') }
  const client = new EnrollmentClient(config()); await client.beginEnrollment({ expectedIdentityVersion: 1 })
  await assert.rejects(client.prove(), { code: 'cancelled', message: 'Enrollment: cancelled' })
  assert.equal(client.state.status, 'ready'); assert.equal(requests.length, 1)
  const abort = new AbortController(); abort.abort('private reason')
  await assert.rejects(client.prove({ signal: abort.signal }), { code: 'cancelled' })
  assert.equal(requests.length, 1)
})

test('dispose aborts in-flight collection and prevents late state resurrection', async () => {
  navigator.credentials.create = ({ signal }) => new Promise((resolve, reject) => signal.addEventListener('abort', () => reject(Error('private diagnostic'))))
  const client = new EnrollmentClient(config()); await client.beginEnrollment({ expectedIdentityVersion: 1 })
  const pending = client.prove()
  await assert.rejects(client.prove(), { code: 'busy' })
  client.dispose(); await assert.rejects(pending, { code: 'cancelled' })
  assert.equal(client.state.status, 'disposed'); assert.equal(client.state.snapshot, null)
  await assert.rejects(client.retry(), { code: 'disposed' })
})

for (const scenario of ['algorithm', 'uv', 'attestation', 'rp', 'challenge', 'fields', 'expired', 'state', 'descriptor']) test(`rejects unsupported server options: ${scenario}`, async () => {
  switch (scenario) {
    case 'algorithm': answer.public_key.pubKeyCredParams[0].alg = -257; break
    case 'uv': answer.public_key.authenticatorSelection.userVerification = 'preferred'; break
    case 'attestation': answer.public_key.attestation = 'direct'; break
    case 'rp': answer.public_key.rp.id = 'foreign.invalid'; break
    case 'challenge': answer.public_key.challenge = 'AB'; break
    case 'fields': answer.public_key.extensions = { appid: 'foreign' }; break
    case 'expired': answer.challenge_expires_at = new Date(Date.now() - 10000).toISOString(); break
    case 'state': answer.state = 'awaiting_current_proof'; break
    case 'descriptor': answer.public_key.excludeCredentials.push({ type: 'public-key', id: 'AA' }); break
  }
  const client = new EnrollmentClient(config())
  await assert.rejects(client.beginEnrollment({ expectedIdentityVersion: 1 }), error => ['invalid_response', 'expired'].includes(error.code))
  assert.equal(prompts.length, 0); assert.equal(client.state.status, 'uncertain')
})

test('response substitution, messaging readiness and wrong identity version fail closed', async () => {
  for (const scenario of ['ceremony', 'device', 'messaging', 'version']) {
    answer = fixture('EnrollmentRegistrationOptions'); credential = browserCredential(true)
    const client = new EnrollmentClient(config()); await client.beginEnrollment({ expectedIdentityVersion: 1 })
    answer = fixture('EnrollmentCandidateOptions'); await client.prove()
    credential = browserCredential(false); answer = fixture('EnrollmentCompleted')
    answer.committed_identity_version = 2; answer.current_lifecycle.identity_version = 2
    if (scenario === 'ceremony') answer.ceremony_id = TENANT
    if (scenario === 'device') answer.device_id = TENANT
    if (scenario === 'messaging') answer.messaging_ready = true
    if (scenario === 'version') answer.committed_identity_version = 3
    await assert.rejects(client.prove(), { code: 'invalid_response' })
    assert.equal(client.state.status, 'uncertain')
  }
})

test('HTTP failures expose only status and bounded Retry-After, keeping uncertain commands', async () => {
  globalThis.fetch = async () => new Response('private diagnostic', { status: 503, headers: { 'Retry-After': '5' } })
  const client = new EnrollmentClient(config())
  await assert.rejects(client.beginEnrollment({ expectedIdentityVersion: 1 }), { code: 'http', status: 503, retryAfter: 5, message: 'Enrollment: http' })
  assert.equal(client.state.status, 'uncertain')
})

test('oversized response and malformed UTF-8 cannot produce usable options', async () => {
  for (const data of [new Uint8Array([0xff]), new Uint8Array(65537)]) {
    globalThis.fetch = async () => new Response(data, { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } })
    const client = new EnrollmentClient(config())
    await assert.rejects(client.beginEnrollment({ expectedIdentityVersion: 1 }), { code: 'invalid_response' })
    assert.equal(client.state.status, 'uncertain')
  }
})

test('invalid response headers cancel the unread stream and preserve retry material', async () => {
  let cancelled = false
  globalThis.fetch = async () => new Response(new ReadableStream({ cancel() { cancelled = true } }), { headers: { 'Content-Type': 'text/plain' } })
  const client = new EnrollmentClient(config())
  await assert.rejects(client.beginEnrollment({ expectedIdentityVersion: 1 }), { code: 'invalid_response' })
  assert.equal(cancelled, true); assert.equal(client.state.status, 'uncertain')
})

test('definitive authentication failure permits a fresh explicit begin without claiming success', async () => {
  let attempts = 0
  globalThis.fetch = async () => ++attempts === 1 ? new Response('private diagnostic', { status: 401 })
    : new Response(JSON.stringify(answer), { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } })
  const client = new EnrollmentClient(config())
  await assert.rejects(client.beginEnrollment({ expectedIdentityVersion: 1 }), { code: 'http', status: 401 })
  assert.equal(client.state.status, 'idle')
  await client.beginEnrollment({ expectedIdentityVersion: 1 })
  const state = client.state; state.snapshot.public_key.authenticatorSelection.userVerification = 'discouraged'
  assert.equal(client.state.snapshot.public_key.authenticatorSelection.userVerification, 'required')
})

test('rejects insecure, framed and unavailable browser environments', () => {
  globalThis.isSecureContext = false
  assert.throws(() => new EnrollmentClient(config()), { code: 'unsupported' })
  globalThis.isSecureContext = true; globalThis.top = {}
  assert.throws(() => new EnrollmentClient(config()), { code: 'unsupported' })
  globalThis.top = globalThis; globalThis.PublicKeyCredential = undefined
  assert.throws(() => new EnrollmentClient(config()), { code: 'unsupported' })
})

test('origin remains pinned even when current page context changes during token acquisition', async () => {
  const client = new EnrollmentClient({ ...config(), getAccessToken: async () => {
    globalThis.location = new URL('https://foreign.invalid'); return 'synthetic-token'
  } })
  await assert.rejects(client.beginEnrollment({ expectedIdentityVersion: 1 }), { code: 'invalid_state' })
  assert.equal(requests.length, 0)
})
