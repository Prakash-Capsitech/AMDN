import { readFile, writeFile, mkdir } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { createHash } from 'node:crypto'
import assert from 'node:assert/strict'

const repository = fileURLToPath(new URL('../../', import.meta.url)).replace(/\/$/, '')
const manifest = JSON.parse(await readFile(`${repository}/.tools/browser-matrix/manifest.json`, 'utf8'))
process.env.PLAYWRIGHT_BROWSERS_PATH = manifest.browsers
process.env.CHROME_DEVEL_SANDBOX = manifest.sandboxHelper
// Playwright resolves its browser registry during import, after this local path is set.
const { chromium, firefox, webkit, devices } = await import('playwright')
const moduleSource = await readFile(`${repository}/clients/web/enrollment.mjs`, 'utf8')
const moduleSha256 = createHash('sha256').update(moduleSource).digest('hex')
const fixtures = {}
for (const name of ['EnrollmentRegistrationOptions', 'EnrollmentCandidateOptions', 'EnrollmentCompleted', 'WebAuthnRegistration', 'WebAuthnAssertion'])
  fixtures[name] = JSON.parse(await readFile(`${repository}/docs/protocols/examples/enrollment/${name}.json`, 'utf8'))
const origin = 'https://localhost'
const cases = [
  ['chrome-desktop', chromium, { executablePath: manifest.chrome, chromiumSandbox: true }, {}],
  ['edge-desktop', chromium, { executablePath: manifest.edge, chromiumSandbox: true }, {}],
  ['chromium-desktop', chromium, { channel: 'chromium', chromiumSandbox: true }, {}],
  ['firefox-desktop', firefox, {}, {}], ['webkit-desktop', webkit, {}, {}],
  ['android-chromium-emulation', chromium, { channel: 'chromium', chromiumSandbox: true }, devices['Pixel 7']],
  ['iphone-webkit-emulation', webkit, {}, devices['iPhone 14']]
]
const results = []
for (const [name, browserType, launch, device] of cases) {
  let browser
  try {
    browser = await browserType.launch({ headless: true, timeout: 20000, ...launch })
    const { defaultBrowserType, ...emulation } = device
    const context = await browser.newContext(emulation)
    await context.addCookies([{ name: 'must_be_omitted', value: 'synthetic', url: origin, secure: true }])
    let reply = { status: 200, body: fixtures.EnrollmentRegistrationOptions }; const requests = []
    await context.route('**/*', async route => {
      const request = route.request(); const url = new URL(request.url())
      if (url.origin !== origin) return route.abort()
      if (url.pathname === '/enrollment.mjs') return route.fulfill({ contentType: 'text/javascript', body: moduleSource })
      if (!url.pathname.startsWith('/v1/')) return route.fulfill({ contentType: 'text/html', body: '<!doctype html><title>AMDN synthetic adapter checks</title>' })
      requests.push({ url: request.url(), method: request.method(), body: request.postData(), headers: await request.allHeaders() })
      if (reply.abort) return route.abort('connectionfailed')
      return route.fulfill({ status: reply.status ?? 200,
        headers: { 'Content-Type': reply.contentType ?? 'application/json', 'Cache-Control': 'no-store', 'Retry-After': '5' },
        body: reply.invalidUtf8 ? Buffer.from([255]) : reply.raw ?? JSON.stringify(reply.body) })
    })
    const page = await context.newPage()
    await page.exposeFunction('setMatrixReply', value => { reply = value })
    await page.exposeFunction('matrixRequests', () => requests)
    await page.goto(`${origin}/matrix`)
    const outcome = await page.evaluate(async ({ fixtures, origin }) => {
      const { EnrollmentClient } = await import('/enrollment.mjs')
      const check = (condition, label) => { if (!condition) throw new Error(label) }
      const rejection = async (operation, allowed) => {
        try { await operation; throw new Error('operation-unexpectedly-succeeded') }
        catch (error) { check(allowed.includes(error.code), 'unexpected-public-error'); return error }
      }
      const data = name => {
        const value = structuredClone(fixtures[name])
        if (value.public_key) {
          value.expires_at = new Date(Date.now() + 300000).toISOString(); value.challenge_expires_at = new Date(Date.now() + 120000).toISOString()
          if (value.public_key.rp) value.public_key.rp.id = 'localhost'; else value.public_key.rpId = 'localhost'
        }
        if (value.committed_identity_version) { value.committed_identity_version = 2; value.current_lifecycle.identity_version = 2 }
        return value
      }
      let tokenCount = 0; let promptCount = 0; let cancelPrompt = false
      const credential = registration => {
        const value = fixtures[registration ? 'WebAuthnRegistration' : 'WebAuthnAssertion']
        const buffer = text => Uint8Array.from(atob(text.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - text.length % 4) % 4)), c => c.charCodeAt(0)).buffer
        return { id: value.id, rawId: buffer(value.rawId), type: 'public-key', getClientExtensionResults: () => ({}),
          response: Object.fromEntries(Object.entries(value.response).map(([key, bytes]) => [key, bytes === null ? null : buffer(bytes)])),
          toJSON() { throw new Error('native-toJSON-is-forbidden') } }
      }
      const nativeWebAuthnApiAvailable = Boolean(navigator.credentials?.create && navigator.credentials?.get)
      if (!nativeWebAuthnApiAvailable) {
        let rejected = false
        try { new EnrollmentClient({tenantId:'10000000-0000-0000-0000-000000000001',rpId:'localhost',getAccessToken:async()=> 'synthetic'}) }
        catch (error) { rejected = error.code === 'unsupported' }
        check(rejected, 'missing-native-api-must-be-unsupported')
        Object.defineProperty(navigator, 'credentials', { configurable: true, value: {} })
      }
      for (const method of ['create', 'get']) Object.defineProperty(navigator.credentials, method, { configurable: true, value: async ({ publicKey, signal }) => {
        ++promptCount
        if (cancelPrompt) return new Promise((resolve, reject) => signal.addEventListener('abort', () => reject(new DOMException('fixture cancellation', 'AbortError')), { once: true }))
        check(publicKey.challenge instanceof ArrayBuffer && publicKey.challenge.byteLength === 32, 'binary-challenge')
        if (method === 'create') check(publicKey.attestation === 'none' && publicKey.pubKeyCredParams[0].alg === -7 && publicKey.authenticatorSelection.userVerification === 'required', 'creation-profile')
        else check(publicKey.allowCredentials.length === 1 && publicKey.allowCredentials[0].id instanceof ArrayBuffer && publicKey.userVerification === 'required', 'assertion-profile')
        return credential(method === 'create')
      } })
      const client = () => new EnrollmentClient({ tenantId: '10000000-0000-0000-0000-000000000001', rpId: 'localhost', getAccessToken: async () => `synthetic-${++tokenCount}` })
      const serve = async (body, extra = {}) => setMatrixReply({ status: 200, body, ...extra })
      const labels = []
      await serve(data('EnrollmentRegistrationOptions')); const flow = client(); await flow.beginEnrollment({ expectedIdentityVersion: 1 })
      await serve(data('EnrollmentCandidateOptions')); await flow.prove()
      await serve(data('EnrollmentCompleted')); await flow.prove()
      check(flow.state.status === 'completed' && flow.state.snapshot.messaging_ready === false, 'completion-state')
      const initialRequests = await matrixRequests()
      check(initialRequests.every(r => !r.headers.cookie && !r.headers.referer && r.headers.origin === origin && r.method === 'POST'),
        'request-origin-cookie-referrer:' + JSON.stringify(initialRequests.map(r=>({origin:r.headers.origin,cookie:Boolean(r.headers.cookie),referrer:Boolean(r.headers.referer),method:r.method}))))
      check(new Set(initialRequests.map(r => r.headers.authorization)).size === 3, 'fresh-token-per-command')
      check(!Object.hasOwn(JSON.parse(initialRequests[1].body), 'authenticatorAttachment'), 'closed-proof-projection')
      labels.push('synthetic-proof-projection-and-state', 'same-origin-fetch-without-cookies-or-referrer')
      for (const [label, mutate] of [
        ['algorithm', v => { v.public_key.pubKeyCredParams[0].alg = -257 }],
        ['uv', v => { v.public_key.authenticatorSelection.userVerification = 'preferred' }],
        ['attestation', v => { v.public_key.attestation = 'direct' }], ['rp', v => { v.public_key.rp.id = 'foreign.invalid' }],
        ['encoding', v => { v.public_key.challenge = 'AB' }], ['extra', v => { v.public_key.extensions = {} }],
        ['profile', v => { v.profile = 'other' }], ['uuid', v => { v.ceremony_id = 'invalid' }],
        ['stage', v => { v.state = 'awaiting_current_proof' }], ['expiry', v => { v.challenge_expires_at = '2020-01-01T00:00:00Z' }]
      ]) {
        const value = data('EnrollmentRegistrationOptions'); mutate(value); await serve(value)
        const guard = client(); const before = promptCount
        await rejection(guard.beginEnrollment({ expectedIdentityVersion: 1 }), ['invalid_response', 'expired'])
        check(promptCount === before && guard.state.status === 'uncertain', 'hostile-dto-does-not-prompt'); labels.push(`dto-${label}`)
      }
      for (const status of [400, 401, 403, 404, 409, 413, 415]) {
        await serve({}, { status }); const guard = client()
        const error = await rejection(guard.beginEnrollment({ expectedIdentityVersion: 1 }), ['http'])
        check(error.status === status && guard.state.status === 'idle', 'definitive-status'); labels.push(`http-${status}`)
      }
      for (const extra of [{ status: 429 }, { status: 503 }, { raw: '{' }, { invalidUtf8: true }, { contentType: 'text/html' }, { raw: ' '.repeat(65537) }, { abort: true }]) {
        await serve({}, extra); const guard = client(); const before = (await matrixRequests()).length
        await rejection(guard.beginEnrollment({ expectedIdentityVersion: 1 }), ['http', 'invalid_response', 'unavailable'])
        check(guard.state.status === 'uncertain', 'uncertain-retention')
        await serve(data('EnrollmentRegistrationOptions')); await guard.retry()
        const records = (await matrixRequests()).slice(before)
        check(records.length === 2 && records[0].body === records[1].body && records[0].headers['idempotency-key'] === records[1].headers['idempotency-key'], 'exact-command-retry')
        check(records[0].headers.authorization !== records[1].headers.authorization, 'retry-fresh-token')
      }
      labels.push('uncertain-byte-identical-retries')
      await serve(data('EnrollmentRegistrationOptions')); const cancellation = client(); await cancellation.beginEnrollment({ expectedIdentityVersion: 1 })
      const beforeCancel = (await matrixRequests()).length; cancelPrompt = true
      const abort = new AbortController(); const collecting = cancellation.prove({ signal: abort.signal }); abort.abort()
      await rejection(collecting, ['cancelled']); cancelPrompt = false
      check((await matrixRequests()).length === beforeCancel && cancellation.state.status === 'ready', 'cancel-before-dispatch')
      const copy = cancellation.state; copy.snapshot.public_key.authenticatorSelection.userVerification = 'discouraged'
      check(cancellation.state.snapshot.public_key.authenticatorSelection.userVerification === 'required', 'defensive-copy')
      cancellation.dispose(); check(cancellation.state.snapshot === null && cancellation.state.status === 'disposed', 'disposed-state')
      await rejection(cancellation.retry(), ['disposed']); labels.push('cancellation-disposal-defensive-state')
      return { passed: labels, nativeWebAuthn: false, nativeWebAuthnApiAvailable, backend: 'synthetic intercepted HTTPS responses', publicKeyCredentialPresent: typeof PublicKeyCredential === 'function' }
    }, { fixtures, origin })
    assert.ok(outcome.passed.length > 20)
    const row = { name, version: browser.version(), result: 'passed', mobileEmulation: name.includes('emulation'), ...outcome }
    results.push(row); process.stdout.write(JSON.stringify({ name, version: row.version, result: row.result, checks: row.passed.length, nativeWebAuthn: false }) + '\n')
  } catch (error) {
    const row = { name, result: 'failed-or-unavailable', diagnostic: String(error.message).slice(0, 3500), nativeWebAuthn: false }
    results.push(row); process.stdout.write(JSON.stringify({ name, result: row.result, diagnostic: row.diagnostic }) + '\n')
  } finally { await browser?.close() }
}
await mkdir(`${repository}/.local/browser-evidence`, { recursive: true })
await writeFile(`${repository}/.local/browser-evidence/adapter-matrix.json`, JSON.stringify({ moduleSha256, scope: 'real browser runtime with synthetic WebAuthn and intercepted HTTPS responses; not native authenticator or physical-device qualification', results }, null, 2))
if (results.some(row => row.result !== 'passed')) process.exitCode = 1
