// First-party management credential adapter. No login, key storage or messaging.
export const PROFILE = 'amdn-webauthn-enrollment/1'
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const ZERO = '00000000-0000-0000-0000-000000000000'
const PENDING = ['awaiting_registration', 'awaiting_candidate_proof', 'awaiting_current_proof', 'awaiting_revocation_proof']

export class EnrollmentError extends Error {
  constructor(code, { status, retryAfter } = {}) {
    super(`Enrollment: ${code}`)
    this.name = 'EnrollmentError'
    this.code = code
    this.status = status
    this.retryAfter = retryAfter
  }
}
function require(value, code = 'invalid_response') { if (!value) throw new EnrollmentError(code) }
function id(value) { return typeof value === 'string' && UUID.test(value) && value !== ZERO }
function fields(value, names, optional = []) {
  require(value !== null && typeof value === 'object' && !Array.isArray(value))
  require(names.every(name => Object.hasOwn(value, name)))
  require(Object.keys(value).every(name => names.includes(name) || optional.includes(name)))
}
function text(value, max) { require(typeof value === 'string' && value.length > 0 && value.length <= max) }
function version(value) { return Number.isSafeInteger(value) && value >= 1 }
function instant(value) {
  require(typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,7})?Z$/.test(value))
  const result = Date.parse(value)
  require(Number.isFinite(result))
  return result
}
function encode(value, max, exact) {
  require(value instanceof ArrayBuffer, 'invalid_credential')
  const bytes = new Uint8Array(value)
  require(bytes.length > 0 && bytes.length <= max && (!exact || bytes.length === exact), 'invalid_credential')
  return btoa(String.fromCharCode(...bytes)).replace(/=+$/, '').replaceAll('+', '-').replaceAll('/', '_')
}
function decode(value, max, exact) {
  require(typeof value === 'string' && value.length > 0 && value.length <= Math.ceil(max * 4 / 3) && /^[A-Za-z0-9_-]+$/.test(value))
  let bytes
  try { bytes = Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - value.length % 4) % 4)), c => c.charCodeAt(0)) }
  catch { throw new EnrollmentError('invalid_response') }
  require(bytes.length > 0 && bytes.length <= max && (!exact || bytes.length === exact))
  require(encode(bytes.buffer, max, exact) === value)
  return bytes.buffer
}
function descriptors(values, count) {
  require(Array.isArray(values) && values.length === count)
  return values.map(value => {
    fields(value, ['type', 'id']); require(value.type === 'public-key')
    return { type: 'public-key', id: decode(value.id, 1023) }
  })
}
function options(snapshot, rpId, replacing) {
  const value = snapshot.public_key
  const registration = snapshot.state === 'awaiting_registration'
  fields(value, registration
    ? ['challenge', 'timeout', 'rp', 'user', 'pubKeyCredParams', 'excludeCredentials', 'authenticatorSelection', 'attestation']
    : ['challenge', 'timeout', 'rpId', 'allowCredentials', 'userVerification'])
  require(value.timeout === 120000)
  const result = { challenge: decode(value.challenge, 32, 32), timeout: 120000 }
  if (registration) {
    fields(value.rp, ['id', 'name']); require(value.rp.id === rpId); text(value.rp.name, 64)
    fields(value.user, ['id', 'name', 'displayName']); text(value.user.name, 64); text(value.user.displayName, 64)
    require(Array.isArray(value.pubKeyCredParams) && value.pubKeyCredParams.length === 1)
    fields(value.pubKeyCredParams[0], ['type', 'alg'])
    require(value.pubKeyCredParams[0].type === 'public-key' && value.pubKeyCredParams[0].alg === -7)
    fields(value.authenticatorSelection, ['residentKey', 'userVerification'])
    require(value.authenticatorSelection.residentKey === 'discouraged' && value.authenticatorSelection.userVerification === 'required' && value.attestation === 'none')
    Object.assign(result, {
      rp: { ...value.rp }, user: { ...value.user, id: decode(value.user.id, 32, 32) },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }], excludeCredentials: descriptors(value.excludeCredentials, replacing ? 1 : 0),
      authenticatorSelection: { residentKey: 'discouraged', userVerification: 'required' }, attestation: 'none'
    })
  } else {
    require(value.rpId === rpId && value.userVerification === 'required')
    Object.assign(result, { rpId, allowCredentials: descriptors(value.allowCredentials, 1), userVerification: 'required' })
  }
  return result
}
function project(credential, registration) {
  require(credential !== null && credential?.type === 'public-key', 'invalid_credential')
  const rawId = encode(credential.rawId, 1023)
  require(credential.id === rawId, 'invalid_credential')
  const extensions = credential.getClientExtensionResults()
  require(extensions !== null && typeof extensions === 'object' && Object.keys(extensions).length === 0, 'unsupported')
  const source = credential.response
  const response = { clientDataJSON: encode(source.clientDataJSON, 8192) }
  if (registration) response.attestationObject = encode(source.attestationObject, 16384)
  else {
    response.authenticatorData = encode(source.authenticatorData, 4096)
    response.signature = encode(source.signature, 1024)
    if (source.userHandle != null) response.userHandle = encode(source.userHandle, 32, 32)
  }
  return { id: rawId, rawId, type: 'public-key', clientExtensionResults: {}, response }
}

async function responseJson(response) {
  require(response.headers.get('content-type')?.split(';')[0].trim().toLowerCase() === 'application/json')
  require(response.headers.get('cache-control')?.split(',').some(item => item.trim().toLowerCase() === 'no-store'))
  const reader = response.body?.getReader()
  require(reader)
  const decoder = new TextDecoder('utf-8', { fatal: true })
  let size = 0; let body = ''
  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      size += value.byteLength
      require(size <= 65536)
      body += decoder.decode(value, { stream: true })
    }
    return JSON.parse(body + decoder.decode())
  } catch { throw new EnrollmentError('invalid_response') }
  finally { await reader.cancel().catch(() => {}); reader.releaseLock() }
}

export class EnrollmentClient {
  #tenant; #rp; #origin; #token; #fetch; #credentials
  #snapshot = null; #pending = null; #mode = null; #target = null; #version = null
  #busy = false; #disposed = false; #active = null

  constructor({ tenantId, rpId, getAccessToken }) {
    require(globalThis.isSecureContext && globalThis.location?.protocol === 'https:' && globalThis.top === globalThis.self, 'unsupported')
    require(globalThis.navigator?.credentials?.create && globalThis.navigator?.credentials?.get && globalThis.PublicKeyCredential && globalThis.crypto?.randomUUID, 'unsupported')
    require(id(tenantId) && typeof getAccessToken === 'function', 'invalid_configuration')
    require(typeof rpId === 'string' && rpId.length <= 253 && /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/.test(rpId)
      && !/(^|\.)([0-9]+|0x[0-9a-f]*)$/.test(rpId), 'invalid_configuration')
    const host = globalThis.location.hostname
    require(host === rpId || host.endsWith('.' + rpId), 'invalid_configuration')
    this.#tenant = tenantId; this.#rp = rpId; this.#origin = globalThis.location.origin; this.#token = getAccessToken
    this.#fetch = globalThis.fetch.bind(globalThis); this.#credentials = globalThis.navigator.credentials
  }

  get state() {
    return { status: this.#disposed ? 'disposed' : this.#pending ? 'uncertain' : this.#snapshot?.state === 'completed' ? 'completed' : this.#snapshot ? 'ready' : 'idle',
      busy: this.#busy, snapshot: this.#snapshot ? structuredClone(this.#snapshot) : null }
  }

  beginEnrollment({ expectedIdentityVersion, replaceDeviceId = null }, { signal } = {}) {
    return this.#exclusive(signal, async token => {
      require(!this.#snapshot && !this.#pending, 'invalid_state')
      require(Number.isSafeInteger(expectedIdentityVersion) && expectedIdentityVersion >= 0 && expectedIdentityVersion < Number.MAX_SAFE_INTEGER
        && (replaceDeviceId === null || id(replaceDeviceId)), 'invalid_request')
      this.#mode = replaceDeviceId === null ? 'initial' : 'replacement'; this.#target = replaceDeviceId
      this.#version = expectedIdentityVersion
      return this.#command('/v1/device-enrollments', { profile: PROFILE, expected_identity_version: expectedIdentityVersion, replace_device_id: replaceDeviceId }, 'awaiting_registration', token)
    })
  }

  beginRevocation({ deviceId, expectedIdentityVersion }, { signal } = {}) {
    return this.#exclusive(signal, async token => {
      require(!this.#snapshot && !this.#pending, 'invalid_state')
      require(id(deviceId) && version(expectedIdentityVersion) && expectedIdentityVersion < Number.MAX_SAFE_INTEGER, 'invalid_request')
      this.#mode = 'revocation'; this.#target = deviceId
      this.#version = expectedIdentityVersion
      return this.#command(`/v1/devices/${deviceId}/revocations`, { profile: PROFILE, expected_identity_version: expectedIdentityVersion }, 'awaiting_revocation_proof', token)
    })
  }

  prove({ signal } = {}) {
    return this.#exclusive(signal, async token => {
      require(this.#snapshot && !this.#pending && PENDING.includes(this.#snapshot.state), 'invalid_state')
      const current = this.#snapshot
      const publicKey = options(current, this.#rp, this.#mode === 'replacement')
      publicKey.timeout = Math.min(120000, instant(current.expires_at) - Date.now(), instant(current.challenge_expires_at) - Date.now())
      require(publicKey.timeout > 0, 'expired')
      const registration = current.state === 'awaiting_registration'
      let credential
      try { credential = await this.#credentials[registration ? 'create' : 'get']({ publicKey, signal: token }) }
      catch (error) { throw new EnrollmentError(token.aborted || ['AbortError', 'NotAllowedError'].includes(error?.name) ? 'cancelled' : 'credential_unavailable') }
      require(!token.aborted, 'cancelled')
      let body
      try { body = project(credential, registration) }
      catch (error) { throw error instanceof EnrollmentError ? error : new EnrollmentError('invalid_credential') }
      const routes = {
        awaiting_registration: [`/v1/device-enrollments/${current.ceremony_id}/registration`, 'awaiting_candidate_proof'],
        awaiting_candidate_proof: [`/v1/device-enrollments/${current.ceremony_id}/candidate-proof`, this.#mode === 'replacement' ? 'awaiting_current_proof' : 'completed'],
        awaiting_current_proof: [`/v1/device-enrollments/${current.ceremony_id}/current-proof`, 'completed'],
        awaiting_revocation_proof: [`/v1/device-revocations/${current.ceremony_id}/proof`, 'completed']
      }
      return this.#command(routes[current.state][0], body, routes[current.state][1], token)
    })
  }

  retry({ signal } = {}) {
    return this.#exclusive(signal, token => { require(this.#pending, 'invalid_state'); return this.#send(token) })
  }

  dispose() {
    this.#disposed = true; this.#active?.abort(); this.#pending = null; this.#snapshot = null; this.#token = null
  }

  async #exclusive(signal, action) {
    require(!this.#disposed, 'disposed'); require(!this.#busy, 'busy')
    this.#busy = true
    const controller = new AbortController(); this.#active = controller
    const abort = () => controller.abort()
    signal?.addEventListener('abort', abort, { once: true })
    if (signal?.aborted) controller.abort()
    try { require(!controller.signal.aborted, 'cancelled'); return await action(controller.signal) }
    finally { signal?.removeEventListener('abort', abort); this.#active = null; this.#busy = false }
  }

  #command(path, body, expected, signal) {
    require(!signal.aborted, 'cancelled')
    const bytes = JSON.stringify(body)
    require(new TextEncoder().encode(bytes).length <= 65536, 'invalid_credential')
    this.#pending = { path, bytes, key: crypto.randomUUID(), expected }
    return this.#send(signal)
  }

  async #send(signal) {
    const pending = this.#pending
    let bearer
    try { bearer = await this.#token({ signal }) }
    catch { throw new EnrollmentError(signal.aborted ? 'cancelled' : 'authentication_required') }
    require(!signal.aborted, 'cancelled')
    require(typeof bearer === 'string' && bearer.length > 0 && bearer.length <= 16384 && /^[!-~]+$/.test(bearer), 'authentication_required')
    const target = new URL(`${this.#origin}${pending.path}?tenant_id=${this.#tenant}`)
    require(target.origin === this.#origin && globalThis.location.origin === this.#origin, 'invalid_state')
    let response
    try {
      // CORS request mode preserves Origin with no-referrer in Firefox/WebKit.
      // The URL stays pinned to this page's origin; redirects remain forbidden.
      response = await this.#fetch(target.href, {
        method: 'POST', mode: 'cors', credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer', signal,
        headers: { Authorization: `Bearer ${bearer}`, 'Content-Type': 'application/json', Accept: 'application/json', 'Idempotency-Key': pending.key }, body: pending.bytes
      })
    } catch { throw new EnrollmentError(signal.aborted ? 'cancelled' : 'unavailable') }
    require(!signal.aborted && !this.#disposed, 'cancelled')
    if (response.status !== 200) {
      if ([400, 401, 403, 404, 409, 413, 415].includes(response.status)) this.#pending = null
      await response.body?.cancel().catch(() => {})
      const delay = response.headers.get('retry-after')
      throw new EnrollmentError('http', { status: response.status, retryAfter: delay && /^\d{1,6}$/.test(delay) ? Number(delay) : undefined })
    }
    let answer
    try { answer = await responseJson(response) }
    catch (error) {
      await response.body?.cancel().catch(() => {})
      throw signal.aborted || this.#disposed ? new EnrollmentError('cancelled') : error
    }
    require(!signal.aborted && !this.#disposed, 'cancelled')
    this.#validate(answer, pending.expected)
    this.#snapshot = answer; this.#pending = null
    return structuredClone(answer)
  }

  #validate(value, expected) {
    const completed = expected === 'completed'
    fields(value, ['ceremony_id', 'profile', 'device_id', 'state', ...(completed
      ? ['completed_at', 'committed_identity_version', 'messaging_ready', 'current_lifecycle']
      : ['expires_at', 'challenge_expires_at', 'public_key'])])
    require(value.profile === PROFILE && value.state === expected && id(value.ceremony_id) && id(value.device_id))
    if (this.#snapshot) require(value.ceremony_id === this.#snapshot.ceremony_id && value.device_id === this.#snapshot.device_id)
    if (this.#mode === 'revocation') require(value.device_id === this.#target)
    if (this.#mode === 'replacement') require(value.device_id !== this.#target)
    if (completed) {
      instant(value.completed_at); require(value.messaging_ready === false && value.committed_identity_version === this.#version + 1)
      const lifecycle = value.current_lifecycle
      fields(lifecycle, ['status', 'identity_version', 'observed_at']); instant(lifecycle.observed_at)
      require(['credential_active', 'revoked'].includes(lifecycle.status) && version(lifecycle.identity_version)
        && lifecycle.identity_version >= value.committed_identity_version && (this.#mode !== 'revocation' || lifecycle.status === 'revoked'))
    } else {
      const expires = instant(value.expires_at); const challengeExpires = instant(value.challenge_expires_at)
      require(expires > Date.now() && challengeExpires > Date.now() && challengeExpires <= expires, 'expired')
      options(value, this.#rp, this.#mode === 'replacement')
    }
  }
}
