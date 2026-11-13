"""Checks of the proposed enrollment artifact, not runtime security evidence."""

import base64
import copy
import json
import unittest

from test_contracts import PROTOCOLS, SPEC, validator


EXAMPLES = PROTOCOLS / 'examples' / 'enrollment'
GRAPH = json.loads((PROTOCOLS / 'enrollment-state-machine.json').read_text())


def example(name):
    return json.loads((EXAMPLES / (name + '.json')).read_text())


def encoded(value):
    return base64.urlsafe_b64encode(value).decode().rstrip('=')


class EnrollmentSchemaTests(unittest.TestCase):
    def test_all_stage_examples_validate(self):
        for path in EXAMPLES.glob('*.json'):
            with self.subTest(schema=path.stem):
                validator(path.stem).validate(json.loads(path.read_text()))

    def test_binary_bounds_use_decoded_bytes_and_canonical_trailing_bits(self):
        for name, limit in [('CredentialId', 1023), ('ClientData', 8192),
                            ('Attestation', 16384), ('AuthenticatorData', 4096),
                            ('Signature', 1024)]:
            check = validator('WebAuthn' + name)
            for size in (1, 2, 3, limit - 1, limit):
                with self.subTest(field=name, size=size):
                    self.assertTrue(check.is_valid(encoded(bytes([255]) * size)))
            self.assertFalse(check.is_valid(encoded(bytes(limit + 1))))
            for malformed in ('', 'A', 'AAAAA', 'AA=', 'AA==', '+A', '/A',
                              'AB', 'AAB', 'AA\n', 'AA\r\n', ' AA', 'AA ', 'AA\u0000'):
                with self.subTest(field=name, malformed=repr(malformed)):
                    self.assertFalse(check.is_valid(malformed))
        # Every final sextet is checked, not just a few noncanonical spellings.
        alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
        check = validator('WebAuthnSignature')
        for prefix, modulus in [('A', 16), ('AA', 4)]:
            for index, char in enumerate(alphabet):
                self.assertEqual(index % modulus == 0, check.is_valid(prefix + char))

    def test_challenge_and_user_handle_are_exactly_32_bytes(self):
        check = validator('WebAuthnChallenge')
        for size in (0, 1, 31, 32, 33, 64):
            self.assertEqual(size == 32, check.is_valid(encoded(bytes(size))))
        for value in (None, encoded(bytes(32))):
            proof = example('WebAuthnAssertion')
            proof['response']['userHandle'] = value
            validator('WebAuthnAssertion').validate(proof)
        proof['response'].pop('userHandle')
        validator('WebAuthnAssertion').validate(proof)
        proof['response']['userHandle'] = 'AA'
        self.assertFalse(validator('WebAuthnAssertion').is_valid(proof))

    def test_begin_cannot_inject_owner_keys_or_reset_version(self):
        for schema in ('BeginEnrollment', 'BeginRevocation'):
            for field in ('tenant_id', 'user_id', 'postman_id', 'device_id',
                          'public_key_package', 'private_key', 'key_id', 'grant'):
                value = example(schema)
                value[field] = 'forged'
                self.assertFalse(validator(schema).is_valid(value))
            for version in (-1, 1.5, '1', True, 9007199254740991):
                value = example(schema)
                value['expected_identity_version'] = version
                self.assertFalse(validator(schema).is_valid(value))
        value = example('BeginEnrollment')
        value['replace_device_id'] = '22222222-2222-4222-8222-222222222222'
        validator('BeginEnrollment').validate(value)
        value['profile'] = 'amdn-synthetic/1'
        self.assertFalse(validator('BeginEnrollment').is_valid(value))

    def test_proofs_are_closed_and_stage_specific(self):
        for schema in ('WebAuthnRegistration', 'WebAuthnAssertion'):
            for field in ('challenge', 'origin', 'publicKey', 'tenant_id', 'private_key'):
                value = example(schema)
                value[field] = 'forged'
                self.assertFalse(validator(schema).is_valid(value))
                value = example(schema)
                value['response'][field] = 'forged'
                self.assertFalse(validator(schema).is_valid(value))
            value = example(schema)
            value['clientExtensionResults'] = {'appid': True}
            self.assertFalse(validator(schema).is_valid(value))
            value = example(schema)
            value['type'] = 'password'
            self.assertFalse(validator(schema).is_valid(value))
        self.assertFalse(validator('WebAuthnRegistration').is_valid(example('WebAuthnAssertion')))
        self.assertFalse(validator('WebAuthnAssertion').is_valid(example('WebAuthnRegistration')))

    def test_options_cannot_downgrade_uv_algorithm_or_attestation(self):
        value = example('EnrollmentRegistrationOptions')['public_key']
        for path, replacement in [(('attestation',), 'direct'),
                                  (('authenticatorSelection', 'userVerification'), 'preferred'),
                                  (('authenticatorSelection', 'residentKey'), 'required'),
                                  (('pubKeyCredParams', 0, 'alg'), -257)]:
            changed = copy.deepcopy(value)
            node = changed
            for part in path[:-1]:
                node = node[part]
            node[path[-1]] = replacement
            self.assertFalse(validator('WebAuthnCreationOptions').is_valid(changed))
        request = example('EnrollmentCandidateOptions')['public_key']
        for allowed in ([], request['allowCredentials'] * 2):
            changed = copy.deepcopy(request)
            changed['allowCredentials'] = allowed
            self.assertFalse(validator('WebAuthnRequestOptions').is_valid(changed))
        request['userVerification'] = 'discouraged'
        self.assertFalse(validator('WebAuthnRequestOptions').is_valid(request))

    def test_completion_never_claims_messaging_or_revives_revoked_device(self):
        for schema in ('EnrollmentCompleted', 'RevocationCompleted'):
            value = example(schema)
            for field, bad in [('messaging_ready', True), ('key_id', value['device_id']),
                               ('public_key', {}), ('committed_identity_version', 0)]:
                changed = copy.deepcopy(value)
                changed[field] = bad
                self.assertFalse(validator(schema).is_valid(changed))
        value = example('EnrollmentCompleted')
        value['current_lifecycle']['status'] = 'revoked'
        value['current_lifecycle']['identity_version'] = 3
        validator('EnrollmentCompleted').validate(value)
        value = example('RevocationCompleted')
        value['current_lifecycle']['status'] = 'credential_active'
        self.assertFalse(validator('RevocationCompleted').is_valid(value))

    def test_route_results_cannot_skip_proof_stages(self):
        from jsonschema import Draft202012Validator
        routes = {
            '/v1/device-enrollments': {'EnrollmentRegistrationOptions'},
            '/v1/device-enrollments/{enrollmentId}/registration': {'EnrollmentCandidateOptions'},
            '/v1/device-enrollments/{enrollmentId}/candidate-proof': {'EnrollmentCurrentOptions', 'EnrollmentCompleted'},
            '/v1/device-enrollments/{enrollmentId}/current-proof': {'EnrollmentCompleted'},
            '/v1/devices/{deviceId}/revocations': {'RevocationOptions'},
            '/v1/device-revocations/{revocationId}/proof': {'RevocationCompleted'},
        }
        results = ['EnrollmentRegistrationOptions', 'EnrollmentCandidateOptions',
                   'EnrollmentCurrentOptions', 'EnrollmentCompleted', 'RevocationOptions']
        for path, expected in routes.items():
            op = SPEC['paths'][path]['post']
            schema = op['responses']['200']['content']['application/json']['schema']
            check = Draft202012Validator({**schema, 'components': SPEC['components']})
            for result in results:
                # RevocationCompleted intentionally shares the completed shape, but requires revoked.
                self.assertEqual(result in expected, check.is_valid(example(result)), (path, result))
            if 'RevocationCompleted' in expected:
                check.validate(example('RevocationCompleted'))
            for param in ('DeviceTenant', 'CeremonyOrigin', 'IdempotencyKey'):
                self.assertIn({'$ref': '#/components/parameters/' + param}, op['parameters'])
            self.assertEqual('device.manage', op['x-required-scope'])
            self.assertEqual('no-store', op['responses']['200']['headers']['Cache-Control']['schema']['const'])
        self.assertNotIn('/v1/devices', SPEC['paths'])
        self.assertNotIn('DeviceRequest', SPEC['components']['schemas'])


class EnrollmentGraphTests(unittest.TestCase):
    def test_flow_paths_require_candidate_then_current_for_replacement(self):
        events = {'initial': ['registration_verified', 'candidate_verified'],
                  'replacement': ['registration_verified', 'candidate_verified', 'current_verified'],
                  'revocation': ['current_verified']}
        for mode, flow in GRAPH['flows'].items():
            edges = {(t['source'], t['event']): t['target'] for t in flow['transitions']}
            self.assertEqual(len(edges), len(flow['transitions']))
            state = flow['initial']
            for event in events[mode]:
                state = edges[(state, event)]
            self.assertEqual('completed', state)
            if mode != 'revocation':
                self.assertNotIn(('awaiting_registration', 'candidate_verified'), edges)
                self.assertNotIn(('awaiting_registration', 'current_verified'), edges)
                self.assertNotIn(('awaiting_candidate_proof', 'current_verified'), edges)
            for (source, _), target in edges.items():
                self.assertIn(target, flow['states'])
                self.assertNotIn(source, GRAPH['terminal'])
                self.assertIn(source, flow['states'])
            for source in set(flow['states']) - set(GRAPH['terminal']):
                self.assertEqual('expired', edges[(source, 'deadline_elapsed')])
                for event in ('attempts_exhausted', 'bound_context_stale'):
                    self.assertEqual('abandoned', edges[(source, event)])

    def test_pending_state_vocabulary_agrees_with_response_schemas(self):
        states = {state for flow in GRAPH['flows'].values() for state in flow['states']}
        states -= set(GRAPH['terminal'])
        response_states = {example(name)['state'] for name in (
            'EnrollmentRegistrationOptions', 'EnrollmentCandidateOptions',
            'EnrollmentCurrentOptions', 'RevocationOptions')}
        self.assertEqual(states, response_states)
        self.assertEqual({'completed', 'expired', 'abandoned'}, set(GRAPH['terminal']))


if __name__ == '__main__':
    unittest.main()
