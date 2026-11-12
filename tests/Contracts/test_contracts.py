"""Executable checks of proposed contracts, not runtime security evidence."""

import copy
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator, FormatChecker
from openapi_spec_validator import validate


ROOT = Path(__file__).resolve().parents[2]
PROTOCOLS = ROOT / "docs" / "protocols"
SPEC = json.loads((PROTOCOLS / "openapi.json").read_text())
MACHINE = json.loads((PROTOCOLS / "delivery-state-machine.json").read_text())


def example(name):
    return json.loads((PROTOCOLS / "examples" / f"{name}.json").read_text())


def validator(name):
    return Draft202012Validator(
        {"$ref": f"#/components/schemas/{name}", "components": SPEC["components"]},
        format_checker=FormatChecker(),
    )


def walk(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)


class HttpContractTests(unittest.TestCase):
    def test_standard_openapi_validation_and_local_references(self):
        # Prevent validation from resolving references across a network boundary.
        for node in walk(SPEC):
            if "$ref" in node:
                self.assertTrue(node["$ref"].startswith("#/"))
                target = SPEC
                for token in node["$ref"][2:].split("/"):
                    target = target[token.replace("~1", "/").replace("~0", "~")]
        validate(SPEC)
        for schema in SPEC["components"]["schemas"].values():
            Draft202012Validator.check_schema(schema)

    def test_every_blueprint_operation_declares_auth_and_failure_contracts(self):
        expected = {
            "provisionTenant", "registerDevice", "resolveDirectory", "submitMessage",
            "getMessageStatus", "getInbox", "acknowledgeDelivery", "getPostman",
            "updatePostmanPolicy", "getPostmanAudit",
        }
        operations = [op for path in SPEC["paths"].values() for op in path.values()]
        self.assertEqual(expected, {op["operationId"] for op in operations})
        self.assertEqual(len(expected), len(operations))
        for op in operations:
            with self.subTest(operation=op["operationId"]):
                self.assertEqual([{"accessToken": []}], op.get("security", SPEC["security"]))
                for field in ("x-required-scope", "x-authorization", "x-idempotency", "x-rate-limit"):
                    self.assertTrue(op[field])
                self.assertTrue({"400", "401", "403", "404", "429", "503"} <= op["responses"].keys())
                for code, response in op["responses"].items():
                    if code.startswith("2"):
                        self.assertIn("schema", response["content"]["application/json"])

    def test_synthetic_examples_match_their_schemas(self):
        for name, schema in [("submit-message", "SubmitMessage"), ("device-ack", "AckRequest"),
                             ("message-status", "MessageStatus"), ("accepted", "Accepted")]:
            with self.subTest(example=name):
                validator(schema).validate(example(name))

    def test_submission_rejects_forged_identity_and_plaintext_fields(self):
        for field in ("sender", "tenant_id", "envelope_id", "plaintext", "private_key"):
            value = example("submit-message")
            value[field] = "synthetic-forbidden-field"
            with self.subTest(field=field):
                self.assertFalse(validator("SubmitMessage").is_valid(value))
        value = example("submit-message")
        value["payload"]["plaintext"] = "synthetic-forbidden-field"
        self.assertFalse(validator("SubmitMessage").is_valid(value))

    def test_submission_shape_bounds_and_versions(self):
        cases = [
            (("version",), "amdn-envelope/2"),
            (("client_message_id",), "alice@example.test"),
            (("created_at",), "2026-99-12T10:00:00Z"),
            (("created_at",), "2026-11-12T10:00:00+05:30"),
            (("payload", "ciphertext"), ""),
            (("payload", "ciphertext"), "AA=="),
            (("payload", "ciphertext"), "A" * 174764),
            (("payload", "encryption_profile"), "unversioned"),
            (("recipient", "expected_device_id"), "claimed-device"),
        ]
        for path, replacement in cases:
            value = example("submit-message")
            node = value
            for part in path[:-1]:
                node = node[part]
            node[path[-1]] = replacement
            with self.subTest(path=path, length=len(replacement)):
                self.assertFalse(validator("SubmitMessage").is_valid(value))

    def test_ack_does_not_claim_read_or_decryption(self):
        for kind in ("read", "decrypted", "broker_acked"):
            value = example("device-ack")
            value["receipt_kind"] = kind
            self.assertFalse(validator("AckRequest").is_valid(value))
        value = example("device-ack")
        value["plaintext"] = "not-a-receipt-field"
        self.assertFalse(validator("AckRequest").is_valid(value))

    def test_delivered_is_true_only_for_device_ack(self):
        for state in MACHINE["states"]:
            status = example("message-status")
            status["state"] = state
            status["reason"] = {"EXPIRED": "expired", "FAILED": "retry_exhausted"}.get(state, "none")
            status["delivered"] = state == "DEVICE_ACKED"
            validator("MessageStatus").validate(status)
            status["delivered"] = not status["delivered"]
            self.assertFalse(validator("MessageStatus").is_valid(status))
        status["state"] = "READ"
        self.assertFalse(validator("MessageStatus").is_valid(status))

    def test_policy_has_no_arbitrary_capability_grant(self):
        policy = {"receive_enabled": True, "dispatch_enabled": True, "retry_enabled": True}
        validator("Policy").validate(policy)
        for field in ("message.read_content", "message.reply", "tenant_id", "owner_user_id"):
            forged = copy.deepcopy(policy)
            forged[field] = True
            self.assertFalse(validator("Policy").is_valid(forged))

    def test_pagination_and_conditional_commands(self):
        for path in ("/v1/inbox", "/v1/postman/audit"):
            self.assertIn("410", SPEC["paths"][path]["get"]["responses"])
        patch = SPEC["paths"]["/v1/postman/policy"]["patch"]
        self.assertIn({"$ref": "#/components/parameters/IfMatch"}, patch["parameters"])
        self.assertIn("412", patch["responses"])
        for path in ("/v1/tenants", "/v1/devices", "/v1/messages"):
            command = SPEC["paths"][path]["post"]
            self.assertIn({"$ref": "#/components/parameters/IdempotencyKey"}, command["parameters"])
            self.assertIn("409", command["responses"])
        self.assertEqual({"202"}, {s for s in SPEC["paths"]["/v1/messages"]["post"]["responses"] if s.startswith("2")})


class DeliveryContractTests(unittest.TestCase):
    """Check the declared transition graph, not a delivery implementation."""

    def setUp(self):
        self.edges = {(t["source"], t["event"]): t["target"] for t in MACHINE["transitions"]}

    def path(self, events):
        state = MACHINE["initial"]
        for event in events:
            state = self.edges[(state, event)]
        return state

    def test_public_status_vocabulary_matches_graph_and_terminals_do_not_regress(self):
        self.assertEqual(set(MACHINE["states"]), set(SPEC["components"]["schemas"]["DeliveryState"]["enum"]))
        self.assertEqual(len(self.edges), len(MACHINE["transitions"]))
        self.assertEqual({"DEVICE_ACKED", "EXPIRED", "FAILED"}, set(MACHINE["terminal"]))
        for (source, _), target in self.edges.items():
            self.assertIn(source, MACHINE["states"])
            self.assertIn(target, MACHINE["states"])
            self.assertNotIn(source, MACHINE["terminal"])

    def test_normal_and_late_publication_paths(self):
        self.assertEqual("DEVICE_ACKED", self.path(["publication_confirmed", "inbox_committed", "authorized_device_stored"]))
        self.assertEqual("DEVICE_ACKED", self.path(["inbox_committed", "authorized_device_stored"]))
        self.assertNotIn(("INBOX_STORED", "publication_confirmed"), self.edges)
        self.assertNotIn(("ACCEPTED", "authorized_device_stored"), self.edges)
        self.assertNotIn(("QUEUED", "authorized_device_stored"), self.edges)

    def test_expiry_and_failure_cannot_turn_into_success(self):
        for events in (["expiry_due"], ["publication_confirmed", "expiry_due"],
                       ["inbox_committed", "expiry_due"], ["permanent_failure"]):
            terminal = self.path(events)
            self.assertNotIn((terminal, "authorized_device_stored"), self.edges)
        self.assertNotIn(("INBOX_STORED", "permanent_failure"), self.edges)
        self.assertNotIn(("DEVICE_ACKED", "expiry_due"), self.edges)

    def test_duplicate_events_do_not_declare_an_extra_transition(self):
        for state, event in [("QUEUED", "publication_confirmed"), ("INBOX_STORED", "inbox_committed"),
                             ("DEVICE_ACKED", "authorized_device_stored")]:
            self.assertNotIn((state, event), self.edges)


if __name__ == "__main__":
    unittest.main()
