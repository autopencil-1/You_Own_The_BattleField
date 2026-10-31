"""Behavioral checks for retrieval and the capability gate; no model call."""

import json
from pathlib import Path
import unittest

from threat_model import _gap_text, example_result, generate_result, parse_model_json, plan_paths, retrieve


SNAPSHOT = json.loads((Path(__file__).parent / "snapshot.json").read_text())


class ThreatModelTests(unittest.TestCase):
    def test_independent_actions_do_not_form_a_false_sequence(self):
        actions = [
            {"id": "a", "kind": "hypothesis", "asset_id": "store-role:ticket-files", "preconditions": ["network_reach:store-role:ticket-files"],
             "effects": ["read:store-role:ticket-files"], "missing_evidence": ["EFS permission"], "status": "conditional"},
            {"id": "b", "kind": "hypothesis", "asset_id": "store-role:public-uploads", "preconditions": ["network_reach:store-role:public-uploads"],
             "effects": ["read:store-role:public-uploads"], "missing_evidence": ["S3 permission"], "status": "conditional"},
        ]
        paths, blocked = plan_paths(actions, ["network_reach:store-role:ticket-files",
                                             "network_reach:store-role:public-uploads"], None)
        self.assertEqual([path["action_ids"] for path in paths], [["a"], ["b"]])
        self.assertEqual(blocked, [])

    def test_model_json_parser_accepts_wrapped_object_and_rejects_truncation(self):
        self.assertEqual(parse_model_json('Result:\n```json\n{"actions": [], "gaps": []}\n```'),
                         {"actions": [], "gaps": []})
        with self.assertRaisesRegex(RuntimeError, "malformed JSON"):
            parse_model_json('{"actions": [')

    def test_retrieval_has_bounded_cited_evidence_and_no_raw_body(self):
        context = retrieve(SNAPSHOT, "public ticket access and database permissions")
        self.assertLessEqual(len(context["documents"]), 44)
        self.assertEqual(len({doc["id"] for doc in context["documents"]}), len(context["documents"]))
        self.assertIn("finding:30987", {doc["id"] for doc in context["documents"]})
        self.assertIn("network_reach:store-role:relational-db", context["initial_capabilities"])
        self.assertNotIn("read:store-role:relational-db", context["initial_capabilities"])
        self.assertNotIn("role_session:REPORTER", context["initial_capabilities"])
        self.assertFalse(any("response_body" in doc["text"] for doc in context["documents"]))

    def test_network_reach_alone_makes_store_route_conditional(self):
        raw = {"actions": [{"id": "db-read", "name": "Read database", "asset_id": "store-role:relational-db",
            "preconditions": ["network_reach:store-role:relational-db"],
            "effects": ["read:store-role:relational-db"],
            "evidence_ids": ["asset:store-role:relational-db"], "missing_evidence": [],
            "rationale": "Hypothetical only"}], "gaps": []}
        result = generate_result(SNAPSHOT, "Assess a route to the relational database",
                                 "store-role:relational-db", model_output=raw)
        self.assertEqual(len(result["paths"]), 1)
        self.assertEqual(result["paths"][0]["status"], "conditional")
        self.assertTrue(result["paths"][0]["missing_evidence"])

    def test_unmet_role_prerequisite_blocks_path_and_bad_citation_is_rejected(self):
        raw = {"actions": [
            {"id": "manager-wallet", "name": "Read company wallet", "asset_id": "app:bugcamp-api",
             "preconditions": ["role_session:MANAGER"], "effects": ["read:app:bugcamp-api"],
             "evidence_ids": ["access:manager-area"], "missing_evidence": ["Manager session"],
             "rationale": "Requires manager access"},
            {"id": "invented", "name": "Invented CVE", "asset_id": "app:bugcamp-api",
             "preconditions": ["network_reach:app:bugcamp-api"], "effects": ["execute:app:bugcamp-api"],
             "evidence_ids": ["finding:CVE-DOES-NOT-EXIST"], "missing_evidence": [], "rationale": ""}
        ], "gaps": []}
        result = generate_result(SNAPSHOT, "Assess manager wallet access", model_output=raw)
        self.assertEqual(result["paths"], [])
        self.assertEqual([row["id"] for row in result["hypotheses"]], ["manager-wallet"])
        self.assertEqual(len(result["rejected_actions"]), 1)
        self.assertEqual(next(row for row in result["blocked_actions"] if row["action_id"] == "manager-wallet")
                         ["unmet_preconditions"], ["role_session:MANAGER"])

    def test_inferred_public_read_never_becomes_supported_path(self):
        raw = {"actions": [{"id": "disclosed", "name": "Read a disclosed ticket",
            "asset_id": "surface:api", "preconditions": ["network_reach:alb:bugcamp-main"],
            "effects": ["public_read:disclosed-ticket-read"],
            "evidence_ids": ["access:disclosed-ticket-read"], "missing_evidence": [],
            "rationale": "Disclosure is conditional"}], "gaps": []}
        result = generate_result(SNAPSHOT, "Assess public disclosed ticket reading", model_output=raw)
        self.assertEqual(result["hypotheses"], [])
        self.assertEqual(result["paths"], [])
        self.assertEqual(len(result["rejected_actions"]), 1)

    def test_sql_injection_credential_login_and_authorization_chain(self):
        def hypothesis(identity, name, category, asset, pre, effect, evidence):
            return {"id": identity, "name": name, "category": category, "asset_id": asset,
                    "entry_point": "/api/example", "preconditions": pre, "effects": [effect],
                    "evidence_ids": [evidence], "missing_evidence": [f"Verify {identity}"],
                    "rationale": "Conditional", "verification_question": f"Does {identity} exist?"}
        raw = {"hypotheses": [
            hypothesis("sqli", "Possible SQL injection", "SQL injection", "app:bugcamp-api",
                       ["route_access:surface:api"], "read:store-role:relational-db", "asset:app:bugcamp-api"),
            hypothesis("secret", "Reusable credential exposure", "credential exposure", "store-role:relational-db",
                       ["read:store-role:relational-db"], "credential:MANAGER", "asset:store-role:relational-db"),
            hypothesis("manager-read", "Manager authorization failure", "authorization", "app:bugcamp-api",
                       ["role_session:MANAGER"], "read:app:bugcamp-api", "access:manager-area"),
        ], "gaps": []}
        result = generate_result(SNAPSHOT, "Assess a possible multi-step API route", model_output=raw)
        self.assertEqual(result["planner_version"], 3)
        self.assertIn(["known-route-api", "sqli", "secret", "known-login-manager", "manager-read"],
                      [path["action_ids"] for path in result["paths"]])
        self.assertTrue(all(path["status"] == "conditional" for path in result["paths"]))

    def test_sql_injection_cannot_directly_claim_credential(self):
        raw = {"hypotheses": [{"id": "bad", "name": "SQL injection yields password", "category": "SQL injection",
            "asset_id": "app:bugcamp-api", "entry_point": "/api/auth/login",
            "preconditions": ["route_access:surface:api"], "effects": ["credential:MANAGER"],
            "evidence_ids": ["asset:app:bugcamp-api"], "missing_evidence": ["Verify password disclosure"],
            "rationale": "Unverified", "verification_question": "Does this happen?"}], "gaps": []}
        result = generate_result(SNAPSHOT, "Assess possible SQL injection effects", model_output=raw)
        self.assertEqual(result["hypotheses"], [])
        self.assertEqual(len(result["rejected_actions"]), 1)

    def test_and_prerequisites_keep_both_causal_branches(self):
        def action(identity, pre, effect):
            return {"id": identity, "kind": "hypothesis", "asset_id": "app:bugcamp-api",
                    "preconditions": pre, "effects": [effect], "missing_evidence": [identity],
                    "status": "conditional"}
        actions = [
            action("credential", ["route_access:surface:api"], "credential:MANAGER"),
            action("object-id", ["route_access:surface:api"], "read:surface:api"),
            action("combine", ["credential:MANAGER", "read:surface:api"], "write:app:bugcamp-api"),
            action("unrelated", ["route_access:surface:api"], "read:store-role:public-uploads"),
        ]
        paths, blocked = plan_paths(actions, ["route_access:surface:api"], None)
        self.assertIn(["credential", "object-id", "combine"], [path["action_ids"] for path in paths])
        self.assertFalse(any("unrelated" in path["action_ids"] and "combine" in path["action_ids"]
                             for path in paths))
        self.assertEqual(blocked, [])

    def test_offline_preview_is_labeled_and_has_distinct_credential_step(self):
        result = example_result(SNAPSHOT)
        self.assertTrue(result["example"])
        self.assertEqual(result["provider"], "offline")
        self.assertEqual(len(result["hypotheses"]), 10)
        self.assertTrue(any(path["action_ids"] == ["known-route-api", "sql-query", "db-credential",
                                                      "known-login-manager", "cross-company"]
                            for path in result["paths"]))

    def test_followup_hypothesis_extends_first_pass(self):
        def hypothesis(identity, category, pre, effect, evidence):
            return {"id": identity, "name": identity, "category": category,
                    "asset_id": "app:bugcamp-api", "entry_point": "/api/example",
                    "preconditions": pre, "effects": [effect], "evidence_ids": [evidence],
                    "missing_evidence": ["Verify " + identity], "rationale": "Conditional",
                    "verification_question": "Does this exist?"}
        first = {"hypotheses": [hypothesis("query", "SQL injection", ["route_access:surface:api"],
                                            "read:store-role:relational-db", "asset:app:bugcamp-api")], "gaps": []}
        second = {"hypotheses": [hypothesis("credential", "credential exposure",
                                             ["read:store-role:relational-db"], "credential:MANAGER",
                                             "asset:store-role:relational-db")], "gaps": []}
        result = generate_result(SNAPSHOT, "Assess downstream manager credential access",
                                 model_output=first, followup_output=second)
        self.assertEqual(result["hypothesis_stages"], {"entry": 1, "downstream": 1,
                                                         "downstream_status": "completed"})
        self.assertIn(["known-route-api", "query", "next-credential", "known-login-manager"],
                      [path["action_ids"] for path in result["paths"]])

    def test_capability_scope_rejects_cookie_to_store_and_api_to_full_db(self):
        def item(identity, category, effect):
            return {"id": identity, "name": identity, "category": category,
                    "asset_id": "app:bugcamp-api", "entry_point": "/api/example",
                    "preconditions": ["route_access:surface:api"], "effects": [effect],
                    "evidence_ids": ["asset:app:bugcamp-api"],
                    "missing_evidence": ["Verify " + identity], "rationale": "Conditional",
                    "verification_question": "Does this exist?"}
        raw = {"hypotheses": [
            item("cookie", "session handling", "session_access:store-role:session"),
            item("wallet", "object authorization", "read:store-role:relational-db"),
            item("admin", "authentication", "role_session:ADMIN_ACCOUNT"),
        ], "gaps": []}
        result = generate_result(SNAPSHOT, "Check capability scope on app routes", model_output=raw)
        self.assertEqual(result["hypotheses"], [])
        self.assertEqual(len(result["rejected_actions"]), 3)

    def test_disclosed_ticket_public_read_is_scoped_to_disclosed_rule(self):
        result = generate_result(SNAPSHOT, "Assess disclosed ticket public access",
                                 model_output={"hypotheses": [], "gaps": []})
        action = next(a for a in result["actions"] if a["id"] == "known-public-disclosed-ticket-read")
        self.assertEqual(action["preconditions"], ["route_access:surface:api"])
        self.assertEqual(action["effects"], ["public_read:disclosed-ticket-read"])
        self.assertIn("private tickets are outside", action["rationale"])

    def test_model_gap_with_alternate_keys_keeps_its_content(self):
        self.assertEqual(_gap_text({"issue": "Session grants unknown", "check": "Inspect session rows"}),
                         "issue: Session grants unknown; check: Inspect session rows")


if __name__ == "__main__":
    unittest.main()
