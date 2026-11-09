"""Startup validation for the successor path-derived semantic catalog."""

from copy import deepcopy
import json
from pathlib import Path
import unittest

from filesystem_decoy_2b.semantic_v2 import parse_semantic_v2


FIXTURE = Path(__file__).resolve().parents[1] / "config" / "exp_2b_path_story_v1.json"


class SemanticV2ParserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.raw = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def copy(self):
        return deepcopy(self.raw)

    def test_catalog_resolves_nested_roles_and_authored_anchors(self) -> None:
        catalog = parse_semantic_v2(self.raw)
        self.assertEqual(catalog.version, 2)
        self.assertEqual(catalog.generator_version, "path-hash-v1")
        self.assertEqual(catalog.limits.max_depth, 7)
        self.assertEqual(catalog.bindings["/var/backups/ledger"], "backups")
        self.assertEqual(
            catalog.profiles["backups"].directory_families["snapshot"].child_profile,
            "backup_set",
        )
        self.assertEqual(catalog.profiles["backup_set"].bounds.min_directories, 2)
        self.assertEqual(catalog.profiles["backup_set"].bounds.min_continuations, 2)
        self.assertEqual(catalog.profiles["backup_leaf"].bounds.max_directories, 0)
        self.assertEqual(catalog.profiles["backup_leaf"].bounds.min_continuations, 0)
        self.assertEqual(catalog.profiles["backup_set"].metadata.file.uid, 998)
        self.assertEqual(catalog.anchors["config_anchor"], "/etc/ledger-api/production.yaml")
        self.assertEqual(len(catalog.fingerprint), 64)

    def test_fingerprint_ignores_object_key_order_but_covers_template_order(self) -> None:
        original = parse_semantic_v2(self.raw).fingerprint
        reordered = json.loads(json.dumps(self.raw, sort_keys=True))
        self.assertEqual(parse_semantic_v2(reordered).fingerprint, original)
        changed = self.copy()
        changed["semantic_profiles"]["content_families"]["backup_manifest"]["templates"].append(
            "backup={{path}}\n"
        )
        self.assertNotEqual(parse_semantic_v2(changed).fingerprint, original)

    def test_unknown_fields_and_cross_references_fail(self) -> None:
        bad = self.copy()
        bad["semantic_profiles"]["surprise"] = True
        with self.assertRaisesRegex(ValueError, "unknown fields"):
            parse_semantic_v2(bad)

        bad = self.copy()
        bad["semantic_profiles"]["anchors"]["config_anchor"] = "/etc/not-authored"
        with self.assertRaisesRegex(ValueError, "authored"):
            parse_semantic_v2(bad)

        bad = self.copy()
        bad["semantic_profiles"]["profiles"]["backups"]["directory_families"]["snapshot"]["child_profile"] = "missing"
        with self.assertRaisesRegex(ValueError, "unknown child_profile"):
            parse_semantic_v2(bad)

        bad = self.copy()
        bad["semantic_profiles"]["content_families"]["backup_manifest"]["templates"] = [
            "manifest={{unknown_anchor}}\n"
        ]
        with self.assertRaisesRegex(ValueError, "unknown or malformed token"):
            parse_semantic_v2(bad)

    def test_depth_fanout_and_rendered_name_limits_fail_at_startup(self) -> None:
        bad = self.copy()
        bad["semantic_profiles"]["limits"]["max_depth"] = 9
        with self.assertRaisesRegex(ValueError, "max_depth"):
            parse_semantic_v2(bad)

        bad = self.copy()
        bad["semantic_profiles"]["profiles"]["backup_set"]["bounds"]["max_files"] = 4
        with self.assertRaisesRegex(ValueError, "fanout"):
            parse_semantic_v2(bad)

        bad = self.copy()
        bad["semantic_profiles"]["profiles"]["backups"]["bounds"]["min_continuations"] = 2
        with self.assertRaisesRegex(ValueError, "fanout"):
            parse_semantic_v2(bad)

        bad = self.copy()
        backup_families = bad["semantic_profiles"]["profiles"]["backup_set"]["directory_families"]
        backup_families["incremental"]["max_per_directory"] = 1
        backup_families["part"]["child_profile"] = "backup_leaf"
        with self.assertRaisesRegex(ValueError, "min_continuations"):
            parse_semantic_v2(bad)

        bad = self.copy()
        bad["semantic_profiles"]["context"]["service"] = "s" * 64
        bad["semantic_profiles"]["profiles"]["backups"]["directory_families"]["snapshot"]["names"] = [
            "snapshot-{{service}}-{{sequence}}"
        ]
        with self.assertRaisesRegex(ValueError, "over 64 characters"):
            parse_semantic_v2(bad)

        bad = self.copy()
        bad["semantic_profiles"]["profiles"]["log_bucket"]["directory_families"]["archive"]["names"] = [
            "a" * 55 + "{{sequence}}"
        ]
        with self.assertRaisesRegex(ValueError, "max_path_chars"):
            parse_semantic_v2(bad)

        bad = self.copy()
        bad["semantic_profiles"]["content_families"]["restore_note"]["templates"] = [
            "{{path}}" * 17
        ]
        with self.assertRaisesRegex(ValueError, "max_content_bytes"):
            parse_semantic_v2(bad)

        bad = self.copy()
        bad["system"]["hostname"] = "h" * 64
        bad["semantic_profiles"]["profiles"]["logs"]["directory_families"]["node"]["names"] = [
            "node-{{hostname}}"
        ]
        with self.assertRaisesRegex(ValueError, "over 64 characters"):
            parse_semantic_v2(bad)

    def test_credential_signature_and_unsafe_component_fail(self) -> None:
        bad = self.copy()
        bad["semantic_profiles"]["content_families"]["restore_note"]["templates"] = [
            "-----BEGIN PRIVATE KEY-----\n"
        ]
        with self.assertRaisesRegex(ValueError, "credential material"):
            parse_semantic_v2(bad)

        bad = self.copy()
        bad["semantic_profiles"]["profiles"]["logs"]["directory_families"]["node"]["names"] = [
            "../escape"
        ]
        with self.assertRaisesRegex(ValueError, "safe path-component"):
            parse_semantic_v2(bad)


if __name__ == "__main__":
    unittest.main()
