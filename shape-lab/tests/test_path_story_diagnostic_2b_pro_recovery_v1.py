"""Model-free checks for the exact archived Pro B3 DNS reconciliation."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from subprocess import CompletedProcess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from experiment_controller import path_story_diagnostic_2b_pro_recovery_v1 as recovery
from experiment_controller import path_story_diagnostic_2b_pro_v1 as pro
from experiment_controller import path_story_pilot_2b_v2 as committed


@unittest.skipUnless(
    (pro.LAB / "runs" / recovery.DNS_RUN_ID / "result.json").is_file(),
    "The exact DNS archive is not present in this checkout",
)
class ExactDNSRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        # The frozen study is already hash committed. Avoid Docker image lookup
        # in these archive-only checks so they remain model-free and local.
        self.study = committed._read_committed(recovery.SCHEDULE)
        handle = patch.object(pro, "_schedule", return_value=(self.study, {}, {}))
        handle.start()
        self.addCleanup(handle.stop)

    def test_exact_dns_failure_is_priced_and_never_becomes_behavioral_outcome(self) -> None:
        record = recovery._expected_dns_reconciliation(self.study)
        self.assertEqual(record["successful_provider_calls_with_reported_usage"], 24)
        self.assertEqual(record["reported_usage_credit_estimate"], "79.807400000")
        self.assertEqual(record["dns_failure_error_type"], "gaierror")
        self.assertFalse(record["provider_charge_independently_verified"])
        self.assertFalse(record["creates_behavioral_outcome"])

    def test_different_gateway_failure_cannot_use_the_dns_exception(self) -> None:
        run_dir = pro.LAB / "runs" / recovery.DNS_RUN_ID
        altered = deepcopy(recovery._rows(run_dir))
        altered[-2]["error_type"] = "TimeoutError"
        with patch.object(recovery, "_rows", return_value=altered):
            with self.assertRaisesRegex(recovery.DNSRecoveryIntegrityError, "DNS failure lifecycle differs"):
                recovery._expected_dns_reconciliation(self.study)

    def test_other_run_identity_cannot_use_signed_reconciliation(self) -> None:
        self.assertFalse(recovery.verify_reconciled_exposure("2b-path-20261109192156-08a4c0", "a" * 64))

    def test_gateway_image_source_check_requires_both_expected_hashes(self) -> None:
        expected = (
            f"{recovery.PINS['gateway_server_source_sha256']}  /app/model_gateway/server.py\n"
            f"{recovery.PINS['gateway_entry_source_sha256']}  /app/model_gateway/server_path_story_v2.py\n"
        )
        with patch.object(recovery.subprocess, "run", return_value=CompletedProcess([], 0, expected)) as command:
            recovery._verify_gateway_image_source()
            self.assertIn("--network", command.call_args.args[0])
            self.assertIn("none", command.call_args.args[0])
        with patch.object(recovery.subprocess, "run", return_value=CompletedProcess([], 0, "wrong\n")):
            with self.assertRaisesRegex(recovery.DNSRecoveryIntegrityError, "image source differs"):
                recovery._verify_gateway_image_source()

    def test_signed_dns_recovery_handles_sidecar_only_pending_after_crash(self) -> None:
        with TemporaryDirectory() as temporary:
            pending = Path(temporary) / "pending-run.json"
            pending.with_suffix(".sha256").write_text(recovery.PINS["pending_sha256"] + "\n", encoding="utf-8")
            with patch.object(recovery, "_pending_path", return_value=pending), \
                    patch.object(recovery, "_reconciliation", return_value={"run_id": recovery.DNS_RUN_ID}):
                self.assertEqual(recovery._pending()["run_id"], recovery.DNS_RUN_ID)
            pending.with_suffix(".sha256").write_text("0" * 64 + "\n", encoding="utf-8")
            with patch.object(recovery, "_pending_path", return_value=pending), \
                    patch.object(recovery, "_reconciliation", return_value={"run_id": recovery.DNS_RUN_ID}):
                with self.assertRaisesRegex(recovery.DNSRecoveryIntegrityError, "Partial pending digest differs"):
                    recovery._pending()


if __name__ == "__main__":
    unittest.main()
