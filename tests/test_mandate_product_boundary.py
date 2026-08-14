"""Regression checks for the neutral Mandate seam's product boundary."""

from pathlib import Path
import ast
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "minority_prophet" / "mandate_gate.py"


class MandateProductBoundaryTests(unittest.TestCase):
    def test_seam_has_no_provider_or_transport_dependency(self):
        tree = ast.parse(MODULE.read_text(encoding="utf-8"))
        imports = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imports.update(
            node.module.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        )
        self.assertTrue(imports.isdisjoint({"requests", "httpx", "boto3", "openai"}))

    def test_runtime_context_is_not_presented_as_a_credential_or_root(self):
        source = MODULE.read_text(encoding="utf-8")
        self.assertIn("This is context, not a new credential", source)
        self.assertIn("does not mint a new evidence root", source)
        self.assertIn('"assessment": "observed"', source)


if __name__ == "__main__":
    unittest.main()
