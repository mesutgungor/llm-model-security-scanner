"""
Unit tests for the Model Context Protocol (MCP) Server.
"""

import unittest
import asyncio
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from llm_security_scanner.mcp_server import create_mcp_server


class TestMCPServer(unittest.TestCase):
    def test_mcp_server_tools_registered(self):
        server = create_mcp_server()
        tools = asyncio.run(server.list_tools())
        tool_names = [t.name for t in tools]

        self.assertIn("scan_huggingface_model", tool_names)
        self.assertIn("audit_local_model", tool_names)
        self.assertIn("verify_model_proof", tool_names)
        self.assertIn("explain_security_rule", tool_names)

    def test_mcp_explain_security_rule(self):
        server = create_mcp_server()
        res = asyncio.run(server.call_tool("explain_security_rule", {"rule_id": "SEC-RCE-003"}))
        data = json.loads(res[0][0].text)

        self.assertEqual(data["rule_id"], "SEC-RCE-003")
        self.assertIn("owasp_llm_top10", data["compliance"])
        self.assertIn("AML.T0048", data["compliance"]["mitre_atlas"])

    def test_mcp_audit_local_model(self):
        with TemporaryDirectory() as tmpdir:
            dummy = Path(tmpdir) / "model.py"
            dummy.write_text("import torch\n", encoding="utf-8")

            server = create_mcp_server()
            res = asyncio.run(server.call_tool("audit_local_model", {"target_path": str(dummy)}))
            data = json.loads(res[0][0].text)

            self.assertTrue(data["safe_to_load"])
            self.assertEqual(data["verdict"], "SAFE")
            self.assertEqual(data["findings_count"], 0)


if __name__ == "__main__":
    unittest.main()
