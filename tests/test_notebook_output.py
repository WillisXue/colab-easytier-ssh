"""Exercise the actual notebook bootstrap function with mocked Colab I/O."""
import ast
import contextlib
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
import urllib.request
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]


def bootstrap_source():
    tree = ast.parse((ROOT / "tools" / "build_notebook.py").read_text(encoding="utf-8"))
    assignment = next(node for node in tree.body if isinstance(node, ast.Assign)
                      and any(isinstance(target, ast.Name) and target.id == "source" for target in node.targets))
    return eval(compile(ast.Expression(assignment.value), "template", "eval"),
                {"args": SimpleNamespace(commit="1" * 40), "digest": "0" * 64})


class NotebookOutputTests(unittest.TestCase):
    def execute_bootstrap(self, result):
        tree = ast.parse(bootstrap_source())
        fn = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                  and node.name == "install_from_secrets")
        # Compile only the function, so imports and the real top-level call
        # never require a Colab runtime or access a user's account.
        code = compile(ast.Module(body=[fn], type_ignores=[]), "bootstrap", "exec")
        private = {name: "PRIVATE-" + name for name in (
            "ET_NETWORK_NAME", "ET_NETWORK_SECRET", "ET_PEERS", "SSH_PUBLIC_KEY")}
        fake_installer = b"# test installer\n"
        runner = Mock(return_value=result)
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as temp:
            env = {"hashlib": hashlib, "json": json, "urllib": SimpleNamespace(request=urllib.request),
                   "subprocess": SimpleNamespace(run=runner), "sys": sys,
                   "userdata": SimpleNamespace(get=lambda name: private[name]),
                   "INSTALLER_COMMIT": "1" * 40,
                   "INSTALLER_SHA256": hashlib.sha256(fake_installer).hexdigest(),
                   "INSTALLER_PATH": Path(temp) / "install.py", "ET_IPV4": "", "SSH_PORT": 2222}
            exec(code, env)
            with patch.object(urllib.request, "urlopen", return_value=io.BytesIO(fake_installer)), \
                 contextlib.redirect_stdout(output):
                env["install_from_secrets"]()
        return output.getvalue(), runner, private

    def test_child_stdout_stderr_and_exit_code_are_shown_in_cell(self):
        result = subprocess.CompletedProcess([], 1, "[2/5] SSH configuration\n", "错误: SSH_PUBLIC_KEY 格式错误。\n")
        output, runner, private = self.execute_bootstrap(result)
        self.assertIn("[2/5] SSH configuration", output)
        self.assertIn("SSH_PUBLIC_KEY 格式错误", output)
        self.assertIn("退出码：1", output)
        kwargs = runner.call_args.kwargs
        self.assertTrue(kwargs["capture_output"])
        for value in private.values():
            self.assertNotIn(value, output)
            self.assertNotIn(value, " ".join(runner.call_args.args[0]))
            self.assertIn(value, kwargs["input"])

    def test_no_child_output_still_produces_useful_failure(self):
        result = subprocess.CompletedProcess([], -9, "", "")
        output, _, _ = self.execute_bootstrap(result)
        self.assertIn("退出码：-9", output)
        self.assertIn("没有返回日志", output)

    def test_success_output_is_displayed(self):
        result = subprocess.CompletedProcess([], 0, "虚拟 IPv4: 10.144.144.2\n安装完成。\n", "")
        output, _, _ = self.execute_bootstrap(result)
        self.assertIn("虚拟 IPv4: 10.144.144.2", output)
        self.assertIn("安装完成", output)
        self.assertNotIn("安装失败", output)


if __name__ == "__main__":
    unittest.main()
