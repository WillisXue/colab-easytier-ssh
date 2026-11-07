import base64
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("installer", ROOT / "install.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def config():
    # A structurally valid public test key; never used to authenticate.
    kind = b"ssh-ed25519"
    raw = struct.pack(">I", len(kind)) + kind + struct.pack(">I", 32) + bytes(range(32))
    return {"ET_NETWORK_NAME": 'test-network-"\\-中文',
            "ET_NETWORK_SECRET": 'TEST-secret-"\\-$()-`-123456',
            "ET_PEERS": ["tcp://private-example.invalid:11010"],
            "SSH_PUBLIC_KEY": "ssh-ed25519 " + base64.b64encode(raw).decode() + " private-comment"}


class InstallerTests(unittest.TestCase):
    def test_private_parameters_travel_in_stdin_and_never_in_output(self):
        cfg = config()
        for action in ("check", "start"):
            # 'start' exits before mutation on Windows/non-root; Linux root is
            # covered by dedicated integration instead.
            if action == "start" and os.name != "nt":
                continue
            proc = subprocess.run([sys.executable, str(ROOT / "install.py"), action, "--config-stdin"],
                                  input=json.dumps(cfg), text=True, encoding="utf-8", capture_output=True)
            for secret in (cfg["ET_NETWORK_NAME"], cfg["ET_NETWORK_SECRET"], cfg["ET_PEERS"][0], "private-comment"):
                self.assertNotIn(secret, proc.stdout + proc.stderr)
            if action == "check":
                self.assertEqual(proc.returncode, 0)

    def test_toml_round_trip_prevents_config_injection(self):
        import tomllib
        cfg = m.validate(config())
        toml = tomllib.loads(m.make_toml(cfg))
        self.assertEqual(toml["network_identity"]["network_name"], cfg["ET_NETWORK_NAME"])
        self.assertEqual(toml["network_identity"]["network_secret"], cfg["ET_NETWORK_SECRET"])
        self.assertNotIn("tcp_whitelist", toml)
        self.assertNotIn("udp_whitelist", toml)
        self.assertTrue(toml["flags"]["no_tun"])
        self.assertNotIn("private-comment", cfg["SSH_PUBLIC_KEY"])

    def test_reject_invalid_config_without_echoing_values(self):
        cases = [("ET_NETWORK_SECRET", None), ("ET_PEERS", ["https://secret-host.invalid:443"]),
                 ("ET_PEERS", ["tcp://user:secret@host.invalid:11010"]),
                 ("SSH_PUBLIC_KEY", "-----BEGIN OPENSSH PRIVATE KEY-----"),
                 ("SSH_PUBLIC_KEY", 'command="bad" ssh-ed25519 aaaa'),
                 ("ET_IPV4", "127.0.0.1"), ("SSH_PORT", 22),
                 ("ET_NETWORK_NAME", "injected\n[flags]"),
                 ("EASYTIER_VERSION", "latest")]
        for field, value in cases:
            with self.subTest(field=field):
                cfg = config()
                cfg[field] = value
                with self.assertRaises(m.SetupError) as caught:
                    m.validate(cfg)
                self.assertNotIn(str(value), str(caught.exception))

    def test_network_secret_accepts_any_nonempty_string(self):
        for secret in ("a", "short", " "):
            with self.subTest(length=len(secret)):
                cfg = config()
                cfg["ET_NETWORK_SECRET"] = secret
                self.assertEqual(m.validate(cfg)["ET_NETWORK_SECRET"], secret)

    def test_empty_network_secret_is_rejected(self):
        cfg = config()
        cfg["ET_NETWORK_SECRET"] = ""
        with self.assertRaises(m.SetupError):
            m.validate(cfg)

    def test_blank_or_missing_ipv4_enables_automatic_allocation(self):
        import tomllib
        for value in (None, "", "   "):
            cfg = config()
            if value is not None:
                cfg["ET_IPV4"] = value
            validated = m.validate(cfg)
            self.assertEqual(validated["ET_IPV4"], "")
            result = tomllib.loads(m.make_toml(validated))
            self.assertTrue(result["dhcp"])
            self.assertNotIn("ipv4", result)

    def test_explicit_ipv4_uses_static_allocation(self):
        import tomllib
        cfg = config()
        cfg["ET_IPV4"] = "10.200.1.2/24"
        result = tomllib.loads(m.make_toml(m.validate(cfg)))
        self.assertFalse(result["dhcp"])
        self.assertEqual(result["ipv4"], "10.200.1.2/24")

    def test_precedence_and_multi_peer_input(self):
        parser_args = type("Args", (), dict(config_stdin=True, config_file=None, ipv4="10.200.1.2/24",
                           ssh_port=3333, easytier_version=None))()
        cfg = config()
        cfg["ET_PEERS"] = "tcp://one.invalid:11010,udp://two.invalid:11010"
        with patch.dict(os.environ, {"SSH_PORT": "4444"}), patch("sys.stdin", io.StringIO(json.dumps(cfg))):
            result = m.read_config(parser_args)
        self.assertEqual(result["SSH_PORT"], 3333)
        self.assertEqual(len(result["ET_PEERS"]), 2)

    def test_subprocess_failure_does_not_reveal_captured_output(self):
        proc = subprocess.CompletedProcess([], 1, "SECRET-SERVER", "SECRET-KEY")
        with patch.object(m.subprocess, "run", return_value=proc):
            with self.assertRaises(m.SetupError) as caught:
                m.run(["fake"])
        self.assertNotIn("SECRET", str(caught.exception))
        self.assertFalse(any(k.startswith("ET_") for k in m.clean_env()))

    def test_system_tool_error_includes_tool_exit_code_and_diagnostic(self):
        proc = subprocess.CompletedProcess([], 1, "", "Missing privilege separation directory: /run/sshd\n")
        with patch.object(m.subprocess, "run", return_value=proc):
            with self.assertRaises(m.SetupError) as caught:
                m.run(["/usr/sbin/sshd", "-t", "-f", "/run/project/config"])
        self.assertIn("sshd", str(caught.exception))
        self.assertIn("1", str(caught.exception))
        self.assertIn("Missing privilege separation directory", str(caught.exception))

    def test_timeout_identifies_command_and_duration(self):
        with patch.object(m.subprocess, "run", side_effect=subprocess.TimeoutExpired(["apt-get"], 300)):
            with self.assertRaises(m.SetupError) as caught:
                m.run(["apt-get", "update"], timeout=300)
        self.assertIn("apt-get", str(caught.exception))
        self.assertIn("300", str(caught.exception))

    def test_unexpected_error_identifies_type_without_private_context(self):
        output = io.StringIO()
        with patch.object(m, "read_config", side_effect=PermissionError(13, "PRIVATE-CONTEXT")), \
             contextlib.redirect_stderr(output):
            self.assertEqual(m.main(["check"]), 1)
        self.assertIn("PermissionError", output.getvalue())
        self.assertIn("errno=13", output.getvalue())
        self.assertNotIn("PRIVATE-CONTEXT", output.getvalue())

    def test_existing_sshd_launch_options_are_read_without_a_shell(self):
        path, options = m.ssh_launch_options('sshd: /usr/sbin/sshd -D -f /etc/ssh/custom.conf -p2222 -o "UsePAM=yes" [listener]')
        self.assertEqual(path, "/etc/ssh/custom.conf")
        self.assertEqual(options, ["-p", "2222", "-o", "UsePAM=yes"])

    def test_managed_ssh_block_cleanup_preserves_surrounding_settings(self):
        existing = "Port 2222\nUsePAM no\n# Existing settings\n"
        modified = m.SSH_BEGIN + "UsePAM yes\n" + m.SSH_END + existing
        self.assertEqual(m.remove_ssh_block(modified), existing)

    @unittest.skipUnless(os.name == "posix", "POSIX private file writes")
    def test_adding_public_key_preserves_existing_keys_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "authorized_keys"
            existing = "existing-key-data existing-comment\n"
            path.write_text(existing)
            key = "test-key-type public-key-test-data"
            entry = m.add_authorized_key(path, key)
            self.assertTrue(path.read_text().startswith(existing))
            self.assertEqual(path.read_text().count(key), 1)
            self.assertIsNone(m.add_authorized_key(path, key))
            m.cleanup_ssh({"key_entries": [entry]})
            self.assertEqual(path.read_text(), existing)

    @unittest.skipUnless(os.name == "posix", "POSIX private file writes")
    def test_preexisting_public_key_is_not_claimed_for_cleanup(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "authorized_keys"
            key = "test-key-type public-key-test-data"
            path.write_text(key + " user-comment\n")
            self.assertIsNone(m.add_authorized_key(path, key))
            self.assertEqual(path.read_text(), key + " user-comment\n")

    def test_cli_handles_non_utf8_terminal(self):
        result = subprocess.run([sys.executable, str(ROOT / "install.py"), "check", "--config-stdin"],
                                input=json.dumps(config()), text=True, encoding="utf-8", capture_output=True,
                                env={**os.environ, "PYTHONIOENCODING": "ascii"})
        self.assertEqual(result.returncode, 0)
        self.assertNotIn("Traceback", result.stderr)

    def test_digest_failure_removes_download(self):
        with tempfile.TemporaryDirectory() as temp:
            dest = Path(temp) / "bad.zip"
            with patch.object(m.urllib.request, "urlopen", return_value=io.BytesIO(b"tampered")):
                with self.assertRaises(m.SetupError):
                    m.fetch("https://github.com/example/file", dest, hashlib.sha256(b"expected").hexdigest())
            self.assertFalse(dest.exists())

    def test_pid_reuse_and_unrelated_process_are_never_owned(self):
        with patch.object(m, "proc_identity", return_value=("new", [b"/run/colab-easytier-ssh/config"])):
            self.assertFalse(m.is_owned({"pid": 123, "start": "old"}))
        with patch.object(m, "proc_identity", return_value=("same", [b"unrelated-command"])):
            self.assertFalse(m.is_owned({"pid": 123, "start": "same"}))

    def test_route_check_excludes_local_node_and_does_not_print_peers(self):
        payload = [{"ipv4": "10.144.144.2", "cost": "Local"},
                   {"ipv4": "10.144.144.1", "cost": "1", "hostname": "PRIVATE-HOST"}]
        proc = subprocess.CompletedProcess([], 0, json.dumps(payload), "")
        state = {"version": m.VERSION, "rpc_port": 15888, "ipv4": None}
        with patch.object(m, "run", return_value=proc):
            count = m.routes(state)
        self.assertEqual(count, 1)
        self.assertEqual(state["ipv4"], "10.144.144.2")

    def test_status_waits_for_assigned_address(self):
        state = {"processes": {}, "ssh_port": 2222, "ipv4": None}
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(m, "STATE", Path(temp) / "absent"), \
                 patch.object(m, "is_owned", return_value=True), \
                 patch.object(m, "ssh_reference_alive", return_value=True), \
                 patch.object(m, "port_open", return_value=True), \
                 patch.object(m, "routes", return_value=1), \
                 contextlib.redirect_stdout(output):
                self.assertTrue(m.status(state))
        self.assertIn("等待 EasyTier 分配", output.getvalue())
        self.assertNotIn("root@", output.getvalue())
        self.assertNotIn("http://", output.getvalue())

    @unittest.skipUnless(os.name == "posix", "POSIX file permissions")
    def test_private_write_permissions(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "config"
            m.private_write(path, "secret")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
