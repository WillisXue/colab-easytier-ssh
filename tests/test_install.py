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
        self.assertEqual(toml["tcp_whitelist"], ["2222"])
        self.assertTrue(toml["flags"]["no_tun"])
        self.assertNotIn("private-comment", cfg["SSH_PUBLIC_KEY"])

    def test_reject_invalid_config_without_echoing_values(self):
        cases = [("ET_NETWORK_SECRET", None), ("ET_PEERS", ["https://secret-host.invalid:443"]),
                 ("ET_PEERS", ["tcp://user:secret@host.invalid:11010"]),
                 ("SSH_PUBLIC_KEY", "-----BEGIN OPENSSH PRIVATE KEY-----"),
                 ("SSH_PUBLIC_KEY", 'command="bad" ssh-ed25519 aaaa'),
                 ("ET_IPV4", "127.0.0.1"), ("SSH_PORT", 22),
                 ("SSH_USER", "root"), ("ET_NETWORK_NAME", "injected\n[flags]"),
                 ("EASYTIER_VERSION", "latest"), ("DIRECT_TCP_PORTS", ["not-port"])]
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

    def test_precedence_and_multi_peer_input(self):
        parser_args = type("Args", (), dict(config_stdin=True, config_file=None, ipv4="10.200.1.2/24",
                           ssh_user=None, ssh_port=3333, easytier_version=None, direct_tcp_port=[8000]))()
        cfg = config()
        cfg["ET_PEERS"] = "tcp://one.invalid:11010,udp://two.invalid:11010"
        with patch.dict(os.environ, {"SSH_PORT": "4444"}), patch("sys.stdin", io.StringIO(json.dumps(cfg))):
            result = m.read_config(parser_args)
        self.assertEqual(result["SSH_PORT"], 3333)
        self.assertEqual(len(result["ET_PEERS"]), 2)
        self.assertEqual(result["DIRECT_TCP_PORTS"], [8000])

    def test_subprocess_failure_does_not_reveal_captured_output(self):
        proc = subprocess.CompletedProcess([], 1, "SECRET-SERVER", "SECRET-KEY")
        with patch.object(m.subprocess, "run", return_value=proc):
            with self.assertRaises(m.SetupError) as caught:
                m.run(["fake"])
        self.assertNotIn("SECRET", str(caught.exception))
        self.assertFalse(any(k.startswith("ET_") for k in m.clean_env()))

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
        with patch.object(m, "run", return_value=proc):
            count, expected = m.routes({"version": m.VERSION, "rpc_port": 15888, "expect_peer": "10.144.144.1"})
        self.assertEqual(count, 1)
        self.assertTrue(expected)

    @unittest.skipUnless(os.name == "posix", "POSIX file permissions")
    def test_private_write_permissions(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "config"
            m.private_write(path, "secret")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
