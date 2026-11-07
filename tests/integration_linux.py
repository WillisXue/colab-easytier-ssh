#!/usr/bin/env python3
"""Real two-node no-TUN, SSH, tunnel, repeat-start and cleanup smoke test.

Runs only on a disposable root Linux runner. Uses random test credentials;
never use this against a user's configured Colab runtime.
"""
import http.server
import importlib.util
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("installer", ROOT / "install.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def command(argv, *, data=None, ok=(0,)):
    result = subprocess.run([str(x) for x in argv], input=data, text=True,
                            capture_output=True, timeout=180)
    if result.returncode not in ok:
        # Test inputs are synthetic, but do not normalize raw diagnostics as a
        # practice for users. Only the command's tool name is reported.
        if any(str(x).endswith("install.py") for x in argv):
            # install.py's public output contract excludes config/raw logs.
            print(result.stdout, result.stderr, flush=True)
        raise RuntimeError("integration subcommand failed: " + Path(str(argv[0])).name)
    return result


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"COLAB_TUNNEL_OK"
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


def main():
    assert sys.platform.startswith("linux") and os.geteuid() == 0
    assert not m.STATE.exists(), "Use a disposable runner without an existing instance."
    # EasyTier's connector binds a physical interface. A loopback peer URL is
    # not a valid underlay target for that socket; use this runner's NIC IP.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect(("192.0.2.1", 9))  # select route; no datagram is sent
        underlay_ip = probe.getsockname()[0]
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 18080), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    peer = tunnel = None
    with tempfile.TemporaryDirectory() as temp:
        temp = Path(temp)
        key = temp / "id_test"
        command(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key])
        cfg = {"ET_NETWORK_NAME": "ci-" + secrets.token_hex(8),
               # Intentionally short: verify existing short-key networks work.
               "ET_NETWORK_SECRET": secrets.token_hex(2),
               "ET_PEERS": [f"tcp://{underlay_ip}:31110"],
               "SSH_PUBLIC_KEY": key.with_suffix(".pub").read_text().strip(),
               "ET_IPV4": "10.244.144.2/24"}
        payload = json.dumps(cfg)
        try:
            command([sys.executable, ROOT / "install.py", "--config-stdin"], data=payload)
            first = m.load_state()
            peer_cfg = m.validate({**cfg, "ET_IPV4": "10.244.144.1/24"})
            text = m.make_toml(peer_cfg).replace("listeners = []", f'listeners = ["tcp://{underlay_ip}:31110"]')
            text += '\n[[port_forward]]\nproto = "tcp"\nbind_addr = "127.0.0.1:18022"\ndst_addr = "10.244.144.2:2222"\n'
            # Deliberately test that direct HTTP access is denied by default.
            text += '\n[[port_forward]]\nproto = "tcp"\nbind_addr = "127.0.0.1:18081"\ndst_addr = "10.244.144.2:18080"\n'
            peer_path = temp / "peer.toml"
            peer_path.write_text(text)
            peer = subprocess.Popen([str(m.ROOT / m.VERSION / "easytier-core"), "-c", str(peer_path),
                                     "-r", "127.0.0.1:31589"], stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, env=m.clean_env())
            public = (m.STATE / "ssh_host_ed25519_key.pub").read_text().split()
            known = temp / "known_hosts"
            known.write_text("\n".join(f"[127.0.0.1]:{p} " + " ".join(public[:2]) for p in (18022, 2222)) + "\n")
            ssh = ["ssh", "-p", "18022", "-i", str(key), "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
                   "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={known}",
                   "-o", "ConnectTimeout=3"]
            local_ssh = ["2222" if x == "18022" else x for x in ssh]
            command(local_ssh + ["colabssh@127.0.0.1", "true"])
            print("PASS: isolated SSH login on the host loopback", flush=True)
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                attempt = command(ssh + ["colabssh@127.0.0.1", "printf SSH_OK"], ok=(0, 255))
                if attempt.returncode == 0 and attempt.stdout == "SSH_OK":
                    break
                time.sleep(1)
            else:
                # These are disposable CI nodes and synthetic test keys. Never
                # add this raw diagnostic path to the production installer.
                print("Synthetic SSH transport diagnostic:", attempt.stderr, flush=True)
                m.status()
                for rpc in (first["rpc_port"], 31589):
                    result = command([m.ROOT / m.VERSION / "easytier-cli", "-p", f"127.0.0.1:{rpc}", "-o", "json", "peer"], ok=(0, 1))
                    print("Synthetic peer diagnostic:", result.stdout, result.stderr, flush=True)
                raise RuntimeError("no-TUN SSH did not become reachable")
            print("PASS: real no-TUN SSH public-key authentication")
            # Confirm an untrusted key is refused.
            wrong = temp / "wrong"
            command(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", wrong])
            wrong_ssh = [str(wrong) if x == str(key) else x for x in ssh]
            denied = command(wrong_ssh + ["colabssh@127.0.0.1", "true"], ok=(255,))
            assert denied.returncode == 255
            print("PASS: wrong SSH key rejected")
            tunnel = subprocess.Popen(ssh + ["-N", "-o", "ExitOnForwardFailure=yes", "-L",
                                            "127.0.0.1:19080:127.0.0.1:18080", "colabssh@127.0.0.1"],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                try:
                    with urllib.request.urlopen("http://127.0.0.1:19080", timeout=2) as response:
                        assert response.read() == b"COLAB_TUNNEL_OK"
                        break
                except OSError:
                    time.sleep(0.3)
            else:
                raise RuntimeError("HTTP over SSH -L failed")
            print("PASS: real HTTP over SSH local port forwarding")
            try:
                with urllib.request.urlopen("http://127.0.0.1:18081", timeout=3) as response:
                    assert response.read() != b"COLAB_TUNNEL_OK", "direct TCP whitelist failed"
            except OSError:
                pass
            print("PASS: direct non-SSH service denied by default")
            tunnel.terminate()
            tunnel.wait(timeout=5)
            tunnel = None
            # Repeat with adversarial environment variables to verify that the
            # child is isolated from EasyTier env-var overrides.
            os.environ["ET_NETWORK_SECRET"] = "MUST_NOT_OVERRIDE_PRIVATE_CONFIG"
            os.environ["ET_PEERS"] = "tcp://environment-must-not-connect.invalid:1"
            command([sys.executable, ROOT / "install.py", "--config-stdin"], data=payload)
            assert not any(m.is_owned(r) for r in first["processes"].values())
            assert all(m.is_owned(r) for r in m.load_state()["processes"].values())
            command(ssh + ["colabssh@127.0.0.1", "true"])
            print("PASS: repeat-start replaces only owned processes; environment cannot override secrets")
            command([sys.executable, ROOT / "install.py", "stop"])
            assert not m.port_open(2222)
            command([sys.executable, ROOT / "install.py", "uninstall"])
            assert not m.STATE.exists() and not m.ROOT.exists()
            print("PASS: stop and uninstall clean up project resources")
        finally:
            if tunnel:
                tunnel.terminate()
                tunnel.wait(timeout=5)
            if peer:
                peer.terminate()
                peer.wait(timeout=5)
            if m.STATE.exists():
                command([sys.executable, ROOT / "install.py", "uninstall"])
            server.shutdown()


if __name__ == "__main__":
    main()
