#!/usr/bin/env python3
"""Colab EasyTier + isolated OpenSSH installer. Python 3.10+, standard library only."""
from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import zipfile

APP = "colab-easytier-ssh"
STATE = Path("/run") / APP
ROOT = Path("/opt") / APP
VERSION = "v2.6.4"
# Pinned upstream GitHub release-asset digests; never fetch a checksum next to
# an untrusted download and then treat the pair as an authenticity check.
RELEASES = {VERSION: {
    "x86_64": "61b659eaedba658fa66fe47d17e1426cdd77e5d02fa15fed447bb4357c09dfd6",
    "aarch64": "f533ec25a7ea714e09f645615012200278058525795cc3bb690ff011aec1a70f",
}}
FIELDS = {"ET_NETWORK_NAME", "ET_NETWORK_SECRET", "ET_PEERS", "SSH_PUBLIC_KEY",
          "ET_IPV4", "SSH_USER", "SSH_PORT", "EASYTIER_VERSION", "DIRECT_TCP_PORTS"}


class SetupError(Exception):
    """Messages must contain field names or fixed text, never user values."""


def private_write(path: Path, text: str, mode: int = 0o600):
    """Atomic write; callers own and validate the parent directory."""
    fd, name = tempfile.mkstemp(prefix=".new-", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as out:
            out.write(text)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def clean_env():
    # Do not pass credentials or attacker-controlled SSH/loader overrides to
    # downloaded binaries or privileged system tools.
    return {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root",
            "LANG": "C.UTF-8", "DEBIAN_FRONTEND": "noninteractive"}


def run(argv, *, data=None, timeout=60, ok=(0,)):
    try:
        proc = subprocess.run([str(x) for x in argv], input=data, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              env=clean_env(), timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise SetupError("子命令启动失败或超时；原始输出已隐藏。") from None
    if proc.returncode not in ok:
        raise SetupError("子命令执行失败；原始输出已隐藏。")
    return proc


def port_number(value, field):
    try:
        if isinstance(value, bool):
            raise ValueError
        value = int(value)
        if not 1024 <= value <= 65535:
            raise ValueError
        return value
    except (ValueError, TypeError):
        raise SetupError(f"{field} 必须为 1024–65535 的端口。") from None


def text_field(data, name, default=None):
    value = data.get(name, default)
    if not isinstance(value, str) or not value or len(value) > 8192:
        raise SetupError(f"{name} 缺失或格式错误。")
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise SetupError(f"{name} 不允许控制字符。")
    return value


def validate(data):
    if not isinstance(data, dict) or set(data) - FIELDS:
        raise SetupError("配置必须为 JSON 对象，且只能包含文档中列出的字段。")
    cfg = dict(data)
    cfg["ET_NETWORK_NAME"] = text_field(cfg, "ET_NETWORK_NAME")
    if not isinstance(cfg.get("ET_NETWORK_SECRET"), str) or not cfg["ET_NETWORK_SECRET"]:
        raise SetupError("ET_NETWORK_SECRET 必须为非空字符串。")
    peers = cfg.get("ET_PEERS")
    if isinstance(peers, str):
        peers = [x.strip() for x in re.split(r"[,\n]", peers) if x.strip()]
    if not isinstance(peers, list) or not peers or len(peers) > 16:
        raise SetupError("ET_PEERS 必须包含 1–16 个连接地址。")
    for peer in peers:
        try:
            if not isinstance(peer, str) or len(peer) > 2048 or any(c.isspace() for c in peer):
                raise ValueError
            url = urllib.parse.urlsplit(peer)
            if url.scheme not in {"tcp", "udp", "ws", "wss", "quic"}:
                raise ValueError
            if not url.hostname or url.port is None or not 1 <= url.port <= 65535:
                raise ValueError
            if url.username or url.password or url.fragment:
                raise ValueError
        except ValueError:
            raise SetupError("ET_PEERS 包含无效地址；需为带端口的 tcp/udp/ws/wss/quic URL。") from None
    cfg["ET_PEERS"] = peers
    try:
        address = ipaddress.IPv4Interface(cfg.get("ET_IPV4", "10.144.144.2/24"))
        if not address.ip.is_private or address.ip.is_loopback or address.ip.is_link_local or address.ip.is_unspecified:
            raise ValueError
    except (ValueError, TypeError):
        raise SetupError("ET_IPV4 必须为私网 IPv4 地址或 CIDR。") from None
    cfg["ET_IPV4"] = str(address)
    cfg["SSH_USER"] = text_field(cfg, "SSH_USER", "colabssh")
    if not re.fullmatch(r"[a-z][a-z0-9_-]{0,30}", cfg["SSH_USER"]) or cfg["SSH_USER"] in {"root", "nobody"}:
        raise SetupError("SSH_USER 必须为普通 Linux 用户名。")
    cfg["SSH_PORT"] = port_number(cfg.get("SSH_PORT", 2222), "SSH_PORT")
    cfg["EASYTIER_VERSION"] = text_field(cfg, "EASYTIER_VERSION", VERSION)
    if cfg["EASYTIER_VERSION"] not in RELEASES:
        raise SetupError("EASYTIER_VERSION 不在此安装器的校验清单中；请更新安装器。")
    key = text_field(cfg, "SSH_PUBLIC_KEY")
    parts = key.strip().split()
    if len(parts) < 2 or parts[0] not in {"ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-rsa"}:
        raise SetupError("SSH_PUBLIC_KEY 必须是单行 OpenSSH 公钥，不能是私钥或 authorized_keys 选项。")
    try:
        raw = base64.b64decode(parts[1], validate=True)
        size = int.from_bytes(raw[:4], "big")
        if raw[4:4 + size].decode("ascii") != parts[0] or len(raw) < size + 12:
            raise ValueError
    except (ValueError, UnicodeError):
        raise SetupError("SSH_PUBLIC_KEY 公钥数据无效。") from None
    cfg["SSH_PUBLIC_KEY"] = " ".join(parts[:2])  # discard identifying comments
    direct = cfg.get("DIRECT_TCP_PORTS", [])
    if isinstance(direct, str):
        direct = [x.strip() for x in direct.split(",") if x.strip()]
    if not isinstance(direct, list) or len(direct) > 32:
        raise SetupError("DIRECT_TCP_PORTS 必须为最多 32 个端口的列表。")
    cfg["DIRECT_TCP_PORTS"] = sorted({port_number(x, "DIRECT_TCP_PORTS") for x in direct})
    return cfg


def make_toml(cfg):
    q = lambda x: json.dumps(x, ensure_ascii=True)
    ports = sorted({cfg["SSH_PORT"], *cfg["DIRECT_TCP_PORTS"]})
    lines = [f'instance_name = "{APP}"', f'hostname = "{APP}"',
             f'ipv4 = {q(cfg["ET_IPV4"])}', "dhcp = false", "listeners = []",
             "tcp_whitelist = " + q([str(x) for x in ports]),
             'udp_whitelist = ["0"]', "", "[network_identity]",
             "network_name = " + q(cfg["ET_NETWORK_NAME"]),
             "network_secret = " + q(cfg["ET_NETWORK_SECRET"])]
    for peer in cfg["ET_PEERS"]:
        lines += ["", "[[peer]]", "uri = " + q(peer)]
    lines += ["", "[flags]", "no_tun = true", "private_mode = true",
              "enable_encryption = true", "use_smoltcp = true", ""]
    return "\n".join(lines)


def fetch(url, dest: Path, digest: str):
    # Only fixed trusted GitHub HTTPS URLs are passed by the installer/bootstrap.
    request = urllib.request.Request(url, headers={"User-Agent": APP})
    hasher = hashlib.sha256()
    try:
        with urllib.request.urlopen(request, timeout=60) as source, dest.open("wb") as out:
            count = 0
            while chunk := source.read(1024 * 1024):
                count += len(chunk)
                if count > 200 * 1024 * 1024:
                    raise SetupError("下载文件超过大小限制。")
                hasher.update(chunk)
                out.write(chunk)
    except Exception:
        dest.unlink(missing_ok=True)
        raise SetupError("下载失败；请检查 Colab 到 GitHub 的网络。") from None
    if not secrets.compare_digest(hasher.hexdigest(), digest):
        dest.unlink(missing_ok=True)
        raise SetupError("下载文件 SHA-256 不匹配，已拒绝安装。")


def install_binaries(version):
    arch = {"amd64": "x86_64", "arm64": "aarch64"}.get(platform.machine().lower(), platform.machine().lower())
    if arch not in RELEASES[version]:
        raise SetupError("此安装器仅支持 Linux x86_64/aarch64。")
    target = ROOT / version
    if all((target / name).is_file() for name in ("easytier-core", "easytier-cli")):
        return target
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="download-", dir=ROOT) as temp:
        temp = Path(temp)
        archive = temp / "release.zip"
        name = f"easytier-linux-{arch}-{version}.zip"
        fetch(f"https://github.com/EasyTier/EasyTier/releases/download/{version}/{name}", archive, RELEASES[version][arch])
        stage = temp / "bin"
        stage.mkdir()
        try:
            with zipfile.ZipFile(archive) as bundle:
                for name in ("easytier-core", "easytier-cli"):
                    matches = [i for i in bundle.infolist() if Path(i.filename).name == name and not i.is_dir()]
                    if len(matches) != 1 or matches[0].file_size > 200 * 1024 * 1024:
                        raise SetupError("发布包内容不符合预期。")
                    # Select only the two binaries; never extract archive paths.
                    with bundle.open(matches[0]) as src, (stage / name).open("wb") as dst:
                        shutil.copyfileobj(src, dst)
                    (stage / name).chmod(0o700)
        except zipfile.BadZipFile:
            raise SetupError("发布包格式无效。") from None
        stage.rename(target)
    return target


def proc_identity(pid):
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
        start = stat[stat.rfind(")") + 2:].split()[19]
        cmd = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
        return start, cmd
    except (OSError, IndexError):
        return None


def is_owned(record):
    if not isinstance(record, dict) or not isinstance(record.get("pid"), int):
        return False
    current = proc_identity(record["pid"])
    if not current or current[0] != record.get("start"):
        return False
    # Both commands carry a dedicated project config path. OpenSSH may rewrite
    # its process title, so check the marker in the whole command line.
    return str(STATE).encode() in b" ".join(current[1])


def load_state():
    try:
        return json.loads((STATE / "state.json").read_text())
    except (OSError, ValueError):
        return {}


def stop(state=None):
    state = load_state() if state is None else state
    for record in state.get("processes", {}).values():
        if is_owned(record):
            pid = record["pid"]
            try:
                if os.getpgid(pid) == pid:
                    os.killpg(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and any(is_owned(r) for r in state.get("processes", {}).values()):
        time.sleep(0.1)
    for record in state.get("processes", {}).values():
        if is_owned(record):
            try:
                if os.getpgid(record["pid"]) == record["pid"]:
                    os.killpg(record["pid"], signal.SIGKILL)
            except ProcessLookupError:
                pass
    state["processes"] = {}
    if STATE.exists():
        private_write(STATE / "state.json", json.dumps(state))
    return state


def launch(argv):
    try:
        child = subprocess.Popen([str(x) for x in argv], stdin=subprocess.DEVNULL,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 env=clean_env(), start_new_session=True)
        identity = proc_identity(child.pid)
        if identity is None:
            raise SetupError("后台服务启动失败。")
        return {"pid": child.pid, "start": identity[0]}
    except OSError:
        raise SetupError("后台服务启动失败。") from None


def port_open(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.3):
            return True
    except OSError:
        return False


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def ensure_user(user, previous):
    import pwd
    try:
        info = pwd.getpwnam(user)
        if (user != previous.get("managed_user") and info.pw_gecos != APP) or info.pw_uid == 0:
            raise SetupError("SSH_USER 已存在且不属于本项目；请选择其他用户名。")
    except KeyError:
        run(["useradd", "--create-home", "--shell", "/bin/bash", "--comment", APP, user])
        # An unlocked account is needed with UsePAM=no. Random password is never
        # displayed and password authentication is disabled by this sshd.
        run(["chpasswd"], data=f"{user}:{secrets.token_urlsafe(48)}\n")
        info = pwd.getpwnam(user)
    home = Path(info.pw_dir)
    key_dir = home / ".ssh"
    if key_dir.is_symlink():
        raise SetupError("SSH 用户目录含不安全的符号链接。")
    key_dir.mkdir(mode=0o700, exist_ok=True)
    key_dir.chmod(0o700)
    os.chown(key_dir, info.pw_uid, info.pw_gid)
    return info, key_dir / f"authorized_keys.{APP}"


def make_sshd(cfg, key_path):
    return f"""Port {cfg['SSH_PORT']}
ListenAddress 127.0.0.1
HostKey {STATE}/ssh_host_ed25519_key
PidFile {STATE}/sshd.pid
AuthorizedKeysFile {key_path}
AllowUsers {cfg['SSH_USER']}
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
PubkeyAuthentication yes
AuthenticationMethods publickey
UsePAM no
StrictModes yes
AllowTcpForwarding local
GatewayPorts no
AllowAgentForwarding no
X11Forwarding no
PermitTunnel no
PermitUserEnvironment no
Subsystem sftp internal-sftp
LogLevel ERROR
"""


def routes(state):
    try:
        proc = run([ROOT / state["version"] / "easytier-cli", "-p",
                    f"127.0.0.1:{state['rpc_port']}", "-o", "json", "peer"], timeout=5)
        parsed = json.loads(proc.stdout)
        # Upstream 2.6.x emits a JSON list of peer/route objects.
        pairs = parsed if isinstance(parsed, list) else parsed.get("peer_routes", [])
        pairs = [pair for pair in pairs if pair.get("cost") != "Local"]
        ips = set()
        for pair in pairs:
            route = pair.get("route") or {}
            value = route.get("ipv4_addr") or pair.get("ipv4") or pair.get("cidr")
            if isinstance(value, str):
                try:
                    ips.add(str(ipaddress.IPv4Interface(value).ip))
                except ValueError:
                    pass
        return len(pairs), state.get("expect_peer") in ips if state.get("expect_peer") else None
    except (SetupError, ValueError, KeyError, TypeError, AttributeError):
        return None, None


def status(state=None):
    state = load_state() if state is None else state
    processes = state.get("processes", {})
    ssh_alive = is_owned(processes.get("sshd"))
    et_alive = is_owned(processes.get("easytier"))
    ssh_ready = bool(ssh_alive and port_open(state.get("ssh_port", 0)))
    count, expected = routes(state) if et_alive else (None, None)
    print("SSH: " + ("运行且端口可达" if ssh_ready else "未运行或未就绪"))
    print("EasyTier: " + ("运行" if et_alive else "未运行"))
    print("组网: " + (f"发现 {count} 个同网对端" if count else "等待同网对端 / RPC 未就绪"))
    if state.get("expect_peer"):
        print("指定 Windows 对端: " + ("已发现" if expected else "尚未发现"))
    if ssh_ready and et_alive:
        print(f"连接: ssh -p {state['ssh_port']} {state['managed_user']}@{state['ipv4']}")
        print(f"端口转发示例: ssh -N -p {state['ssh_port']} -L 127.0.0.1:8000:127.0.0.1:8000 {state['managed_user']}@{state['ipv4']}")
        print("以上为本地进程检查；请从 Windows 验证 SSH 和端口转发。")
    return ssh_ready and et_alive


def start(cfg, expect_peer=None):
    # Config is validated before installation or stopping any existing process.
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    STATE.chmod(0o700)
    previous = load_state()
    print("[1/5] 检查依赖与固定版本下载（不显示私密参数）")
    if not shutil.which("sshd") or not shutil.which("useradd"):
        run(["apt-get", "update", "-qq"], timeout=300)
        run(["apt-get", "install", "-y", "-qq", "--no-install-recommends", "openssh-server", "passwd", "ca-certificates"], timeout=300)
    binaries = install_binaries(cfg["EASYTIER_VERSION"])
    print("[2/5] 配置独立 SSH 实例与公钥")
    info, key_path = ensure_user(cfg["SSH_USER"], previous)
    if previous.get("managed_user") and previous["managed_user"] != cfg["SSH_USER"]:
        raise SetupError("更换 SSH_USER 前请先卸载原实例。")
    # Record ownership immediately so a later failed setup is recoverable.
    previous.update(managed_user=cfg["SSH_USER"], authorized_key=str(key_path))
    private_write(STATE / "state.json", json.dumps(previous))
    private_write(key_path, cfg["SSH_PUBLIC_KEY"] + "\n")
    os.chown(key_path, info.pw_uid, info.pw_gid)
    run(["ssh-keygen", "-l", "-f", key_path])
    host_key = STATE / "ssh_host_ed25519_key"
    if not host_key.exists():
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", host_key])
    Path("/run/sshd").mkdir(mode=0o755, exist_ok=True)
    ssh_config = STATE / "sshd_config.next"
    private_write(ssh_config, make_sshd(cfg, key_path))
    sshd = Path(shutil.which("sshd")).resolve()
    run([sshd, "-t", "-f", ssh_config])
    print("[3/5] 写入私有配置并重启本项目服务")
    previous = stop(previous)
    if port_open(cfg["SSH_PORT"]):
        raise SetupError("SSH_PORT 已被其他服务占用；请修改端口。")
    os.replace(ssh_config, STATE / "sshd_config")
    private_write(STATE / "easytier.toml", make_toml(cfg))
    rpc_port = free_port()
    state = {**previous, "version": cfg["EASYTIER_VERSION"], "rpc_port": rpc_port,
             "ssh_port": cfg["SSH_PORT"], "ipv4": str(ipaddress.IPv4Interface(cfg["ET_IPV4"]).ip),
             "expect_peer": expect_peer, "processes": {}}
    try:
        state["processes"]["sshd"] = launch([sshd, "-D", "-e", "-f", STATE / "sshd_config"])
        private_write(STATE / "state.json", json.dumps(state))
        state["processes"]["easytier"] = launch([
            binaries / "easytier-core", "-c", STATE / "easytier.toml",
            "-r", f"127.0.0.1:{rpc_port}", "--rpc-portal-whitelist", "127.0.0.1/32"])
        private_write(STATE / "state.json", json.dumps(state))
        print("[4/5] 等待本地服务就绪")
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if not all(is_owned(r) for r in state["processes"].values()):
                raise SetupError("服务提前退出；请检查版本、端口和运行时支持。原始输出已隐藏。")
            if port_open(cfg["SSH_PORT"]) and port_open(rpc_port):
                break
            time.sleep(0.25)
        else:
            raise SetupError("本地服务启动超时。")
        # Give routing a bounded opportunity to discover the other node.
        for _ in range(5):
            count, _ = routes(state)
            if count:
                break
            time.sleep(1)
        print("[5/5] 状态与 SSH 主机公钥指纹")
        fingerprint = run(["ssh-keygen", "-l", "-f", host_key.with_suffix(".pub")]).stdout.split()
        print("主机指纹: " + fingerprint[1])
        status(state)
        print("安装完成。运行时重建后重新运行安装单元格；原始服务输出不会保存。")
    except BaseException:
        stop(state)
        raise


def read_config(args):
    data = {name: os.environ[name] for name in FIELDS if name in os.environ}
    try:
        if args.config_stdin:
            raw = sys.stdin.read(65537)
        elif args.config_file:
            raw = args.config_file.read_text(encoding="utf-8")
        else:
            raw = "{}"
        if len(raw) > 65536:
            raise ValueError
        loaded = json.loads(raw)
        if not isinstance(loaded, dict):
            raise ValueError
        data.update(loaded)
    except (OSError, UnicodeError, ValueError):
        raise SetupError("私有配置必须为不超过 64 KiB 的有效 JSON 对象。") from None
    for name, value in (("ET_IPV4", args.ipv4), ("SSH_USER", args.ssh_user),
                        ("SSH_PORT", args.ssh_port), ("EASYTIER_VERSION", args.easytier_version),
                        ("DIRECT_TCP_PORTS", args.direct_tcp_port)):
        if value is not None:
            data[name] = value
    return validate(data)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", nargs="?", choices=["start", "status", "stop", "uninstall", "check"], default="start")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--config-stdin", action="store_true")
    source.add_argument("--config-file", type=Path)
    parser.add_argument("--ipv4")
    parser.add_argument("--ssh-user")
    parser.add_argument("--ssh-port", type=int)
    parser.add_argument("--easytier-version")
    parser.add_argument("--direct-tcp-port", type=int, action="append")
    parser.add_argument("--expect-peer", help="Optional Windows virtual IPv4 for route discovery checks")
    args = parser.parse_args(argv)
    lock = None
    try:
        cfg = read_config(args) if args.action in {"start", "check"} else None
        if args.expect_peer:
            try:
                args.expect_peer = str(ipaddress.IPv4Address(args.expect_peer))
            except ValueError:
                raise SetupError("--expect-peer 必须为 IPv4 地址。") from None
        if args.action == "check":
            print("配置校验通过（未安装、未连接、未输出参数）。")
            return 0
        if platform.system() != "Linux" or os.geteuid() != 0:
            raise SetupError("安装与管理需要 Linux root；请从 Colab 网页运行。")
        for path in (STATE, ROOT):
            if path.is_symlink():
                raise SetupError("项目目录不能是符号链接。")
        import fcntl
        STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
        STATE.chmod(0o700)
        lock = (STATE / ".lock").open("a")
        os.chmod(STATE / ".lock", 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SetupError("另一个本项目管理操作正在运行，请稍后重试。") from None
        if args.action == "start":
            start(cfg, args.expect_peer)
        elif args.action == "status":
            return 0 if status() else 1
        else:
            state = stop()
            if args.action == "uninstall":
                # Only fixed project directories and the recorded project key.
                key = state.get("authorized_key")
                if key and Path(key).name == f"authorized_keys.{APP}":
                    Path(key).unlink(missing_ok=True)
                for path in (STATE, ROOT):
                    if path.exists():
                        shutil.rmtree(path)
                print("已卸载本项目服务、密钥授权和配置；保留创建的 Linux 用户及其文件。")
            else:
                print("已停止本项目服务；配置仍保留在当前运行时。")
        return 0
    except SetupError as error:
        print("错误: " + str(error), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("已中断。", file=sys.stderr)
        return 130
    except Exception:
        # No traceback: exception text may contain peer URLs or configuration.
        print("错误: 操作失败；敏感上下文与原始输出已隐藏。", file=sys.stderr)
        return 1
    finally:
        if lock is not None:
            lock.close()


if __name__ == "__main__":
    # Windows terminals/runners may default to an ANSI code page. Keep the
    # Chinese status messages usable over pipes as well as in Colab.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    sys.exit(main())
