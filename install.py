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
          "ET_IPV4", "SSH_PORT", "EASYTIER_VERSION"}


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
        raise SetupError(f"子命令 {Path(str(argv[0])).name} 启动失败或超时；原始输出已隐藏。") from None
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
    value = cfg.get("ET_IPV4", "")
    if not isinstance(value, str):
        raise SetupError("ET_IPV4 必须为字符串；留空自动分配地址。")
    value = value.strip()
    if value:
        try:
            address = ipaddress.IPv4Interface(value)
            if not address.ip.is_private or address.ip.is_loopback or address.ip.is_link_local or address.ip.is_unspecified:
                raise ValueError
        except ValueError:
            raise SetupError("ET_IPV4 请填写私网 IPv4 地址或 CIDR，或留空自动分配。") from None
        value = str(address)
    cfg["ET_IPV4"] = value
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
    return cfg


def make_toml(cfg):
    q = lambda x: json.dumps(x, ensure_ascii=True)
    lines = [f'instance_name = "{APP}"', f'hostname = "{APP}"']
    if cfg["ET_IPV4"]:
        lines += [f'ipv4 = {q(cfg["ET_IPV4"])}', "dhcp = false"]
    else:
        lines += ["dhcp = true"]
    lines += ["listeners = []", "", "[network_identity]",
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


def make_sshd(cfg, key_path):
    return f"""Port {cfg['SSH_PORT']}
ListenAddress 127.0.0.1
HostKey {STATE}/ssh_host_ed25519_key
PidFile {STATE}/sshd.pid
AuthorizedKeysFile {key_path}
AllowUsers root
PermitRootLogin prohibit-password
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
PubkeyAuthentication yes
AuthenticationMethods publickey
UsePAM yes
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
        # The local row reports the address actually assigned by EasyTier,
        # including DHCP changes. Never synthesize an address for auto mode.
        for pair in pairs:
            if pair.get("cost") == "Local":
                try:
                    local = ipaddress.IPv4Interface(pair.get("ipv4") or pair.get("cidr") or "")
                    state["ipv4"] = None if local.ip.is_unspecified else str(local.ip)
                except ValueError:
                    state["ipv4"] = None
                break
        pairs = [pair for pair in pairs if pair.get("cost") != "Local"]
        return len(pairs)
    except (SetupError, ValueError, KeyError, TypeError, AttributeError):
        return None


def status(state=None):
    state = load_state() if state is None else state
    processes = state.get("processes", {})
    ssh_alive = is_owned(processes.get("sshd"))
    et_alive = is_owned(processes.get("easytier"))
    ssh_ready = bool(ssh_alive and port_open(state.get("ssh_port", 0)))
    count = routes(state) if et_alive else None
    if et_alive and (STATE / "state.json").is_file():
        private_write(STATE / "state.json", json.dumps(state))
    print("SSH: " + ("运行且端口可达" if ssh_ready else "未运行或未就绪"))
    print("EasyTier: " + ("运行" if et_alive else "未运行"))
    print("组网: " + (f"发现 {count} 个同网对端" if count else "等待同网对端 / RPC 未就绪"))
    if ssh_ready and et_alive:
        if state.get("ipv4"):
            print(f"虚拟 IPv4: {state['ipv4']}")
            print(f"连接: ssh -p {state['ssh_port']} root@{state['ipv4']}")
            print(f"服务直连示例: http://{state['ipv4']}:8000（需先启动对应服务）")
            print("通过 EasyTier 虚拟 IP 和应用实际监听端口访问 TCP/UDP 服务。")
        else:
            print("虚拟 IPv4: 等待 EasyTier 分配；稍后运行 status 查看。")
        print("以上为本地进程检查；请从 Windows 验证 SSH 和服务直连。")
    return ssh_ready and et_alive


def start(cfg):
    # Config is validated before installation or stopping any existing process.
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    STATE.chmod(0o700)
    previous = load_state()
    print("[1/5] 检查依赖与固定版本下载（不显示私密参数）")
    if not shutil.which("sshd"):
        run(["apt-get", "update", "-qq"], timeout=300)
        run(["apt-get", "install", "-y", "-qq", "--no-install-recommends", "openssh-server", "ca-certificates"], timeout=300)
    binaries = install_binaries(cfg["EASYTIER_VERSION"])
    print("[2/5] 配置独立 SSH 实例与公钥")
    key_path = STATE / f"authorized_keys.{APP}"
    private_write(key_path, cfg["SSH_PUBLIC_KEY"] + "\n")
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
    state = {"authorized_key": str(key_path), "version": cfg["EASYTIER_VERSION"], "rpc_port": rpc_port,
             "ssh_port": cfg["SSH_PORT"],
             "ipv4": str(ipaddress.IPv4Interface(cfg["ET_IPV4"]).ip) if cfg["ET_IPV4"] else None,
             "processes": {}}
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
            count = routes(state)
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
    for name, value in (("ET_IPV4", args.ipv4),
                        ("SSH_PORT", args.ssh_port), ("EASYTIER_VERSION", args.easytier_version)):
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
    parser.add_argument("--ssh-port", type=int)
    parser.add_argument("--easytier-version")
    args = parser.parse_args(argv)
    lock = None
    try:
        cfg = read_config(args) if args.action in {"start", "check"} else None
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
            start(cfg)
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
                print("已卸载本项目服务、密钥授权和配置。")
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
