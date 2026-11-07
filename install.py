#!/usr/bin/env python3
"""Colab EasyTier installer with existing root SSH. Python 3.10+, standard library only."""
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
import shlex
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
STAGE = "配置校验"
SSH_BEGIN = f"# BEGIN {APP}\n"
SSH_END = f"# END {APP}\n"


class SetupError(Exception):
    """Messages must never include private network configuration or keys."""


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
    tool = Path(str(argv[0])).name
    try:
        proc = subprocess.run([str(x) for x in argv], input=data, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              env=clean_env(), timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        raise SetupError(f"{tool} 执行超时（{timeout} 秒）。") from None
    except OSError as error:
        raise SetupError(f"{tool} 启动失败（{type(error).__name__}，errno={error.errno}）。") from None
    if proc.returncode not in ok:
        message = f"{tool} 执行失败，退出码 {proc.returncode}。"
        # These tools receive only fixed project file paths and non-secret
        # options. Do not relay diagnostics from tools that see network config.
        if tool in {"apt-get", "sshd", "ssh-keygen"}:
            lines = (proc.stderr or proc.stdout or "").strip().splitlines()[-8:]
            if lines:
                message += "\n" + "\n".join(lines)[:2000]
        raise SetupError(message)
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


def ssh_reference_alive(ref):
    if not isinstance(ref, dict):
        return False
    identity = proc_identity(ref.get("pid"))
    try:
        return bool(identity and identity[0] == ref.get("start")
                    and Path(f"/proc/{ref['pid']}/exe").resolve().name == "sshd")
    except OSError:
        return False


def ssh_launch_options(command):
    """Read only sshd flags that affect its effective config; never run a shell."""
    words = shlex.split(command.split(" [listener]")[0])
    config, options = "/etc/ssh/sshd_config", []
    index = 0
    while index < len(words):
        word = words[index]
        if word in {"-f", "-o", "-p"} and index + 1 < len(words):
            value = words[index + 1]
            index += 2
            if word == "-f":
                config = value
            else:
                options += [word, value]
        elif word.startswith(("-f", "-o", "-p")) and len(word) > 2:
            if word[:2] == "-f":
                config = word[2:]
            else:
                options += [word[:2], word[2:]]
            index += 1
        else:
            index += 1
    return config, options


def find_existing_sshd(port):
    inodes = set()
    for table in ("tcp", "tcp6"):
        for line in Path(f"/proc/net/{table}").read_text().splitlines()[1:]:
            row = line.split()
            if row[3] == "0A" and int(row[1].rsplit(":", 1)[1], 16) == port:
                inodes.add(row[9])
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit():
            continue
        try:
            executable = (proc / "exe").resolve(strict=True)
            if executable.name != "sshd":
                continue
            sockets = set()
            for fd in (proc / "fd").iterdir():
                try:
                    sockets.add(os.readlink(fd))
                except OSError:
                    continue
            if not any(f"socket:[{inode}]" in sockets for inode in inodes):
                continue
            identity = proc_identity(int(proc.name))
            if not identity:
                continue
            config, options = ssh_launch_options(b" ".join(identity[1]).decode("utf-8", "replace"))
            return {"pid": int(proc.name), "start": identity[0], "exe": str(executable),
                    "config": str(Path(config).resolve()), "options": options, "port": port}
        except (OSError, ValueError):
            continue
    raise SetupError("SSH_PORT 上没有找到现有 sshd 服务。")


def ssh_config(ref, path=None):
    result = run([ref["exe"], "-T", "-f", path or ref["config"], *ref["options"],
                  "-C", f"user=root,host=localhost,addr=127.0.0.1,laddr=127.0.0.1,lport={ref['port']}"])
    values = {}
    for line in result.stdout.splitlines():
        field, _, value = line.partition(" ")
        values.setdefault(field, []).append(value)
    return values


def remove_ssh_block(text):
    return re.sub(re.escape(SSH_BEGIN) + r".*?" + re.escape(SSH_END), "", text, flags=re.S)


def reload_existing_sshd(ref):
    if not ssh_reference_alive(ref):
        raise SetupError("现有 sshd 实例已变化，请重新运行安装。")
    os.kill(ref["pid"], signal.SIGHUP)
    time.sleep(0.2)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if ssh_reference_alive(ref) and port_open(ref["port"]):
            return
        time.sleep(0.1)
    raise SetupError("现有 sshd 重载后未就绪。")


def enable_root_key_login(ref):
    values = ssh_config(ref)
    first = lambda name: values.get(name, [""])[0]
    if first("permitrootlogin") not in {"yes", "prohibit-password", "without-password"} or first("pubkeyauthentication") != "yes":
        raise SetupError("现有 sshd 需要先允许 root 公钥登录。")
    if first("forcecommand") not in {"", "none"} or first("authenticationmethods") not in {"", "any", "publickey"}:
        raise SetupError("现有 sshd 的认证策略不支持直接 root 公钥登录。")
    account = run(["passwd", "-S", "root"]).stdout.split()
    if len(account) > 1 and account[1] == "L" and first("usepam") != "yes":
        if not Path("/etc/pam.d/sshd").is_file():
            raise SetupError("现有 sshd 缺少 PAM 配置，无法启用锁定 root 的公钥登录。")
        config = Path(ref["config"])
        original = config.read_text()
        modified = SSH_BEGIN + "UsePAM yes\n" + SSH_END + remove_ssh_block(original)
        candidate = STATE / "sshd-check.conf"
        private_write(candidate, modified)
        run([ref["exe"], "-t", "-f", candidate, *ref["options"]])
        if ssh_config(ref, candidate).get("usepam") != ["yes"]:
            raise SetupError("现有 sshd 的启动参数阻止启用 PAM。")
        mode = config.stat().st_mode & 0o777
        private_write(config, modified, mode)
        try:
            reload_existing_sshd(ref)
        except BaseException:
            private_write(config, original, mode)
            if ssh_reference_alive(ref):
                os.kill(ref["pid"], signal.SIGHUP)
            raise
        values = ssh_config(ref)
    return values


def authorized_key_path(values):
    import pwd
    user = pwd.getpwnam("root")
    paths = shlex.split(values.get("authorizedkeysfile", [""])[0])
    for name in paths:
        if name == "none":
            continue
        name = name.replace("%h", user.pw_dir).replace("%u", "root").replace("%U", "0").replace("%%", "%")
        if "%" in name or name.startswith("~"):
            raise SetupError("现有 AuthorizedKeysFile 路径含不支持的占位符。")
        path = Path(name)
        return path if path.is_absolute() else Path(user.pw_dir) / path
    raise SetupError("现有 sshd 未配置公钥授权文件。")


def add_authorized_key(path, key):
    if path.is_symlink() or path.parent.is_symlink():
        raise SetupError("公钥授权文件路径不能是符号链接。")
    existed = path.exists()
    text = path.read_text() if existed else ""
    if any(line.split()[:2] == key.split() for line in text.splitlines()):
        return None
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    line = key + " " + APP
    private_write(path, text + ("\n" if text and not text.endswith("\n") else "") + line + "\n")
    return {"path": str(path), "line": line, "created": not existed}


def cleanup_ssh(state):
    for entry in state.get("key_entries", []):
        path = Path(entry["path"])
        if not path.is_file() or path.is_symlink():
            continue
        lines = path.read_text().splitlines(keepends=True)
        result = "".join(line for line in lines if line.rstrip("\r\n") != entry["line"])
        if result != "".join(lines):
            if not result and entry.get("created"):
                path.unlink()
            else:
                private_write(path, result)
    ref = state.get("ssh")
    if ref:
        config = Path(ref["config"])
        original = config.read_text()
        restored = remove_ssh_block(original)
        if restored != original:
            candidate = STATE / "sshd-check.conf"
            private_write(candidate, restored)
            run([ref["exe"], "-t", "-f", candidate, *ref["options"]])
            private_write(config, restored, config.stat().st_mode & 0o777)
            if ssh_reference_alive(ref):
                reload_existing_sshd(ref)


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
    ssh_alive = ssh_reference_alive(state.get("ssh"))
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
    global STAGE
    # Config is validated before installation or stopping any existing process.
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    STATE.chmod(0o700)
    previous = load_state()
    STAGE = "1/5 安装依赖和下载 EasyTier"
    print("[1/5] 检查依赖与固定版本下载（不显示私密参数）")
    if not shutil.which("sshd"):
        raise SetupError("此运行时未安装 sshd；请使用带 SSH 服务的 Colab 运行时。")
    binaries = install_binaries(cfg["EASYTIER_VERSION"])
    STAGE = "2/5 配置 SSH 与公钥"
    print("[2/5] 配置现有 SSH 服务与公钥")
    key_path = STATE / f"authorized_keys.{APP}"
    private_write(key_path, cfg["SSH_PUBLIC_KEY"] + "\n")
    run(["ssh-keygen", "-l", "-f", key_path])
    ref = find_existing_sshd(cfg["SSH_PORT"])
    if is_owned(ref):
        raise SetupError("SSH_PORT 对应旧版独立 SSH 实例，请选择运行时现有 SSH 服务端口。")
    previous["ssh"] = ref
    private_write(STATE / "state.json", json.dumps(previous))
    values = enable_root_key_login(ref)
    entry = add_authorized_key(authorized_key_path(values), cfg["SSH_PUBLIC_KEY"])
    entries = previous.get("key_entries", [])
    if entry:
        entries.append(entry)
    previous.update(ssh=ref, key_entries=entries)
    private_write(STATE / "state.json", json.dumps(previous))
    STAGE = "3/5 启动服务"
    print("[3/5] 写入私有配置并启动 EasyTier")
    previous = stop(previous)
    private_write(STATE / "easytier.toml", make_toml(cfg))
    rpc_port = free_port()
    state = {"ssh": ref, "key_entries": entries, "version": cfg["EASYTIER_VERSION"], "rpc_port": rpc_port,
             "ssh_port": cfg["SSH_PORT"],
             "ipv4": str(ipaddress.IPv4Interface(cfg["ET_IPV4"]).ip) if cfg["ET_IPV4"] else None,
             "processes": {}}
    try:
        state["processes"]["easytier"] = launch([
            binaries / "easytier-core", "-c", STATE / "easytier.toml",
            "-r", f"127.0.0.1:{rpc_port}", "--rpc-portal-whitelist", "127.0.0.1/32"])
        private_write(STATE / "state.json", json.dumps(state))
        STAGE = "4/5 检查服务就绪状态"
        print("[4/5] 等待本地服务就绪")
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            failed = [name for name, record in state["processes"].items() if not is_owned(record)]
            if failed:
                raise SetupError("服务提前退出：" + ", ".join(failed) + "。")
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
        STAGE = "5/5 读取网络状态和 SSH 指纹"
        print("[5/5] 状态与 SSH 主机公钥指纹")
        host_keys = values.get("hostkey", [])
        host_keys.sort(key=lambda name: "ed25519" not in name)
        if host_keys:
            host_key = Path(host_keys[0])
            public_key = Path(str(host_key) + ".pub")
            fingerprint = run(["ssh-keygen", "-l", "-f", public_key if public_key.exists() else host_key]).stdout.split()
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
                cleanup_ssh(state)
                for path in (STATE, ROOT):
                    if path.exists():
                        shutil.rmtree(path)
                print("已卸载本项目服务、密钥授权和配置。")
            else:
                print("已停止本项目服务；配置仍保留在当前运行时。")
        return 0
    except SetupError as error:
        print(f"错误 [{STAGE}]: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("已中断。", file=sys.stderr)
        return 130
    except Exception as error:
        # No traceback: exception text may contain peer URLs or configuration.
        code = f"，errno={error.errno}" if isinstance(error, OSError) else ""
        print(f"错误 [{STAGE}]: {type(error).__name__}{code}。", file=sys.stderr)
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
