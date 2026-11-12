"""Maintainer tool: pin the Notebook to a committed, checksummed installer."""
import argparse
import hashlib
import json
from pathlib import Path
import re

parser = argparse.ArgumentParser()
parser.add_argument("--commit", required=True)
args = parser.parse_args()
assert re.fullmatch(r"[a-f0-9]{40}", args.commit)
root = Path(__file__).resolve().parents[1]
digest = hashlib.sha256((root / "install.py").read_bytes()).hexdigest()
source = '''# @title 一键安装 EasyTier + SSH（先配置左侧 Secrets）
ET_IPV4 = "" # @param {type:"string"}
SSH_PORT = 2222 # @param {type:"integer"}

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import urllib.request
from google.colab import userdata

INSTALLER_COMMIT = "COMMIT_PLACEHOLDER"
INSTALLER_SHA256 = "DIGEST_PLACEHOLDER"
INSTALLER_PATH = Path("/content/colab-easytier-ssh-install.py")

def install_from_secrets():
    # Download and verify before retrieving secrets. The installer is pinned
    # to a commit; changes to main cannot silently replace executed code.
    url = f"https://raw.githubusercontent.com/WillisXue/colab-easytier-ssh/{INSTALLER_COMMIT}/install.py"
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "colab-easytier-ssh"})
        with urllib.request.urlopen(request, timeout=60) as response:
            code = response.read(1024 * 1024 + 1)
        if len(code) > 1024 * 1024 or hashlib.sha256(code).hexdigest() != INSTALLER_SHA256:
            print("安装器校验失败，已停止。请使用仓库中的最新正式 Notebook。")
            return
        INSTALLER_PATH.write_bytes(code)
    except Exception:
        print("下载失败，请检查 Colab 到 GitHub 的网络。")
        return
    config = {"ET_IPV4": ET_IPV4, "SSH_PORT": SSH_PORT}
    try:
        for name in ("ET_NETWORK_NAME", "ET_NETWORK_SECRET", "ET_PEERS", "SSH_PUBLIC_KEY"):
            config[name] = userdata.get(name)
    except Exception:
        print("读取 Secrets 失败，请检查四个 Secrets 是否已填写并允许此 Notebook 访问。")
        return
    argv = [sys.executable, str(INSTALLER_PATH), "start", "--config-stdin"]
    try:
        print("正在安装，完成后将显示执行结果。", flush=True)
        # Credentials go over stdin, never in argv or notebook source/output.
        result = subprocess.run(argv, input=json.dumps(config), text=True,
                                encoding="utf-8", errors="replace", capture_output=True,
                                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "LANG": "C.UTF-8"})
        # Colab displays Python output, while inherited child file descriptors
        # can bypass the cell. Explicitly relay the installer's filtered logs.
        output = (result.stdout or "").strip()
        errors = (result.stderr or "").strip()
        if output:
            print(output)
        if errors:
            print(errors)
        if result.returncode:
            print(f"安装失败，退出码：{result.returncode}。")
            if not output and not errors:
                print("安装进程没有返回日志；可能在启动前退出，或被运行时终止。")
    except Exception as error:
        code = f"，errno={error.errno}" if isinstance(error, OSError) else ""
        print(f"安装器启动失败（{type(error).__name__}{code}）。")
    finally:
        config.clear()

install_from_secrets()
'''.replace("COMMIT_PLACEHOLDER", args.commit).replace("DIGEST_PLACEHOLDER", digest)

intro = '''# Colab EasyTier + SSH

先在左侧 🔑 Secrets 添加并授权四项：`ET_NETWORK_NAME`、`ET_NETWORK_SECRET`、`ET_PEERS`、`SSH_PUBLIC_KEY`。

- `ET_PEERS` 填完整地址，例如 `tcp://你的服务器:11010`；多个地址用英文逗号分隔。
- `SSH_PUBLIC_KEY` 填 Windows 的 OpenSSH **公钥**，私钥始终留在 Windows。
- 安装器使用运行时现有的 2222 SSH 服务，将公钥加入 root 授权文件。
- Windows EasyTier 使用相同网络名、密钥和连接节点。
- `ET_IPV4` 留空由 EasyTier 自动分配地址，也可以手填固定地址。安装后会显示实际虚拟 IP。
- 首次填写并授权后，运行下方安装单元格即可。初始化运行时、授权 Secrets 可能需要你操作。
- Windows 通过 Colab 虚拟 IP 和应用端口访问 TCP/UDP 服务。运行时重建后重新运行此单元格。
- [中文文档](https://github.com/WillisXue/colab-easytier-ssh) · [Colab 使用限制](https://research.google.com/colaboratory/faq.html)

运行时会读取机密；不要向不信任的代码授权 Secrets。免费运行时的 SSH 限制仍适用。
'''
monitor_intro = '''## 可选：前台监控 EasyTier + SSH

安装成功后，需要长时间用 SSH 时，勾选 `ENABLE_MONITOR`，按需修改 `MONITOR_MINUTES`，再运行下方单元格。监控默认持续 120 分钟，约每分钟检查 EasyTier、组网和 SSH 的本地状态，仅在状态变化时输出。发现同网对端不代表 Windows 一定可以连通。

监控会占用 Notebook 内核；运行其他单元格前，先点击停止按钮。停止或到期只结束监控，不停止 EasyTier、SSH 或 Colab 运行时。Windows 仍按原方式连接。前台执行能否减少闲置断开取决于 Colab 的运行时策略和算力余额，不能保证持续在线。
'''

monitor = '''# @title 可选：前台监控 EasyTier + SSH（先完成安装）
ENABLE_MONITOR = False # @param {type:"boolean"}
MONITOR_MINUTES = 120 # @param {type:"integer"}

from pathlib import Path
import subprocess
import sys
import time


def monitor_services(minutes):
    if type(minutes) is not int or not 1 <= minutes <= 1440:
        print("MONITOR_MINUTES 必须是 1 至 1440 的整数。")
        return
    installer = Path("/content/colab-easytier-ssh-install.py")
    if not installer.is_file():
        print("当前运行时找不到安装器，请先运行上方安装单元格。")
        return

    deadline = time.monotonic() + minutes * 60
    previous = None
    print(f"开始前台监控（{minutes} 分钟）。仅在状态变化时输出；点击停止按钮可结束。", flush=True)
    try:
        while (remaining := deadline - time.monotonic()) > 0:
            try:
                result = subprocess.run(
                    [sys.executable, str(installer), "status"], stdin=subprocess.DEVNULL,
                    capture_output=True, text=True, encoding="utf-8", errors="replace",
                    timeout=min(15, remaining),
                    env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "LANG": "C.UTF-8"},
                )
                snapshot = (result.returncode, result.stdout.strip(), result.stderr.strip())
            except subprocess.TimeoutExpired:
                snapshot = (None, "", "状态检查超时。")
            except OSError as error:
                snapshot = (None, "", f"无法启动状态检查（{type(error).__name__}）。")

            if snapshot != previous:
                exit_code, output, error = snapshot
                for message in (output, error):
                    if message:
                        print(message, flush=True)
                if exit_code:
                    print(f"状态检查退出码：{exit_code}。", flush=True)
                previous = snapshot

            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(60, remaining))
    except KeyboardInterrupt:
        print("已手动停止监控。", flush=True)
    else:
        print("监控已到期。", flush=True)


if ENABLE_MONITOR:
    monitor_services(MONITOR_MINUTES)
else:
    print("监控未启用。勾选 ENABLE_MONITOR 后重新运行本单元格。")
'''

manage = '''## 管理和 Windows 访问

安装后可在新的代码单元格执行（命令不包含机密）：

```python
!python /content/colab-easytier-ssh-install.py status
!python /content/colab-easytier-ssh-install.py stop
!python /content/colab-easytier-ssh-install.py uninstall
```

先在 Colab 启动应用，Windows 随后通过安装器显示的虚拟 IP 和应用端口访问，例如 `http://<虚拟IP>:8000`。

需要终端时，在 Windows PowerShell 执行（按实际 IP 和端口修改）：

```powershell
ssh -p 2222 root@<虚拟IP>
```

首次 SSH 连接核对 Colab 打印的主机公钥指纹。
'''
notebook = {"cells": [
    {"cell_type": "markdown", "metadata": {}, "source": intro.splitlines(True)},
    {"cell_type": "code", "metadata": {"cellView": "form"}, "execution_count": None,
     "outputs": [], "source": source.splitlines(True)},
    {"cell_type": "markdown", "metadata": {}, "source": monitor_intro.splitlines(True)},
    {"cell_type": "code", "metadata": {"cellView": "form"}, "execution_count": None,
     "outputs": [], "source": monitor.splitlines(True)},
    {"cell_type": "markdown", "metadata": {}, "source": manage.splitlines(True)}],
    "metadata": {"colab": {"name": "colab-easytier-ssh.ipynb", "provenance": []},
                 "kernelspec": {"display_name": "Python 3", "name": "python3"},
                 "language_info": {"name": "python"}}, "nbformat": 4, "nbformat_minor": 4}
(root / "colab.ipynb").write_text(json.dumps(notebook, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print("Notebook generated with pinned installer and empty outputs.")
