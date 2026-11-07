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
ET_IPV4 = "10.144.144.2/24" # @param {type:"string"}
SSH_USER = "colabssh" # @param {type:"string"}
SSH_PORT = 2222 # @param {type:"integer"}
EXPECT_WINDOWS_IP = "10.144.144.1" # @param {type:"string"}

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
    config = {"ET_IPV4": ET_IPV4, "SSH_USER": SSH_USER, "SSH_PORT": SSH_PORT}
    try:
        for name in ("ET_NETWORK_NAME", "ET_NETWORK_SECRET", "ET_PEERS", "SSH_PUBLIC_KEY"):
            config[name] = userdata.get(name)
    except Exception:
        print("读取 Secrets 失败，请检查四个 Secrets 是否已填写并允许此 Notebook 访问。")
        return
    argv = [sys.executable, str(INSTALLER_PATH), "start", "--config-stdin"]
    if EXPECT_WINDOWS_IP.strip():
        argv += ["--expect-peer", EXPECT_WINDOWS_IP.strip()]
    try:
        # Credentials go over stdin, never in argv or notebook source/output.
        result = subprocess.run(argv, input=json.dumps(config), text=True,
                                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "LANG": "C.UTF-8"})
        if result.returncode:
            print("安装未完成，请根据上方过滤后的错误信息检查配置。")
    except Exception:
        print("安装器未能运行；未显示私密配置。")
    finally:
        config.clear()

install_from_secrets()
'''.replace("COMMIT_PLACEHOLDER", args.commit).replace("DIGEST_PLACEHOLDER", digest)

intro = '''# Colab EasyTier + SSH

先在左侧 🔑 Secrets 添加并授权四项：`ET_NETWORK_NAME`、`ET_NETWORK_SECRET`、`ET_PEERS`、`SSH_PUBLIC_KEY`。

- `ET_PEERS` 填完整地址，例如 `tcp://你的服务器:11010`；多个地址用英文逗号分隔。
- `SSH_PUBLIC_KEY` 填 Windows 的 OpenSSH **公钥**，私钥始终留在 Windows。
- Windows EasyTier 使用相同网络名、密钥和连接节点，虚拟 IP 与下方配置同网段且不重复。
- 首次填写并授权后，运行下面一个单元格即可。初始化运行时、授权 Secrets 可能需要你操作。
- 默认只开放 SSH；应用通过 `ssh -L` 访问。运行时重建后重新运行此单元格。
- [中文文档](https://github.com/WillisXue/colab-easytier-ssh) · [Colab 使用限制](https://research.google.com/colaboratory/faq.html)

运行时会读取机密；不要向不信任的代码授权 Secrets。免费运行时的 SSH 限制仍适用。
'''
manage = '''## 管理和 Windows 访问

安装后可在新的代码单元格执行（命令不包含机密）：

```python
!python /content/colab-easytier-ssh-install.py status
!python /content/colab-easytier-ssh-install.py stop
!python /content/colab-easytier-ssh-install.py uninstall
```

Windows PowerShell 示例（按实际 IP、用户和端口修改）：

```powershell
ssh -p 2222 colabssh@10.144.144.2
ssh -N -p 2222 -L 127.0.0.1:8000:127.0.0.1:8000 colabssh@10.144.144.2
```

首次连接核对 Colab 打印的主机公钥指纹。保持转发命令运行，本机访问 `http://127.0.0.1:8000`。
'''
notebook = {"cells": [
    {"cell_type": "markdown", "metadata": {}, "source": intro.splitlines(True)},
    {"cell_type": "code", "metadata": {"cellView": "form"}, "execution_count": None,
     "outputs": [], "source": source.splitlines(True)},
    {"cell_type": "markdown", "metadata": {}, "source": manage.splitlines(True)}],
    "metadata": {"colab": {"name": "colab-easytier-ssh.ipynb", "provenance": []},
                 "kernelspec": {"display_name": "Python 3", "name": "python3"},
                 "language_info": {"name": "python"}}, "nbformat": 4, "nbformat_minor": 4}
(root / "colab.ipynb").write_text(json.dumps(notebook, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print("Notebook generated with pinned installer and empty outputs.")
