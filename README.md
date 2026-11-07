# Colab EasyTier + SSH

[![Test](https://github.com/WillisXue/colab-easytier-ssh/actions/workflows/test.yml/badge.svg)](https://github.com/WillisXue/colab-easytier-ssh/actions/workflows/test.yml)
[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/WillisXue/colab-easytier-ssh/blob/main/colab.ipynb)

在 Colab 网页中运行一个单元格，安装固定版本 EasyTier，以无 TUN 模式加入你的虚拟网络，并配置现有 SSH 服务的 root 公钥登录。Windows 可以通过 Colab 的 EasyTier 虚拟 IP 直接访问应用 TCP/UDP 端口，也可以 SSH 登录。

**公开仓库不保存你的网络名称、密钥、服务器地址或 SSH 私钥。**首次配置 Colab Secrets 后，每个新运行时重新运行安装单元格即可。启动运行时、授权 Secrets 仍可能需要点击操作。

## 1. Windows 准备

安装并配置 [EasyTier](https://github.com/EasyTier/EasyTier/releases/tag/v2.6.4)，使用你已有的网络名称、密钥和初始连接节点。建议两端先使用 v2.6.4。Windows 使用正常 TUN 模式。Colab 默认由 EasyTier 自动分配虚拟 IPv4，也可以在安装表单中填写固定地址。使用固定地址时，选择与你现有局域网、VPN 不冲突的网段。

在 PowerShell 生成专用 SSH 密钥（已有密钥可以直接使用）：

```powershell
ssh-keygen -t ed25519 -f "$env:USERPROFILE\.ssh\id_ed25519_colab"
Get-Content "$env:USERPROFILE\.ssh\id_ed25519_colab.pub"
```

把 `.pub` 文件的整行公钥复制到下一步；**不复制私钥**。创建密钥时可以设置口令，连接时由本地 SSH 询问。

## 2. 配置 Colab Secrets

点击上方 **Open in Colab**，在左侧钥匙图标 Secrets 中添加下表四项，并打开此 Notebook 的访问权限。值只填在 Secrets 中，不写入代码单元格或分享链接。

| Secret 名称 | 填写内容 |
| --- | --- |
| `ET_NETWORK_NAME` | 与 Windows 一致的网络名称 |
| `ET_NETWORK_SECRET` | 与 Windows 一致的网络密钥；非空即可，无最小长度限制 |
| `ET_PEERS` | 完整连接地址，如 `tcp://你的服务器:11010`；多个地址用英文逗号分隔 |
| `SSH_PUBLIC_KEY` | Windows SSH 公钥的完整一行 |

支持 `tcp://`、`udp://`、`ws://`、`wss://`、`quic://`，地址必须显式带端口。可以使用自己的中继，也可以使用可信的公共节点；脚本不会安装中继服务器或自动填写公共服务器。

Colab Secrets 使用 `google.colab.userdata.get()`，需要从 **Colab 网页界面**运行；它不是可在任意 Python/CLI 环境读取的通用密钥库。

## 3. 一键安装

连接 Colab 运行时，在安装单元格中按需设置：

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `ET_IPV4` | 空 | 留空由 EasyTier 自动分配；也可填写固定私网 IPv4 或 CIDR |
| `SSH_PORT` | `2222` | 运行时现有 SSH 服务端口 |

运行该单元格。安装器下载固定版本的 EasyTier，校验 SHA-256，写入权限为 `600` 的运行时私有配置，将公钥追加到现有 SSH 服务使用的 root 授权文件，并启动 EasyTier。重复执行时复用已有授权。

对于锁定的 root 账户，安装器会在现有 sshd 配置中添加带项目标记的 `UsePAM yes` 设置，校验后重载原服务，使 root 可以通过公钥认证。

显示本地服务就绪，只表示本地进程及端口正常；**发现同网对端也不等于已从 Windows 完成端到端连接**。最后需要从 Windows 访问实际服务或执行 SSH。若 Windows 尚未在线，安装仍会完成并显示等待对端。

## 4. 从 Windows 连接

安装器会显示实际虚拟 IPv4。组网成功后，通过该地址和应用端口访问。下面以 `10.144.144.2` 为例，使用时替换成实际地址：

```text
http://10.144.144.2:8000
http://10.144.144.2:7860
```

先在 Colab 启动应用，再通过虚拟 IP 和应用实际监听端口访问。无 TUN 模式将发往本节点虚拟 IP 的服务连接转到宿主机对应端口，因此也支持监听 Colab localhost 的服务。实际连通受 EasyTier 网络策略、服务自身配置和防火墙影响。

需要终端时，使用 SSH：

```powershell
# 登录；首次连接时核对 Colab 打印的主机公钥指纹
ssh -i "$env:USERPROFILE\.ssh\id_ed25519_colab" -p 2222 root@10.144.144.2
```


也可以下载并使用 `windows/connect.ps1`：

```powershell
.\windows\connect.ps1 -Target 10.144.144.2 -IdentityFile "$env:USERPROFILE\.ssh\id_ed25519_colab"
```

助手使用独立的 `%LOCALAPPDATA%\colab-easytier-ssh\known_hosts`，首次连接需核对指纹。

新 Colab 运行时会生成新的 SSH 主机密钥。若 SSH 提示主机密钥变更，先核对新指纹，再用 `ssh-keygen -R '[10.144.144.2]:2222'` 清理对应的旧记录；使用助手时还需指定 `-f` 指向上述独立 known_hosts 文件。不要直接关闭主机校验。

## 管理当前运行时

安装后，在 Colab 新单元格中执行以下任一命令：

```python
!python /content/colab-easytier-ssh-install.py status
!python /content/colab-easytier-ssh-install.py stop
!python /content/colab-easytier-ssh-install.py uninstall
```

安装单元格会显示安装器的执行结果。失败时显示具体步骤、命令名和退出码；系统依赖安装、SSH 配置检查的错误会附上诊断内容。安装成功后显示实际虚拟 IPv4 和 root SSH 连接命令。自动分配地址尚未就绪时，稍后运行 `status` 查看。

- 再次运行安装单元格会更新配置、重启 EasyTier，并复用当前运行时的 SSH 服务和主机密钥。
- `stop` 停止 EasyTier，保留当前运行时的配置和 SSH 授权。
- `uninstall` 清理本项目进程、安装目录、追加的公钥和认证设置；原有 SSH 服务继续运行。
- SSH 使用 root 公钥登录，进入与 Colab Notebook 一致的 root 环境。
- 安装目录 `/opt/colab-easytier-ssh`，配置及状态 `/run/colab-easytier-ssh`；不保存到 Google Drive。

## 外部参数与自动化

安装器只依赖 Python 3.10+ 标准库，运行时需要 Linux root、现有 sshd 服务和访问 GitHub 的网络。`check` 可在 Windows 验证配置。

机密入口任选其一：

```text
python install.py start --config-stdin
python install.py start --config-file /path/to/config.private.json
python install.py check --config-file /path/to/config.private.json
```

`--config-stdin` 从标准输入接收 JSON。Python 调用示例（`private_config` 由你的外部密钥源读取）：

```python
subprocess.run(
    [sys.executable, 'install.py', 'start', '--config-stdin'],
    input=json.dumps(private_config), text=True, check=True,
)
```

不要把真实值写进命令、Notebook 或 shell here-document。`config.example.json` 只有占位符。将真实文件保存在仓库之外，权限设为 `600`；不要上传 Notebook 运行输出。

还支持同名环境变量。覆盖优先级：**普通命令行参数 > JSON 配置 > 环境变量 > 默认值**。JSON 字段：

| 字段 | JSON 类型 | 说明 |
| --- | --- | --- |
| `ET_NETWORK_NAME` | string | 必填 |
| `ET_NETWORK_SECRET` | string | 必填且非空；无最小长度限制 |
| `ET_PEERS` | string 或 string[] | 必填；字符串用逗号/换行分隔 |
| `SSH_PUBLIC_KEY` | string | 必填；单行 OpenSSH 公钥 |
| `ET_IPV4` | string | 默认空，由 EasyTier 自动分配；也可填写固定私网 IPv4 或 CIDR |
| `SSH_PORT` | integer | 默认 2222 |
| `EASYTIER_VERSION` | string | 仅接受安装器内置校验清单版本，目前 v2.6.4 |

普通参数可以用 `--ipv4`、`--ssh-port`、`--easytier-version` 覆盖。

自动分配模式下，安装器通过 EasyTier 本机状态读取实际地址，并在 `status` 中更新连接命令。若安装结束时仍在分配，稍后运行 `status` 查看。

应用 TCP/UDP 服务通过 EasyTier 虚拟 IP 和实际端口访问。

## 隐私边界与版本

- Colab Secrets 由 Notebook 在内存中读取，通过标准输入传给安装器；真实参数不写入 GitHub。
- EasyTier 启动命令只携带配置路径。原始 stdout/stderr 被丢弃，避免启动配置、异常中的密钥或服务器地址进入 Notebook；代价是没有原始 EasyTier 调试日志。
- 错误包含字段名、失败步骤、命令名、退出码及系统工具诊断。SSH 公钥注释被移除。默认可显示虚拟 IP、登录用户名和主机公钥指纹，它们用于连接。
- 运行时 root、被授权的 Notebook 代码仍可读取机密。公网中继可见连接元数据，服务器本身也能知道连接来源；这里保护的是仓库、命令行和输出中的机密，并非向运行平台或中继隐藏一切。
- Notebook 下载的安装器固定到提交 SHA，并校验内置 SHA-256；EasyTier 固定为 v2.6.4，Linux x86_64/aarch64 发行包哈希写入安装器，不在运行时跟随 `latest`。
- 安装器不提供保活、不绕过 Colab 限制。免费运行时的 SSH 限制、付费余额要求以及运行时寿命仍适用。见 [Colab FAQ](https://research.google.com/colaboratory/faq.html)。
- P2P 直连受网络环境影响；需要可用的初始连接节点和必要时的中继。此工具不会保证直连，也不会让断开的 Colab 运行时继续提供服务。

## 测试和维护

```text
python -m unittest discover -s tests -v
python tools/check_notebook.py
```

GitHub Actions 在 Windows/Linux 上运行配置校验、泄漏防护、下载校验和 Notebook 检查；独立 Ubuntu runner 模拟 Colab 的现有 2222 SSH 服务，验证复用原 PID、公钥追加、重复安装、固定及自动地址的 root SSH、TCP/UDP 服务直连和卸载清理，并检查原有 SSH、公钥及系统账户记录。Linux 集成测试必须在可丢弃的 root 环境执行，使用专用目录和临时测试密钥。

更新 `install.py` 后，先提交安装器，再执行 `python tools/build_notebook.py --commit <安装器所在完整提交SHA>`，将新的 Notebook 提交。不要把用户配置加入测试或版本历史。

CI 不等于真实 Colab GPU 运行时与用户 Windows 网络的验证；后者仍需用户在自己的网络中运行一次。

## 上游

- [EasyTier](https://github.com/EasyTier/EasyTier)，EasyTier 二进制来自其官方发行版，遵循上游许可；本仓库不重新打包二进制。
- [无 TUN 模式文档](https://github.com/EasyTier/easytier.github.io/blob/main/guide/network/no-root.md)
- [Colab Secrets 官方实现](https://github.com/googlecolab/colabtools/blob/main/google/colab/userdata.py)

本仓库代码使用 MIT 许可。
