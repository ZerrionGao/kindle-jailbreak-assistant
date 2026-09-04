# KJA — Kindle 越狱助手

[![CI](https://github.com/ZerrionGao/kindle-jailbreak-assistant/actions/workflows/tests.yml/badge.svg)](https://github.com/ZerrionGao/kindle-jailbreak-assistant/actions/workflows/tests.yml)
[![许可证：MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB.svg)](https://www.python.org/)

**旧 Kindle，新篇章。**

[English](README.md) | 简体中文

KJA 是我的“周末闲不住系列日记”第三篇：**Kindle Paperwhite 3 越狱并安装
KOReader**。

家里那台 Paperwhite 3 吃灰很久了。硬件其实好好的，只是原来的使用方式已经
不太合拍。越狱、安装 [KOReader](https://github.com/koreader/koreader)，再按需
装上阅读插件以后，这个老物件又重新回到了书桌上。KJA 把这次折腾中真正重要的
安全检查、电脑端操作和停止条件整理成了一个可以复用的 Agent Skill。

KJA 不是越狱包，也不是“一键刷机神器”。它是一个默认保守、遇到不确定就停止的
协作助手：先识别精确设备和固件，再核对当前社区路线，备份电脑可见存储，校验
下载内容，并在每次需要写入 Kindle 前停下来取得明确授权。

> [!WARNING]
> Kindle 越狱属于非官方修改，可能造成内容丢失、系统异常、OTA 自动升级受阻，
> 极端情况下设备可能无法启动。电脑可见备份不是 NAND 或完整系统镜像。选定路线
> 允许前，请保持 Kindle 离线并阅读当次上游原始说明。

## 为什么要做 KJA

Kindle 越狱教程很容易过期。“Paperwhite”或“5.18 左右”都不足以选择安全路线。
能否继续可能同时取决于精确型号、设备变体、完整固件、注册/广告状态，以及电脑
看到的是 USB 大容量存储还是 MTP。

KJA 把这些门槛放到明面上：

```text
只读探测
  → OTA／离线检查
  → 当次上游路线复核
  → 电脑可见用户存储备份与校验
  → 一个写入动作的一次性授权
  → Kindle 端操作
  → 当前方法专属成功证据
  → KOReader 真实可见启动
  → 精确清理本次创建的文件
```

没有精确匹配时，KJA 会停止，而不是尝试相近固件、论坛转载包或未知载荷。

## 它能帮你做什么

- 在 macOS、Linux、Windows 上识别 Kindle USB 大容量存储设备。
- 使用受支持的 Windows MTP 和 Linux GIO/GVFS MTP 传输路径。
- 根据当前 [KindleModding](https://kindlemodding.org/) 数据解析设备码和完整固件。
- 保存四份路线来源的 SHA-256，并要求逐项明确复核。
- 创建并逐文件校验电脑可见用户存储备份。
- 只从当前路线绑定的 HTTPS 地址下载载荷，复制前检查归档安全。
- 断线后仅在稳定设备身份仍一致时恢复会话。
- 使用当前方法专属标记或日志验证越狱，不相信泛化的“成功”提示。
- 依据 KOReader 当前官方安装页选择包，并要求用户真实进入阅读器界面。
- 只清理由本次会话明确记录创建的文件。

## 它刻意不做什么

- 不承诺所有 Kindle、所有固件都能越狱。
- 不打包、镜像或重新授权越狱包、KOReader 或阅读插件。
- 不猜型号、固件、成功标记、下载链接或安装包。
- 不自动恢复出厂、降级、安装固件、修改 Amazon 账户设置，也不自动安装电脑
  驱动和 MTP 依赖。
- 不把文件复制、二维码、错误弹窗或回到主页当成成功证据。
- 不替代原方法维护者和当次上游文档。

精确支持情况和证据等级见 [COMPATIBILITY.md](COMPATIBILITY.md)。

## 安装为 Codex Skill

macOS 或 Linux：

```bash
git clone https://github.com/ZerrionGao/kindle-jailbreak-assistant.git kja
mkdir -p ~/.codex/skills
cp -R kja/kindle-jailbreak-assistant ~/.codex/skills/kindle-jailbreak-assistant
python3 ~/.codex/skills/kindle-jailbreak-assistant/scripts/kindle_jailbreak.py --help
```

Windows PowerShell：

```powershell
git clone https://github.com/ZerrionGao/kindle-jailbreak-assistant.git kja
New-Item -ItemType Directory -Force "$env:USERPROFILE\.codex\skills" | Out-Null
Copy-Item -Recurse ".\kja\kindle-jailbreak-assistant" "$env:USERPROFILE\.codex\skills\kindle-jailbreak-assistant"
py -3 "$env:USERPROFILE\.codex\skills\kindle-jailbreak-assistant\scripts\kindle_jailbreak.py" --help
```

支持跨运行时 Agent Skills 目录的工具也可以安装到
`~/.agents/skills/kindle-jailbreak-assistant`，复制其中的 Skill 子目录即可。

如果 Agent 运行时不会自动刷新 Skill，安装后请重新启动一次。

## 第一次怎样安全地用

显式调用 Skill：

```text
请使用 $kindle-jailbreak-assistant，以只读方式识别已连接的 Kindle，说明风险，
并只告诉我一个最安全的下一步。不要写入设备。
```

直接使用 CLI 时，下面三个入口也都是只读的：

```bash
python3 kindle-jailbreak-assistant/scripts/kindle_jailbreak.py --help
python3 kindle-jailbreak-assistant/scripts/kindle_jailbreak.py --json self-test
python3 kindle-jailbreak-assistant/scripts/kindle_jailbreak.py --json probe
```

Windows 把 `python3` 换成 `py -3`。

不要为了“让它跑起来”随手加 `--apply`。真正写入前必须已经建立与当前路线绑定
的会话，完成备份校验和新鲜 OTA 检查，并对一个明确命名的操作取得一次性授权。

## 运行要求

- Python 3.10 或更高版本；核心实现仅使用 Python 标准库。
- 一根确定支持数据传输的 USB 线。
- 电脑端有足够空间完整保存 Kindle 的电脑可见用户存储。
- Linux MTP：系统已经有可用的 GIO/GVFS 环境。
- Windows MTP：PowerShell 和受支持的 Windows 便携设备访问路径。
- macOS MTP：只有系统已经具备安全传输能力时才继续；KJA 不会自行安装
  Homebrew、驱动或 MTP 工具。

## 本地验证

在仓库根目录运行：

```bash
PYTHONPATH=kindle-jailbreak-assistant/scripts python3 -m unittest discover -s kindle-jailbreak-assistant/tests -v
python3 kindle-jailbreak-assistant/scripts/kindle_jailbreak.py --json self-test
python3 -m compileall -q kindle-jailbreak-assistant/scripts
bash -n kindle-jailbreak-assistant/scripts/kindle_mtp_linux.sh
```

首次公开版本在作者的 macOS／Python 3.11 环境中有 215 项自动化测试通过。本机
没有 `pwsh` 时会跳过 5 项 Windows PowerShell 测试。GitHub Actions 已配置为在
Linux 和 macOS 上运行完整套件，并在 Windows 上运行跨平台核心与 Windows 专属
套件。公开的 Python 3.10/3.13 三平台矩阵已经全部通过。模拟验证和 CI 仍然不能
等同于“所有 Kindle 真机都验证过”。

## 目录结构

```text
README.md / LICENSE      仓库介绍与许可证
.github/                 CI、Issue 表单和 Pull Request 模板
kindle-jailbreak-assistant/
├── SKILL.md             Agent 使用的流程与安全门槛
├── agents/              Codex 界面元数据
├── references/          安全、路由、设备操作和恢复说明
├── scripts/             CLI 与主机传输适配器
└── tests/               离线单元测试与集成测试
```

`tests/` 会随源码仓库发布。普通使用 Skill 时不依赖它，但三平台 CI、安全回归检查
和外部贡献者复现问题都需要这些测试。

## 怎样反馈问题

提交设备问题前请阅读 [COMPATIBILITY.md](COMPATIBILITY.md)，并提供电脑系统、
Python 版本、Kindle 型号或脱敏设备码、精确固件、传输方式、子命令、退出码和
脱敏输出。不要公开完整序列号、账户信息、二维码登录数据、Cookie、带签名的下载
地址或整个会话目录。

安全问题按 [SECURITY.md](SECURITY.md) 报告，代码和文档贡献见
[CONTRIBUTING.md](CONTRIBUTING.md)。

## “周末闲不住系列”

1. **clawd**：AI Agent 桌面状态监控器，显示 Codex、Claude Code 等工具的模型、
   用量、Git 文件变更和工作状态。
2. **8.8 英寸 macOS 副屏**：给原本只有 Windows 驱动的硬件补上 macOS 驱动，
   顺便自己做主题，继续显示 CPU、GPU、网络、磁盘和温度信息。
3. **KJA**：让吃灰的 Kindle Paperwhite 3 完成越狱、装上 KOReader，再次成为
   真正好用的阅读器。
4. **Q30 Root & Flash Kit**：把黑莓 Q30 和那块舒服的实体键盘变成口袋终端，
   用来监控 AI 编程状态和发送指令。

这个系列的共同原则很简单：只要硬件还有一口气，就值得再占用我一个周末。

## 致谢与独立性说明

KJA 依赖 [KindleModding](https://kindlemodding.org/) 社区维护的当前路线，以及
[KOReader](https://github.com/koreader/koreader) 提供的安装说明和 Release。
请优先尊重、支持并感谢这些上游社区。

KJA 是 [ZerrionGao](https://github.com/ZerrionGao) 的独立项目，与 Amazon、
KindleModding、KOReader 或插件作者没有隶属、授权或官方支持关系。“Kindle”
商标归其权利人所有。

## 许可证

KJA 原创代码和文档采用 [MIT License](LICENSE)。第三方项目及其发布的载荷继续
适用各自许可证，详见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
