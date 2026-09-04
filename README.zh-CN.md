# KJA — Kindle 越狱助手

[![CI](https://github.com/ZerrionGao/kindle-jailbreak-assistant/actions/workflows/tests.yml/badge.svg)](https://github.com/ZerrionGao/kindle-jailbreak-assistant/actions/workflows/tests.yml)
[![许可证：MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB.svg)](https://www.python.org/)

**别再让你的老 Kindle 吃灰了，一句话搞定越狱，让老 Kindle 焕发新生！**

[English](README.md) | 简体中文

KJA 是一个安全优先的 Agent Skill：识别 Kindle、核对当前越狱路线、备份电脑
可见存储，再引导安装 KOReader。

它起源于家里吃灰的 Paperwhite 3，也是“周末闲不住系列”第三篇。它不是给越狱
压缩包套了层聊天壳。型号或固件说不清时，KJA 最重要的功能是：礼貌地踩刹车。

> [!WARNING]
> Kindle 越狱属于非官方修改，可能丢数据、破坏 OTA，甚至把设备变砖。电脑可见
> 备份不是 NAND 镜像。KJA 能减少低级错误，但不能把危险操作变成无风险操作。

## 快速上手

### 1. 安装 Skill

macOS / Linux：

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

支持共享 Agent Skills 目录的运行时，也可以复制到 `~/.agents/skills/`。

### 2. 先做只读检查

```text
请使用 $kindle-jailbreak-assistant，以只读方式识别已连接的 Kindle，说明风险，
然后只给我一个安全的下一步。暂时不要写入设备。
```

在当前上游方法明确允许前，保持 Kindle 离线。

### 3. CLI 自检

在克隆后的仓库根目录：

```bash
python3 kindle-jailbreak-assistant/scripts/kindle_jailbreak.py --json self-test
python3 kindle-jailbreak-assistant/scripts/kindle_jailbreak.py --json probe
```

Windows 使用 `py -3`。`--apply` 不是“大力出奇迹”按钮：真正写入仍然需要精确
路线、已校验备份、新鲜 OTA 检查和一次性授权。

## 它在后台做什么

```text
探测 → OTA 检查 → 当前路线 → 校验备份 → 一个写入动作的一次性授权
     → Kindle 端证据 → KOReader 真实启动 → 精确清理
```

- 只认精确型号和固件；“Paperwhite，5.18 左右”不算。
- 实时读取并核对 KindleModding 四份来源，同时记录哈希。
- 未知路线、重定向、包或文件身份一律停止。
- 下载内容绑定当前路线，归档检查通过后才能接近 Kindle。
- 清理只处理本次会话明确记录创建的对象。
- KOReader 必须真的进入界面并打开一本本地书，文件复制不算毕业。

## 兼容性

| 电脑系统 | 传输方式 | 当前证据 |
|---|---|---|
| macOS | USB 存储 | Python 3.10/3.13 完整 CI |
| Linux | USB 存储 + GIO/GVFS MTP | 完整 CI；欢迎真机 MTP 报告 |
| Windows | USB 存储 + MTP | Windows 专属 CI，包含真实 `pwsh` |
| macOS | MTP | 没有现成安全传输能力就停止 |

实际能否越狱仍取决于当前 [KindleModding](https://kindlemodding.org/) 支持的精确
型号与固件。动真机前请看 [COMPATIBILITY.md](COMPATIBILITY.md)。

## 验证

```bash
PYTHONPATH=kindle-jailbreak-assistant/scripts \
  python3 -m unittest discover -s kindle-jailbreak-assistant/tests -v
python3 kindle-jailbreak-assistant/scripts/kindle_jailbreak.py --json self-test
bash -n kindle-jailbreak-assistant/scripts/kindle_mtp_linux.sh
```

当前版本本地 **215 项测试**；Linux/macOS/Windows × Python 3.10/3.13 矩阵全绿。
Windows 运行 78 项跨平台核心和平台专属测试，其中包含真实 PowerShell MTP 检查。
CI 是证据，但不是“世界上每一台 Kindle 都测过”。

## 周末闲不住系列

1. **clawd**：AI Agent 模型、用量、Git 和工作状态监控器。
2. **8.8 英寸 macOS 副屏**：给吃灰硬件补驱动，再顺手做几个主题。
3. **KJA**：越狱老 PW3，装上 KOReader，继续读书。
4. **Q30 Root & Flash Kit**：把黑莓实体键盘变成 AI 编程终端。

只要硬件还有一口气，就值得再占用我一个周末。

## 更多

- [兼容性](COMPATIBILITY.md)
- [安全策略](SECURITY.md)
- [参与贡献](CONTRIBUTING.md)
- [更新记录](CHANGELOG.md)
- [v0.1.0 Beta](https://github.com/ZerrionGao/kindle-jailbreak-assistant/releases/tag/v0.1.0)

KJA 是 [ZerrionGao](https://github.com/ZerrionGao) 的独立项目，依赖
[KindleModding](https://kindlemodding.org/) 社区知识和
[KOReader](https://github.com/koreader/koreader) 项目成果，与 Amazon 或这些
上游项目没有官方隶属关系。

原创代码和文档采用 [MIT License](LICENSE)，仓库不打包第三方载荷。
