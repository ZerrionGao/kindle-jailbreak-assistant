# Compatibility and evidence / 兼容性与证据

KJA uses current upstream data at runtime. This page describes what the
repository itself has actually verified; it is not a permanent Kindle
jailbreak compatibility list.

KJA 在运行时读取当前上游数据。本页只说明仓库自身实际验证过什么，不是一份永久
有效的 Kindle 越狱兼容表。

## Release status / 发布状态

**v0.1.x: Beta**

- The safety state machine, route validation, backup, archive validation,
  one-time authorization, simulated USB/MTP operations, recovery, and cleanup
  are covered by automated tests.
- Physical-device coverage is intentionally reported separately.
- “Supported by current KindleModding data” means KJA can identify and review
  the route. It does not guarantee that a jailbreak will succeed.

- 安全状态机、路线校验、备份、归档检查、一次性授权、模拟 USB/MTP 操作、恢复和
  清理均有自动化测试。
- 真机覆盖单独列出，不与模拟测试混为一谈。
- “当前 KindleModding 数据支持”表示 KJA 能识别和复核路线，不代表越狱必然成功。

## Host and transport matrix / 电脑系统与传输方式

| Host / 电脑系统 | Transport / 传输 | Repository evidence / 仓库证据 | Current status / 当前状态 |
|---|---|---|---|
| macOS | USB mass storage | `diskutil`/`ioreg` parsing, identity binding, safe-path and storage tests; full suite passes on Python 3.10/3.13 CI and macOS arm64/Python 3.11 locally | Beta; physical-device reports welcome |
| macOS | MTP | Detection and safe-stop behavior | No bundled write path; requires a safe pre-existing tool |
| Linux | USB mass storage | Mount/`udevadm` fixtures and full Python 3.10/3.13 CI suite | CI verified; physical validation pending |
| Linux | GIO/GVFS MTP | Adapter protocol, end-to-end simulated CLI flow, and full Linux CI suite | CI verified; physical validation pending |
| Windows | USB mass storage | PowerShell volume fixtures, Windows-specific storage safety tests, and Python 3.10/3.13 CI | CI verified; physical validation pending |
| Windows | MTP | Portable-device adapter, duplicate-name, stable-identity, copy completion, and real `pwsh` fixture runs on Windows CI | CI verified; physical validation pending |

The local 2026-09-04 release audit ran 215 tests successfully. Five Windows
PowerShell fixture tests were skipped because `pwsh` was not installed on the
author's macOS host. The CI matrix is intended to run those tests on Windows;
the first complete public matrix passed all six jobs on 2026-09-04.

2026-09-04 的本地发布审计共通过 215 项测试。由于作者的 macOS 主机没有安装
`pwsh`，其中 5 项 Windows PowerShell 测试被跳过。CI 矩阵会在 Windows 上运行
这些测试；2026-09-04 的首个完整公开矩阵六项任务已全部通过。

## Kindle model and firmware routing / Kindle 型号与固件路由

KJA does not ship a frozen list saying “model X always uses method Y.” Each
session fetches and reviews:

1. `https://kindlemodding.org/models.json`
2. `https://kindlemodding.org/jailbreaks.json`
3. `https://kindlemodding.org/jailbreakFinder.js`
4. The exact method page selected for the detected device

All four sources must be HTTPS, non-empty, structurally understood, hashed, and
explicitly confirmed. Unknown models, ambiguous firmware, schema drift, changed
redirects, or policy conflicts stop before a device write.

KJA 不保存“某型号永远使用某方法”的静态表。每次会话都重新读取并复核上述四份
来源。四者必须使用 HTTPS、内容非空、结构可理解、已记录哈希并得到明确确认。
未知型号、模糊固件、结构变化、重定向变化或策略冲突都会在写入前停止。

During the 2026-09-04 audit, the live KindleModding files still matched KJA's
strict schema and all 13 live method names had a corresponding local safety
policy. That is a point-in-time result, not a future guarantee.

2026-09-04 审计时，KindleModding 实时文件仍符合 KJA 的严格结构要求，13 个当前
方法名称也都有对应的本地安全策略。这只是当时结果，不是永久保证。

## Known device evidence / 已知设备证据

| Device / 设备 | Evidence / 证据 | Claim allowed / 可作出的结论 |
|---|---|---|
| Kindle Paperwhite 3 | The author's successful personal jailbreak and KOReader journey motivated the project; `PW3 + 5.16.2.1.1` is also covered as a simulated routing/package sample | The workflow has a real-world origin; the automated CLI is not yet claimed as broadly hardware-certified |
| Other Kindle models | Current upstream route data plus offline fixtures and strict failure behavior | Route review is available when exact data matches; no blanket success guarantee |

Please contribute physical-device results through the compatibility report
Issue form. Report failures too—they are often more valuable than a success
checkbox.

欢迎通过兼容性报告 Issue 表单补充真机结果，失败报告同样有价值。

## Python versions / Python 版本

The code requires Python 3.10 or later. The public CI matrix targets Python 3.10
and 3.13: Linux and macOS run the full suite, while Windows runs the
cross-platform core and Windows-specific transport, volume, and output tests.
The author's fresh local evidence is Python 3.11.15 on macOS arm64.

代码要求 Python 3.10 或更高版本。公开 CI 矩阵覆盖 Python 3.10 和 3.13：Linux
与 macOS 运行完整套件，Windows 运行跨平台核心以及 Windows 专属传输、卷与输出
测试。作者本次新鲜本地证据来自 macOS arm64 上的 Python 3.11.15。

## How to report a useful compatibility result / 如何提交有效兼容性报告

Include:

- host OS and version;
- Python version;
- exact Kindle marketing model and redacted device code;
- exact firmware;
- USB mass storage or MTP;
- KJA subcommand and stable exit code;
- whether the device was modified;
- sanitized output and the visible Kindle result.

Never include a full serial number, Amazon account data, QR-login data, cookies,
signed download URLs, or a complete KJA session directory.

请提供电脑系统、Python 版本、精确 Kindle 型号、脱敏设备码、完整固件、传输方式、
KJA 子命令与退出码、设备是否已修改，以及脱敏输出和 Kindle 可见结果。不要公开
完整序列号、Amazon 账户数据、二维码登录数据、Cookie、签名下载地址或完整会话
目录。
