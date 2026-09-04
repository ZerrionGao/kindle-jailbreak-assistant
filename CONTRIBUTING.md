# Contributing / 参与贡献

Thank you for helping old hardware stay useful. KJA welcomes focused fixes,
tests, documentation improvements, and carefully evidenced compatibility
reports.

感谢你帮助老硬件继续发挥价值。KJA 欢迎边界清晰的缺陷修复、测试、文档改进和有
证据的兼容性报告。

## Before changing code / 修改代码前

1. Search existing Issues and pull requests.
2. For a new jailbreak method, transport backend, or change that writes to a
   device, open an Issue first and link the current upstream source.
3. Never add a mirrored jailbreak payload, firmware image, credential, full
   serial number, signed URL, or real session directory.
4. Preserve fail-closed behavior. Unknown input must not silently fall back to
   the nearest model, firmware, route, path, or package.

1. 先搜索已有 Issue 和 Pull Request。
2. 新越狱方法、新传输后端或任何会写设备的改动，请先开 Issue，并提供当前上游
   原始来源。
3. 不得提交转载越狱载荷、固件镜像、凭据、完整序列号、签名地址或真实会话目录。
4. 保持“无法确认就停止”。未知输入不得悄悄退回到相近型号、固件、路线、路径或包。

## Development setup / 开发环境

KJA requires Python 3.10 or later and otherwise uses the standard library.

```bash
git clone https://github.com/ZerrionGao/kindle-jailbreak-assistant.git
cd kindle-jailbreak-assistant
python3 kindle-jailbreak-assistant/scripts/kindle_jailbreak.py --json self-test
PYTHONPATH=kindle-jailbreak-assistant/scripts python3 -m unittest discover -s kindle-jailbreak-assistant/tests -v
```

Windows uses `py -3` in place of `python3`. Windows MTP changes should be
tested with `pwsh` available. Linux adapter changes should also pass:

```bash
bash -n kindle-jailbreak-assistant/scripts/kindle_mtp_linux.sh
```

## Change rules / 修改规则

- Keep the core implementation dependency-free unless a dependency is
  essential and discussed first.
- Add or update tests for changed behavior, especially authorization, identity,
  path handling, downloads, archive extraction, cleanup, and recovery.
- Use temporary directories and simulated devices in automated tests. Never
  require a contributor's real Kindle for the default test suite.
- Keep user-visible explanations clear. Paths, commands, protocol fields, and
  original errors may stay in English.
- Make the smallest change that solves the reported problem. Avoid unrelated
  refactors and formatting churn.
- Upstream compatibility is live data. Do not freeze a broad model/firmware
  table into the code or README.

- 除非依赖不可替代且已经讨论，不要给核心实现新增第三方依赖。
- 行为变化必须新增或更新测试，尤其关注授权、身份、路径、下载、解压、清理和恢复。
- 自动化测试使用临时目录和模拟设备，默认测试不得要求贡献者连接真实 Kindle。
- 用户可见说明应清楚易懂；路径、命令、协议字段和原始错误可以保留英文。
- 只做解决问题所需的最小修改，不顺带重构或大范围格式化。
- 上游兼容信息是实时数据，不要在代码或 README 中固化宽泛的型号/固件表。

## Pull request checklist / Pull Request 检查清单

- [ ] The change has a narrow, explained purpose.
- [ ] Relevant tests pass on the contributor's host.
- [ ] `self-test`, Python compilation, and adapter syntax checks pass.
- [ ] New device writes still require the correct fresh gates and one-time
      authorization.
- [ ] No secrets, personal identifiers, payloads, generated caches, or device
      backups are included.
- [ ] User-facing behavior and known limitations are documented.
- [ ] The PR states which platforms and physical devices were actually tested.

- [ ] 改动目的清晰且边界明确。
- [ ] 相关测试在贡献者电脑上通过。
- [ ] `self-test`、Python 编译和适配器语法检查通过。
- [ ] 新设备写入仍要求正确的新鲜门槛和一次性授权。
- [ ] 没有提交密钥、个人标识、载荷、生成缓存或设备备份。
- [ ] 用户可见行为和已知限制已经写入文档。
- [ ] PR 明确说明真正测试过哪些电脑系统和物理设备。

## Compatibility reports / 兼容性报告

Use the compatibility Issue form for both success and failure reports. Redact
the device serial to a non-reversible device code or partial hint, keep the
exact firmware, and describe the visible on-device result. A simulated result
must be labelled simulated.

无论成功还是失败，请使用兼容性 Issue 表单。序列号必须脱敏成不可逆设备码或局部
提示，固件版本要保持完整，并描述设备上真正看到的结果。模拟结果必须明确标为模拟。

## Security / 安全问题

Do not open a public Issue for a vulnerability. Follow
[SECURITY.md](SECURITY.md).

漏洞不要提交公开 Issue，请按 [SECURITY.md](SECURITY.md) 私下报告。
