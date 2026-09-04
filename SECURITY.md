# Security policy / 安全策略

## Supported versions / 支持版本

Before KJA reaches 1.0, security fixes are provided for the latest release only.
Users should reproduce an issue against the latest commit or release using
read-only or simulated inputs whenever possible.

KJA 到达 1.0 之前，只为最新版本提供安全修复。请尽可能使用只读或模拟输入，在
最新提交或 Release 上复现问题。

## Report a vulnerability privately / 私下报告安全问题

Use GitHub's private vulnerability report:

https://github.com/ZerrionGao/kindle-jailbreak-assistant/security/advisories/new

If private reporting is not yet enabled, contact the maintainer through
[ZerrionGao's GitHub profile](https://github.com/ZerrionGao) and ask for a
private reporting channel. Do not publish exploit details, secrets, a full
serial number, signed download URLs, or a session archive in a public Issue.

请优先使用上面的 GitHub 私密漏洞报告入口。如果该功能尚未启用，请通过
[ZerrionGao 的 GitHub 主页](https://github.com/ZerrionGao) 联系维护者并索取
私密报告方式。不要在公开 Issue 中发布利用细节、密钥、完整序列号、签名下载
地址或会话归档。

Useful reports include:

- affected commit or release;
- host OS and Python version;
- transport type, using a simulated device when possible;
- the smallest safe reproduction;
- expected and observed safety behavior;
- whether any real device was written to;
- a proposed mitigation, if known.

有效报告应包含受影响版本、电脑系统、Python 版本、传输方式、最小安全复现、
预期与实际安全行为、是否写入过真机，以及已知的缓解办法。

## High-priority security areas / 高优先级安全范围

- device identity confusion or cross-device session reuse;
- path traversal, symlink/reparse-point following, or writes outside the
  selected Kindle root;
- overwrite or deletion of pre-existing user files;
- write authorization replay or bypass;
- accepting unconfirmed, redirected, replaced, or route-unbound payloads;
- leaking serial numbers, credentials, signed URLs, QR data, or cookies;
- treating unverified host-side output as on-device success;
- automatic installation or execution outside the user's explicit authority.

- 设备身份混淆或跨设备复用会话；
- 路径越界、跟随符号链接/重解析点或写出 Kindle 根目录；
- 覆盖、删除用户原有文件；
- 重放或绕过一次性写入授权；
- 接受未确认、被重定向、被替换或未绑定路线的载荷；
- 泄露序列号、凭据、签名地址、二维码数据或 Cookie；
- 把未经验证的电脑端输出当作 Kindle 端成功；
- 超出用户明确授权自动安装或执行内容。

## Operational safety / 操作安全

KJA is designed to fail closed, but it cannot make an unofficial device
modification risk-free. Keep the Kindle offline before route review, make a
verified computer-visible backup, stop when the exact model or firmware is
unknown, and do not run `--apply` outside the state machine.

KJA 的目标是遇到不确定就停止，但它无法让非官方设备修改变得零风险。路线复核前
保持 Kindle 离线，先创建并校验电脑可见备份，型号或固件不精确时停止，也不要绕过
状态机直接使用 `--apply`。

## Disclosure / 披露

The maintainer will acknowledge a complete report when practical, investigate
without asking the reporter to risk a physical device unnecessarily, prepare a
fix and regression test, and coordinate public disclosure after users have a
safe upgrade path. No fixed response-time promise is made for this volunteer
project.

维护者会在可行时确认完整报告，避免要求报告者无必要地冒险操作真机，并在准备好
修复、回归测试和安全升级路径后协调公开披露。本项目由个人业余维护，不承诺固定
响应时限。
