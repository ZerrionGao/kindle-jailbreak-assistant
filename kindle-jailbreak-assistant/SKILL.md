---
name: kindle-jailbreak-assistant
description: Use when a user wants to jailbreak, prepare, recover, or install KOReader on a Kindle, especially when the connected device model, firmware, USB/MTP transport, compatibility, or safe next step must be determined.
---

# Kindle 越狱与 KOReader 助手

用于 Kindle 越狱准备、恢复、路线判断或 KOReader 安装。越狱是非官方修改，可能导致数据丢失、系统异常或 OTA（联网自动升级）受阻，极端情况下设备无法启动。电脑可见存储的备份不是 NAND 或完整系统镜像。不得承诺成功、跳过安全门槛，或把一次设备经验泛化到其他 Kindle。

默认只读，绝不因用户说“直接做”“赶时间”而隐含写入授权。先确认本次解释器：Windows 使用 `py -3`，macOS/Linux 使用 `python3`；每次运行前以相应命令确认 Python 3。没有 Python 3 时说明缺失并停止，不自动安装解释器、驱动、Homebrew、MTP 工具或其他依赖。

运行命令前，必须从运行时提供的 Skill 位置取得**包含本 `SKILL.md` 的目录绝对路径**，并据此得到 `scripts/kindle_jailbreak.py` 的绝对路径。不得假定当前工作目录是仓库父目录、仓库根目录或 Skill 安装目录，也不得要求用户猜路径。下文的 `<KJA_SCRIPT>` 只表示 Agent 已经解析出的真实绝对路径；实际调用工具时必须先替换，不能把尖括号占位符原样交给 shell。

## 催促、信息未知时的首次回应

面对“跳过备份直接刷”“大概是某型号/固件”或要求使用近似版本的请求，首次答复必须先按下列要点逐项明确写出，不能只引用本 Skill 或说“稍后核对”：

首次答复中必须原样保留下列不可省略文字块；不能依赖本 Skill 的其他段落、链接或后续回应补全。其中包含普通写入授权与六项危险动作的第二段必须在固定进度块之前逐字复现：

```text
当前由社区维护的上游权威是 KindleModding。本次必须分别刷新并逐项确认 KindleModding 的 `models.json`、`jailbreaks.json`、`jailbreakFinder.js` 和 finder 选中的具体方法页，并分别记录和确认这四份当次来源的 SHA-256；任一来源、哈希或页面语义未知、变化或冲突时，只能审查，不能写入。

在精确路由、风险说明和电脑可见备份的清单、哈希及逐文件差异均已核验后，仍须由用户对这台已识别设备的下一项普通设备写入给出一次新的明确肯定；不得从初始请求、催促、泛化风险确认、只读备份或较早的探测许可推断该肯定。该一次性授权只覆盖当前方法允许的一个占位、已核验上游载荷复制或精确清理操作，开始写入后即消费。以下每一项都必须在即将执行前，分别取得用户对该精确动作的新的明确肯定；普通写入授权、初始请求、催促或泛化风险确认均不覆盖任何一项：恢复出厂；刷写固件 `.bin`；系统降级；修改 Amazon 地区、付款方式或广告状态；安装主机驱动、Homebrew 或 MTP 依赖；写入非上游或未知载荷。

Windows：USB 大容量存储或受支持的 MTP 适配器；Linux：USB 大容量存储或 GIO/GVFS MTP；macOS：USB 大容量存储，MTP 仅在已有安全工具可用时继续。任何分支缺少安全能力都暂停；不自动安装驱动、Homebrew 或 MTP 依赖，安装前另取明确同意。
```

上列三平台映射是首次答复的逐字引用：必须完整复现，不得概括为“各平台不同”或以链接、Skill 其他段落或后续回应代替。

1. 明确拒绝直刷、跳过备份、所谓最新包和近似固件；没有精确匹配即安全停止。
2. 说明这是非官方修改，可能造成数据、系统和 OTA 风险；电脑可见备份不是 NAND，Skill、脚本作者、维护者和 Agent 不承担设备、账户或数据损失责任，用户可以安全停止并从会话状态或已验证备份恢复。
3. 在联网刷新或写入前保持 Kindle 飞行模式/离线，核对 OTA 阻止状态和残留升级包；没有证据不继续。
4. 先只读获取精确型号/设备码、完整固件、USB 大容量存储或 MTP、可写状态、空间或电量；注册和广告等路线依赖项未知时停在只读阶段，并且一次只问一个可观察问题。
5. 明确按平台和传输分流：Windows 用 USB 大容量存储分支或受支持的 MTP 适配器；Linux 用 USB 大容量存储分支或 GIO/GVFS MTP；macOS 用 USB 大容量存储分支，MTP 仅限已有的安全工具。任何分支没有安全能力都暂停，说明缺少的依赖，并在安装前另取明确授权；绝不自动安装驱动、Homebrew 或 MTP 工具。
6. 按上述不可省略文字块刷新 KindleModding 的四份当次来源并确认 SHA-256；未知方法、页面语义变化或冲突只能审查，不能写入。
7. 说明备份本身只读取设备并写入主机；只有电脑可见备份的清单、哈希和逐文件差异一致后才可取得设备写入授权。在精确路由、风险说明和上述备份证据齐备后，仍须由用户对这台已识别设备和下一项普通设备写入给出一次新的明确肯定。不得从初始请求、催促、泛化风险确认、备份或较早的只读探测许可推断。授权只覆盖一个占位、已核验上游载荷复制或精确清理操作；恢复出厂、固件 `.bin`、降级、Amazon 地区/付款方式/广告状态修改、安装主机依赖、非上游或未知载荷仍须逐项另取明确同意。
8. 说明越狱完成需要当前方法规定的设备端标记或日志，不能以复制、脚本输出、二维码、错误弹窗或主页恢复代替；KOReader 还须由用户在 Kindle 主页实际点击进入阅读器界面，再实际打开一本本地书进入阅读。

首次答复最后必须附上本入口的固定进度格式，并把“是否需要你操作”限制为一个动作；用户未提供足够信息时，该动作只能是一个只读观察或回答，不能要求写入。

## 状态与推进规则

按 `probe → ota-check → RISK_ACK → route → backup → prepare → ota-check → authorize-write → 用户在 Kindle 执行当前方法 → verify → KOReader 待验 → ota-check → authorize-write → cleanup` 推进。确认路线时，方法成功证据只能从 `method-policies.json` 的结构化安全允许列表中选择，并用 `--confirm-method-marker-rule` 或 `--confirm-method-log-rule` 明确记录人工复核结果；不得从自然语言关键词猜规则。生产会话的载荷必须由 `fetch-payload` 从当前上游明确授权的 HTTPS 链接下载，并自动绑定当前路线、四来源摘要、方法页摘要、最终 URL、精确 Release tag、大小和实际字节 SHA-256；不能让调用者用本地文件自签记录。每一步只能在前一步有成功证据时进行；每项设备写入使用一个新的授权并消费当次 OTA 门槛。断线时保留会话并在确认同一稳定设备身份后恢复。

首次运行先查看 CLI 帮助、确认 Python 3 和会话路径，然后使用默认只读命令：

```text
macOS/Linux:
python3 "<KJA_SCRIPT>" --help
python3 "<KJA_SCRIPT>" --json probe

Windows:
py -3 "<KJA_SCRIPT>" --help
py -3 "<KJA_SCRIPT>" --json probe
```

`--apply` 不是默认选项；只读备份不授予后续设备写入。占位、载荷复制和清理仅在 `authorize-write --operation <单一操作> --confirmed-by-user` 已绑定当前设备、路线和四来源摘要，且新的 `ota-check` 通过时才可执行。先运行 `--help` 核对本次子命令参数，不能从此入口猜测载荷、路径或参数。

## 先识别，再路由

在联网、下载或写入前，要求 Kindle 保持飞行模式/离线，并检查 OTA 阻止状态与残留升级包；没有证据就停。只读探测精确型号、完整固件、USB 大容量存储或 MTP、可读写状态、可用空间；电量、注册或广告状态若会影响路线而未知，每次只问一个可观察问题或停止。拒绝“Paperwhite”“5.18 左右”及最接近固件的猜测。

运行时刷新并逐项显式确认四份来源及其当前 SHA-256：`models.json`、`jailbreaks.json`、`jailbreakFinder.js` 和 finder 选出的具体方法页。方法未知、来源哈希未确认、页面语义变化或四者冲突时仅进入引导审查，不能写入。方法页中的成功证据还必须与本地结构化安全允许列表取交集，并由用户明确确认其是正向成功规则；未确认时不得自动从页面措辞推断。特别是 SpringBreak 不使用通用 filler（占位文件）；不保留静态兼容表、发布版本或哈希。

普通设备写入须在精确路由、风险说明和备份清单、哈希、逐文件差异验证齐备后，取得用户对本次已识别设备及下一项单一操作的新明确肯定；不得从初始请求、催促、泛化风险确认、备份或较早的只读探测许可推断。授权仅针对一个占位、已校验上游载荷复制或精确清理操作，并绑定当前设备、路线和四来源摘要；开始写入后即消费。恢复出厂、固件 `.bin`、系统降级、Amazon 地区/付款方式/广告状态修改、安装主机依赖、非上游镜像或未知载荷，均须在即将执行前逐项另取明确肯定；用户拒绝备份或备份的清单、哈希与差异校验不一致时安全停止，绝不写入。

按平台和传输方式分流：Windows 的 USB 大容量存储走 USB 存储分支，MTP 走受支持的 MTP 适配器；Linux 的 USB 大容量存储走 USB 存储分支，MTP 走 GIO/GVFS；macOS 的 USB 大容量存储走 USB 存储分支，MTP 仅在已有安全工具可处理时继续。任何分支没有安全能力时，说明所缺依赖并暂停，安装前另取明确授权；不能自动安装、替换成不明工具或把 MTP 假定为磁盘。每次写入后先同步并安全弹出，再让用户断线。

## 面向用户的更新与完成证据

每次更新固定给出：

```text
当前阶段：<阶段>
正在做什么：<当前一件事>
已完成：<已证实事实>
还差什么：<下一项证据或门槛>
是否需要你操作：<否，或一个动作>
停止是否安全：<结论与恢复入口>
```

只报告已处理文件数、字节数或实际子阶段，不捏造百分比。触屏与插拔一次只要求一个动作，按钮文字、顺序和成功标记均从本次具体方法页实时读取。发生同一根因三次失败且没有新证据时停止，并按安全中止格式报告已修改内容、下一步和恢复入口。

设备端成功必须有当前方法规定的标记、日志或等价证据；文件复制、脚本文字、二维码、错误弹窗或主页恢复都不能单独证明成功。CLI 只能把 KOReader 报为待验：用户必须在 Kindle 主页实际点击并进入 KOReader，确认看到阅读器界面后再实际打开一本本地书进入阅读，才可完成 KOReader 验收。

浏览器引导路线的设备端操作不由主机 CLI 代做或伪造。只有用户明确确认已完成当前方法指定的设备端步骤后，才可记录 `checkpoint --kind exploit-complete --confirmed-by-user`。若当前结构化规则允许 `;log`，还须另行记录 `checkpoint --kind jailbreak-log --confirmed-by-user`；文件标记则使用 `checkpoint --kind jailbreak-marker --evidence-path <路径> --confirmed-by-user`，CLI 会当场确认文件存在并保存大小、SHA-256 与时间，验证时再次回读比对。备份前旧标记和本会话主机暂存的标记一律拒绝。随后仍须用 `verify --kind jailbreak` 核对。KOReader 安装前先用 `confirm-koreader-package` 把当前官方安装页的 SHA-256、设备型号、固件和包族绑定；`fetch-payload --purpose koreader` 只接受该包族的精确 Release 资产。只有用户明确确认已从主页进入 KOReader、打开一本本地书进入阅读后，才可记录 `checkpoint --kind koreader-visible-launch --confirmed-by-user`，再执行精确清理。

## 按需读取的参考

- 风险确认、授权、OTA、备份拒绝或安全停止：`references/safety.md`
- 四来源刷新、三态路线、未知方法及 SpringBreak：`references/routing.md`
- Kindle 屏幕、插拔和安全弹出的一步一动作提示：`references/on-device-checkpoints.md`
- 连接、校验、标记、KPM、KOReader 或觅阅故障：`references/troubleshooting.md`
- 越狱后 KOReader 安装、可见启动验收和按需觅阅：`references/post-jailbreak.md`
- 当前方法自动化边界、占位限制与单独授权：`references/method-policies.json`
