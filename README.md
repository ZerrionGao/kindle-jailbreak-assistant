# KJA — Kindle Jailbreak Assistant

[![CI](https://github.com/ZerrionGao/kindle-jailbreak-assistant/actions/workflows/tests.yml/badge.svg)](https://github.com/ZerrionGao/kindle-jailbreak-assistant/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB.svg)](https://www.python.org/)

**Old Kindle. New chapter.**

English | [简体中文](README.zh-CN.md)

KJA is the third entry in my “Weekend Restlessness” diary: **jailbreaking a
Kindle Paperwhite 3 and installing KOReader**.

The Paperwhite 3 had been gathering dust at home. Its hardware was still fine;
its software possibilities were not. After jailbreaking it, installing
[KOReader](https://github.com/koreader/koreader), and adding an optional reading
plugin, the old reader became useful again. KJA turns the safety checks and
host-side work from that journey into a reusable Agent Skill.

KJA is not a jailbreak bundle and not a “one-click flasher.” It is a
fail-closed assistant that identifies the exact device and firmware, checks the
current community-maintained route, backs up computer-visible storage, verifies
downloads, and pauses before every device write that needs consent.

> [!WARNING]
> Kindle jailbreaking is an unofficial modification. It can cause data loss,
> software failure, blocked OTA updates, or—in extreme cases—an unbootable
> device. A computer-visible backup is not a NAND or full-system image. Read the
> current upstream instructions and keep the Kindle offline until the selected
> method says otherwise.

## Why KJA exists

Kindle jailbreak advice ages quickly. A model name such as “Paperwhite” or an
approximate firmware such as “5.18-ish” is not enough to select a safe route.
Current eligibility can depend on the exact variant, full firmware version,
registration or ad state, and whether the host sees USB mass storage or MTP.

KJA keeps those decisions explicit:

```text
read-only probe
  → OTA/offline check
  → current upstream route review
  → verified user-storage backup
  → one-time authorization for one write
  → on-device steps
  → method-specific jailbreak evidence
  → KOReader visible-launch check
  → exact cleanup
```

If an exact route cannot be established, KJA stops. It does not try the nearest
firmware, a forum mirror, or an unknown payload.

## What it can help with

- Detect Kindle USB mass-storage devices on macOS, Linux, and Windows.
- Work with supported Windows MTP and Linux GIO/GVFS MTP transports.
- Resolve device codes and full firmware versions against current
  [KindleModding](https://kindlemodding.org/) data.
- Record the SHA-256 of all four route sources and require explicit review.
- Create and verify a computer-visible user-storage backup.
- Download only a route-bound HTTPS payload and validate archives before copy.
- Resume a session only when the stable device identity still matches.
- Verify method-specific jailbreak evidence instead of trusting a success
  message.
- Guide KOReader package selection from its current official installation page
  and require a real, visible launch.
- Remove only files recorded as created by the current session.

## What it deliberately does not do

- Guarantee that every Kindle or firmware can be jailbroken.
- Bundle, mirror, or relicense jailbreak packages, KOReader, or plugins.
- Guess a model, firmware, success marker, download link, or install package.
- Automatically factory-reset, downgrade, install firmware, change Amazon
  account settings, or install host drivers and MTP dependencies.
- Treat copied files, a QR code, an error dialog, or return to the home screen as
  proof of success.
- Replace the original method maintainers or their current documentation.

See [COMPATIBILITY.md](COMPATIBILITY.md) for the precise support and evidence
matrix.

## Install as a Codex Skill

macOS or Linux:

```bash
git clone https://github.com/ZerrionGao/kindle-jailbreak-assistant.git kja
mkdir -p ~/.codex/skills
cp -R kja/kindle-jailbreak-assistant ~/.codex/skills/kindle-jailbreak-assistant
python3 ~/.codex/skills/kindle-jailbreak-assistant/scripts/kindle_jailbreak.py --help
```

Windows PowerShell:

```powershell
git clone https://github.com/ZerrionGao/kindle-jailbreak-assistant.git kja
New-Item -ItemType Directory -Force "$env:USERPROFILE\.codex\skills" | Out-Null
Copy-Item -Recurse ".\kja\kindle-jailbreak-assistant" "$env:USERPROFILE\.codex\skills\kindle-jailbreak-assistant"
py -3 "$env:USERPROFILE\.codex\skills\kindle-jailbreak-assistant\scripts\kindle_jailbreak.py" --help
```

For agent runtimes that discover the cross-runtime Agent Skills directory, use
`~/.agents/skills/kindle-jailbreak-assistant` as the copy destination instead.

Restart the agent runtime after installation if it does not refresh skills
automatically.

## First safe request

Invoke the skill explicitly:

```text
Use $kindle-jailbreak-assistant to identify my connected Kindle in read-only
mode, explain the risks, and tell me the single safest next step. Do not write
to the device.
```

The first useful CLI commands are also read-only:

```bash
python3 kindle-jailbreak-assistant/scripts/kindle_jailbreak.py --help
python3 kindle-jailbreak-assistant/scripts/kindle_jailbreak.py --json self-test
python3 kindle-jailbreak-assistant/scripts/kindle_jailbreak.py --json probe
```

On Windows, replace `python3` with `py -3`.

Do not add `--apply` merely to “make it work.” A real write requires a
route-bound session, a verified backup, a fresh OTA check, and a one-time
authorization for one named operation.

## Requirements

- Python 3.10 or later; the core implementation uses only the Python standard
  library.
- A data-capable USB cable.
- Enough host storage for a complete copy of computer-visible Kindle storage.
- For Linux MTP: an already installed and working GIO/GVFS environment.
- For Windows MTP: PowerShell and the supported Windows portable-device path.
- For macOS MTP: KJA stops unless a safe, already available transport exists; it
  does not install Homebrew, drivers, or an MTP tool on its own.

## Verification

From the repository root:

```bash
PYTHONPATH=kindle-jailbreak-assistant/scripts python3 -m unittest discover -s kindle-jailbreak-assistant/tests -v
python3 kindle-jailbreak-assistant/scripts/kindle_jailbreak.py --json self-test
python3 -m compileall -q kindle-jailbreak-assistant/scripts
bash -n kindle-jailbreak-assistant/scripts/kindle_mtp_linux.sh
```

The initial public release contains 212 passing automated tests on the author's
macOS/Python 3.11 environment. Five Windows PowerShell tests are skipped locally
when `pwsh` is unavailable. GitHub Actions is configured to run the suite on
Linux, macOS, and Windows; its first public result remains pending until the
repository is published. Simulation and CI are not substitutes for testing
every physical Kindle.

## Repository map

```text
README.md / LICENSE      Repository introduction and license
.github/                 CI, Issue forms, and pull request template
kindle-jailbreak-assistant/
├── SKILL.md             Agent-facing workflow and safety gates
├── agents/              Codex UI metadata
├── references/          Safety, routing, device-step, and recovery guidance
├── scripts/             CLI and host transport adapters
└── tests/               Offline unit and integration tests
```

The tests are intentionally published. They are not required during ordinary
Skill use, but they are required for CI, safety regression checks, and
reproducible contributions.

## Reporting problems

Before filing a device problem, read [COMPATIBILITY.md](COMPATIBILITY.md) and
include the host OS, Python version, Kindle model or redacted device code, exact
firmware, transport, subcommand, exit code, and sanitized output. Never post a
full serial number, account information, QR-login data, cookies, signed URLs, or
an entire session directory.

Security issues follow [SECURITY.md](SECURITY.md). Contributions follow
[CONTRIBUTING.md](CONTRIBUTING.md).

## The “Weekend Restlessness” series

1. **clawd** — a small desk monitor for AI-agent model, usage, Git, and working
   state.
2. **8.8-inch macOS system display** — a macOS driver and custom themes for a
   Windows-only CPU/GPU/network/disk/temperature side screen.
3. **KJA** — jailbreak a dusty Kindle Paperwhite 3, install KOReader, and give
   old hardware a new job.
4. **Q30 Root & Flash Kit** — turn a BlackBerry Q30 and its excellent keyboard
   into a pocket terminal for monitoring and commanding AI coding sessions.

The common theme is simple: if the hardware still has a pulse, it deserves one
more interesting weekend.

## Credits and independence

KJA relies on current information maintained by
[KindleModding](https://kindlemodding.org/) and installation guidance and
releases from [KOReader](https://github.com/koreader/koreader). Please support
and credit those upstream communities.

KJA is an independent project by
[ZerrionGao](https://github.com/ZerrionGao). It is not affiliated with,
authorized by, or supported by Amazon, KindleModding, KOReader, or plugin
authors. “Kindle” is a trademark of its respective owner.

## License

KJA's original code and documentation are released under the [MIT
License](LICENSE). Third-party projects and any payloads they publish retain
their own licenses; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
