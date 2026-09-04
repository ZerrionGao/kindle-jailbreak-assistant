# KJA — Kindle Jailbreak Assistant

[![CI](https://github.com/ZerrionGao/kindle-jailbreak-assistant/actions/workflows/tests.yml/badge.svg)](https://github.com/ZerrionGao/kindle-jailbreak-assistant/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB.svg)](https://www.python.org/)

**Stop letting your old Kindle gather dust. One sentence to jailbreak it and
bring it back to life.**

English | [简体中文](README.zh-CN.md)

KJA is a safety-first Agent Skill for identifying a Kindle, checking its
current jailbreak route, backing up visible storage, and installing KOReader.

It started with a dusty Paperwhite 3—the third entry in my “Weekend
Restlessness” series. It is not a jailbreak ZIP with a chatbot taped to it.
When the device or firmware is unclear, KJA does its most important job: it
stops.

> [!WARNING]
> Jailbreaking is unofficial and can lose data, break OTA updates, or brick the
> device. A visible-storage backup is not a NAND image. KJA reduces avoidable
> mistakes; it does not make risky operations risk-free.

## Quick start

### 1. Install the Skill

macOS / Linux:

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

`~/.agents/skills/` also works with runtimes that discover the shared Agent
Skills directory.

### 2. Ask for a read-only check

```text
Use $kindle-jailbreak-assistant to identify my connected Kindle in read-only
mode, explain the risks, and give me one safe next step. Do not write yet.
```

Keep the Kindle offline until the selected upstream method says otherwise.

### 3. CLI sanity check

From the cloned repository:

```bash
python3 kindle-jailbreak-assistant/scripts/kindle_jailbreak.py --json self-test
python3 kindle-jailbreak-assistant/scripts/kindle_jailbreak.py --json probe
```

Use `py -3` on Windows. `--apply` is not a “make it work” button: writes still
need an exact route, verified backup, fresh OTA check, and one-time
authorization.

## What happens under the hood

```text
probe → OTA check → current route → verified backup → one authorized write
      → on-device proof → KOReader visible launch → exact cleanup
```

- Exact model and firmware only; “Paperwhite, about 5.18” is not a match.
- Four current KindleModding sources are fetched, hashed, and cross-checked.
- Unknown routes, redirects, packages, and filesystem identities fail closed.
- Downloads are route-bound; archives are checked before reaching the Kindle.
- Cleanup touches only objects recorded as created by the current session.
- KOReader counts as working only after it visibly opens and loads a local book.

## Compatibility

| Host | Transport | Evidence |
|---|---|---|
| macOS | USB storage | Full Python 3.10/3.13 CI |
| Linux | USB storage + GIO/GVFS MTP | Full CI; physical MTP reports wanted |
| Windows | USB storage + MTP | Windows-specific CI with real `pwsh` |
| macOS | MTP | Stops unless a safe transport already exists |

Jailbreak availability still depends on the exact Kindle and firmware supported
by current [KindleModding](https://kindlemodding.org/) data. See
[COMPATIBILITY.md](COMPATIBILITY.md) before trying a real device.

## Verify

```bash
PYTHONPATH=kindle-jailbreak-assistant/scripts \
  python3 -m unittest discover -s kindle-jailbreak-assistant/tests -v
python3 kindle-jailbreak-assistant/scripts/kindle_jailbreak.py --json self-test
bash -n kindle-jailbreak-assistant/scripts/kindle_mtp_linux.sh
```

Current release: **215 local tests**, plus a green Linux/macOS/Windows ×
Python 3.10/3.13 matrix. Windows runs 78 cross-platform and platform-specific
tests, including real PowerShell MTP checks. CI is evidence; it is not every
Kindle ever made.

## Weekend Restlessness

1. **clawd** — AI-agent model, usage, Git, and status monitor.
2. **8.8-inch macOS side screen** — a driver and themes for abandoned hardware.
3. **KJA** — jailbreak the old PW3, install KOReader, read again.
4. **Q30 Root & Flash Kit** — turn a BlackBerry keyboard into an AI terminal.

If the hardware still has a pulse, it deserves one more interesting weekend.

## More

- [Compatibility](COMPATIBILITY.md)
- [Security](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)
- [v0.1.0 Beta](https://github.com/ZerrionGao/kindle-jailbreak-assistant/releases/tag/v0.1.0)

KJA is an independent project by
[ZerrionGao](https://github.com/ZerrionGao), built on community knowledge from
[KindleModding](https://kindlemodding.org/) and
[KOReader](https://github.com/koreader/koreader). It is not affiliated with
Amazon or those upstream projects.

Released under the [MIT License](LICENSE). Third-party payloads are not bundled.
