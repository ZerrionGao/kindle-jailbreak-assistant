# Changelog

All notable changes to KJA are documented here. The project follows
[Semantic Versioning](https://semver.org/) after the first public release.

## [Unreleased]

- No changes yet.

## [0.1.0] - 2026-09-04

### Added

- Agent Skill entrypoint for safe Kindle jailbreak and KOReader guidance.
- Cross-platform read-only detection for macOS, Linux, and Windows.
- Windows MTP and Linux GIO/GVFS MTP adapters.
- Dynamic route review against four current KindleModding sources.
- Strict model, firmware, source, redirect, and method-policy validation.
- Verified computer-visible storage backup with resume support.
- Route-bound payload downloads, archive safety checks, and write verification.
- One-time, operation-specific write authorization and fresh OTA gates.
- Method-specific jailbreak evidence and visible KOReader launch checkpoints.
- Exact cleanup based on a session-owned creation journal.
- 215 automated tests plus an offline four-part CLI self-test.
- English and Simplified Chinese public documentation, CI, and Issue forms.

### Known limitations

- Physical Windows MTP and Linux GIO/GVFS MTP validation is still pending.
- macOS MTP has no bundled write backend and stops without a safe existing
  transport.
- Physical-device coverage is not broad enough for a universal compatibility
  claim.
- Upstream route and installation pages can change; unknown changes stop
  automatic writes until reviewed.

[Unreleased]: https://github.com/ZerrionGao/kindle-jailbreak-assistant/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ZerrionGao/kindle-jailbreak-assistant/releases/tag/v0.1.0
