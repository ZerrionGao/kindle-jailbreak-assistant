# Release checklist / 发布检查清单

This checklist keeps public claims aligned with fresh evidence.

本清单用于保证公开描述与新鲜证据一致。

## Before tagging / 打标签前

- [ ] Use the current project directory as the public repository root. Keep the
      installable Skill in `kindle-jailbreak-assistant/` and the GitHub-facing
      documents at the repository root.
- [ ] Start from a clean current snapshot or audit the full existing history
      before publishing it.
- [ ] Review `git status` and confirm only intended repository files are
      included.
- [ ] Confirm no `.DS_Store`, `__pycache__`, `*.pyc`, device backup, payload,
      session directory, full serial number, or secret is tracked.
- [ ] Run the full test suite on a clean checkout.
- [ ] Run `self-test`, Python compilation, Linux adapter syntax check, Skill
      validation, and `git diff --check`.
- [ ] Fetch the current KindleModding `models.json`, `jailbreaks.json`, and
      `jailbreakFinder.js`; confirm they still match the strict local parser.
- [ ] Confirm every live method name has a local safety policy or safely falls
      back to guided review.
- [ ] Review the current KOReader Kindle installation page and releases.
- [ ] Update `COMPATIBILITY.md` with the exact host, Python, CI, and physical
      device evidence.
- [ ] Update `CHANGELOG.md` and remove stale claims.
- [ ] Review both READMEs for matching facts and working relative links.

## GitHub repository settings / GitHub 仓库设置

- [ ] Set the description without claiming universal compatibility.
- [ ] Suggested topics: `kindle`, `koreader`, `agent-skill`, `codex`,
      `jailbreak-assistant`, `e-reader`, `python`.
- [ ] Confirm GitHub recognizes the MIT license.
- [ ] Enable Issues and the supplied Issue forms.
- [ ] Enable private vulnerability reporting under Security settings.
- [ ] Enable Actions and require the `tests` workflow before merging.
- [ ] Protect the default branch if outside contributions are accepted.
- [ ] Add a social preview image only if it is original or correctly licensed.

## Tag and release / 标签与发布

```bash
git tag -a v0.1.0 -m "KJA v0.1.0"
git push origin main
git push origin v0.1.0
```

The commands above are examples for the maintainer; do not run them
automatically. Publishing and pushing require an explicit maintainer decision.

以上命令只供维护者手动发布时参考，不得自动执行；推送和公开发布必须由维护者明确
决定。

The release notes should include:

- the Beta label;
- what was tested;
- what was simulated;
- which physical devices were tested;
- the skipped-test count, if non-zero;
- current known limitations;
- the non-affiliation and device-risk warning;
- a link to `COMPATIBILITY.md` and `SECURITY.md`.

Release 说明应包含 Beta 标记、真实测试范围、模拟范围、已测真机、跳过测试数量、
已知限制、独立性与设备风险说明，以及兼容性和安全文档链接。

## After publishing / 发布后

- [ ] Confirm the CI badge and all matrix jobs are green.
- [ ] Confirm a clean install from the public URL is discovered by Codex.
- [ ] Run only `--help`, `self-test`, and a read-only `probe` as the public
      installation smoke test.
- [ ] Update `COMPATIBILITY.md` if CI differs from local evidence.
- [ ] Do not promote the release from Beta until the documented physical
      Windows, Linux, and Kindle coverage exists.
