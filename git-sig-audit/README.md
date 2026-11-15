# git-sig-audit

提交签名审计工具:直接读取 git 仓库对象(经 libgit2,不依赖 `git log`),逐个分支统计
未签名 / 签名无效 / 签名人不在白名单的提交,输出可接 CI 的报告。

## 行为对齐 git

签名验证刻意复刻 git 自身的做法:

- **GPG**:把 `gpgsig` 头从 commit 对象中剥离、重建原始 payload,交给
  `gpg --status-fd --verify` 判定(`VALIDSIG` / `BADSIG` / `EXPKEYSIG` / `REVKEYSIG` / `NO_PUBKEY`)。
- **SSH**:用 `ssh-keygen -Y verify -f allowed_signers -I <committer email> -n git`
  校验,payload 走 stdin——与 git 的 ssh 签名验证完全一致。

## 密钥过期/吊销:按提交时间判断

gpg 只报告密钥*现在*是否过期/吊销。工具在此基础上取密钥的过期时间
(`gpg --with-colons --list-keys`)和吊销时间(`--list-sigs` 的 `rev` 记录),
与 committer 时间戳比较:

| 状态 | 含义 |
|---|---|
| `valid` | 签名有效,签名人在白名单 |
| `valid-expired-key` | 提交时密钥仍有效,后来才过期(不算违规) |
| `valid-revoked-key` | 提交时密钥未被吊销,后来才吊销(不算违规) |
| `unsigned` | 无签名 |
| `invalid` | 签名对不上内容,或提交时间晚于密钥过期/吊销时间 |
| `untrusted` | 签名密码学有效,但签名人不在白名单(GPG 指纹 / SSH principal) |
| `unverifiable` | 无法检查(缺公钥、未配置 allowed_signers 等) |

## 合并提交与 rebase

- 合并提交就是多 parent 的普通提交,同样审计,报告中带 `merge: true`。
- 每个本地分支(或 `--all` 的全部 ref)独立 revwalk;rebase 丢弃的旧提交只要还有
  ref 可达就会被审计;同一提交在多个分支上去重,全局汇总只计一次。
- rebase 后的提交签名会被 git 丢弃,自然落入 `unsigned`。

## 用法

```sh
git-sig-audit <repo> \
  --allowed-signers allowed_signers \   # SSH 白名单(git 同格式)
  --gpg-whitelist fingerprints.txt \    # GPG 白名单,每行一个指纹,# 注释
  --format json --output report.json
```

选项:`--all`(审计所有 ref)、`--fail-on unsigned,invalid,untrusted,unverifiable`(默认)、
`--gpg-homedir`(默认取 `$GNUPGHOME`)、`--format text|json`、`--output`。

退出码:`0` 无违规,`1` 有命中 `--fail-on` 的提交,`2` 工具自身错误。

## CI 接入(GitHub Actions 示例)

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }
- run: cargo install --path git-sig-audit   # 或缓存好的二进制
- name: Import trusted GPG keys
  run: gpg --import ci/trusted-keys.asc
- name: Audit commit signatures
  run: |
    git-sig-audit . \
      --allowed-signers ci/allowed_signers \
      --gpg-whitelist ci/gpg_whitelist.txt \
      --format json --output sig-report.json
- uses: actions/upload-artifact@v4
  if: always()
  with: { name: sig-report, path: sig-report.json }
```

## 测试

```sh
scripts/make_test_repo.sh /tmp/sig-audit-test   # 造覆盖全部场景的测试仓库
scripts/check_test_repo.sh                      # 端到端断言(17 项)
```

测试仓库覆盖:未签名、有效 GPG、白名单外签名人、篡改内容、过期密钥(提交时间在
过期前/后)、吊销密钥(提交时间在吊销前/后)、SSH 有效/白名单外、签名与未签名的
合并提交、rebase 后签名丢失的分支。
