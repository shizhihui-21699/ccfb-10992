#!/usr/bin/env bash
# 一键复现：编译漏洞样例 -> 构建 Rust 热补丁工具 -> 打补丁 -> 校验 -> 攻击/回归测试。
# 仅在 arm64 macOS 上验证（依赖 Mach-O 与 codesign）。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

echo "############ 1. 编译含漏洞的样例 UDP 服务（无栈保护）############"
clang -O0 -fno-stack-protector -o vuln_app/vuln_udp_server vuln_app/vuln_udp_server.c

echo "############ 2. 构建热补丁工具（离线、零警告）############"
cargo build --release --offline --manifest-path hotpatch/Cargo.toml
HP="$ROOT/hotpatch/target/release/hotpatch"

echo "############ 3. 无源码静态定位缺陷点 ############"
"$HP" info vuln_app/vuln_udp_server | sed -n '/缺陷点扫描/,$p'

echo "############ 4. 打补丁（输出独立文件，自动重签）############"
"$HP" patch vuln_app/vuln_udp_server -o vuln_app/vuln_udp_server.patched --no-backup

echo "############ 5. 安装完整性校验 ############"
# 给 verify 提供原始参考文件用于逐节区比对
cp -f vuln_app/vuln_udp_server vuln_app/vuln_udp_server.patched.orig
"$HP" verify vuln_app/vuln_udp_server.patched

echo "############ 6. 溢出触发 + 功能回归测试 ############"
python3 -I tests/test_overflow.py
echo
python3 -I tests/test_equivalence.py

echo
echo "全部完成。补丁文件: vuln_app/vuln_udp_server.patched"
