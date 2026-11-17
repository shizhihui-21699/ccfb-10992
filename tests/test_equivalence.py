#!/usr/bin/env python3
"""
test_equivalence.py — 正常功能逐字节等价性 + 长度边界测试。

两部分：
  A. 对一系列【安全长度】(1..63) 报文，原版与补丁版的应答必须逐字节相同，
     且 STATUS 统计在相同输入序列下完全一致 —— 量化证明“其他功能一模一样”。
  B. 边界探测（仅对补丁版，原版在 >63 时会崩溃无法跑完）：
     长度 63/64/65/128/300/511/512 的数据报都必须被安全处理为最多 63 字节，
     进程全程存活、栈哨兵不报警。

用法: python3 test_equivalence.py [原版] [补丁版]
"""
import socket
import subprocess
import sys
import time
from pathlib import Path

DEFAULT_ORIG = Path(__file__).resolve().parent.parent / "vuln_app" / "vuln_udp_server"
DEFAULT_PATCHED = DEFAULT_ORIG.with_suffix(".patched")
SAFE_LEN = 63


def free_port():
    """向内核申请一个空闲 TCP/UDP 端口号后立即释放，供被测服务绑定。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Server:
    def __init__(self, binary):
        self.binary = binary
        self.proc = None
        self.port = None
        self.sock = None

    def start(self):
        self.port = free_port()
        self.proc = subprocess.Popen(
            [str(self.binary), str(self.port)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            line = self.proc.stdout.readline()
            if line.startswith("READY"):
                break
            if self.proc.poll() is not None:
                raise RuntimeError(f"{self.binary} 启动即退出: {self.proc.stderr.read()}")
        else:
            raise RuntimeError(f"{self.binary} 启动失败/等待 READY 超时")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(2.0)

    def send(self, payload: bytes):
        self.sock.sendto(payload, ("127.0.0.1", self.port))
        try:
            data, _ = self.sock.recvfrom(4096)
            return data
        except socket.timeout:
            return None

    def alive(self):
        return self.proc.poll() is None

    def stop(self):
        if self.sock:
            self.sock.close()
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.proc.kill()


def main():
    orig = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_ORIG
    patched = Path(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PATCHED
    failures = 0

    # ---- A. 安全长度下两版逐字节等价 ----
    print("=== A. 安全报文（长度 1..63）两版应答逐字节比对 ===")
    # 用可确定重建的负载，避免两版随机差异（本服务也没有随机源）
    payloads = [b"x" * n for n in (1, 2, 10, 32, 62, 63)]
    payloads += [b"PING\n", b"STATUS\n", b"CMD-abc-123", b"\x01\x02binary"]
    a, b = Server(orig), Server(patched)
    try:
        a.start(); b.start()
        for p in payloads:
            ra, rb = a.send(p), b.send(p)
            same = ra == rb and not (rb and b"stack guard corrupted" in rb)
            print(f"  [{'通过' if same else '失败'}] len={len(p):<3} {p[:12]!r}")
            if not same:
                print(f"         原版={ra!r} 补丁版={rb!r}")
                failures += 1
        # 统计一致性：都跑了相同数量的包
        sa, sb = a.send(b"STATUS\n"), b.send(b"STATUS\n")
        if sa == sb:
            print(f"  [通过] STATUS 统计两版一致: {sa.decode().strip()}")
        else:
            print(f"  [失败] STATUS 不一致: {sa!r} vs {sb!r}")
            failures += 1
    finally:
        a.stop(); b.stop()

    # ---- B. 边界：补丁版对各种超长/临界长度都安全 ----
    print("\n=== B. 长度边界（仅补丁版，验证钳制与存活）===")
    s = Server(patched)
    try:
        s.start()
        for n in (63, 64, 65, 128, 300, 511, 512):
            payload = bytes((i % 26) + 65 for i in range(n))  # A,B,C,...
            reply = s.send(payload)
            time.sleep(0.05)
            # 期望：ECHO: + 恰好 min(n,63) 个负载字节，无告警，进程存活
            expected_body = payload[:SAFE_LEN]
            ok = (
                reply == b"ECHO:" + expected_body
                and s.alive()
                and b"stack guard corrupted" not in (reply or b"")
            )
            print(f"  [{'通过' if ok else '失败'}] 输入 {n:>3} 字节 -> "
                  f"回显负载 {len(reply)-5 if reply else 0:>2} 字节, 存活={s.alive()}")
            if not ok:
                failures += 1
        # 全部攻击后服务仍正常
        ok = s.send(b"PING\n") == b"PONG" and s.alive()
        print(f"  [{'通过' if ok else '失败'}] 全部边界攻击后服务仍正常响应 PING")
        if not ok:
            failures += 1
    finally:
        s.stop()

    print("\n=== 结论 ===")
    if failures == 0:
        print("安全流量两版逐字节等价；所有临界/超长输入在补丁版上均被安全钳制，"
              "进程不崩溃、栈不被破坏。")
        return 0
    print(f"{failures} 项未通过。", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
