#!/usr/bin/env python3
"""
test_overflow.py — 缓冲区溢出触发与热补丁有效性回归测试。

做法：分别启动【原版】和【补丁版】UDP 服务，发送完全相同的报文序列，
对比两者在正常流量和攻击流量下的行为。

攻击报文：300 字节 UDP 数据报，而服务端栈缓冲区只有 64 字节，
原版 recvfrom 的长度参数是 512 且无检查 → 栈溢出；
补丁版在 recvfrom 前被钳制到 63（为 NUL 终止符留位）→ 超长部分被内核丢弃，
栈不被破坏，字符串也不会失去终止符。

通过条件：
  1. 两版在正常报文（PING/普通 ECHO/STATUS）下应答逐字节一致；
  2. 原版在 300 字节攻击下出现栈哨兵破坏（ERROR 应答）或进程崩溃；
  3. 补丁版在同样攻击下：只回显前 63 字节、无 ERROR、进程存活，
     且攻击后服务仍能正常响应（证明没有遗留破坏）。

用法: python3 test_overflow.py [原版路径] [补丁版路径]
"""
import socket
import subprocess
import sys
import time
from pathlib import Path

DEFAULT_ORIG = Path(__file__).resolve().parent.parent / "vuln_app" / "vuln_udp_server"
DEFAULT_PATCHED = DEFAULT_ORIG.with_suffix(".patched")
OVERFLOW_LEN = 300          # > 64 字节缓冲区，< 512 的失控长度参数
BUF_SIZE = 64               # 服务端栈缓冲区容量
# C 字符串缓冲必须为 NUL 终止符留 1 字节，因此安全接收长度是 63
# （hotpatch --cap 63）。这也是补丁钳制语义正确、而非单纯“写满 64”的关键。
SAFE_LEN = BUF_SIZE - 1
WAIT_READY_TIMEOUT = 5.0


def free_port():
    """向内核申请一个空闲 UDP 端口号后立即释放，供被测服务绑定。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Server:
    def __init__(self, binary: Path, label: str):
        self.binary = binary
        self.label = label
        self.proc = None
        self.port = None
        self.sock = None

    def start(self):
        self.port = free_port()
        self.proc = subprocess.Popen(
            [str(self.binary), str(self.port)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        deadline = time.monotonic() + WAIT_READY_TIMEOUT
        ready = False
        while time.monotonic() < deadline:
            line = self.proc.stdout.readline()
            if line.startswith("READY"):
                ready = True
                break
            if self.proc.poll() is not None:
                raise RuntimeError(f"{self.label} 启动即退出: {self.proc.stderr.read()}")
        if not ready:
            raise RuntimeError(f"{self.label} 等待 READY 超时")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(2.0)

    def send(self, payload: bytes):
        self.sock.sendto(payload, ("127.0.0.1", self.port))
        try:
            data, _ = self.sock.recvfrom(2048)
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


def expect(cond, msg):
    mark = "  [通过] " if cond else "  [失败] "
    print(mark + msg)
    return cond


def run_phase(binary: Path, label: str, is_patched: bool):
    print(f"\n=== 阶段：{label}（{binary.name}）===")
    srv = Server(binary, label)
    results = []
    try:
        srv.start()
        print(f"  服务已启动，端口 {srv.port}")

        # --- 正常流量：两版必须逐字节一致 ---
        pong = srv.send(b"PING\n")
        results.append(expect(pong == b"PONG", f"PING -> PONG（实际 {pong!r}）"))

        echo = srv.send(b"HELLO")
        results.append(expect(echo == b"ECHO:HELLO", f"普通报文 -> ECHO:HELLO（实际 {echo!r}）"))

        # --- 攻击流量 ---
        attack = b"A" * OVERFLOW_LEN
        reply = srv.send(attack)

        if is_patched:
            # 补丁版：长度被钳到 63（留 NUL），回显 63 个 A，无栈破坏告警
            want = b"ECHO:" + b"A" * SAFE_LEN
            results.append(expect(
                reply == want,
                f"300 字节攻击被钳制为 {SAFE_LEN} 字节回显（应答长度 {len(reply) if reply else 0}，期望 {len(want)}）",
            ))
            results.append(expect(
                reply is not None and b"stack guard corrupted" not in reply,
                "栈哨兵未被破坏（无 ERROR 告警）",
            ))
            # 给内核一点时间，确认进程没有在返回时崩溃
            time.sleep(0.2)
            results.append(expect(srv.alive(), "攻击后进程仍然存活"))
            # 攻击后继续服务，证明没有遗留破坏
            again = srv.send(b"PING\n")
            results.append(expect(again == b"PONG", "攻击后 PING 仍正常（服务未受影响）"))
            stats = srv.send(b"STATUS\n")
            results.append(expect(
                stats is not None and stats.startswith(b"STATS "),
                f"STATUS 统计正常（{stats!r}）",
            ))
        else:
            # 原版：必然观测到破坏 —— ERROR 应答，或进程直接崩溃
            corrupted = reply is not None and b"stack guard corrupted" in reply
            time.sleep(0.3)
            crashed = not srv.alive()
            results.append(expect(
                corrupted or crashed,
                f"300 字节攻击触发栈溢出（哨兵告警={corrupted}，进程崩溃={crashed}，应答={reply!r}）",
            ))
    finally:
        srv.stop()
    return all(results)


def main():
    orig = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_ORIG
    patched = Path(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PATCHED
    for p in (orig, patched):
        if not p.exists():
            print(f"找不到二进制: {p}", file=sys.stderr)
            return 2

    ok_orig = run_phase(orig, "原版（含漏洞）", is_patched=False)
    ok_patched = run_phase(patched, "补丁版", is_patched=True)

    print("\n=== 总结 ===")
    if ok_orig and ok_patched:
        print("结论：原版可被稳定触发栈溢出；补丁版同样攻击下溢出被阻断，"
              "且正常功能与原版完全一致。")
        return 0
    print("存在未通过项，见上方 [失败]。", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
