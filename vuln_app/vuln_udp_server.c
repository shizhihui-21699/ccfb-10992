/*
 * vuln_udp_server.c — 模拟车间老设备的控制程序（无源码场景的替身）。
 *
 * 这是一个 UDP 控制服务：
 *   PING\n   -> PONG
 *   STATUS\n -> 运行统计
 *   其它     -> ECHO:<内容>
 *
 * 缺陷（与题目一致）：handle_packet() 里调用 recvfrom 读取网络数据时，
 * 长度参数直接使用远端可控的协议长度 512，而栈上缓冲区只有 64 字节，
 * 没有任何长度检查 —— 经典栈缓冲区溢出。
 *
 * 另外在 __TEXT,__patchcave 段预留一块 0x100 字节的空闲区（全 0，
 * arm64 上是 udf 永远不会执行到），供热补丁工具写入补丁代码。
 * 这模拟老设备固件中常见的“函数对齐填充/废弃函数留下的空闲代码空间”。
 *
 * 编译（模拟老程序的典型宽松编译选项，无栈保护、无 PIE 之外的加固）：
 *   clang -O0 -fno-stack-protector -o vuln_udp_server vuln_udp_server.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BUF_SIZE         64    /* 栈缓冲区大小 */
#define RCV_ALLOC        512   /* recvfrom 声称的长度 —— 远端可控，未与 BUF_SIZE 校验 */
#define STACK_GUARD_MAGIC 0x53464755u  /* "SF GU"，溢出哨兵，方便观察内存破坏 */

/* 运行统计（STATUS 命令用） */
static volatile unsigned long g_packets = 0;
static volatile unsigned long g_pings   = 0;
static volatile unsigned long g_echoes  = 0;

/*
 * 预留补丁洞穴：单独 section，链接进 __TEXT 段，最大执行权限，
 * 与普通代码不相邻、没有任何符号引用它，内容全 0（不可达指令）。
 */
__attribute__((used, section("__TEXT,__patchcave")))
static const unsigned char g_patch_cave[0x100] = {0};

static volatile sig_atomic_t g_stop = 0;
static void on_term(int sig) { (void)sig; g_stop = 1; }

/*
 * 处理一个入站报文。缺陷点就在本函数：
 * recvfrom(..., RCV_ALLOC, ...) 把最多 512 字节写进 64 字节栈缓冲。
 */
static void handle_packet(int sockfd, struct sockaddr_in *cliaddr, socklen_t *clilen)
{
    char buf[BUF_SIZE];
    /* 哨兵紧挨缓冲区；溢出时它先被踩，函数返回前会发现并报警 */
    volatile unsigned int guard = STACK_GUARD_MAGIC;
    ssize_t n;

    memset(buf, 0, sizeof(buf));

    /* *** 缺陷：长度参数 RCV_ALLOC(512) > sizeof(buf)(64)，无检查 *** */
    n = recvfrom(sockfd, buf, RCV_ALLOC, 0,
                 (struct sockaddr *)cliaddr, clilen);
    if (n < 0) {
        perror("recvfrom");
        return;
    }

    g_packets++;

    if (strncmp(buf, "PING", 4) == 0) {
        g_pings++;
        sendto(sockfd, "PONG", 4, 0,
               (struct sockaddr *)cliaddr, *clilen);
    } else if (strncmp(buf, "STATUS", 6) == 0) {
        char reply[128];
        int len = snprintf(reply, sizeof(reply),
                           "STATS packets=%lu pings=%lu echoes=%lu\n",
                           g_packets, g_pings, g_echoes);
        sendto(sockfd, reply, (size_t)len, 0,
               (struct sockaddr *)cliaddr, *clilen);
    } else {
        char reply[BUF_SIZE + 8];
        int len = snprintf(reply, sizeof(reply), "ECHO:%s", buf);
        if (len > (int)sizeof(reply) - 1)
            len = (int)sizeof(reply) - 1;
        g_echoes++;
        sendto(sockfd, reply, (size_t)len, 0,
               (struct sockaddr *)cliaddr, *clilen);
    }

    if (guard != STACK_GUARD_MAGIC) {
        /* 未打补丁时，超长报文会走到这里（若进程还没崩） */
        const char *warn = "ERROR: stack guard corrupted\n";
        sendto(sockfd, warn, strlen(warn), 0,
               (struct sockaddr *)cliaddr, *clilen);
    }
}

int main(int argc, char **argv)
{
    int port = 0;
    int sockfd;
    int on = 1;
    struct sockaddr_in servaddr;

    if (argc >= 2)
        port = atoi(argv[1]);
    if (port <= 0 || port > 65535)
        port = 9000;

    signal(SIGINT, on_term);
    signal(SIGTERM, on_term);
    signal(SIGPIPE, SIG_IGN);

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) { perror("socket"); return 1; }
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family      = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    servaddr.sin_port        = htons((uint16_t)port);

    if (bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("bind");
        close(sockfd);
        return 1;
    }

    /* 把实际端口打印出来，方便测试端拾取（端口 0 由内核分配时） */
    socklen_t alen = sizeof(servaddr);
    getsockname(sockfd, (struct sockaddr *)&servaddr, &alen);
    printf("READY port=%d\n", ntohs(servaddr.sin_port));
    fflush(stdout);

    while (!g_stop) {
        struct sockaddr_in cliaddr;
        socklen_t clilen = sizeof(cliaddr);
        handle_packet(sockfd, &cliaddr, &clilen);
    }

    close(sockfd);
    printf("STOPPED\n");
    return 0;
}
