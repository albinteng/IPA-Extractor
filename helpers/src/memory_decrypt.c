// memory_decrypt (see the end of this file for the command line): decrypts an installed app's FairPlay-encrypted executables by letting the system map them
// (as the kernel does for any process) and reading the decrypted code out of a suspended process.
// For iOS 16 and later, where mremap_encrypted() from a helper is refused (see mremap_decrypt.c for iOS 15 and
// earlier).
//
//   memory_decrypt dump [--no-run] [--bundle-id ID] <exec_path> <bundle_root> <out_root>
//
// 1. posix_spawn()s <exec_path> suspended (no code of the app runs) and gets its task port.
// 2. Reads the main executable's decrypted __TEXT range from memory.
// 3. Unless --no-run: resumes the process until dyld has mapped its frameworks, suspends it again and
//    dumps every encrypted image that lies inside <bundle_root>.
// 4. Kills the process. Each decrypted image is written to <out_root>/<path relative to bundle_root> as a
//    copy of the installed file with the range replaced and cryptid set to 0.
//
// stdout, one line per image:  OK|SKIP|FAIL <TAB> <relative path> <TAB> <detail>
// stderr: "# ..." diagnostics (task_for_pid result, timings, errors).

#include <dirent.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach/mach.h>
#include <signal.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef POSIX_SPAWN_START_SUSPENDED
#define POSIX_SPAWN_START_SUSPENDED 0x0080
#endif
#ifndef LC_ENCRYPTION_INFO
#define LC_ENCRYPTION_INFO 0x21
#endif
#ifndef LC_ENCRYPTION_INFO_64
#define LC_ENCRYPTION_INFO_64 0x2C
#endif

// The iOS SDK hides these; they exist in libsystem_kernel at run time.
extern kern_return_t xvm_read(vm_map_t, uint64_t, uint64_t, uint64_t, uint64_t *) __asm("_mach_vm_read_overwrite");
extern kern_return_t xtfp(mach_port_t, int, mach_port_t *) __asm("_task_for_pid");
extern kern_return_t xsuspend(mach_port_t) __asm("_task_suspend");
extern kern_return_t xresume(mach_port_t) __asm("_task_resume");
extern kern_return_t xterminate(mach_port_t) __asm("_task_terminate");
extern pid_t xfork(void) __asm("_fork");
extern int xptrace(int, pid_t, char *, int) __asm("_ptrace");
extern char **environ;
#define PT_TRACE_ME_ 0
#define PT_KILL_ 8
#define PT_DETACH_ 11

static void note(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fputs("# ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

static uint64_t now_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

// ---------------------------------------------------------------- memory
static int read_mem(task_t task, uint64_t addr, void *buf, uint64_t len) {
    uint64_t done = 0;
    while (done < len) {
        uint64_t chunk = len - done > (1u << 20) ? (1u << 20) : len - done;
        uint64_t got = 0;
        kern_return_t kr = xvm_read(task, addr + done, chunk, (uint64_t)(uintptr_t)buf + done, &got);
        if (kr != KERN_SUCCESS || got == 0) {
            note("vm_read 0x%llx+0x%llx failed kr=%d", (unsigned long long)(addr + done), (unsigned long long)chunk, kr);
            return -1;
        }
        done += got;
    }
    return 0;
}

// ---------------------------------------------------------------- files
static int mkdir_p(const char *path) {
    char tmp[4096];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    return 0;
}

static int copy_file(const char *src, const char *dst) {
    int in = open(src, O_RDONLY);
    if (in < 0) return -1;
    mkdir_p(dst);
    int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (out < 0) {
        close(in);
        return -1;
    }
    static char buf[1 << 20];
    ssize_t n;
    int rc = 0;
    while ((n = read(in, buf, sizeof(buf))) > 0) {
        char *p = buf;
        while (n > 0) {
            ssize_t w = write(out, p, (size_t)n);
            if (w < 0) {
                if (errno == EINTR) continue;
                rc = -1;
                goto done;
            }
            p += w;
            n -= w;
        }
    }
    if (n < 0) rc = -1;
done:
    close(in);
    close(out);
    return rc;
}

static uint32_t be32(uint32_t v) { return __builtin_bswap32(v); }

// Offset of the slice with this cputype/subtype in the file (0 for a thin file).
static int find_slice(int fd, cpu_type_t cpu, cpu_subtype_t sub, uint64_t *slice_off) {
    uint8_t head[4096];
    if (pread(fd, head, sizeof(head), 0) < 32) return -1;
    uint32_t magic = *(uint32_t *)head;
    if (magic == FAT_CIGAM) {
        uint32_t n = be32(((struct fat_header *)head)->nfat_arch);
        struct fat_arch *arch = (struct fat_arch *)(head + sizeof(struct fat_header));
        for (uint32_t i = 0; i < n && (uint8_t *)(arch + i + 1) <= head + sizeof(head); i++) {
            if ((cpu_type_t)be32((uint32_t)arch[i].cputype) == cpu &&
                ((cpu_subtype_t)be32((uint32_t)arch[i].cpusubtype) & 0xffffff) == (sub & 0xffffff)) {
                *slice_off = be32(arch[i].offset);
                return 0;
            }
        }
        return -1;
    }
    if (magic == FAT_CIGAM_64) return -1;
    struct mach_header *mh = (struct mach_header *)head;
    if ((magic == MH_MAGIC || magic == MH_MAGIC_64) && mh->cputype == cpu && (mh->cpusubtype & 0xffffff) == (sub & 0xffffff)) {
        *slice_off = 0;
        return 0;
    }
    return -1;
}

struct crypt {
    uint32_t cryptoff, cryptsize, cryptid;
    uint64_t cryptid_pos; // file offset of the cryptid field
};

static int get_crypt(int fd, uint64_t slice_off, struct crypt *out) {
    uint8_t buf[32768];
    ssize_t got = pread(fd, buf, sizeof(buf), (off_t)slice_off);
    if (got < (ssize_t)sizeof(struct mach_header)) return -1;
    struct mach_header *mh = (struct mach_header *)buf;
    size_t off = mh->magic == MH_MAGIC_64 ? sizeof(struct mach_header_64) : sizeof(struct mach_header);
    for (uint32_t i = 0; i < mh->ncmds && off + sizeof(struct load_command) <= (size_t)got; i++) {
        struct load_command *lc = (struct load_command *)(buf + off);
        if ((lc->cmd == LC_ENCRYPTION_INFO || lc->cmd == LC_ENCRYPTION_INFO_64) && off + 20 <= (size_t)got) {
            struct encryption_info_command *e = (struct encryption_info_command *)lc;
            out->cryptoff = e->cryptoff;
            out->cryptsize = e->cryptsize;
            out->cryptid = e->cryptid;
            out->cryptid_pos = slice_off + off + 16;
            return 0;
        }
        if (lc->cmdsize == 0) break;
        off += lc->cmdsize;
    }
    return 1; // no encryption command
}

// ---------------------------------------------------------------- images
static int g_ranges; // --ranges: write only the decrypted ranges

// Dumps the image mapped at `base` in the task. `rel` is its path relative to the bundle.
static void dump_image(task_t task, uint64_t base, const char *src, const char *rel, const char *out_root) {
    struct mach_header_64 rt;
    if (read_mem(task, base, &rt, sizeof(rt)) != 0) {
        printf("FAIL\t%s\tcannot read the image header\n", rel);
        return;
    }
    if (rt.magic != MH_MAGIC_64 && rt.magic != MH_MAGIC) {
        printf("FAIL\t%s\tnot a Mach-O image in memory\n", rel);
        return;
    }
    int fd = open(src, O_RDONLY);
    if (fd < 0) {
        printf("FAIL\t%s\topen: %s\n", rel, strerror(errno));
        return;
    }
    uint64_t slice_off = 0;
    struct crypt c;
    if (find_slice(fd, rt.cputype, rt.cpusubtype, &slice_off) != 0) {
        printf("FAIL\t%s\tno file slice for cpu 0x%x/%d\n", rel, rt.cputype, rt.cpusubtype & 0xffffff);
        close(fd);
        return;
    }
    int cr = get_crypt(fd, slice_off, &c);
    if (cr != 0 || c.cryptid == 0) {
        printf("SKIP\t%s\t%s\n", rel, cr == 0 ? "cryptid 0" : "no encryption info");
        close(fd);
        return;
    }
    uint8_t *mem = malloc(c.cryptsize);
    uint8_t *enc = malloc(c.cryptsize);
    if (!mem || !enc) {
        printf("FAIL\t%s\tout of memory (0x%x)\n", rel, c.cryptsize);
        free(mem);
        free(enc);
        close(fd);
        return;
    }
    if (read_mem(task, base + c.cryptoff, mem, c.cryptsize) != 0) {
        printf("FAIL\t%s\tcannot read the decrypted range\n", rel);
        goto out;
    }
    if (pread(fd, enc, c.cryptsize, (off_t)(slice_off + c.cryptoff)) != (ssize_t)c.cryptsize) {
        printf("FAIL\t%s\tcannot read the encrypted range from the file\n", rel);
        goto out;
    }
    int nonzero = 0;
    for (uint32_t i = 0; i < c.cryptsize && !nonzero; i++) nonzero = mem[i] != 0;
    if (!nonzero) {
        printf("FAIL\t%s\trange is all zero (not paged in)\n", rel);
        goto out;
    }
    if (memcmp(mem, enc, c.cryptsize) == 0) {
        printf("FAIL\t%s\tmemory still equals the encrypted bytes\n", rel);
        goto out;
    }
    char dst[4096];
    if (g_ranges) {
        // Only the decrypted range, as <out_root>/<rel>.range: no copy of a file that may be hundreds of MB.
        snprintf(dst, sizeof(dst), "%s/%s.range", out_root, rel);
        mkdir_p(dst);
        int rfd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        uint64_t done = 0;
        while (rfd >= 0 && done < c.cryptsize) {
            ssize_t w = write(rfd, mem + done, c.cryptsize - done);
            if (w < 0) {
                if (errno == EINTR) continue;
                break;
            }
            done += (uint64_t)w;
        }
        if (rfd >= 0) close(rfd);
        if (rfd < 0 || done != c.cryptsize) {
            printf("FAIL\t%s\twrite: %s\n", rel, strerror(errno));
            goto out;
        }
        printf("OK\t%s\t%d\t%d\t%u\t%u\n", rel, rt.cputype, rt.cpusubtype & 0xffffff, c.cryptoff, c.cryptsize);
        goto out;
    }
    snprintf(dst, sizeof(dst), "%s/%s", out_root, rel);
    if (copy_file(src, dst) != 0) {
        printf("FAIL\t%s\tcopy: %s\n", rel, strerror(errno));
        goto out;
    }
    int ofd = open(dst, O_WRONLY);
    uint32_t zero = 0;
    if (ofd < 0 || pwrite(ofd, mem, c.cryptsize, (off_t)(slice_off + c.cryptoff)) != (ssize_t)c.cryptsize ||
        pwrite(ofd, &zero, 4, (off_t)c.cryptid_pos) != 4) {
        printf("FAIL\t%s\twrite: %s\n", rel, strerror(errno));
        if (ofd >= 0) close(ofd);
        goto out;
    }
    close(ofd);
    printf("OK\t%s\tcpu 0x%x/%d cryptsize %u\n", rel, rt.cputype, rt.cpusubtype & 0xffffff, c.cryptsize);
out:
    free(mem);
    free(enc);
    close(fd);
    fflush(stdout);
}

static int find_main_base(task_t task, uint64_t *out) {
    vm_address_t addr = 0;
    for (;;) {
        vm_size_t size = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj = MACH_PORT_NULL;
        if (vm_region_64(task, &addr, &size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &cnt, &obj) != KERN_SUCCESS) return -1;
        if (obj != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), obj);
        struct mach_header_64 hdr;
        uint64_t got = 0;
        if (xvm_read(task, addr, sizeof(hdr), (uint64_t)(uintptr_t)&hdr, &got) == KERN_SUCCESS && got == sizeof(hdr) &&
            (hdr.magic == MH_MAGIC_64 || hdr.magic == MH_MAGIC) && hdr.filetype == MH_EXECUTE) {
            *out = addr;
            return 0;
        }
        if (size == 0 || addr + size <= addr) return -1;
        addr += size;
    }
}

// dyld's list of loaded images in the task. Returns the count (0 when dyld has not published any yet).
static uint32_t list_images(task_t task, struct dyld_image_info **infos, char **paths) {
    struct task_dyld_info tdi;
    mach_msg_type_number_t cnt = TASK_DYLD_INFO_COUNT;
    if (task_info(task, TASK_DYLD_INFO, (task_info_t)&tdi, &cnt) != KERN_SUCCESS || !tdi.all_image_info_addr) return 0;
    struct dyld_all_image_infos aii;
    uint64_t got = 0;
    if (xvm_read(task, tdi.all_image_info_addr, sizeof(aii), (uint64_t)(uintptr_t)&aii, &got) != KERN_SUCCESS) return 0;
    if (aii.infoArrayCount == 0 || !aii.infoArray) return 0;
    uint32_t n = aii.infoArrayCount;
    struct dyld_image_info *arr = calloc(n, sizeof(*arr));
    char *pool = calloc(n, 1024);
    if (!arr || !pool) return 0;
    if (xvm_read(task, (uint64_t)(uintptr_t)aii.infoArray, sizeof(*arr) * n, (uint64_t)(uintptr_t)arr, &got) != KERN_SUCCESS) {
        free(arr);
        free(pool);
        return 0;
    }
    for (uint32_t i = 0; i < n; i++) {
        char *slot = pool + (size_t)i * 1024;
        uint64_t g = 0;
        if (arr[i].imageFilePath && xvm_read(task, (uint64_t)(uintptr_t)arr[i].imageFilePath, 1023, (uint64_t)(uintptr_t)slot, &g) == KERN_SUCCESS) {
            slot[1023] = 0;
            arr[i].imageFilePath = slot;
        } else {
            arr[i].imageFilePath = NULL;
        }
    }
    *infos = arr;
    *paths = pool;
    return n;
}

static const char *relative_to(const char *path, const char *root) {
    size_t n = strlen(root);
    if (strncmp(path, root, n) == 0 && path[n] == '/') return path + n + 1;
    if (strncmp(path, "/private", 8) == 0 && strncmp(path + 8, root, n) == 0 && path[8 + n] == '/') return path + 8 + n + 1;
    return NULL;
}


// ---------------------------------------------------------------- probe
extern int xcsops(pid_t, unsigned int, void *, size_t) __asm("_csops");
extern int xlistpids(uint32_t, uint32_t, void *, int) __asm("_proc_listpids");
extern int xpidpath(int, void *, uint32_t) __asm("_proc_pidpath");

static void probe_tfp(const char *label, pid_t pid) {
    task_t t = MACH_PORT_NULL;
    kern_return_t kr = xtfp(mach_task_self(), pid, &t);
    note("tfp %-22s pid %d -> %d %s", label, pid, kr, kr == KERN_SUCCESS ? "OK" : mach_error_string(kr));
    if (kr == KERN_SUCCESS) mach_port_deallocate(mach_task_self(), t);
}

static void run_probe(const char *spawn_path) {
    uint32_t flags = 0;
    int r = xcsops(getpid(), 0, &flags, sizeof(flags));
    note("self pid %d uid %d csflags 0x%x (csops rc %d)", getpid(), getuid(), flags, r);
    char *blob = calloc(1, 65536);
    r = xcsops(getpid(), 7, blob, 65536); // CS_OPS_ENTITLEMENTS_BLOB
    note("entitlements blob rc %d: task_for_pid-allow %s, platform-application %s, cs.debugger %s", r,
         strstr(blob + 8, "task_for_pid-allow") ? "yes" : "no", strstr(blob + 8, "platform-application") ? "yes" : "no",
         strstr(blob + 8, "private.cs.debugger") ? "yes" : "no");
    free(blob);
    probe_tfp("self", getpid());
    probe_tfp("launchd", 1);
    // SpringBoard and a few more processes by name
    int n = xlistpids(1 /*PROC_ALL_PIDS*/, 0, NULL, 0);
    pid_t *pids = calloc(n / sizeof(pid_t) + 16, sizeof(pid_t));
    n = xlistpids(1, 0, pids, n + 64 * (int)sizeof(pid_t));
    for (int i = 0; i < n / (int)sizeof(pid_t); i++) {
        char p[4096] = {0};
        if (xpidpath(pids[i], p, sizeof(p)) > 0 && (strstr(p, "SpringBoard.app/SpringBoard") || strstr(p, "/frida-server") || strstr(p, "/mediaserverd")))
            probe_tfp(strrchr(p, '/') + 1, pids[i]);
    }
    free(pids);
    // host priv port
    mach_port_t hp = MACH_PORT_NULL;
    kern_return_t kr = host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 2, &hp);
    note("host_priv special port 2 -> %d %s", kr, kr == KERN_SUCCESS ? "OK" : mach_error_string(kr));
    // spawned children: platform tool suspended / running, then the target
    const char *paths[] = {"/usr/bin/sleep", spawn_path};
    for (int k = 0; k < 2; k++) {
        for (int susp = 1; susp >= 0; susp--) {
            posix_spawnattr_t attr;
            posix_spawnattr_init(&attr);
            if (susp) posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED);
            char *av[] = {(char *)paths[k], "30", NULL};
            pid_t pid = 0;
            int rc = posix_spawn(&pid, paths[k], NULL, &attr, av, environ);
            if (rc != 0) {
                note("spawn %s %s failed: %s", paths[k], susp ? "suspended" : "running", strerror(rc));
                continue;
            }
            char label[64];
            snprintf(label, sizeof(label), "%s %s", k ? "app" : "sleep", susp ? "susp" : "run");
            probe_tfp(label, pid);
            kill(pid, SIGKILL);
            waitpid(pid, NULL, 0);
        }
    }
}

// ---------------------------------------------------------------- SpringBoard launch
#include <dlfcn.h>
static pid_t find_pid_by_path(const char *exec_path, int budget_ms) {
    const char *want = strncmp(exec_path, "/private", 8) == 0 ? exec_path + 8 : exec_path;
    for (int waited = 0; waited < budget_ms; waited += 20) {
        int n = xlistpids(1, 0, NULL, 0);
        if (n > 0) {
            pid_t *pids = calloc(n / sizeof(pid_t) + 64, sizeof(pid_t));
            int got = xlistpids(1, 0, pids, n + 32 * (int)sizeof(pid_t)) / (int)sizeof(pid_t);
            for (int i = 0; i < got; i++) {
                char p[4096] = {0};
                if (xpidpath(pids[i], p, sizeof(p)) > 0) {
                    const char *q = strncmp(p, "/private", 8) == 0 ? p + 8 : p;
                    if (strcmp(q, want) == 0) {
                        pid_t r = pids[i];
                        free(pids);
                        return r;
                    }
                }
            }
            free(pids);
        }
        usleep(20000);
    }
    return 0;
}

static void *sbs_thread(void *p) {
    struct job_s {
        int (*launch)(const void *, unsigned char);
        const void *bid;
        volatile int done, rc;
    } *j = p;
    j->rc = j->launch(j->bid, 1);
    j->done = 1;
    return NULL;
}

// Calls SBSLaunchApplicationWithIdentifier in a child process: on some systems loading SpringBoardServices or the
// call itself never returns, and the helper must be able to give up and use another way to start the app.
static int sbs_launch_child(const char *bundle_id) {
    pid_t ch = xfork();
    if (ch < 0) return -1;
    if (ch == 0) {
        void *cf = dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", RTLD_NOW);
        void *sbs = dlopen("/System/Library/PrivateFrameworks/SpringBoardServices.framework/SpringBoardServices", RTLD_NOW);
        if (!cf || !sbs) _exit(10);
        const void *(*mkstr)(void *, const char *, unsigned) = dlsym(cf, "CFStringCreateWithCString");
        int (*launch)(const void *, unsigned char) = dlsym(sbs, "SBSLaunchApplicationWithIdentifier");
        if (!mkstr || !launch) _exit(11);
        int rc = launch(mkstr(NULL, bundle_id, 0x08000100), 1);
        _exit(rc == 0 ? 0 : 12);
    }
    int status = 0;
    for (int waited = 0; waited < 8000; waited += 20) {
        pid_t w = waitpid(ch, &status, WNOHANG);
        if (w == ch) return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + (WIFSIGNALED(status) ? WTERMSIG(status) : 0);
        usleep(20000);
    }
    note("SBS: the launch call did not return within 8 s; stopping it");
    kill(ch, SIGTERM);
    for (int i = 0; i < 100; i++) {
        if (waitpid(ch, &status, WNOHANG) == ch) return -2;
        usleep(20000);
    }
    kill(ch, SIGKILL);
    waitpid(ch, &status, 0);
    return -2;
}

static int sbs_spawn(const char *bundle_id, const char *exec_path, pid_t *out_pid, task_t *out_task) {
    int lr = sbs_launch_child(bundle_id);
    note("SBS: launch of %s (suspended) -> %d", bundle_id, lr);
    if (lr != 0) return 0;
    pid_t pid = find_pid_by_path(exec_path, 3000);
    if (!pid) {
        note("SBS: no process with path %s appeared", exec_path);
        return 0;
    }
    task_t t = MACH_PORT_NULL;
    kern_return_t kr = xtfp(mach_task_self(), pid, &t);
    note("SBS: pid %d, task_for_pid = %d %s", pid, kr, kr == KERN_SUCCESS ? "ok" : mach_error_string(kr));
    if (kr != KERN_SUCCESS) {
        kill(pid, SIGKILL);
        return 0;
    }
    xsuspend(t);
    *out_pid = pid;
    *out_task = t;
    return 1;
}

enum { MODE_PTRACE = 1, MODE_RACE = 2, MODE_SUSPENDED = 3, MODE_SBS = 4 };

// Starts the executable without letting any of its code run if possible. Returns the mode used.
static int spawn_target(const char *bundle_id, const char *exec_path, pid_t *out_pid, task_t *out_task) {
    kern_return_t kr;
    if (bundle_id && sbs_spawn(bundle_id, exec_path, out_pid, out_task)) return MODE_SBS;
    // 1. fork + PT_TRACE_ME + exec: the child stops right after exec, before dyld runs.
    pid_t pid = xfork();
    if (pid == 0) {
        if (xptrace(PT_TRACE_ME_, 0, NULL, 0) != 0) _exit(127);
        int dn = open("/dev/null", O_RDWR);
        if (dn >= 0) {
            dup2(dn, 0);
            dup2(dn, 1);
            dup2(dn, 2);
            close(dn);
        }
        char *av[] = {(char *)exec_path, NULL};
        execve(exec_path, av, environ);
        _exit(127);
    }
    if (pid > 0) {
        int status = 0;
        pid_t w;
        do { w = waitpid(pid, &status, WUNTRACED); } while (w < 0 && errno == EINTR);
        if (w == pid && WIFSTOPPED(status)) {
            task_t t = MACH_PORT_NULL;
            kr = xtfp(mach_task_self(), pid, &t);
            note("fork+PT_TRACE_ME: stopped (signal %d), task_for_pid = %d %s", WSTOPSIG(status), kr,
                 kr == KERN_SUCCESS ? "ok" : mach_error_string(kr));
            if (kr == KERN_SUCCESS) {
                *out_pid = pid;
                *out_task = t;
                return MODE_PTRACE;
            }
        } else {
            note("fork+PT_TRACE_ME: child did not stop (status 0x%x)", status);
        }
        xptrace(PT_KILL_, pid, NULL, 0);
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
    } else {
        note("fork failed: %s", strerror(errno));
    }

    // 2. start it running and stop it as fast as possible
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addopen(&fa, 0, "/dev/null", O_RDWR, 0);
    posix_spawn_file_actions_addopen(&fa, 1, "/dev/null", O_RDWR, 0);
    posix_spawn_file_actions_addopen(&fa, 2, "/dev/null", O_RDWR, 0);
    char *av[] = {(char *)exec_path, NULL};
    int rc = posix_spawn(&pid, exec_path, &fa, NULL, av, environ);
    if (rc == 0) {
        task_t t = MACH_PORT_NULL;
        kr = xtfp(mach_task_self(), pid, &t);
        note("posix_spawn running: task_for_pid = %d", kr);
        if (kr == KERN_SUCCESS) {
            xsuspend(t);
            *out_pid = pid;
            *out_task = t;
            return MODE_RACE;
        }
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
    }

    // 3. suspended spawn, retrying task_for_pid
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED);
    rc = posix_spawn(&pid, exec_path, &fa, &attr, av, environ);
    if (rc == 0) {
        for (int i = 0; i < 50; i++) {
            task_t t = MACH_PORT_NULL;
            kr = xtfp(mach_task_self(), pid, &t);
            if (kr == KERN_SUCCESS) {
                note("posix_spawn suspended: task_for_pid ok after %d tries", i + 1);
                *out_pid = pid;
                *out_task = t;
                return MODE_SUSPENDED;
            }
            usleep(10000);
        }
        note("posix_spawn suspended: task_for_pid kept failing (%d)", kr);
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
    }
    return 0;
}

// ---------------------------------------------------------------- bookkeeping of what was dumped
static char *g_dumped[8192];
static int g_ndumped;

static int was_dumped(const char *rel) {
    for (int i = 0; i < g_ndumped; i++)
        if (strcmp(g_dumped[i], rel) == 0) return 1;
    return 0;
}

static void mark_dumped(const char *rel) {
    if (g_ndumped < 8192) g_dumped[g_ndumped++] = strdup(rel);
}

// Dumps every image dyld lists that lies inside the bundle and was not dumped yet.
static void dump_loaded(task_t task, uint64_t main_base, const char *bundle_root, const char *out_root) {
    struct dyld_image_info *infos = NULL;
    char *paths = NULL;
    uint32_t count = list_images(task, &infos, &paths);
    for (uint32_t i = 0; i < count; i++) {
        if (!infos[i].imageFilePath) continue;
        const char *rel = relative_to(infos[i].imageFilePath, bundle_root);
        if (!rel || !*rel || was_dumped(rel)) continue;
        if (infos[i].imageLoadAddress == NULL) continue;
        if ((uint64_t)(uintptr_t)infos[i].imageLoadAddress == main_base) continue;
        char src[4096];
        snprintf(src, sizeof(src), "%s/%s", bundle_root, rel);
        mark_dumped(rel);
        dump_image(task, (uint64_t)(uintptr_t)infos[i].imageLoadAddress, src, rel, out_root);
    }
    free(infos);
    free(paths);
}

static int is_macho_file(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    uint32_t m = 0;
    ssize_t n = pread(fd, &m, 4, 0);
    close(fd);
    return n == 4 && (m == MH_MAGIC_64 || m == MH_MAGIC || m == FAT_CIGAM || m == FAT_CIGAM_64);
}

// ---------------------------------------------------------------- dlopen injection
// Frameworks the app links are mapped by dyld at launch. Others (loaded later with dlopen) are only mapped, and
// so only decrypted, when something loads them. This makes the app's main thread call dlopen() on each one:
// the thread's state is replaced (pc = dlopen, x0 = path, x1 = RTLD_NOW, lr = an address that faults) and the
// fault is caught on an exception port, which also gives the result (x0) before the next call is set up.
#define SENTINEL 0x41414141ULL

extern kern_return_t xvm_allocate(vm_map_t, uint64_t *, uint64_t, int) __asm("_mach_vm_allocate");
extern kern_return_t xvm_write(vm_map_t, uint64_t, vm_offset_t, mach_msg_type_number_t) __asm("_mach_vm_write");

#pragma pack(4)
typedef struct {
    mach_msg_header_t head;
    mach_msg_body_t body;
    mach_msg_port_descriptor_t thread;
    mach_msg_port_descriptor_t task;
    NDR_record_t ndr;
    exception_type_t exception;
    mach_msg_type_number_t code_count;
    int64_t code[2];
    char trailer[256];
} exc_request_t;
typedef struct {
    mach_msg_header_t head;
    NDR_record_t ndr;
    kern_return_t ret;
} exc_reply_t;
#pragma pack()

static int exc_wait(mach_port_t port, exc_request_t *req, int ms) {
    memset(req, 0, sizeof(*req));
    mach_msg_return_t mr = mach_msg(&req->head, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(*req), port, ms, MACH_PORT_NULL);
    return mr == MACH_MSG_SUCCESS ? 0 : (int)mr;
}

static void exc_reply(exc_request_t *req) {
    exc_reply_t rep;
    memset(&rep, 0, sizeof(rep));
    rep.head.msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(req->head.msgh_bits), 0);
    rep.head.msgh_remote_port = req->head.msgh_remote_port;
    rep.head.msgh_local_port = MACH_PORT_NULL;
    rep.head.msgh_size = sizeof(rep);
    rep.head.msgh_id = req->head.msgh_id + 100;
    rep.ndr = NDR_record;
    rep.ret = KERN_SUCCESS;
    mach_msg(&rep.head, MACH_SEND_MSG, sizeof(rep), 0, MACH_PORT_NULL, 0, MACH_PORT_NULL);
}

// Calls dlopen(path, RTLD_NOW) in the task for every path; results[i] gets the handle (0 = failed).
// Returns how many calls completed.
static int inject_dlopen(task_t task, char **paths, int n, uint64_t *results) {
    void *dl = dlsym(RTLD_DEFAULT, "dlopen");
    if (!dl) {
        note("inject: dlopen not found");
        return 0;
    }
    thread_act_array_t threads;
    mach_msg_type_number_t tcount = 0;
    if (task_threads(task, &threads, &tcount) != KERN_SUCCESS || tcount == 0) {
        note("inject: task_threads failed");
        return 0;
    }
    thread_act_t th = threads[0];
    for (mach_msg_type_number_t i = 1; i < tcount; i++) thread_suspend(threads[i]); // only ours may run
    thread_abort(th);

    arm_thread_state64_t saved;
    mach_msg_type_number_t sc = ARM_THREAD_STATE64_COUNT;
    if (thread_get_state(th, ARM_THREAD_STATE64, (thread_state_t)&saved, &sc) != KERN_SUCCESS) {
        note("inject: thread_get_state failed");
        return 0;
    }
    uint64_t buf = 0;
    uint64_t size = 0x1000 * (uint64_t)((n * 1024 + 0xfff) / 0x1000 + 1);
    if (xvm_allocate(task, &buf, size, 1 /*VM_FLAGS_ANYWHERE*/) != KERN_SUCCESS) {
        note("inject: cannot allocate memory in the task");
        return 0;
    }
    for (int i = 0; i < n; i++) {
        char tmp[1024];
        snprintf(tmp, sizeof(tmp), "%s", paths[i]);
        xvm_write(task, buf + (uint64_t)i * 1024, (vm_offset_t)(uintptr_t)tmp, sizeof(tmp));
    }

    mach_port_t port = MACH_PORT_NULL;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
    kern_return_t kr = task_set_exception_ports(task, EXC_MASK_BAD_ACCESS | EXC_MASK_BAD_INSTRUCTION | EXC_MASK_BREAKPOINT, port,
                                                EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES, ARM_THREAD_STATE64);
    if (kr != KERN_SUCCESS) {
        note("inject: task_set_exception_ports failed %d", kr);
        return 0;
    }

    int done = 0;
    exc_request_t req;
    int have_req = 0;
    for (int i = 0; i < n; i++) {
        arm_thread_state64_t st = saved;
        st.__x[0] = buf + (uint64_t)i * 1024;
        st.__x[1] = 2; // RTLD_NOW
        st.__pc = (uint64_t)(uintptr_t)dl;
        st.__lr = SENTINEL;
        st.__sp = (saved.__sp - 0x4000) & ~0xfULL;
        if (thread_set_state(th, ARM_THREAD_STATE64, (thread_state_t)&st, ARM_THREAD_STATE64_COUNT) != KERN_SUCCESS) {
            note("inject: thread_set_state failed");
            break;
        }
        if (!have_req) {
            task_basic_info_data_t tbi;
            mach_msg_type_number_t tc = TASK_BASIC_INFO_COUNT;
            int suspends = 1;
            if (task_info(task, TASK_BASIC_INFO, (task_info_t)&tbi, &tc) == KERN_SUCCESS) suspends = tbi.suspend_count;
            for (int k = 0; k < (suspends > 0 ? suspends : 1); k++) xresume(task);
        } else {
            exc_reply(&req); // let the thread run from the state set above
        }
        int w = exc_wait(port, &req, 8000);
        if (w != 0) {
            note("inject: no answer for %s (mach_msg %d): the thread is stuck or the app died", paths[i], w);
            break;
        }
        have_req = 1;
        arm_thread_state64_t now;
        mach_msg_type_number_t nc = ARM_THREAD_STATE64_COUNT;
        thread_act_t who = req.thread.name;
        if (thread_get_state(who, ARM_THREAD_STATE64, (thread_state_t)&now, &nc) != KERN_SUCCESS) {
            note("inject: cannot read the thread state after the call");
            break;
        }
        if (now.__pc != SENTINEL) {
            note("inject: unexpected exception %d at pc 0x%llx (code 0x%llx 0x%llx) during %s", req.exception, (unsigned long long)now.__pc,
                 (unsigned long long)req.code[0], (unsigned long long)req.code[1], paths[i]);
            break;
        }
        results[i] = now.__x[0];
        done++;
    }
    xsuspend(task);
    return done;
}

// Frameworks and dylibs in the bundle that are encrypted but not mapped in the task. With `force`, every one.
static int inject_candidates(const char *bundle_root, cpu_type_t cpu, cpu_subtype_t sub, struct dyld_image_info *infos, uint32_t count,
                             int force, char **out, int max) {
    int n = 0;
    const char *dirs[] = {"Frameworks", NULL};
    for (int d = 0; dirs[d]; d++) {
        char dir[4096];
        snprintf(dir, sizeof(dir), "%s/%s", bundle_root, dirs[d]);
        DIR *dp = opendir(dir);
        if (!dp) continue;
        struct dirent *e;
        while ((e = readdir(dp)) && n < max) {
            char cand[4096];
            size_t len = strlen(e->d_name);
            if (len > 10 && strcmp(e->d_name + len - 10, ".framework") == 0) {
                char base[512];
                snprintf(base, sizeof(base), "%.*s", (int)(len - 10), e->d_name);
                snprintf(cand, sizeof(cand), "%s/%s/%s", dir, e->d_name, base);
            } else if (len > 6 && strcmp(e->d_name + len - 6, ".dylib") == 0) {
                snprintf(cand, sizeof(cand), "%s/%s", dir, e->d_name);
            } else {
                continue;
            }
            if (!is_macho_file(cand)) continue;
            int loaded = 0;
            for (uint32_t i = 0; i < count && !loaded; i++) {
                const char *p = infos[i].imageFilePath;
                if (!p) continue;
                const char *a = strncmp(p, "/private", 8) == 0 ? p + 8 : p;
                const char *b = strncmp(cand, "/private", 8) == 0 ? cand + 8 : cand;
                loaded = strcmp(a, b) == 0;
            }
            if (loaded && !force) continue;
            if (!force) {
                int fd = open(cand, O_RDONLY);
                if (fd < 0) continue;
                uint64_t so = 0;
                struct crypt c;
                int ok = find_slice(fd, cpu, sub, &so) == 0 && get_crypt(fd, so, &c) == 0 && c.cryptid != 0;
                close(fd);
                if (!ok) continue;
            }
            out[n++] = strdup(cand);
        }
        closedir(dp);
    }
    return n;
}

// ---------------------------------------------------------------- app extensions
// An extension cannot be started by its identifier, so it is exec'ed in a child that stops right after the exec
// (PT_TRACE_ME): its main executable is mapped, and decrypted on read, before any of its code runs.
static int spawn_ptrace(const char *exec_path, pid_t *out_pid, task_t *out_task) {
    pid_t pid = xfork();
    if (pid == 0) {
        if (xptrace(PT_TRACE_ME_, 0, NULL, 0) != 0) _exit(127);
        int dn = open("/dev/null", O_RDWR);
        if (dn >= 0) {
            dup2(dn, 0);
            dup2(dn, 1);
            dup2(dn, 2);
            close(dn);
        }
        char *av[] = {(char *)exec_path, NULL};
        execve(exec_path, av, environ);
        _exit(127);
    }
    if (pid < 0) return 0;
    int status = 0;
    pid_t w;
    do { w = waitpid(pid, &status, WUNTRACED); } while (w < 0 && errno == EINTR);
    if (w == pid && WIFSTOPPED(status)) {
        task_t t = MACH_PORT_NULL;
        if (xtfp(mach_task_self(), pid, &t) == KERN_SUCCESS) {
            *out_pid = pid;
            *out_task = t;
            return 1;
        }
    }
    xptrace(PT_KILL_, pid, NULL, 0);
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
    return 0;
}

static int find_bundle_exec(const char *bundle, char *out, size_t cap) {
    char base[1024];
    snprintf(base, sizeof(base), "%s", bundle);
    char *slash = strrchr(base, '/');
    const char *name = slash ? slash + 1 : base;
    char stem[512];
    snprintf(stem, sizeof(stem), "%s", name);
    char *dot = strrchr(stem, '.');
    if (dot) *dot = 0;
    snprintf(out, cap, "%s/%s", bundle, stem);
    if (is_macho_file(out)) return 0;
    DIR *dp = opendir(bundle);
    if (!dp) return -1;
    struct dirent *e;
    while ((e = readdir(dp))) {
        if (e->d_name[0] == '.') continue;
        snprintf(out, cap, "%s/%s", bundle, e->d_name);
        struct stat st;
        if (stat(out, &st) == 0 && S_ISREG(st.st_mode) && is_macho_file(out)) {
            closedir(dp);
            return 0;
        }
    }
    closedir(dp);
    return -1;
}

static void dump_extensions(const char *bundle_root, const char *out_root) {
    const char *subdirs[] = {"PlugIns", "Extensions", NULL};
    for (int s = 0; subdirs[s]; s++) {
        char dir[4096];
        snprintf(dir, sizeof(dir), "%s/%s", bundle_root, subdirs[s]);
        DIR *dp = opendir(dir);
        if (!dp) continue;
        struct dirent *e;
        while ((e = readdir(dp))) {
            size_t len = strlen(e->d_name);
            if (len < 7 || strcmp(e->d_name + len - 6, ".appex") != 0) continue;
            char bundle[4096], exe[4096];
            snprintf(bundle, sizeof(bundle), "%s/%s", dir, e->d_name);
            const char *rel = relative_to(bundle, bundle_root);
            if (find_bundle_exec(bundle, exe, sizeof(exe)) != 0) {
                printf("SKIP\t%s\tno executable\n", rel ? rel : e->d_name);
                continue;
            }
            // skip it without starting anything when it is not encrypted
            const char *erel = relative_to(exe, bundle_root);
            if (!erel) continue;
            pid_t pid = 0;
            task_t task = MACH_PORT_NULL;
            if (!spawn_ptrace(exe, &pid, &task)) {
                printf("FAIL\t%s\tcould not start the extension and get its task port\n", erel);
                continue;
            }
            uint64_t base = 0;
            if (find_main_base(task, &base) == 0) {
                mark_dumped(erel);
                dump_image(task, base, exe, erel, out_root);
            } else {
                printf("FAIL\t%s\tmain image not found in the task\n", erel);
            }
            xptrace(PT_KILL_, pid, NULL, 0);
            xterminate(task);
            kill(pid, SIGKILL);
            waitpid(pid, NULL, 0);
        }
        closedir(dp);
    }
}

// ---------------------------------------------------------------- hang diagnosis
// memory_decrypt hang <dylib>: dlopen()s the library in a child process, waits, then prints where every thread of the child
// is stuck (pc and a frame-pointer backtrace, symbolised with dladdr: system libraries sit at the same addresses
// in every process).
static void print_frame(task_t task, uint64_t pc, int depth) {
    Dl_info info;
    memset(&info, 0, sizeof(info));
    const char *img = "?", *sym = "?";
    if (dladdr((void *)(uintptr_t)pc, &info)) {
        if (info.dli_fname) {
            img = strrchr(info.dli_fname, '/') ? strrchr(info.dli_fname, '/') + 1 : info.dli_fname;
        }
        if (info.dli_sname) sym = info.dli_sname;
    }
    printf("  #%d 0x%llx %s`%s +%llu\n", depth, (unsigned long long)pc, img, sym,
           info.dli_saddr ? (unsigned long long)(pc - (uint64_t)(uintptr_t)info.dli_saddr) : 0ULL);
}

static void run_hang(const char *dylib) {
    pid_t ch = xfork();
    if (ch == 0) {
        void *h = dlopen(dylib, RTLD_NOW);
        _exit(h ? 0 : 3);
    }
    if (ch < 0) {
        printf("fork failed\n");
        return;
    }
    int status = 0;
    for (int i = 0; i < 250; i++) {
        if (waitpid(ch, &status, WNOHANG) == ch) {
            printf("dlopen(%s) finished by itself: exit status 0x%x (no hang)\n", dylib, status);
            return;
        }
        usleep(20000);
    }
    printf("dlopen(%s) still running after 5 s: stuck\n", dylib);
    task_t task = MACH_PORT_NULL;
    kern_return_t kr = xtfp(mach_task_self(), ch, &task);
    printf("task_for_pid(child) = %d\n", kr);
    if (kr == KERN_SUCCESS) {
        thread_act_array_t threads;
        mach_msg_type_number_t n = 0;
        if (task_threads(task, &threads, &n) == KERN_SUCCESS) {
            for (mach_msg_type_number_t t = 0; t < n; t++) {
                arm_thread_state64_t st;
                mach_msg_type_number_t sc = ARM_THREAD_STATE64_COUNT;
                if (thread_get_state(threads[t], ARM_THREAD_STATE64, (thread_state_t)&st, &sc) != KERN_SUCCESS) continue;
                printf("thread %u:\n", t);
                print_frame(task, st.__pc, 0);
                print_frame(task, st.__lr, 1);
                uint64_t fp = st.__fp;
                for (int d = 2; d < 40 && fp; d++) {
                    uint64_t frame[2];
                    if (read_mem(task, fp, frame, sizeof(frame)) != 0) break;
                    print_frame(task, frame[1], d);
                    if (frame[0] <= fp) break;
                    fp = frame[0];
                }
            }
        }
    }
    kill(ch, SIGTERM);
    for (int i = 0; i < 100; i++) {
        if (waitpid(ch, &status, WNOHANG) == ch) return;
        usleep(20000);
    }
    kill(ch, SIGKILL);
    waitpid(ch, &status, 0);
}

// ---------------------------------------------------------------- main
static void usage(const char *prog) {
    fprintf(stderr, "usage: %s dump [--no-run] [--no-inject] [--force-inject] [--no-appex] [--ranges] [--bundle-id ID] <exec_path> <bundle_root> <out_root>\n", prog);
}

// Jailbreaks such as Substitute put a library in DYLD_INSERT_LIBRARIES for every process (the SSH session inherits it).
// It would be injected into this helper and into every app started from it, and its tweak loader deadlocks when an
// Objective-C framework is loaded (seen on older iOS). Start again without it.
static void drop_inserted_libraries(char **argv) {
    if (!getenv("DYLD_INSERT_LIBRARIES") || getenv("MEMORY_DECRYPT_CLEAN_ENV")) return;
    unsetenv("DYLD_INSERT_LIBRARIES");
    setenv("MEMORY_DECRYPT_CLEAN_ENV", "1", 1);
    char path[4096];
    uint32_t size = sizeof(path);
    if (_NSGetExecutablePath(path, &size) != 0) snprintf(path, sizeof(path), "%s", argv[0]);
    // The inserter hooks execve() to put itself back into the environment; the system call itself is not hooked.
    extern int syscall(int, ...);
    syscall(59 /*SYS_execve*/, path, argv, environ);
    // exec failed: carry on as we are
}

int main(int argc, char **argv) {
    drop_inserted_libraries(argv);
    int run = 1, inject = 1, force_inject = 0, appex = 1;
    const char *inject_path = NULL;
    if (argc >= 3 && strcmp(argv[1], "hang") == 0) {
        run_hang(argv[2]);
        return 0;
    }
    if (argc >= 3 && strcmp(argv[1], "probe") == 0) {
        run_probe(argv[2]);
        return 0;
    }
    int a = 1;
    if (a < argc && strcmp(argv[a], "dump") == 0) {
        a++;
    } else {
        usage(argv[0]);
        return 2;
    }
    const char *bundle_id = NULL;
    while (a < argc && argv[a][0] == '-' && argv[a][1] == '-') {
        if (strcmp(argv[a], "--no-run") == 0) {
            run = 0;
            a++;
        } else if (strcmp(argv[a], "--no-inject") == 0) {
            inject = 0;
            a++;
        } else if (strcmp(argv[a], "--force-inject") == 0) {
            force_inject = 1;
            a++;
        } else if (strcmp(argv[a], "--ranges") == 0) {
            g_ranges = 1;
            a++;
        } else if (strcmp(argv[a], "--no-appex") == 0) {
            appex = 0;
            a++;
        } else if (strcmp(argv[a], "--inject-path") == 0 && a + 1 < argc) {
            inject_path = argv[a + 1]; // test aid: dlopen this path in the app
            a += 2;
        } else if (strcmp(argv[a], "--bundle-id") == 0 && a + 1 < argc) {
            bundle_id = argv[a + 1];
            a += 2;
        } else {
            break;
        }
    }
    if (argc - a != 3) {
        usage(argv[0]);
        return 2;
    }
    const char *exec_path = argv[a], *bundle_root = argv[a + 1], *out_root = argv[a + 2];

    // 1. start the process without running its code
    pid_t pid = 0;
    task_t task = MACH_PORT_NULL;
    int mode = spawn_target(bundle_id, exec_path, &pid, &task);
    if (!mode) {
        printf("FAIL\t-\tcould not start the app and get its task port\n");
        return 1;
    }
    note("spawned pid %d, mode %s", pid, mode == MODE_SBS ? "sbs" : mode == MODE_PTRACE ? "ptrace-stop" : mode == MODE_RACE ? "race" : "suspended");

    // 2. main executable
    uint64_t main_base = 0;
    int have_main = find_main_base(task, &main_base) == 0;
    note("main image %s at 0x%llx", have_main ? "found" : "NOT found", (unsigned long long)main_base);
    struct mach_header_64 main_hdr;
    memset(&main_hdr, 0, sizeof(main_hdr));
    if (have_main) {
        const char *rel = relative_to(exec_path, bundle_root);
        if (!rel) rel = strrchr(exec_path, '/') + 1;
        mark_dumped(rel);
        dump_image(task, main_base, exec_path, rel, out_root);
        read_mem(task, main_base, &main_hdr, sizeof(main_hdr));
    } else {
        printf("FAIL\t-\tmain image not found in the task\n");
    }

    // 3. frameworks mapped by dyld
    if (run && have_main) {
        if (mode == MODE_PTRACE) {
            // let go of the child: it runs on its own from the exec stop (it is killed soon after this)
            note("PT_DETACH, letting the process run");
            xptrace(PT_DETACH_, pid, (char *)1, 0);
        } else {
            task_basic_info_data_t tbi;
            mach_msg_type_number_t tc = TASK_BASIC_INFO_COUNT;
            int suspends = 1;
            if (task_info(task, TASK_BASIC_INFO, (task_info_t)&tbi, &tc) == KERN_SUCCESS) suspends = tbi.suspend_count;
            note("task suspend count %d, resuming", suspends);
            for (int i = 0; i < (suspends > 0 ? suspends : 1); i++) xresume(task);
        }

        uint64_t t0 = now_ms(), last_change = t0;
        uint32_t last_count = 0;
        while (now_ms() - t0 < 4000) {
            usleep(3000);
            // Peek without stopping: dyld publishes the list as it goes.
            struct task_dyld_info tdi;
            mach_msg_type_number_t cnt = TASK_DYLD_INFO_COUNT;
            kern_return_t tk = task_info(task, TASK_DYLD_INFO, (task_info_t)&tdi, &cnt);
            if (tk != KERN_SUCCESS) {
                int st = 0;
                pid_t wr = waitpid(pid, &st, WNOHANG | WUNTRACED);
                note("task_info failed kr=%d (%s); waitpid=%d status=0x%x signaled=%d sig=%d", tk, mach_error_string(tk), wr, st, WIFSIGNALED(st),
                     WIFSIGNALED(st) ? WTERMSIG(st) : 0);
                break;
            }
            struct dyld_all_image_infos aii;
            uint64_t got = 0;
            if (!tdi.all_image_info_addr || xvm_read(task, tdi.all_image_info_addr, sizeof(aii), (uint64_t)(uintptr_t)&aii, &got) != KERN_SUCCESS) continue;
            if (aii.infoArrayCount != last_count) {
                last_count = aii.infoArrayCount;
                last_change = now_ms();
            }
            if (last_count >= 2 && now_ms() - last_change >= 80) break;
        }
        xsuspend(task);
        note("suspended after %llu ms, dyld lists %u images", (unsigned long long)(now_ms() - t0), last_count);
        dump_loaded(task, main_base, bundle_root, out_root);

        // 4. frameworks the app did not link: have the app load them
        if (inject && mode != MODE_PTRACE) {
            struct dyld_image_info *infos = NULL;
            char *pool = NULL;
            uint32_t count = list_images(task, &infos, &pool);
            char *cands[512];
            int nc = 0;
            if (inject_path) cands[nc++] = strdup(inject_path);
            else nc = inject_candidates(bundle_root, main_hdr.cputype, main_hdr.cpusubtype, infos, count, force_inject, cands, 512);
            if (nc > 0) {
                note("injecting dlopen for %d framework(s)", nc);
                uint64_t *res = calloc(nc, sizeof(uint64_t));
                int done = inject_dlopen(task, cands, nc, res);
                for (int i = 0; i < nc; i++) {
                    const char *rel = relative_to(cands[i], bundle_root);
                    printf("INJECT\t%s\t%s\n", rel ? rel : cands[i], i < done ? (res[i] ? "loaded" : "dlopen returned NULL") : "not run");
                }
                free(res);
                if (inject_path) {
                    struct dyld_image_info *after = NULL;
                    char *pool2 = NULL;
                    uint32_t n2 = list_images(task, &after, &pool2);
                    int before = 0, now_listed = 0;
                    for (uint32_t i = 0; i < count; i++) before |= infos[i].imageFilePath && strstr(infos[i].imageFilePath, strrchr(inject_path, '/') + 1);
                    for (uint32_t i = 0; i < n2; i++) now_listed |= after[i].imageFilePath && strstr(after[i].imageFilePath, strrchr(inject_path, '/') + 1);
                    printf("INJECTCHECK\t%s\tlisted before: %d, after: %d (%u -> %u images)\n", inject_path, before, now_listed, count, n2);
                }
                dump_loaded(task, main_base, bundle_root, out_root);
            } else {
                note("no frameworks to inject");
            }
            free(infos);
            free(pool);
        }
    }

    if (mode == MODE_PTRACE && !run) xptrace(PT_KILL_, pid, NULL, 0);
    xterminate(task);
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);

    // 5. app extensions
    if (appex) dump_extensions(bundle_root, out_root);
    fflush(stdout);
    return 0;
}
