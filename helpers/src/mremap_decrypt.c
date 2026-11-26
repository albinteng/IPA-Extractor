// mremap_decrypt: decrypts the FairPlay-encrypted range of one Mach-O slice with the kernel's mremap_encrypted(),
// without running the app. Same steps as the Frida agent's decrypt/read in repair_agent.js.
//
//   mremap_decrypt <file> <offset> <cryptoff> <cryptsize> <cryptid> <cpu> <subtype> <out|->
//
// iOS 16 and later refuse the old way (a read-execute mapping asked to decrypt with cryptid 1). They accept a
// read-only mapping with CRYPTID_MODEL_ENCRYPTION (2), which the kernel hands to the same FairPlay decrypter, so
// that is what is used from Darwin 22 (iOS 16) on.
//
// The decrypted bytes (cryptsize of them) go to <out>, or to stdout for "-". Exit status 0 on success; on
// failure a one-line message "<call> failed: <strerror> (errno N)" goes to stderr, like the agent's errors.

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <unistd.h>

typedef int (*mremap_encrypted_fn)(void *, size_t, uint32_t, uint32_t, uint32_t);

#define CRYPTID_MODEL_ENCRYPTION 2u
#define TIMEOUT_SECONDS 300     // the tool gives up after 600

// Reading the mapping after mremap_encrypted() can fault (SIGBUS) when a page cannot be decrypted. Say what happened
// instead of leaving the tool with only an exit status. The alarm cannot end a thread that is waiting inside the
// kernel (state U): when a 4 KB block cannot be decrypted, the kernel retries the page-in until it gives up by itself
// (about 4.5 minutes on iOS 16.1.2). That is why a range that does not start on a page boundary is refused before the
// kernel is asked on iOS 16 and later: the blocks in front of it in the same page cannot be decrypted.
static void on_signal(int sig) {
    const char *text = sig == SIGALRM ? "timed out: the kernel did not answer in 300 seconds\n"
                                      : "reading the decrypted range faulted (SIGBUS/SIGSEGV)\n";
    ssize_t ignored = write(STDERR_FILENO, text, strlen(text));
    (void)ignored;
    _exit(1);
}

static int fail(const char *call) {
    int e = errno;
    fprintf(stderr, "%s failed: %s (errno %d)\n", call, strerror(e), e);
    return 1;
}

// 1 when at least one byte of the mapped range differs from the file's own bytes, 0 when none does, -1 when the file
// cannot be read for the comparison (errno is set).
static int changed(int fd, const char *data, uint64_t start, uint64_t size) {
    static char original[1u << 16];
    for (uint64_t done = 0; done < size; ) {
        size_t chunk = size - done > sizeof(original) ? sizeof(original) : (size_t)(size - done);
        ssize_t n = pread(fd, original, chunk, (off_t)(start + done));
        if (n < 0 && errno == EINTR) continue;
        if (n == 0) errno = EIO;
        if (n <= 0) return -1;
        if (memcmp(original, data + done, (size_t)n) != 0) return 1;
        done += (uint64_t)n;
    }
    return 0;
}

// True from Darwin 22 (iOS 16 / macOS 13), the first that refuses the executable mapping.
static int model_from_darwin_22(void) {
    struct utsname u;
    return uname(&u) == 0 && strcmp(u.sysname, "Darwin") == 0 && atoi(u.release) >= 22;
}

int main(int argc, char **argv) {
    if (argc != 9) {
        fprintf(stderr, "usage: %s file offset cryptoff cryptsize cryptid cpu subtype out|-\n", argv[0]);
        return 2;
    }
    int model = model_from_darwin_22();
    const char *path = argv[1];
    uint64_t offset = strtoull(argv[2], NULL, 0);
    uint64_t cryptoff = strtoull(argv[3], NULL, 0);
    uint64_t cryptsize = strtoull(argv[4], NULL, 0);
    uint32_t cryptid = (uint32_t)strtoull(argv[5], NULL, 0);
    uint32_t cpu = (uint32_t)strtoull(argv[6], NULL, 0);
    uint32_t subtype = (uint32_t)strtoull(argv[7], NULL, 0);
    const char *out = argv[8];

    signal(SIGBUS, on_signal);
    signal(SIGSEGV, on_signal);
    signal(SIGALRM, on_signal);
    alarm(TIMEOUT_SECONDS);

    mremap_encrypted_fn mremap_encrypted = (mremap_encrypted_fn)dlsym(RTLD_DEFAULT, "mremap_encrypted");
    if (!mremap_encrypted) {
        fprintf(stderr, "mremap_encrypted not found\n");
        return 1;
    }

    int fd = open(path, O_RDONLY);
    if (fd < 0) return fail("open");

    uint64_t page = (uint64_t)getpagesize();
    uint64_t start = offset + cryptoff;
    uint64_t aligned = start - (start % page);
    uint64_t delta = start - aligned;
    uint64_t length = cryptsize + delta;

    if (delta != 0) {
        // The kernel takes only a page-aligned address (it answers EINVAL otherwise), so a range that starts inside a
        // page cannot be decrypted: say so without asking.
        fprintf(stderr, "mremap_encrypted failed: the range starts at 0x%llx, which is not on a %llu-byte page boundary (errno 22)\n",
                (unsigned long long)start, (unsigned long long)page);
        close(fd);
        return 1;
    }

    void *mapped = mmap(NULL, (size_t)length, model ? PROT_READ : (PROT_READ | PROT_EXEC), MAP_PRIVATE, fd, (off_t)aligned);
    if (mapped == MAP_FAILED) {
        int rc = fail("mmap");
        close(fd);
        return rc;
    }

    int status = mremap_encrypted((char *)mapped + delta, (size_t)cryptsize, model ? CRYPTID_MODEL_ENCRYPTION : cryptid, cpu, subtype);
    if (status != 0) {
        int rc = fail("mremap_encrypted");
        munmap(mapped, (size_t)length);
        close(fd);
        return rc;
    }

    // A zero status alone proves nothing: the decrypted range must differ from the file's bytes. (Encrypted
    // text never equals its plain text, so no change means the kernel did not decrypt.)
    int differs = model ? changed(fd, (const char *)mapped + delta, start, cryptsize) : 1;
    if (differs < 0) {
        int rc = fail("pread");
        munmap(mapped, (size_t)length);
        close(fd);
        return rc;
    }
    if (!differs) {
        fprintf(stderr, "mremap_encrypted failed: returned success but the bytes did not change (errno 0)\n");
        munmap(mapped, (size_t)length);
        close(fd);
        return 1;
    }
    close(fd);

    int ofd = strcmp(out, "-") == 0 ? STDOUT_FILENO : open(out, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (ofd < 0) {
        int rc = fail("open output");
        munmap(mapped, (size_t)length);
        return rc;
    }
    const char *data = (const char *)mapped + delta;
    uint64_t done = 0;
    while (done < cryptsize) {
        size_t chunk = cryptsize - done > (1u << 20) ? (1u << 20) : (size_t)(cryptsize - done);
        ssize_t n = write(ofd, data + done, chunk);
        if (n < 0) {
            if (errno == EINTR) continue;
            int rc = fail("write");
            munmap(mapped, (size_t)length);
            return rc;
        }
        if (n == 0) {   // a write that takes nothing would loop for ever
            errno = EIO;
            int rc = fail("write");
            munmap(mapped, (size_t)length);
            return rc;
        }
        done += (uint64_t)n;
    }
    if (ofd != STDOUT_FILENO) close(ofd);
    munmap(mapped, (size_t)length);
    return 0;
}
