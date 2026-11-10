// mremap_decrypt: decrypts the FairPlay-encrypted range of one Mach-O slice with the kernel's mremap_encrypted(),
// without running the app (iOS 8 to 15). Same steps as the Frida agent's decrypt/read in repair_agent.js.
//
//   mremap_decrypt <file> <offset> <cryptoff> <cryptsize> <cryptid> <cpu> <subtype> <out|->
//
// The decrypted bytes (cryptsize of them) go to <out>, or to stdout for "-". Exit status 0 on success; on
// failure a one-line message "<call> failed: <strerror> (errno N)" goes to stderr, like the agent's errors.

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

typedef int (*mremap_encrypted_fn)(void *, size_t, uint32_t, uint32_t, uint32_t);

static int fail(const char *call) {
    int e = errno;
    fprintf(stderr, "%s failed: %s (errno %d)\n", call, strerror(e), e);
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 9) {
        fprintf(stderr, "usage: %s file offset cryptoff cryptsize cryptid cpu subtype out|-\n", argv[0]);
        return 2;
    }
    const char *path = argv[1];
    uint64_t offset = strtoull(argv[2], NULL, 0);
    uint64_t cryptoff = strtoull(argv[3], NULL, 0);
    uint64_t cryptsize = strtoull(argv[4], NULL, 0);
    uint32_t cryptid = (uint32_t)strtoull(argv[5], NULL, 0);
    uint32_t cpu = (uint32_t)strtoull(argv[6], NULL, 0);
    uint32_t subtype = (uint32_t)strtoull(argv[7], NULL, 0);
    const char *out = argv[8];

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

    void *mapped = mmap(NULL, (size_t)length, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, (off_t)aligned);
    if (mapped == MAP_FAILED) {
        int rc = fail("mmap");
        close(fd);
        return rc;
    }
    close(fd);

    if (mremap_encrypted((char *)mapped + delta, (size_t)cryptsize, cryptid, cpu, subtype) != 0) {
        int rc = fail("mremap_encrypted");
        munmap(mapped, (size_t)length);
        return rc;
    }

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
        done += (uint64_t)n;
    }
    if (ofd != STDOUT_FILENO) close(ofd);
    munmap(mapped, (size_t)length);
    return 0;
}
