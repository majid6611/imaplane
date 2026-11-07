// Diagnostic-only LD_PRELOAD shim: counts and times fsync/fdatasync/write/unlink/open per file category.
// It observes the unmodified production binary from outside; it changes no behaviour. Output: $SHIM_OUT (JSON).
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#define MAXFD 4096
enum { C_DB, C_RJ, C_WAL, C_SHM, C_DIR, C_OTHER, C_N };
static const char *NAMES[C_N] = {"db", "rollback_journal", "wal", "shm", "directory", "other"};
static int fdcat[MAXFD];
static struct { long fsyncs, fdatasyncs, writes, opens, unlinks, truncates; double fsync_s, fdatasync_s, write_s; double bytes; } S[C_N];
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;

static double now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec + t.tv_nsec / 1e9; }
static int classify(const char *p, int flags) {
    size_t n = strlen(p);
    if (flags & O_DIRECTORY) return C_DIR;
    if (n >= 8 && !strcmp(p + n - 8, "-journal")) return C_RJ;
    if (n >= 4 && !strcmp(p + n - 4, "-wal")) return C_WAL;
    if (n >= 4 && !strcmp(p + n - 4, "-shm")) return C_SHM;
    if (n >= 15 && !strcmp(p + n - 15, "journal.sqlite3")) return C_DB;
    return C_OTHER;
}
static void track(int fd, const char *p, int flags) {
    if (fd < 0 || fd >= MAXFD) return;
    pthread_mutex_lock(&mu); fdcat[fd] = classify(p, flags) + 1; S[fdcat[fd] - 1].opens++; pthread_mutex_unlock(&mu);
}
#define REAL(name, ...) static __typeof__(&name) real_##name; if (!real_##name) real_##name = dlsym(RTLD_NEXT, #name);
int open(const char *p, int flags, ...) { va_list a; va_start(a, flags); mode_t m = va_arg(a, mode_t); va_end(a); REAL(open); int fd = real_open(p, flags, m); track(fd, p, flags); return fd; }
int open64(const char *p, int flags, ...) { va_list a; va_start(a, flags); mode_t m = va_arg(a, mode_t); va_end(a); REAL(open64); int fd = real_open64(p, flags, m); track(fd, p, flags); return fd; }
int openat(int d, const char *p, int flags, ...) { va_list a; va_start(a, flags); mode_t m = va_arg(a, mode_t); va_end(a); REAL(openat); int fd = real_openat(d, p, flags, m); track(fd, p, flags); return fd; }
int openat64(int d, const char *p, int flags, ...) { va_list a; va_start(a, flags); mode_t m = va_arg(a, mode_t); va_end(a); REAL(openat64); int fd = real_openat64(d, p, flags, m); track(fd, p, flags); return fd; }
int close(int fd) { REAL(close); if (fd >= 0 && fd < MAXFD) fdcat[fd] = 0; return real_close(fd); }
static int cat(int fd) { return (fd >= 0 && fd < MAXFD && fdcat[fd]) ? fdcat[fd] - 1 : C_OTHER; }
int fsync(int fd) { REAL(fsync); double t = now(); int r = real_fsync(fd); double d = now() - t; int c = cat(fd); pthread_mutex_lock(&mu); S[c].fsyncs++; S[c].fsync_s += d; pthread_mutex_unlock(&mu); return r; }
int fdatasync(int fd) { REAL(fdatasync); double t = now(); int r = real_fdatasync(fd); double d = now() - t; int c = cat(fd); pthread_mutex_lock(&mu); S[c].fdatasyncs++; S[c].fdatasync_s += d; pthread_mutex_unlock(&mu); return r; }
static void wr(int fd, long n, double d) { int c = cat(fd); pthread_mutex_lock(&mu); S[c].writes++; if (n > 0) S[c].bytes += n; S[c].write_s += d; pthread_mutex_unlock(&mu); }
ssize_t write(int fd, const void *b, size_t n) { REAL(write); double t = now(); ssize_t r = real_write(fd, b, n); wr(fd, r, now() - t); return r; }
ssize_t pwrite(int fd, const void *b, size_t n, off_t o) { REAL(pwrite); double t = now(); ssize_t r = real_pwrite(fd, b, n, o); wr(fd, r, now() - t); return r; }
ssize_t pwrite64(int fd, const void *b, size_t n, off64_t o) { REAL(pwrite64); double t = now(); ssize_t r = real_pwrite64(fd, b, n, o); wr(fd, r, now() - t); return r; }
int unlink(const char *p) { REAL(unlink); int c = classify(p, 0); pthread_mutex_lock(&mu); S[c].unlinks++; pthread_mutex_unlock(&mu); return real_unlink(p); }
int ftruncate(int fd, off_t l) { REAL(ftruncate); int c = cat(fd); pthread_mutex_lock(&mu); S[c].truncates++; pthread_mutex_unlock(&mu); return real_ftruncate(fd, l); }
int ftruncate64(int fd, off64_t l) { REAL(ftruncate64); int c = cat(fd); pthread_mutex_lock(&mu); S[c].truncates++; pthread_mutex_unlock(&mu); return real_ftruncate64(fd, l); }

__attribute__((destructor)) static void report(void) {
    const char *out = getenv("SHIM_OUT"); if (!out) return;
    FILE *f = fopen(out, "w"); if (!f) return;
    fprintf(f, "{");
    for (int i = 0; i < C_N; i++)
        fprintf(f, "%s\"%s\":{\"opens\":%ld,\"fsyncs\":%ld,\"fsync_s\":%.4f,\"fdatasyncs\":%ld,\"fdatasync_s\":%.4f,\"writes\":%ld,\"write_bytes\":%.0f,\"write_s\":%.4f,\"unlinks\":%ld,\"truncates\":%ld}",
                i ? "," : "", NAMES[i], S[i].opens, S[i].fsyncs, S[i].fsync_s, S[i].fdatasyncs, S[i].fdatasync_s, S[i].writes, S[i].bytes, S[i].write_s, S[i].unlinks, S[i].truncates);
    fprintf(f, "}\n"); fclose(f);
}
