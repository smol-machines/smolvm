/*
 * rosetta-wrapper — ptrace shim for Apple Rosetta under Hypervisor.framework
 *
 * Rosetta's Linux binary validates it's running under Virtualization.framework
 * via an undocumented ioctl (type byte 0x61). Under libkrun's
 * Hypervisor.framework backend that ioctl fails, causing Rosetta to abort.
 *
 * This wrapper intercepts the validation ioctl via ptrace, returns the
 * expected magic string, and then detaches — running at full speed for the
 * rest of the process's lifetime.
 *
 * The wrapper process itself becomes Rosetta (and so the x86_64 program): it
 * keeps the PID its parent forked, so `pg_ctl -w`, PID files, supervisors and
 * `docker stop`'s signals all reach the program. The tracer is one helper at
 * the machine's root (smolvm-agent's rosetta_tracer.rs) that seizes each
 * wrapper as it starts; the wrapper waits for it with a handshake ioctl, then
 * execs Rosetta in place. A wrapper whose interpreter does not advertise the
 * helper (or whose helper never answers) falls back to running Rosetta in a
 * traced child, which works but gives the program a different PID.
 *
 * Installed at /usr/bin/rosetta-wrapper in the agent rootfs. At boot the
 * agent appends the Rosetta binary to a copy of this wrapper (see
 * smolvm-agent's rosetta.rs) and registers that copy as the binfmt_misc
 * interpreter for x86_64 ELF binaries, with the F flag so the kernel keeps it
 * open. The wrapper execs /mnt/rosetta/rosetta when that path exists in the
 * caller's mount namespace (the VM and smolvm's own containers). Elsewhere —
 * a container started by Docker or another runtime inside the machine, which
 * has its own mount namespace — it reads the appended Rosetta back out of its
 * own pinned file (/proc/self/exe) into a memfd and execs that, so x86_64
 * binaries run in any container without mounting anything into it.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <linux/elf.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sendfile.h>

struct user_regs {
    uint64_t regs[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
};

static const char ROSETTA_MAGIC[] =
    "Our hard work\nby these words guarded\nplease don't steal\n\xC2\xA9 Apple Inc\n";

#define SYS_IOCTL 29

static const char ROSETTA_PATH[] = "/mnt/rosetta/rosetta";

/*
 * Trailer the agent writes after the appended Rosetta binary: where the
 * payload starts in this file, how long it is, and a magic. Keep in sync with
 * EMBED_MAGIC / write_embedded_interpreter in smolvm-agent's rosetta.rs.
 */
static const char EMBED_MAGIC[16] __attribute__((nonstring)) = "SMOLVM-ROSETTA\0\1";
struct embed_trailer {
    uint64_t offset;
    uint64_t size;
    uint64_t flags;
    char magic[16];
};
/* Trailer flag: the agent's tracer helper is running and will seize us. */
#define EMBED_FLAG_TRACER 1
/* The ioctl (on fd -1) asking the tracer helper "am I traced yet?". Keep in
 * sync with HANDSHAKE_CMD in smolvm-agent's rosetta_tracer.rs. */
#define HANDSHAKE_CMD 0x534d5652
/* How long to wait for the tracer helper before falling back. */
#define HANDSHAKE_TIMEOUT_US 2000000

#ifndef PTRACE_LISTEN
#define PTRACE_LISTEN 0x4208
#endif
#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif
#define GET_SYSCALL_INFO 0x420e
#define SYSCALL_INFO_ENTRY 1
#define SYSCALL_INFO_EXIT 2

/* struct ptrace_syscall_info (Linux 5.3+), declared here for older headers. */
struct syscall_info {
    uint8_t op;
    uint8_t pad[3];
    uint32_t arch;
    uint64_t instruction_pointer;
    uint64_t stack_pointer;
    union {
        struct {
            uint64_t nr;
            uint64_t args[6];
        } entry;
        struct {
            int64_t rval;
            uint8_t is_error;
        } exit;
        uint8_t raw[64];
    };
};

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif

/*
 * Read the trailer the agent appended to this wrapper's own executable.
 * Returns the open executable (caller closes), or -1 when there is none.
 */
static int read_trailer(struct embed_trailer *trailer) {
    int self = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    if (self < 0)
        return -1;
    struct stat st;
    if (fstat(self, &st) < 0 || st.st_size < (off_t)sizeof(*trailer) ||
        pread(self, trailer, sizeof(*trailer), st.st_size - sizeof(*trailer)) !=
            (ssize_t)sizeof(*trailer) ||
        memcmp(trailer->magic, EMBED_MAGIC, sizeof(EMBED_MAGIC)) != 0 ||
        trailer->size == 0 || trailer->offset > (uint64_t)st.st_size ||
        trailer->size > (uint64_t)st.st_size - sizeof(*trailer) - trailer->offset) {
        close(self);
        return -1;
    }
    return self;
}

/*
 * Copy the Rosetta binary appended to this wrapper (open as `self`) into a
 * memfd. Returns the memfd, or -1.
 */
static int embedded_rosetta(int self, const struct embed_trailer *trailer) {
    int mem = (int)syscall(SYS_memfd_create, "rosetta", MFD_CLOEXEC);
    if (mem < 0)
        return -1;
    off_t off = (off_t)trailer->offset;
    uint64_t left = trailer->size;
    while (left > 0) {
        ssize_t n = sendfile(mem, self, &off, left > 0x40000000 ? 0x40000000 : left);
        if (n <= 0) {
            close(mem);
            return -1;
        }
        left -= (uint64_t)n;
    }
    return mem;
}

static int get_regs(pid_t pid, struct user_regs *regs) {
    struct iovec iov = { regs, sizeof(*regs) };
    return ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov);
}

static int set_regs(pid_t pid, struct user_regs *regs) {
    struct iovec iov = { regs, sizeof(*regs) };
    return ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &iov);
}

static int write_mem(pid_t pid, uint64_t addr, const void *buf, size_t len) {
    const unsigned char *src = buf;
    size_t i;

    for (i = 0; i + 8 <= len; i += 8) {
        uint64_t word;
        memcpy(&word, src + i, 8);
        if (ptrace(PTRACE_POKEDATA, pid, (void *)(addr + i), (void *)word) < 0)
            return -1;
    }
    if (i < len) {
        uint64_t word = 0;
        errno = 0;
        word = (uint64_t)ptrace(PTRACE_PEEKDATA, pid, (void *)(addr + i), NULL);
        if (errno)
            return -1;
        memcpy(&word, src + i, len - i);
        if (ptrace(PTRACE_POKEDATA, pid, (void *)(addr + i), (void *)word) < 0)
            return -1;
    }
    return 0;
}

#define DETACHED (-2)

/*
 * Fallback tracer: `pid` is our child, stopped at its exec and set up for
 * syscall tracing. Answer Rosetta's validation ioctl and detach (DETACHED),
 * or return the child's exit code if it ends first, or -1 on error.
 */
static int answer_validation(pid_t pid) {
    int status;
    int intercept = 0;
    uint64_t buf_addr = 0;
    for (;;) {
        if (waitpid(pid, &status, __WALL) < 0)
            return -1;
        if (WIFEXITED(status))
            return WEXITSTATUS(status);
        if (WIFSIGNALED(status))
            return 128 + WTERMSIG(status);
        if (!WIFSTOPPED(status))
            continue;
        int sig = WSTOPSIG(status);
        int event = (unsigned)status >> 16;

        if (sig == (SIGTRAP | 0x80)) {
            struct syscall_info info;
            memset(&info, 0, sizeof(info));
            if (ptrace(GET_SYSCALL_INFO, pid, (void *)sizeof(info), &info) <= 0)
                return -1;
            if (info.op == SYSCALL_INFO_ENTRY && info.entry.nr == SYS_IOCTL) {
                uint32_t cmd = (uint32_t)info.entry.args[1];
                uint8_t ioc_type = (cmd >> 8) & 0xff;
                uint16_t ioc_size = (cmd >> 16) & 0x3fff;
                /*
                 * Match on type byte 0x61 (Rosetta's Virtualization.framework
                 * validation). The command number changed between macOS
                 * versions so we match on the type byte for version
                 * independence.
                 */
                if (ioc_type == 0x61 && (ioc_size == 0x45 || ioc_size == 0x80)) {
                    intercept = ioc_size == 0x45 ? 1 : 2;
                    buf_addr = info.entry.args[2];
                }
            } else if (info.op == SYSCALL_INFO_EXIT && intercept) {
                struct user_regs regs;
                if (intercept == 1) {
                    /* 0x45-byte validation: write the magic string. */
                    char buf[0x45];
                    memset(buf, 0, sizeof(buf));
                    size_t mlen = strlen(ROSETTA_MAGIC);
                    if (mlen >= sizeof(buf))
                        mlen = sizeof(buf) - 1;
                    memcpy(buf, ROSETTA_MAGIC, mlen);
                    write_mem(pid, buf_addr, buf, sizeof(buf));
                } else {
                    /* 0x80-byte validation: zero-fill. */
                    char buf[0x80];
                    memset(buf, 0, sizeof(buf));
                    write_mem(pid, buf_addr, buf, sizeof(buf));
                }
                if (get_regs(pid, &regs) == 0) {
                    regs.regs[0] = 1;
                    set_regs(pid, &regs);
                }
                /* Validation answered: run at full speed from here on. */
                ptrace(PTRACE_DETACH, pid, NULL, NULL);
                return DETACHED;
            }
            ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
        } else if (event == PTRACE_EVENT_STOP) {
            /* A group stop (SIGSTOP and friends) stays a stop; anything else
             * here is the interrupt-stop and just resumes. */
            if (sig == SIGSTOP || sig == SIGTSTP || sig == SIGTTIN || sig == SIGTTOU)
                ptrace(PTRACE_LISTEN, pid, NULL, NULL);
            else
                ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
        } else {
            /* Signal-delivery stop: deliver it. */
            ptrace(PTRACE_SYSCALL, pid, NULL, (void *)(long)sig);
        }
    }
}

static void exec_rosetta(int rosetta_fd, char **argv, char **envp) {
    if (rosetta_fd >= 0)
        syscall(SYS_execveat, rosetta_fd, "", argv, envp, AT_EMPTY_PATH);
    else
        execve(ROSETTA_PATH, argv, envp);
}

/* Ask the tracer helper whether it has seized us; wait up to the timeout. */
static int handshake(void) {
    long waited = 0, step = 50;
    for (;;) {
        if (syscall(SYS_ioctl, -1, HANDSHAKE_CMD, 0) == 0)
            return 1;
        if (waited >= HANDSHAKE_TIMEOUT_US)
            return 0;
        usleep(step);
        waited += step;
        if (step < 2000)
            step *= 2;
    }
}

int main(int argc, char *argv[], char *envp[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <x86_64-binary> [args...]\n", argv[0]);
        return 1;
    }

    struct embed_trailer trailer;
    int self = read_trailer(&trailer);
    int rosetta_fd = -1;
    if (access(ROSETTA_PATH, X_OK) != 0) {
        if (self >= 0)
            rosetta_fd = embedded_rosetta(self, &trailer);
        if (rosetta_fd < 0) {
            fprintf(stderr, "rosetta-wrapper: %s is not visible here and this wrapper "
                            "carries no embedded copy\n", ROSETTA_PATH);
            return 127;
        }
    }
    int tracer = self >= 0 && (trailer.flags & EMBED_FLAG_TRACER);
    if (self >= 0)
        close(self);

    char **new_argv = malloc((argc + 1) * sizeof(char *));
    if (!new_argv)
        return 1;
    new_argv[0] = (char *)ROSETTA_PATH;
    for (int i = 1; i < argc; i++)
        new_argv[i] = argv[i];
    new_argv[argc] = NULL;

    /* The machine's tracer helper answers the validation: become Rosetta. */
    if (tracer && handshake()) {
        exec_rosetta(rosetta_fd, new_argv, envp);
        perror("rosetta-wrapper: execve");
        return 127;
    }

    /* Fallback: run Rosetta in a child we trace ourselves. */
    pid_t child = fork();
    if (child < 0) {
        perror("rosetta-wrapper: fork");
        return 1;
    }
    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        exec_rosetta(rosetta_fd, new_argv, envp);
        perror("rosetta-wrapper: execve");
        _exit(127);
    }
    if (rosetta_fd >= 0)
        close(rosetta_fd);

    /* Wait for exec-stop (SIGTRAP from execve after TRACEME). */
    int status;
    waitpid(child, &status, 0);
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
        fprintf(stderr, "rosetta-wrapper: unexpected initial stop: %d\n", status);
        kill(child, SIGKILL);
        return 1;
    }
    ptrace(PTRACE_SETOPTIONS, child, NULL, (void *)(long)PTRACE_O_TRACESYSGOOD);
    ptrace(PTRACE_SYSCALL, child, NULL, NULL);
    int answered = answer_validation(child);
    if (answered == -1) {
        kill(child, SIGKILL);
        return 1;
    }
    if (answered != DETACHED)
        return answered;
    for (;;) {
        if (waitpid(child, &status, 0) < 0)
            return 1;
        if (WIFEXITED(status))
            return WEXITSTATUS(status);
        if (WIFSIGNALED(status))
            return 128 + WTERMSIG(status);
    }
}
