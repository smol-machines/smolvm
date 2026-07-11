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
 * Installed at /usr/bin/rosetta-wrapper in the agent rootfs and registered
 * as the binfmt_misc interpreter for x86_64 ELF binaries.
 */

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

struct user_regs {
    uint64_t regs[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
};

static const char ROSETTA_MAGIC[] =
    "Our hard work\nby these words guarded\nplease don't steal\n\xC2\xA9 Apple Inc\n";

#define SYS_IOCTL 29

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

int main(int argc, char *argv[], char *envp[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <x86_64-binary> [args...]\n", argv[0]);
        return 1;
    }

    const char *rosetta = "/mnt/rosetta/rosetta";
    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        return 1;
    }

    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        char **new_argv = malloc((argc + 1) * sizeof(char *));
        new_argv[0] = (char *)rosetta;
        for (int i = 1; i < argc; i++)
            new_argv[i] = argv[i];
        new_argv[argc] = NULL;
        execve(rosetta, new_argv, envp);
        perror("execve");
        _exit(127);
    }

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

    int in_syscall = 0;
    int intercept_exit = 0;
    uint64_t ioctl_buf_addr = 0;

    while (1) {
        waitpid(child, &status, 0);

        if (WIFEXITED(status))
            return WEXITSTATUS(status);
        if (WIFSIGNALED(status))
            return 128 + WTERMSIG(status);

        if (!WIFSTOPPED(status))
            continue;

        int sig = WSTOPSIG(status);

        if (sig != (SIGTRAP | 0x80)) {
            /* Non-syscall signal: deliver it. */
            ptrace(PTRACE_SYSCALL, child, NULL, (void *)(long)sig);
            continue;
        }

        /* Syscall stop. */
        struct user_regs regs;
        get_regs(child, &regs);

        if (!in_syscall) {
            /* Syscall entry. */
            if (regs.regs[8] == SYS_IOCTL) {
                uint32_t cmd = (uint32_t)regs.regs[1];
                uint8_t ioc_type = (cmd >> 8) & 0xff;
                uint16_t ioc_size = (cmd >> 16) & 0x3fff;
                /*
                 * Match on type byte 0x61 (Rosetta's Virtualization.framework
                 * validation). The command number changed between macOS versions
                 * so we match on the type byte for version independence.
                 */
                if (ioc_type == 0x61) {
                    if (ioc_size == 0x45) {
                        intercept_exit = 1;
                        ioctl_buf_addr = regs.regs[2];
                    } else if (ioc_size == 0x80) {
                        intercept_exit = 2;
                        ioctl_buf_addr = regs.regs[2];
                    }
                }
            }
            in_syscall = 1;
        } else {
            /* Syscall exit. */
            if (intercept_exit == 1) {
                /* 0x45-byte validation: write the magic string. */
                char buf[0x45];
                memset(buf, 0, sizeof(buf));
                size_t mlen = strlen(ROSETTA_MAGIC);
                if (mlen >= sizeof(buf))
                    mlen = sizeof(buf) - 1;
                memcpy(buf, ROSETTA_MAGIC, mlen);
                write_mem(child, ioctl_buf_addr, buf, sizeof(buf));
                regs.regs[0] = 1;
                set_regs(child, &regs);
            } else if (intercept_exit == 2) {
                /* 0x80-byte validation: zero-fill. */
                char buf[0x80];
                memset(buf, 0, sizeof(buf));
                write_mem(child, ioctl_buf_addr, buf, sizeof(buf));
                regs.regs[0] = 1;
                set_regs(child, &regs);
            }

            if (intercept_exit) {
                /*
                 * Validation intercepted — Rosetta will proceed. Detach so the
                 * translated process runs at full speed with no ptrace overhead.
                 */
                ptrace(PTRACE_DETACH, child, NULL, NULL);
                waitpid(child, &status, 0);
                if (WIFEXITED(status))
                    return WEXITSTATUS(status);
                if (WIFSIGNALED(status))
                    return 128 + WTERMSIG(status);
                return 0;
            }

            in_syscall = 0;
        }

        ptrace(PTRACE_SYSCALL, child, NULL, NULL);
    }
}
