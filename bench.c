#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <time.h>
#include <errno.h>
#include <stdint.h>
#include <math.h>

#define MAX_SYSCALLS     512
#define MAX_FUNC_SAMPLES 65536

#define RST   "\033[0m"
#define BOLD  "\033[1m"
#define DIM   "\033[2m"
#define RED   "\033[31m"
#define GRN   "\033[32m"
#define YEL   "\033[33m"
#define BLU   "\033[34m"
#define MAG   "\033[35m"
#define CYN   "\033[36m"
#define WHT   "\033[37m"

typedef struct { long nr; size_t count; double total_ns; } SyscallStat;
typedef struct { SyscallStat e[MAX_SYSCALLS]; size_t n; } SyscallTable;

static const char *syscall_name(long nr) {
    switch (nr) {
        case SYS_read:           return "read";
        case SYS_write:          return "write";
        case SYS_open:           return "open";
        case SYS_close:          return "close";
        case SYS_stat:           return "stat";
        case SYS_fstat:          return "fstat";
        case SYS_lstat:          return "lstat";
        case SYS_mmap:           return "mmap";
        case SYS_mprotect:       return "mprotect";
        case SYS_munmap:         return "munmap";
        case SYS_brk:            return "brk";
        case SYS_rt_sigaction:   return "rt_sigaction";
        case SYS_rt_sigprocmask: return "rt_sigprocmask";
        case SYS_ioctl:          return "ioctl";
        case SYS_access:         return "access";
        case SYS_execve:         return "execve";
        case SYS_exit:           return "exit";
        case SYS_exit_group:     return "exit_group";
        case SYS_openat:         return "openat";
        case SYS_newfstatat:     return "newfstatat";
        case SYS_pread64:        return "pread64";
        case SYS_pwrite64:       return "pwrite64";
        case SYS_futex:          return "futex";
        case SYS_clock_gettime:  return "clock_gettime";
        case SYS_getpid:         return "getpid";
        case SYS_getuid:         return "getuid";
        case SYS_gettid:         return "gettid";
        case SYS_lseek:          return "lseek";
        case SYS_socket:         return "socket";
        case SYS_connect:        return "connect";
        case SYS_sendto:         return "sendto";
        case SYS_recvfrom:       return "recvfrom";
        case SYS_nanosleep:      return "nanosleep";
        case SYS_poll:           return "poll";
        case SYS_select:         return "select";
        case SYS_set_tid_address: return "set_tid_address";
        case SYS_set_robust_list: return "set_robust_list";
        case SYS_prlimit64:      return "prlimit64";
        case SYS_getrandom:      return "getrandom";
        default: {
            static char buf[32];
            snprintf(buf, sizeof(buf), "syscall_%ld", nr);
            return buf;
        }
    }
}

static SyscallStat *find_or_create(SyscallTable *t, long nr) {
    for (size_t i = 0; i < t->n; i++)
        if (t->e[i].nr == nr) return &t->e[i];
    if (t->n >= MAX_SYSCALLS) return NULL;
    SyscallStat *s = &t->e[t->n++];
    s->nr = nr; s->count = 0; s->total_ns = 0;
    return s;
}

static long perf_open(struct perf_event_attr *attr, pid_t pid) {
    return syscall(__NR_perf_event_open, attr, pid, -1, -1, 0);
}

static int open_perf(uint32_t type, uint64_t config, pid_t pid) {
    struct perf_event_attr a = {0};
    a.type = type; a.size = sizeof(a); a.config = config;
    a.disabled = 1; a.exclude_hv = 1;
    return (int)perf_open(&a, pid);
}

static uint64_t read_perf(int fd) {
    uint64_t v = 0;
    if (fd >= 0) read(fd, &v, sizeof(v));
    return v;
}

static void perf_ctrl(int fd, int enable) {
    if (fd < 0) return;
    ioctl(fd, enable ? PERF_EVENT_IOC_ENABLE : PERF_EVENT_IOC_DISABLE, 0);
    if (enable) ioctl(fd, PERF_EVENT_IOC_RESET, 0);
}

static double ns_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e9 + ts.tv_nsec;
}

static void bar(double ratio, int width, const char *col) {
    if (ratio < 0) ratio = 0;
    if (ratio > 1) ratio = 1;
    int filled = (int)(ratio * width);
    printf(CYN "[" RST);
    for (int i = 0; i < width; i++)
        printf(i < filled ? "%s█" RST : DIM "░" RST, col);
    printf(CYN "]" RST);
}

static void section(const char *title) {
    printf("\n" BOLD "  %s\n" RST, title);
}

static void fmt_count(uint64_t v, char *out) {
    if      (v >= 1000000000) sprintf(out, "%.2fG", v / 1e9);
    else if (v >= 1000000)    sprintf(out, "%.2fM", v / 1e6);
    else if (v >= 1000)       sprintf(out, "%.2fK", v / 1e3);
    else                      sprintf(out, "%lu",   v);
}

static int is_source(const char *path) {
    const char *dot = strrchr(path, '.');
    return dot && (strcmp(dot, ".c") == 0 || strcmp(dot, ".cpp") == 0 ||
                   strcmp(dot, ".cc") == 0 || strcmp(dot, ".cxx") == 0);
}

static int cmp_sc(const void *a, const void *b) {
    return (int)(((SyscallStat *)b)->count - ((SyscallStat *)a)->count);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr,
            BOLD "usage:\n" RST
            "  bench " YEL "<source.c>" RST " [gcc flags]   — compile + bench\n"
            "  bench " YEL "<binary>"   RST " [args...]     — bench existing binary\n\n");
        return 1;
    }

    char binary[512] = {0};
    char **child_argv;
    int    child_argc;
    int    compiled = 0;

    if (is_source(argv[1])) {
        snprintf(binary, sizeof(binary), "/tmp/bench_bin_%d", getpid());

        char **gcc_argv = malloc((argc + 8) * sizeof(char *));
        int gi = 0;
        gcc_argv[gi++] = "gcc";
        gcc_argv[gi++] = "-g3";
        gcc_argv[gi++] = "-O0";
        gcc_argv[gi++] = "-fno-omit-frame-pointer";
        gcc_argv[gi++] = "-rdynamic";
        for (int i = 2; i < argc; i++) gcc_argv[gi++] = argv[i];
        gcc_argv[gi++] = "-o"; gcc_argv[gi++] = binary;
        gcc_argv[gi++] = argv[1];
        gcc_argv[gi]   = NULL;

        printf(BOLD CYN "\n  compiling " RST "%s " DIM "→" RST " %s\n", argv[1], binary);
        printf(DIM "  flags: -g3 -O0 -fno-omit-frame-pointer -rdynamic\n\n" RST);

        pid_t cp = fork();
        if (cp == 0) { execvp("gcc", gcc_argv); perror("gcc"); exit(1); }
        int cst;
        waitpid(cp, &cst, 0);
        free(gcc_argv);

        if (!WIFEXITED(cst) || WEXITSTATUS(cst) != 0) {
            fprintf(stderr, RED "  compilation failed\n" RST);
            return 1;
        }
        printf(GRN "  compiled ok\n\n" RST);

        child_argv    = malloc(3 * sizeof(char *));
        child_argv[0] = binary;
        child_argv[1] = NULL;
        child_argc    = 1;
        compiled      = 1;
    } else {
        strncpy(binary, argv[1], sizeof(binary) - 1);
        child_argv = &argv[1];
        child_argc = argc - 1;
        (void)child_argc;
    }

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 1; }

    if (pid == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execvp(child_argv[0], child_argv);
        perror("execvp");
        exit(1);
    }

    int status;
    waitpid(pid, &status, 0);

    int fd_cyc   = open_perf(PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES,              pid);
    int fd_ins   = open_perf(PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS,            pid);
    int fd_cref  = open_perf(PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_REFERENCES,        pid);
    int fd_cmis  = open_perf(PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_MISSES,            pid);
    int fd_br    = open_perf(PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_INSTRUCTIONS,     pid);
    int fd_brmis = open_perf(PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_MISSES,           pid);
    int fd_stall = open_perf(PERF_TYPE_HARDWARE, PERF_COUNT_HW_STALLED_CYCLES_FRONTEND, pid);
    int fd_ctx   = open_perf(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CONTEXT_SWITCHES,        pid);
    int fd_fault = open_perf(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS,             pid);
    int fd_migr  = open_perf(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_MIGRATIONS,          pid);

    int fds[] = { fd_cyc, fd_ins, fd_cref, fd_cmis, fd_br, fd_brmis, fd_stall, fd_ctx, fd_fault, fd_migr };
    for (int i = 0; i < 10; i++) perf_ctrl(fds[i], 1);

    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);

    SyscallTable table   = {0};
    double wall_start    = ns_now();
    int    in_syscall    = 0;
    long   current_nr    = -1;
    double sc_enter      = 0;
    size_t total_sc      = 0;

    unsigned long brk_base = 0, brk_peak = 0, brk_cur = 0;

    while (1) {
        ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) || WIFSIGNALED(status)) break;

        if (WIFSTOPPED(status) && (WSTOPSIG(status) & 0x80)) {
            struct user_regs_struct regs;
            ptrace(PTRACE_GETREGS, pid, NULL, &regs);

            if (!in_syscall) {
                current_nr = (long)regs.orig_rax;
                sc_enter   = ns_now();
                in_syscall = 1;
            } else {
                double elapsed = ns_now() - sc_enter;
                SyscallStat *s = find_or_create(&table, current_nr);
                if (s) { s->count++; s->total_ns += elapsed; total_sc++; }

                if (current_nr == SYS_brk) {
                    unsigned long ret = (unsigned long)regs.rax;
                    if (brk_base == 0) brk_base = ret;
                    brk_cur = ret;
                    if (brk_cur > brk_peak) brk_peak = brk_cur;
                }

                in_syscall = 0;
            }
        }
    }

    double wall_ns = ns_now() - wall_start;
    int exit_code  = WIFEXITED(status) ? WEXITSTATUS(status) : -1;

    for (int i = 0; i < 10; i++) perf_ctrl(fds[i], 0);

    uint64_t cyc   = read_perf(fd_cyc);
    uint64_t ins   = read_perf(fd_ins);
    uint64_t cref  = read_perf(fd_cref);
    uint64_t cmis  = read_perf(fd_cmis);
    uint64_t br    = read_perf(fd_br);
    uint64_t brmis = read_perf(fd_brmis);
    uint64_t stall = read_perf(fd_stall);
    uint64_t ctx   = read_perf(fd_ctx);
    uint64_t fault = read_perf(fd_fault);
    uint64_t migr  = read_perf(fd_migr);

    struct rusage ru;
    getrusage(RUSAGE_CHILDREN, &ru);

    printf("\n  " BOLD "bench" RST "  " CYN "%s" RST "  exit %s%d" RST "\n",
           argv[1], exit_code == 0 ? GRN : RED, exit_code);

    section("timing");
    double user_ms = ru.ru_utime.tv_sec * 1e3 + ru.ru_utime.tv_usec / 1e3;
    double sys_ms  = ru.ru_stime.tv_sec * 1e3 + ru.ru_stime.tv_usec / 1e3;
    double wall_ms = wall_ns / 1e6;
    printf("    wall    %s%10.3f ms%s\n", YEL, wall_ms, RST);
    printf("    user    %s%10.3f ms%s\n", GRN, user_ms, RST);
    printf("    sys     %s%10.3f ms%s  ", MAG, sys_ms,  RST);
    bar(sys_ms / (wall_ms + 0.001), 24, MAG);
    printf("  " MAG "%.1f%%" RST "\n", sys_ms / (wall_ms + 0.001) * 100);

    section("cpu");
    char buf[32];
    fmt_count(cyc,   buf); printf("    cycles          %s%18s%s\n", CYN, buf, RST);
    fmt_count(ins,   buf); printf("    instructions    %s%18s%s\n", CYN, buf, RST);
    fmt_count(stall, buf); printf("    stalled cycles  %s%18s%s\n", RED, buf, RST);
    if (cyc > 0) {
        double ipc = (double)ins / cyc;
        printf("    IPC             %s%18.3f%s  ", GRN, ipc, RST);
        bar(ipc / 4.0, 24, GRN); printf("\n");
        printf("    stall rate      %s%17.2f%%%s\n",
               stall > cyc / 2 ? RED : GRN, (double)stall / cyc * 100, RST);
    }

    section("cache");
    fmt_count(cref, buf); printf("    references      %s%18s%s\n", CYN, buf, RST);
    fmt_count(cmis, buf); printf("    misses          %s%18s%s\n", RED, buf, RST);
    if (cref > 0) {
        double mr = (double)cmis / cref;
        printf("    miss rate       ");
        bar(mr, 24, mr > 0.1 ? RED : GRN);
        printf("  %s%.2f%%%s\n", mr > 0.1 ? RED : GRN, mr * 100, RST);
    }

    section("branches");
    fmt_count(br,    buf); printf("    total           %s%18s%s\n", CYN, buf, RST);
    fmt_count(brmis, buf); printf("    mispredicted    %s%18s%s\n", RED, buf, RST);
    if (br > 0) {
        double bm = (double)brmis / br;
        printf("    miss rate       ");
        bar(bm, 24, bm > 0.05 ? RED : GRN);
        printf("  %s%.2f%%%s\n", bm > 0.05 ? RED : GRN, bm * 100, RST);
    }

    section("memory");
    printf("    max rss         %s%15ld KB%s\n", CYN, ru.ru_maxrss, RST);
    if (brk_peak > brk_base)
        printf("    heap peak       %s%15lu KB%s\n", CYN, (brk_peak - brk_base) / 1024, RST);
    fmt_count(fault, buf); printf("    page faults     %s%18s%s\n", fault > 100 ? RED : CYN, buf, RST);
    printf("    minor faults    %s%18lu%s\n", CYN, ru.ru_minflt, RST);
    printf("    major faults    %s%18lu%s\n", ru.ru_majflt > 0 ? RED : CYN, ru.ru_majflt, RST);
    printf("    voluntary ctx   %s%18lu%s\n", CYN, ru.ru_nvcsw, RST);
    printf("    involuntary ctx %s%18lu%s\n", ru.ru_nivcsw > 100 ? RED : CYN, ru.ru_nivcsw, RST);
    fmt_count(ctx,  buf); printf("    ctx switches    %s%18s%s\n", CYN, buf, RST);
    fmt_count(migr, buf); printf("    cpu migrations  %s%18s%s\n", migr > 0 ? YEL : CYN, buf, RST);
    printf("    reclaimed       %s%15lu KB%s\n", CYN, ru.ru_idrss + ru.ru_isrss, RST);

    section("syscalls");
    qsort(table.e, table.n, sizeof(SyscallStat), cmp_sc);

    size_t max_c = table.n > 0 ? table.e[0].count : 1;
    double max_t = 0;
    for (size_t i = 0; i < table.n; i++)
        if (table.e[i].total_ns > max_t) max_t = table.e[i].total_ns;

    printf("    %-22s  %7s  %11s  %10s\n", "name", "calls", "total µs", "avg µs");
    printf("    %-22s  %7s  %11s  %10s\n",
           "──────────────────────", "───────", "───────────", "──────────");

    for (size_t i = 0; i < table.n; i++) {
        SyscallStat *s  = &table.e[i];
        double tot_us   = s->total_ns / 1e3;
        double avg_us   = tot_us / s->count;
        double ratio    = (double)s->count / max_c;
        const char *col = avg_us > 1000 ? RED : avg_us > 100 ? YEL : GRN;

        printf("    " CYN "%-22s" RST "  %7zu  %11.2f  %s%10.3f" RST "  ",
               syscall_name(s->nr), s->count, tot_us, col, avg_us);
        bar(ratio, 14, col);
        printf("\n");
    }

    printf("\n    total  " BOLD "%zu" RST "\n", total_sc);

    section("score");
    double ipc_score     = cyc > 0 ? fmin((double)ins / cyc / 4.0, 1.0) * 25 : 0;
    double cache_score   = cref > 0 ? (1.0 - fmin((double)cmis / cref, 1.0)) * 25 : 25;
    double branch_score  = br > 0 ? (1.0 - fmin((double)brmis / br, 1.0)) * 25 : 25;
    double syscall_score = total_sc < 100 ? 25 : total_sc < 1000 ? 20 : total_sc < 10000 ? 12 : 5;
    double total_score   = ipc_score + cache_score + branch_score + syscall_score;
    const char *grade    = total_score > 85 ? GRN "A" : total_score > 70 ? GRN "B" :
                           total_score > 55 ? YEL "C" : total_score > 40 ? YEL "D" : RED "F";

    printf("    ipc         "); bar(ipc_score    / 25, 24, GRN); printf("  %.1f/25\n", ipc_score);
    printf("    cache       "); bar(cache_score  / 25, 24, CYN); printf("  %.1f/25\n", cache_score);
    printf("    branches    "); bar(branch_score / 25, 24, MAG); printf("  %.1f/25\n", branch_score);
    printf("    syscalls    "); bar(syscall_score/ 25, 24, YEL); printf("  %.1f/25\n", syscall_score);
    printf("\n    overall  " BOLD "%s%.0f/100" RST "  grade " BOLD "%s" RST "\n\n",
           total_score > 70 ? GRN : total_score > 40 ? YEL : RED, total_score, grade);

    if (compiled) unlink(binary);

    return 0;
}
