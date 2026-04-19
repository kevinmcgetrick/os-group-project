/*
 * timedexec - Run a program with CPU and memory limits
 * Usage: timedexec <cpu_seconds> <mem_mb> <command> [args...]
 *
 * cpu_seconds: maximum CPU time in seconds (0 = unlimited)
 * mem_mb:      maximum virtual memory in megabytes (0 = unlimited)
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>

static void print_usage(const char *progname) {
    fprintf(stderr, "Usage: %s <cpu_seconds> <mem_mb> <command> [args...]\n", progname);
    fprintf(stderr, "  cpu_seconds: maximum CPU time in seconds (0 = unlimited)\n");
    fprintf(stderr, "  mem_mb:      maximum virtual memory in megabytes (0 = unlimited)\n");
}

/* Convert string to unsigned long, handle errors */
static unsigned long parse_ulong(const char *str) {
    char *endptr;
    unsigned long val = strtoul(str, &endptr, 10);
    if (*endptr != '\0' || endptr == str) {
        fprintf(stderr, "Invalid number: %s\n", str);
        exit(EXIT_FAILURE);
    }
    return val;
}

/* Signal handler for parent to forward signals to child */
static volatile pid_t child_pid = 0;

static void forward_signal(int sig) {
    if (child_pid > 0) {
        kill(child_pid, sig);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    /* Parse limits */
    unsigned long cpu_sec = parse_ulong(argv[1]);
    unsigned long mem_mb   = parse_ulong(argv[2]);

    /* Remaining arguments are the command and its arguments */
    char **cmd_argv = &argv[3];

    /* Convert memory limit to bytes */
    rlim_t mem_bytes = (rlim_t)mem_mb * 1024 * 1024;

    /* Prepare resource limits */
    struct rlimit cpu_limit, mem_limit;

    if (cpu_sec > 0) {
        cpu_limit.rlim_cur = cpu_sec;
        cpu_limit.rlim_max = cpu_sec;
    } else {
        /* Unlimited */
        cpu_limit.rlim_cur = RLIM_INFINITY;
        cpu_limit.rlim_max = RLIM_INFINITY;
    }

    if (mem_mb > 0) {
        mem_limit.rlim_cur = mem_bytes;
        mem_limit.rlim_max = mem_bytes;
    } else {
        mem_limit.rlim_cur = RLIM_INFINITY;
        mem_limit.rlim_max = RLIM_INFINITY;
    }

    /* Set up signal forwarding */
    struct sigaction sa;
    sa.sa_handler = forward_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP,  &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return EXIT_FAILURE;
    }

    if (pid == 0) {
        /* Child process */

        /* Set resource limits */
        if (setrlimit(RLIMIT_CPU, &cpu_limit) != 0) {
            perror("setrlimit(RLIMIT_CPU)");
            exit(EXIT_FAILURE);
        }

        if (setrlimit(RLIMIT_AS, &mem_limit) != 0) {
            perror("setrlimit(RLIMIT_AS)");
            exit(EXIT_FAILURE);
        }

        /* Execute the command */
        execvp(cmd_argv[0], cmd_argv);

        /* execvp returns only on error */
        perror("execvp");
        exit(EXIT_FAILURE);
    }

    /* Parent process */
    child_pid = pid;

    int status;
    pid_t w;

    do {
        w = waitpid(pid, &status, 0);
    } while (w == -1 && errno == EINTR);

    child_pid = 0;

    if (w == -1) {
        perror("waitpid");
        return EXIT_FAILURE;
    }

    /* Analyze child termination */
    if (WIFEXITED(status)) {
        int exit_code = WEXITSTATUS(status);
        printf("Command exited with status %d\n", exit_code);
        return exit_code;
    } else if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        const char *reason = "unknown signal";

        switch (sig) {
            case SIGXCPU:
                reason = "CPU time limit exceeded";
                break;
            case SIGSEGV:
                /* SIGSEGV can also be caused by memory limit violation */
                reason = "memory limit exceeded (or segmentation fault)";
                break;
            case SIGKILL:
                /* Might be OOM killer or hard CPU limit */
                reason = "killed (possibly due to resource limit)";
                break;
            default:
                reason = strsignal(sig);
        }

        fprintf(stderr, "Command terminated by signal %d: %s\n", sig, reason);
        return 128 + sig;  /* Follow shell convention */
    } else {
        /* Should not happen */
        fprintf(stderr, "Command terminated abnormally\n");
        return EXIT_FAILURE;
    }
}