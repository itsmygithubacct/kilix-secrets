/*
 * SEC-01: drive serve() itself, not the predicate it calls.
 *
 * tests/test_unit.c covers ksec_fd_is_nonblocking() directly, but nothing
 * reached the guard at the top of serve(), so deleting that guard left the
 * whole suite green -- a control that could not fail. This binary calls
 * serve() with a blocking listener and requires it to refuse.
 *
 * Refusing is not enough on its own to prove the guard ran: with the guard
 * removed, serve() falls through to the session-monitor poll setup, which also
 * returns -1 for an unconfigured state. That path is loud and the guard is
 * silent, so the discriminator is the diagnostic. Requiring "-1 AND nothing on
 * stderr" is what distinguishes the guard firing from a later refusal wearing
 * the same return value.
 */

#define _GNU_SOURCE

/* serve() is static; include the translation unit and neutralise its main(). */
int ksec_daemon_main_not_used(int argc, char **argv);
#define main ksec_daemon_main_not_used
#include "../src/daemon.c"
#undef main

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static unsigned int checks_run;
static unsigned int checks_failed;

static void check_condition(int condition, const char *expression,
                            const char *file, int line) {
    checks_run++;
    if (!condition) {
        checks_failed++;
        fprintf(stderr, "FAIL %s:%d: %s\n", file, line, expression);
    }
}

#define CHECK(expr) check_condition((expr) ? 1 : 0, #expr, __FILE__, __LINE__)

/* Run serve(fd) in a child so a guardless build hangs or crashes in the child
 * rather than taking the harness with it, and report how it refused. */
static int serve_refuses_silently(int listener, int *exited_nonzero) {
    int pipefds[2];
    pid_t child;
    int status = 0;
    char buffer[256];
    ssize_t seen;

    *exited_nonzero = 0;
    if (pipe(pipefds) != 0) return -1;

    child = fork();
    if (child < 0) {
        close(pipefds[0]);
        close(pipefds[1]);
        return -1;
    }
    if (child == 0) {
        daemon_state state;
        int result;
        close(pipefds[0]);
        if (dup2(pipefds[1], STDERR_FILENO) < 0) _exit(120);
        close(pipefds[1]);
        alarm(10);                    /* a guardless build blocks in accept4() */
        memset(&state, 0, sizeof state);
        result = serve(listener, &state);
        _exit(result == -1 ? 0 : 1);
    }

    close(pipefds[1]);
    seen = read(pipefds[0], buffer, sizeof buffer);
    close(pipefds[0]);
    if (waitpid(child, &status, 0) != child) return -1;
    *exited_nonzero = !(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    return seen > 0 ? 1 : 0;          /* 1 == it said something */
}

static int blocking_listener(const char *path) {
    struct sockaddr_un address;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);   /* deliberately no SOCK_NONBLOCK */
    if (fd < 0) return -1;
    memset(&address, 0, sizeof address);
    address.sun_family = AF_UNIX;
    (void)snprintf(address.sun_path, sizeof address.sun_path, "%s", path);
    unlink(path);
    if (bind(fd, (struct sockaddr *)&address, sizeof address) != 0
        || listen(fd, 8) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int main(void) {
    const char *tmpdir = getenv("TMPDIR");
    char path[100];   /* under sun_path's 108, so no truncation is possible */
    int listener;
    int said_something;
    int exited_nonzero = 0;

    (void)snprintf(path, sizeof path, "%s/ksec-serve-guard-%d.sock",
                   tmpdir && *tmpdir ? tmpdir : "/tmp", (int)getpid());

    /* 1. A blocking listener must be refused, and refused by the guard: the
     *    guard returns without printing, so any diagnostic means a later path
     *    refused instead and the guard did not run. */
    listener = blocking_listener(path);
    CHECK(listener >= 0);
    if (listener >= 0) {
        said_something = serve_refuses_silently(listener, &exited_nonzero);
        CHECK(exited_nonzero == 0);            /* serve() returned -1 */
        CHECK(said_something == 0);            /* silently -- the guard, not poll setup */
        close(listener);
        unlink(path);
    }

    /* 2. An unusable descriptor is refused the same way. */
    said_something = serve_refuses_silently(-1, &exited_nonzero);
    CHECK(exited_nonzero == 0);
    CHECK(said_something == 0);

    fprintf(stdout, "serve guard checks: %u/%u passed\n",
            checks_run - checks_failed, checks_run);
    return checks_failed == 0 ? 0 : 1;
}
