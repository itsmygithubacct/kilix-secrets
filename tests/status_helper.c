#define _GNU_SOURCE

#include "internal.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static int send_fd(int socket_fd, int passed_fd) {
    char marker = 'S';
    struct iovec iov = {&marker, 1U};
    char control[CMSG_SPACE(sizeof(int))];
    struct msghdr message;
    struct cmsghdr *cmsg;
    ssize_t count;
    memset(control, 0, sizeof control);
    memset(&message, 0, sizeof message);
    message.msg_iov = &iov;
    message.msg_iovlen = 1U;
    message.msg_control = control;
    message.msg_controllen = sizeof control;
    cmsg = CMSG_FIRSTHDR(&message);
    if (cmsg == NULL) return -1;
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &passed_fd, sizeof passed_fd);
    do {
        count = sendmsg(socket_fd, &message, MSG_NOSIGNAL);
    } while (count < 0 && errno == EINTR);
    return count == 1 ? 0 : -1;
}

static int receive_fd(int socket_fd) {
    char marker = 0;
    struct iovec iov = {&marker, 1U};
    char control[CMSG_SPACE(sizeof(int))];
    struct msghdr message;
    struct cmsghdr *cmsg;
    ssize_t count;
    int received = -1;
    memset(control, 0, sizeof control);
    memset(&message, 0, sizeof message);
    message.msg_iov = &iov;
    message.msg_iovlen = 1U;
    message.msg_control = control;
    message.msg_controllen = sizeof control;
    do {
        count = recvmsg(socket_fd, &message, MSG_CMSG_CLOEXEC);
    } while (count < 0 && errno == EINTR);
    if (count != 1 || marker != 'S' || (message.msg_flags & MSG_CTRUNC) != 0) {
        return -1;
    }
    cmsg = CMSG_FIRSTHDR(&message);
    if (cmsg == NULL || CMSG_NXTHDR(&message, cmsg) != NULL
            || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS
            || cmsg->cmsg_len != CMSG_LEN(sizeof(int))) return -1;
    memcpy(&received, CMSG_DATA(cmsg), sizeof received);
    return received;
}

static void print_error(ksec_result result) {
    printf("ERROR %s\n", ksec_result_string(result));
    (void)fflush(stdout);
}

static int parse_u32(const char *text, uint32_t *out) {
    char *end = NULL;
    unsigned long value;
    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value > UINT32_MAX) {
        return -1;
    }
    *out = (uint32_t)value;
    return 0;
}

static int parse_verb(const char *text, uint32_t *out) {
    if (strcmp(text, "doctor") == 0) { *out = KSEC_VERB_DOCTOR; return 0; }
    if (strcmp(text, "create") == 0) { *out = KSEC_VERB_CREATE; return 0; }
    if (strcmp(text, "read") == 0) { *out = KSEC_VERB_READ; return 0; }
    if (strcmp(text, "all") == 0) { *out = KSEC_VERB_ALL; return 0; }
    return -1;
}

/* 0 quiet, -2 peer already hung up, -3 a byte was readable, -1 unusable. */
static int descriptor_is_quiet_watch(int fd) {
    int type = 0;
    socklen_t length = sizeof type;
    uint8_t byte = 0U;
    ssize_t count;
    int fd_flags;
    if (fd < 0 || ksec_fd_is_nonblocking(fd) != 1) return -1;
    fd_flags = fcntl(fd, F_GETFD);
    if (fd_flags < 0 || (fd_flags & FD_CLOEXEC) == 0) return -1;
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &length) != 0
            || length != sizeof type || type != SOCK_SEQPACKET) return -1;
    do {
        count = read(fd, &byte, 1U);
    } while (count < 0 && errno == EINTR);
    if (count == 0) return -2;
    if (count > 0) return -3;
    if (errno != EAGAIN && errno != EWOULDBLOCK) return -1;
    return 0;
}

static int await_hangup(int fd, int timeout_ms) {
    struct pollfd descriptor;
    uint8_t byte = 0U;
    ssize_t count;
    int ready;
    descriptor.fd = fd;
    descriptor.events = POLLIN;
    descriptor.revents = 0;
    do {
        ready = poll(&descriptor, 1U, timeout_ms);
    } while (ready < 0 && errno == EINTR);
    if (ready != 1
            || (descriptor.revents & (POLLHUP | POLLERR)) == 0) {
        printf("TIMEOUT\n");
        (void)fflush(stdout);
        return 3;
    }
    do {
        count = read(fd, &byte, 1U);
    } while (count < 0 && errno == EINTR);
    if (count == 0) {
        printf("CLOSED\n");
        (void)fflush(stdout);
        return 0;
    }
    printf("%s\n", count > 0 ? "DATA" : "ERROR read");
    (void)fflush(stdout);
    return 3;
}

static int run_status(const char *socket_path, int capability_fd, bool twice) {
    ksec_client *client = NULL;
    uint32_t flags = 0U;
    unsigned int left = 3U;
    ksec_result result = ksec_connect_at(&client, socket_path, capability_fd);
    if (result != KSEC_OK) {
        print_error(result);
        ksec_client_free(client);
        return 3;
    }
    result = ksec_status(client, &flags);
    if (result != KSEC_OK) {
        print_error(result);
        ksec_client_free(client);
        return 3;
    }
    printf("FLAGS %lu\n", (unsigned long)flags);
    (void)fflush(stdout);
    if (!twice) {
        ksec_client_free(client);
        return 0;
    }
    while (left > 0U) left = sleep(left);
    flags = 0U;
    result = ksec_status(client, &flags);
    if (result != KSEC_OK) print_error(result);
    else {
        printf("FLAGS %lu\n", (unsigned long)flags);
        (void)fflush(stdout);
    }
    ksec_client_free(client);
    return 0;
}

static int run_watch(const char *socket_path, int capability_fd, int timeout_ms) {
    ksec_client *client = NULL;
    int watch_fd = -1;
    int quiet;
    int exit_code;
    ksec_result result = ksec_connect_at(&client, socket_path, capability_fd);
    if (result != KSEC_OK) {
        print_error(result);
        ksec_client_free(client);
        return 3;
    }
    result = ksec_watch(client, &watch_fd);
    if (result != KSEC_OK) {
        print_error(result);
        ksec_client_free(client);
        return 3;
    }
    quiet = descriptor_is_quiet_watch(watch_fd);
    if (quiet != 0) {
        printf("%s\n", quiet == -3 ? "DATA" : quiet == -2 ? "EARLY-HUP"
                                                          : "ERROR descriptor");
        (void)fflush(stdout);
        (void)close(watch_fd);
        ksec_client_free(client);
        return 3;
    }
    printf("READY\n");
    (void)fflush(stdout);
    exit_code = await_hangup(watch_fd, timeout_ms);
    (void)close(watch_fd);
    ksec_client_free(client);
    return exit_code;
}

static int run_watch_pass(const char *socket_path, int capability_fd,
                          int control_fd) {
    ksec_client *client = NULL;
    int watch_fd = -1;
    int quiet;
    ksec_result result = ksec_connect_at(&client, socket_path, capability_fd);
    if (result != KSEC_OK) {
        print_error(result);
        ksec_client_free(client);
        return 3;
    }
    result = ksec_watch(client, &watch_fd);
    if (result != KSEC_OK) {
        print_error(result);
        ksec_client_free(client);
        return 3;
    }
    quiet = descriptor_is_quiet_watch(watch_fd);
    if (quiet != 0) {
        printf("%s\n", quiet == -3 ? "DATA" : quiet == -2 ? "EARLY-HUP"
                                                          : "ERROR descriptor");
        (void)fflush(stdout);
        (void)close(watch_fd);
        ksec_client_free(client);
        return 3;
    }
    if (send_fd(control_fd, watch_fd) != 0) {
        (void)close(watch_fd);
        ksec_client_free(client);
        return 1;
    }
    (void)close(watch_fd);
    ksec_client_free(client);
    return 0;
}

static int open_quiet_watch(ksec_client *client, int *out_fd) {
    int quiet;
    ksec_result result = ksec_watch(client, out_fd);
    if (result != KSEC_OK) return (int)result;
    quiet = descriptor_is_quiet_watch(*out_fd);
    if (quiet == 0) return 0;
    printf("%s\n", quiet == -3 ? "DATA" : quiet == -2 ? "EARLY-HUP"
                                                      : "ERROR descriptor");
    (void)fflush(stdout);
    return -1;
}

static int run_limit(const char *socket_path, int capability_fd) {
    int watches[KSEC_MAX_WATCHES];
    ksec_client *client = NULL;
    size_t index;
    size_t opened = 0U;
    int extra = -1;
    int opened_code;
    ksec_result result = KSEC_ERR_IO;
    for (index = 0U; index < KSEC_MAX_WATCHES; index++) watches[index] = -1;
    result = ksec_connect_at(&client, socket_path, capability_fd);
    if (result != KSEC_OK) {
        print_error(result);
        ksec_client_free(client);
        return 3;
    }
    while (opened < KSEC_MAX_WATCHES) {
        int fd = -1;
        opened_code = open_quiet_watch(client, &fd);
        if (opened_code != 0) {
            if (fd >= 0) watches[opened++] = fd;
            if (opened_code > 0) print_error((ksec_result)opened_code);
            result = KSEC_ERR_PROTOCOL;
            goto out;
        }
        watches[opened++] = fd;
    }
    result = ksec_watch(client, &extra);
    if (extra >= 0) {
        (void)close(extra);
        extra = -1;
    }
    if (result != KSEC_ERR_LIMIT) {
        if (result == KSEC_OK) {
            printf("ERROR overflow\n");
            (void)fflush(stdout);
        } else {
            print_error(result);
        }
        goto out;
    }
    printf("LIMIT %zu/%u QUIET %zu/%u\n", opened, KSEC_MAX_WATCHES,
           opened, KSEC_MAX_WATCHES);
    (void)fflush(stdout);
    for (index = 0U; index < opened; index++) {
        if (watches[index] >= 0) {
            (void)close(watches[index]);
            watches[index] = -1;
        }
    }
    printf("DROPPED\n");
    (void)fflush(stdout);
    result = KSEC_OK;
out:
    for (index = 0U; index < opened; index++) {
        if (watches[index] >= 0) (void)close(watches[index]);
    }
    ksec_client_free(client);
    return result == KSEC_OK ? 0 : 3;
}

/* 0 = filled 128 and the next was LIMIT, 1 = slots still held, -1 = fatal. */
static int pressure_cycle(const char *socket_path, int capability_fd) {
    int watches[KSEC_MAX_WATCHES];
    ksec_client *client = NULL;
    size_t index;
    size_t opened = 0U;
    int extra = -1;
    int opened_code;
    int outcome = -1;
    ksec_result result;
    for (index = 0U; index < KSEC_MAX_WATCHES; index++) watches[index] = -1;
    result = ksec_connect_at(&client, socket_path, capability_fd);
    if (result != KSEC_OK) {
        print_error(result);
        ksec_client_free(client);
        return -1;
    }
    opened_code = open_quiet_watch(client, &watches[0]);
    if (opened_code == (int)KSEC_ERR_LIMIT && watches[0] < 0) {
        outcome = 1;
        goto out;
    }
    if (opened_code != 0) {
        if (opened_code > 0) print_error((ksec_result)opened_code);
        goto out;
    }
    opened = 1U;
    while (opened < KSEC_MAX_WATCHES) {
        int fd = -1;
        opened_code = open_quiet_watch(client, &fd);
        if (opened_code != 0) {
            if (fd >= 0) watches[opened++] = fd;
            if (opened_code > 0) print_error((ksec_result)opened_code);
            goto out;
        }
        watches[opened++] = fd;
    }
    result = ksec_watch(client, &extra);
    if (extra >= 0) (void)close(extra);
    if (result == KSEC_ERR_LIMIT) outcome = 0;
    else if (result == KSEC_OK) {
        printf("ERROR overflow\n");
        (void)fflush(stdout);
    } else {
        print_error(result);
    }
out:
    for (index = 0U; index < opened; index++) {
        if (watches[index] >= 0) (void)close(watches[index]);
    }
    ksec_client_free(client);
    return outcome;
}

static int run_pressure_child(const char *socket_path, int control_fd,
                              uint32_t cycles) {
    uint32_t done = 0U;
    uint32_t retries = 0U;
    while (done < cycles) {
        char request = 'C';
        char reply;
        int capability_fd;
        int outcome;
        if (write(control_fd, &request, 1U) != 1) return 1;
        capability_fd = receive_fd(control_fd);
        if (capability_fd < 0) return 1;
        outcome = pressure_cycle(socket_path, capability_fd);
        if (outcome == 0) {
            reply = 'K';
            retries = 0U;
            done++;
        } else if (outcome == 1) {
            retries++;
            if (retries > 50U) {
                printf("ERROR reclaim\n");
                (void)fflush(stdout);
                return 3;
            }
            reply = 'R';
            (void)poll(NULL, 0U, 20);
        } else {
            return 3;
        }
        if (write(control_fd, &reply, 1U) != 1) return 1;
    }
    printf("PRESSURE %lu/%lu\n", (unsigned long)done, (unsigned long)cycles);
    (void)fflush(stdout);
    return 0;
}

static int drive_pressure(const char *socket_path, uint32_t cycles) {
    uint8_t record_id[KSEC_RECORD_ID_BYTES];
    int control[2] = {-1, -1};
    int status = 0;
    uint32_t done = 0U;
    pid_t child;
    memset(record_id, 0xA5, sizeof record_id);
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, control) != 0) {
        return 1;
    }
    child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        int result;
        (void)close(control[0]);
        if (prctl(PR_SET_PDEATHSIG, SIGTERM) != 0 || getppid() == 1) _exit(1);
        result = run_pressure_child(socket_path, control[1], cycles);
        (void)close(control[1]);
        _exit(result);
    }
    (void)close(control[1]);
    while (done < cycles) {
        char request = 0;
        ssize_t count;
        do {
            count = read(control[0], &request, 1U);
        } while (count < 0 && errno == EINTR);
        if (count != 1) break;
        if (request == 'C') {
            int capability_fd = -1;
            ksec_result result = ksec_supervisor_mint(
                    socket_path, child, "kilix-secrets.status",
                    KSEC_VERB_DOCTOR, 300U, &capability_fd);
            if (result != KSEC_OK || capability_fd < 0
                    || send_fd(control[0], capability_fd) != 0) {
                if (capability_fd >= 0) (void)close(capability_fd);
                (void)kill(child, SIGTERM);
                break;
            }
            (void)close(capability_fd);
        } else if (request == 'K') {
            done++;
        } else if (request != 'R') {
            (void)kill(child, SIGTERM);
            break;
        }
    }
    (void)close(control[0]);
    if (waitpid(child, &status, 0) != child) return 1;
    sodium_memzero(record_id, sizeof record_id);
    if (done != cycles) return 1;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return 1;
}

int main(int argc, char **argv) {
    const char *mode;
    const char *socket_path;
    uint8_t record_id[KSEC_RECORD_ID_BYTES];
    uint32_t verbs = KSEC_VERB_DOCTOR;
    uint32_t lifetime = 300U;
    uint32_t timeout_value = 30000U;
    int control[2] = {-1, -1};
    int status = 0;
    int watch_fd = -1;
    bool twice = false;
    bool scoped = false;
    bool pass = false;
    bool limit = false;
    pid_t child;
    if (argc < 3 || ksec_crypto_initialize() != KSEC_OK
            || signal(SIGPIPE, SIG_IGN) == SIG_ERR) return 2;
    if (setvbuf(stdout, NULL, _IONBF, 0) != 0) return 1;
    mode = argv[1];
    socket_path = argv[2];
    memset(record_id, 0xA5, sizeof record_id);
    if (strcmp(mode, "status") == 0) {
        if (argc < 4 || argc > 5 || parse_verb(argv[3], &verbs) != 0) return 2;
        if (argc == 5) {
            if (strcmp(argv[4], "scoped") != 0) return 2;
            scoped = true;
        }
    } else if (strcmp(mode, "status-expire") == 0) {
        if (argc != 3) return 2;
        lifetime = 2U;
        twice = true;
    } else if (strcmp(mode, "watch") == 0) {
        if (argc < 4 || argc > 5
                || parse_u32(argv[3], &timeout_value) != 0
                || timeout_value == 0U || timeout_value > 60000U) return 2;
        if (argc == 5
                && (parse_u32(argv[4], &lifetime) != 0 || lifetime == 0U
                    || lifetime > 300U)) return 2;
    } else if (strcmp(mode, "watch-pass") == 0) {
        if (argc != 3) return 2;
        pass = true;
    } else if (strcmp(mode, "watch-limit") == 0) {
        if (argc != 3) return 2;
        limit = true;
    } else if (strcmp(mode, "watch-pressure") == 0) {
        uint32_t cycles = 0U;
        if (argc != 4 || parse_u32(argv[3], &cycles) != 0
                || cycles == 0U || cycles > 64U) return 2;
        return drive_pressure(socket_path, cycles);
    } else {
        return 2;
    }
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, control) != 0) {
        return 1;
    }
    child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        int capability_fd;
        int result;
        (void)close(control[0]);
        if (prctl(PR_SET_PDEATHSIG, SIGTERM) != 0 || getppid() == 1) _exit(1);
        capability_fd = receive_fd(control[1]);
        if (capability_fd < 0) _exit(1);
        if (twice || strcmp(mode, "status") == 0) {
            result = run_status(socket_path, capability_fd, twice);
        } else if (pass) {
            result = run_watch_pass(socket_path, capability_fd, control[1]);
        } else if (limit) {
            result = run_limit(socket_path, capability_fd);
        } else {
            result = run_watch(socket_path, capability_fd, (int)timeout_value);
        }
        (void)close(control[1]);
        _exit(result);
    }
    (void)close(control[1]);
    control[1] = -1;
    {
        int capability_fd = -1;
        ksec_result result = scoped
            ? ksec_supervisor_mint_scoped(socket_path, child,
                                          "kilix-secrets.status", verbs,
                                          record_id, lifetime, &capability_fd)
            : ksec_supervisor_mint(socket_path, child, "kilix-secrets.status",
                                   verbs, lifetime, &capability_fd);
        if (result != KSEC_OK || capability_fd < 0
                || send_fd(control[0], capability_fd) != 0) {
            (void)kill(child, SIGTERM);
        }
        if (capability_fd >= 0) (void)close(capability_fd);
    }
    if (pass) {
        watch_fd = receive_fd(control[0]);
        (void)close(control[0]);
        control[0] = -1;
        if (watch_fd < 0) (void)kill(child, SIGTERM);
        if (waitpid(child, &status, 0) != child) {
            if (watch_fd >= 0) (void)close(watch_fd);
            return 1;
        }
        if (watch_fd < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            if (watch_fd >= 0) (void)close(watch_fd);
            if (WIFEXITED(status)) return WEXITSTATUS(status);
            if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
            return 1;
        }
        status = await_hangup(watch_fd, 2000);
        (void)close(watch_fd);
        sodium_memzero(record_id, sizeof record_id);
        return status;
    }
    if (control[0] >= 0) (void)close(control[0]);
    if (waitpid(child, &status, 0) != child) return 1;
    sodium_memzero(record_id, sizeof record_id);
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return 1;
}
