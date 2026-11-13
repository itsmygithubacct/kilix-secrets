/* Puts, replaces and reads records whose field values are taken byte-exact from a file. */
#define _GNU_SOURCE

#include "internal.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define RECORD_OWNER "kilix-secrets.test"
#define RECORD_TYPE "opaque"
#define RECORD_LABEL "line-endings"
#define RECORD_FIELD "value"

static int send_fd(int socket_fd, int passed_fd) {
    char marker = 'R';
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
    if (count != 1 || marker != 'R' || (message.msg_flags & MSG_CTRUNC) != 0) {
        return -1;
    }
    cmsg = CMSG_FIRSTHDR(&message);
    if (cmsg == NULL || CMSG_NXTHDR(&message, cmsg) != NULL
            || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS
            || cmsg->cmsg_len != CMSG_LEN(sizeof(int))) return -1;
    memcpy(&received, CMSG_DATA(cmsg), sizeof received);
    return received;
}

static void report_error(ksec_result result) {
    printf("ERROR %s\n", ksec_result_string(result));
    (void)fflush(stdout);
}

static int load_value(const char *path, ksec_secure_buffer *value) {
    struct stat info;
    uint8_t extra = 0U;
    ssize_t count;
    int fd;
    ksec_result result;
    memset(value, 0, sizeof *value);
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) || info.st_size <= 0
            || (unsigned long long)info.st_size
                > (unsigned long long)KSEC_MAX_SECRET_BYTES) {
        (void)close(fd);
        return -1;
    }
    result = ksec_secure_alloc(value, (size_t)info.st_size);
    if (result != KSEC_OK) {
        (void)close(fd);
        return -1;
    }
    if (ksec_read_exact(fd, value->data, value->len) != 0) {
        (void)close(fd);
        ksec_secure_free(value);
        return -1;
    }
    do {
        count = read(fd, &extra, 1U);
    } while (count < 0 && errno == EINTR);
    sodium_memzero(&extra, sizeof extra);
    if (close(fd) != 0 || count != 0) {
        ksec_secure_free(value);
        return -1;
    }
    return 0;
}

static void fill_record(ksec_record *record, ksec_field *field,
                        const ksec_secure_buffer *value) {
    memset(field, 0, sizeof *field);
    memset(record, 0, sizeof *record);
    field->name = RECORD_FIELD;
    field->value = value->data;
    field->value_len = value->len;
    record->owner = RECORD_OWNER;
    record->type = RECORD_TYPE;
    record->label = RECORD_LABEL;
    record->expires_at = 0U;
    record->fields = field;
    record->field_count = 1U;
    record->grants = NULL;
    record->grant_count = 0U;
}

static int run_put(const char *socket_path, const char *value_path,
                   int capability_fd) {
    ksec_secure_buffer value = {0};
    ksec_field field;
    ksec_record record;
    ksec_client *client = NULL;
    uint8_t record_id[KSEC_RECORD_ID_BYTES];
    char id_hex[KSEC_RECORD_ID_BYTES * 2U + 1U];
    ksec_result result;
    int exit_code = 3;
    memset(record_id, 0, sizeof record_id);
    memset(id_hex, 0, sizeof id_hex);
    if (load_value(value_path, &value) != 0) goto out;
    result = ksec_connect_at(&client, socket_path, capability_fd);
    if (result != KSEC_OK) {
        report_error(result);
        goto out;
    }
    fill_record(&record, &field, &value);
    result = ksec_put(client, &record, record_id);
    if (result != KSEC_OK) {
        report_error(result);
        goto out;
    }
    ksec_hex_encode(record_id, sizeof record_id, id_hex);
    printf("%s\n", id_hex);
    if (fflush(stdout) == 0) exit_code = 0;
out:
    ksec_client_free(client);
    ksec_secure_free(&value);
    sodium_memzero(record_id, sizeof record_id);
    sodium_memzero(id_hex, sizeof id_hex);
    return exit_code;
}

static int run_replace(const char *socket_path,
                       const uint8_t record_id[KSEC_RECORD_ID_BYTES],
                       const char *value_path, int capability_fd) {
    ksec_secure_buffer value = {0};
    ksec_field field;
    ksec_record record;
    ksec_client *client = NULL;
    ksec_result result;
    int exit_code = 3;
    if (load_value(value_path, &value) != 0) goto out;
    result = ksec_connect_at(&client, socket_path, capability_fd);
    if (result != KSEC_OK) {
        report_error(result);
        goto out;
    }
    fill_record(&record, &field, &value);
    result = ksec_replace(client, record_id, &record);
    if (result != KSEC_OK) {
        report_error(result);
        goto out;
    }
    printf("REPLACED\n");
    if (fflush(stdout) == 0) exit_code = 0;
out:
    ksec_client_free(client);
    ksec_secure_free(&value);
    return exit_code;
}

static int run_get(const char *socket_path,
                   const uint8_t record_id[KSEC_RECORD_ID_BYTES],
                   const char *output_path, int capability_fd) {
    ksec_client *client = NULL;
    ksec_result result;
    int output_fd = -1;
    int exit_code = 3;
    output_fd = open(output_path,
                     O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (output_fd < 0) goto out;
    result = ksec_connect_at(&client, socket_path, capability_fd);
    if (result != KSEC_OK) {
        report_error(result);
        goto out;
    }
    result = ksec_get_to_fd(client, record_id, RECORD_FIELD, output_fd);
    if (result == KSEC_OK && fsync(output_fd) != 0) result = KSEC_ERR_IO;
    if (result != KSEC_OK) {
        report_error(result);
        goto out;
    }
    printf("GOT\n");
    if (fflush(stdout) == 0) exit_code = 0;
out:
    if (output_fd >= 0 && close(output_fd) != 0) exit_code = 3;
    if (exit_code != 0 && output_path != NULL) (void)unlink(output_path);
    ksec_client_free(client);
    return exit_code;
}

static int child_main(const char *command, const char *socket_path,
                      const uint8_t record_id[KSEC_RECORD_ID_BYTES],
                      const char *path, int capability_fd) {
    if (strcmp(command, "put") == 0) {
        return run_put(socket_path, path, capability_fd);
    }
    if (strcmp(command, "replace") == 0) {
        return run_replace(socket_path, record_id, path, capability_fd);
    }
    return run_get(socket_path, record_id, path, capability_fd);
}

int main(int argc, char **argv) {
    uint8_t record_id[KSEC_RECORD_ID_BYTES];
    const char *command;
    const char *socket_path;
    const char *path;
    uint32_t verbs;
    int control[2] = {-1, -1};
    int status = 0;
    int scoped = 0;
    pid_t child;
    memset(record_id, 0, sizeof record_id);
    if (argc < 4 || ksec_crypto_initialize() != KSEC_OK
            || signal(SIGPIPE, SIG_IGN) == SIG_ERR) return 2;
    command = argv[1];
    socket_path = argv[2];
    if (strcmp(command, "put") == 0 && argc == 4) {
        path = argv[3];
        verbs = KSEC_VERB_CREATE;
    } else if (strcmp(command, "replace") == 0 && argc == 5
            && ksec_hex_decode(argv[3], record_id, sizeof record_id) == 0) {
        path = argv[4];
        verbs = KSEC_VERB_REPLACE;
        scoped = 1;
    } else if (strcmp(command, "get") == 0 && argc == 5
            && ksec_hex_decode(argv[3], record_id, sizeof record_id) == 0) {
        path = argv[4];
        verbs = KSEC_VERB_USE;
        scoped = 1;
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
        capability_fd = receive_fd(control[1]);
        (void)close(control[1]);
        if (capability_fd < 0) _exit(1);
        result = child_main(command, socket_path, record_id, path,
                            capability_fd);
        _exit(result);
    }
    (void)close(control[1]);
    {
        int capability_fd = -1;
        ksec_result result = scoped
            ? ksec_supervisor_mint_scoped(socket_path, child, RECORD_OWNER,
                                          verbs, record_id, 300U,
                                          &capability_fd)
            : ksec_supervisor_mint(socket_path, child, RECORD_OWNER, verbs,
                                   300U, &capability_fd);
        if (result != KSEC_OK || capability_fd < 0
                || send_fd(control[0], capability_fd) != 0) {
            (void)kill(child, SIGTERM);
        }
        if (capability_fd >= 0) (void)close(capability_fd);
    }
    (void)close(control[0]);
    if (waitpid(child, &status, 0) != child) return 1;
    sodium_memzero(record_id, sizeof record_id);
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return 1;
}
