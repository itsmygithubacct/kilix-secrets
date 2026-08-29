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
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static int send_fd(int socket_fd, int passed_fd) {
    char marker = 'I';
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
    if (count != 1 || marker != 'I' || (message.msg_flags & MSG_CTRUNC) != 0) {
        return -1;
    }
    cmsg = CMSG_FIRSTHDR(&message);
    if (cmsg == NULL || CMSG_NXTHDR(&message, cmsg) != NULL
            || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS
            || cmsg->cmsg_len != CMSG_LEN(sizeof(int))) return -1;
    memcpy(&received, CMSG_DATA(cmsg), sizeof received);
    return received;
}

static int read_key(int fd, uint8_t key[KSEC_IDENTITY_KEY_BYTES]) {
    uint8_t extra = 0U;
    ssize_t count;
    if (fd < 0 || ksec_read_exact(fd, key, KSEC_IDENTITY_KEY_BYTES) != 0) {
        return -1;
    }
    do {
        count = read(fd, &extra, 1U);
    } while (count < 0 && errno == EINTR);
    sodium_memzero(&extra, sizeof extra);
    return count == 0 ? 0 : -1;
}

static int run_open(const char *mode, const char *socket_path,
                    const uint8_t record_id[KSEC_RECORD_ID_BYTES],
                    const char *expected_text, int capability_fd) {
    uint8_t private_key[KSEC_IDENTITY_KEY_BYTES];
    uint8_t expected[KSEC_IDENTITY_ANCHOR_BYTES];
    const uint8_t *expected_pointer = NULL;
    ksec_identity_info info;
    ksec_client *client = NULL;
    char public_hex[KSEC_IDENTITY_KEY_BYTES * 2U + 1U];
    char anchor_hex[KSEC_IDENTITY_ANCHOR_BYTES * 2U + 1U];
    char uuid_hex[KSEC_UUID_BYTES * 2U + 1U];
    int lease_fd = -1;
    int exit_code = 1;
    ksec_result result;
    memset(private_key, 0, sizeof private_key);
    memset(expected, 0, sizeof expected);
    memset(&info, 0, sizeof info);
    memset(public_hex, 0, sizeof public_hex);
    memset(anchor_hex, 0, sizeof anchor_hex);
    memset(uuid_hex, 0, sizeof uuid_hex);
    if (strcmp(expected_text, "-") != 0) {
        if (ksec_hex_decode(expected_text, expected, sizeof expected) != 0) {
            return 2;
        }
        expected_pointer = expected;
    }
    if (sodium_mlock(private_key, sizeof private_key) != 0) return 1;
    result = ksec_connect_at(&client, socket_path, capability_fd);
    if (result == KSEC_OK) {
        result = ksec_identity_open(client, record_id, expected_pointer,
                                    private_key, &info, &lease_fd);
    }
    if (result != KSEC_OK) {
        printf("ERROR %s\n", ksec_result_string(result));
        (void)fflush(stdout);
        exit_code = 3;
        goto out;
    }
    ksec_hex_encode(info.public_key, sizeof info.public_key, public_hex);
    ksec_hex_encode(info.anchor, sizeof info.anchor, anchor_hex);
    ksec_hex_encode(info.vault_uuid, sizeof info.vault_uuid, uuid_hex);
    printf("READY %s %s %s %llu\n", public_hex, anchor_hex, uuid_hex,
           (unsigned long long)info.record_revision);
    if (fflush(stdout) != 0) goto out;
    if (strcmp(mode, "probe") == 0) {
        exit_code = 0;
        goto out;
    }
    {
        struct pollfd descriptor = {lease_fd, POLLIN | POLLHUP | POLLERR, 0};
        int ready;
        do {
            ready = poll(&descriptor, 1U, 60000);
        } while (ready < 0 && errno == EINTR);
        if (ready != 1
                || (descriptor.revents & (POLLHUP | POLLERR)) == 0) goto out;
    }
    printf("CLOSED\n");
    if (fflush(stdout) != 0) goto out;
    exit_code = 0;
out:
    if (lease_fd >= 0) (void)close(lease_fd);
    ksec_client_free(client);
    sodium_memzero(private_key, sizeof private_key);
    sodium_memzero(expected, sizeof expected);
    sodium_memzero(&info, sizeof info);
    sodium_memzero(public_hex, sizeof public_hex);
    sodium_memzero(anchor_hex, sizeof anchor_hex);
    sodium_memzero(uuid_hex, sizeof uuid_hex);
    (void)sodium_munlock(private_key, sizeof private_key);
    return exit_code;
}

static int run_replace(const char *socket_path,
                       const uint8_t record_id[KSEC_RECORD_ID_BYTES],
                       int key_fd, int capability_fd) {
    uint8_t private_key[KSEC_IDENTITY_KEY_BYTES];
    ksec_field field;
    ksec_record record;
    ksec_client *client = NULL;
    ksec_result result = KSEC_ERR_IO;
    memset(private_key, 0, sizeof private_key);
    memset(&field, 0, sizeof field);
    memset(&record, 0, sizeof record);
    if (sodium_mlock(private_key, sizeof private_key) != 0) return 1;
    if (read_key(key_fd, private_key) != 0) goto out;
    result = ksec_connect_at(&client, socket_path, capability_fd);
    if (result != KSEC_OK) goto out;
    field.name = KSEC_IDENTITY_PRIVATE_FIELD;
    field.value = private_key;
    field.value_len = sizeof private_key;
    record.owner = KSEC_IDENTITY_OWNER;
    record.type = KSEC_IDENTITY_TYPE;
    record.label = "F112/F113 local identity";
    record.fields = &field;
    record.field_count = 1U;
    result = ksec_replace(client, record_id, &record);
    if (result == KSEC_OK) {
        printf("REPLACED\n");
        (void)fflush(stdout);
    } else {
        printf("ERROR %s\n", ksec_result_string(result));
        (void)fflush(stdout);
    }
out:
    ksec_client_free(client);
    sodium_memzero(private_key, sizeof private_key);
    (void)sodium_munlock(private_key, sizeof private_key);
    return result == KSEC_OK ? 0 : 3;
}

static int run_info(const char *socket_path,
                    const uint8_t record_id[KSEC_RECORD_ID_BYTES],
                    const char *expected_text, int capability_fd) {
    uint8_t expected[KSEC_IDENTITY_ANCHOR_BYTES];
    const uint8_t *expected_pointer = NULL;
    ksec_identity_info info;
    ksec_client *client = NULL;
    char public_hex[KSEC_IDENTITY_KEY_BYTES * 2U + 1U];
    char anchor_hex[KSEC_IDENTITY_ANCHOR_BYTES * 2U + 1U];
    char uuid_hex[KSEC_UUID_BYTES * 2U + 1U];
    ksec_result result;
    memset(expected, 0, sizeof expected);
    memset(&info, 0, sizeof info);
    memset(public_hex, 0, sizeof public_hex);
    memset(anchor_hex, 0, sizeof anchor_hex);
    memset(uuid_hex, 0, sizeof uuid_hex);
    if (strcmp(expected_text, "-") != 0) {
        if (ksec_hex_decode(expected_text, expected, sizeof expected) != 0) {
            return 2;
        }
        expected_pointer = expected;
    }
    result = ksec_connect_at(&client, socket_path, capability_fd);
    if (result == KSEC_OK) {
        result = ksec_identity_info_get(client, record_id, expected_pointer,
                                        &info);
    }
    if (result == KSEC_OK) {
        ksec_hex_encode(info.public_key, sizeof info.public_key, public_hex);
        ksec_hex_encode(info.anchor, sizeof info.anchor, anchor_hex);
        ksec_hex_encode(info.vault_uuid, sizeof info.vault_uuid, uuid_hex);
        printf("INFO %s %s %s %llu\n", public_hex, anchor_hex, uuid_hex,
               (unsigned long long)info.record_revision);
    } else {
        printf("ERROR %s\n", ksec_result_string(result));
    }
    (void)fflush(stdout);
    ksec_client_free(client);
    sodium_memzero(expected, sizeof expected);
    sodium_memzero(&info, sizeof info);
    sodium_memzero(public_hex, sizeof public_hex);
    sodium_memzero(anchor_hex, sizeof anchor_hex);
    sodium_memzero(uuid_hex, sizeof uuid_hex);
    return result == KSEC_OK ? 0 : 3;
}

static int run_limit(const char *socket_path,
                     const uint8_t record_id[KSEC_RECORD_ID_BYTES],
                     int capability_fd) {
    uint8_t private_key[KSEC_IDENTITY_KEY_BYTES];
    ksec_identity_info info;
    ksec_client *client = NULL;
    int lease_fds[KSEC_MAX_IDENTITY_LEASES];
    size_t opened = 0U;
    size_t index;
    bool capped = false;
    bool reclaimed = false;
    ksec_result result;
    memset(private_key, 0, sizeof private_key);
    memset(&info, 0, sizeof info);
    for (index = 0U; index < KSEC_MAX_IDENTITY_LEASES; index++) {
        lease_fds[index] = -1;
    }
    if (sodium_mlock(private_key, sizeof private_key) != 0) return 1;
    result = ksec_connect_at(&client, socket_path, capability_fd);
    while (result == KSEC_OK && opened < KSEC_MAX_IDENTITY_LEASES) {
        result = ksec_identity_open(client, record_id, NULL, private_key,
                                    &info, &lease_fds[opened]);
        sodium_memzero(private_key, sizeof private_key);
        sodium_memzero(&info, sizeof info);
        if (result == KSEC_OK) opened++;
    }
    if (result == KSEC_OK) {
        int extra_fd = -1;
        result = ksec_identity_open(client, record_id, NULL, private_key,
                                    &info, &extra_fd);
        if (extra_fd >= 0) (void)close(extra_fd);
    }
    capped = opened == KSEC_MAX_IDENTITY_LEASES && result == KSEC_ERR_LIMIT;
    if (capped) {
        int replacement_fd = -1;
        if (lease_fds[0] >= 0) {
            (void)close(lease_fds[0]);
            lease_fds[0] = -1;
        }
        (void)poll(NULL, 0U, 1500);
        result = ksec_identity_open(client, record_id, NULL, private_key,
                                    &info, &replacement_fd);
        reclaimed = result == KSEC_OK && replacement_fd >= 0;
        if (replacement_fd >= 0) (void)close(replacement_fd);
    }
    if (capped && reclaimed) {
        printf("LIMIT %zu/%u RECLAIM 1/1\n", opened,
               KSEC_MAX_IDENTITY_LEASES);
        (void)fflush(stdout);
    }
    for (index = 0U; index < opened; index++) {
        if (lease_fds[index] >= 0) (void)close(lease_fds[index]);
    }
    ksec_client_free(client);
    sodium_memzero(private_key, sizeof private_key);
    sodium_memzero(&info, sizeof info);
    (void)sodium_munlock(private_key, sizeof private_key);
    return capped && reclaimed ? 0 : 3;
}

static int parse_fd(const char *text, int *out) {
    char *end = NULL;
    long value;
    errno = 0;
    value = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value < 0
            || value > INT_MAX) return -1;
    *out = (int)value;
    return 0;
}

int main(int argc, char **argv) {
    uint8_t record_id[KSEC_RECORD_ID_BYTES];
    uint32_t verbs;
    int control[2] = {-1, -1};
    int key_fd = -1;
    int status = 0;
    pid_t child;
    if (argc < 4 || argc > 5
            || (strcmp(argv[1], "open") != 0
                && strcmp(argv[1], "expire") != 0
                && strcmp(argv[1], "info") != 0
                && strcmp(argv[1], "probe") != 0
                && strcmp(argv[1], "limit") != 0
                && strcmp(argv[1], "replace") != 0)
            || ksec_hex_decode(argv[3], record_id, sizeof record_id) != 0
            || ksec_crypto_initialize() != KSEC_OK
            || signal(SIGPIPE, SIG_IGN) == SIG_ERR) return 2;
    if (strcmp(argv[1], "replace") == 0) {
        if (argc != 5 || parse_fd(argv[4], &key_fd) != 0) return 2;
        verbs = KSEC_VERB_REPLACE;
    } else {
        if (argc != 5) return 2;
        verbs = KSEC_VERB_USE;
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
        if (strcmp(argv[1], "replace") == 0) {
            result = run_replace(argv[2], record_id, key_fd, capability_fd);
        } else if (strcmp(argv[1], "limit") == 0) {
            result = run_limit(argv[2], record_id, capability_fd);
        } else if (strcmp(argv[1], "info") == 0) {
            result = run_info(argv[2], record_id, argv[4], capability_fd);
        } else {
            result = run_open(argv[1], argv[2], record_id, argv[4],
                              capability_fd);
        }
        (void)close(capability_fd);
        _exit(result);
    }
    (void)close(control[1]);
    {
        int capability_fd = -1;
        uint32_t lifetime = strcmp(argv[1], "expire") == 0 ? 2U : 300U;
        ksec_result result = ksec_supervisor_mint_scoped(
                argv[2], child, KSEC_IDENTITY_OWNER, verbs, record_id, lifetime,
                &capability_fd);
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
