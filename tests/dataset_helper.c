/* Drives dataset create, seal and unseal, plus the raw descriptor cases. */
#define _GNU_SOURCE

#include "internal.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static int send_fd(int socket_fd, int passed_fd) {
    char marker = 'D';
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
    if (count != 1 || marker != 'D' || (message.msg_flags & MSG_CTRUNC) != 0) {
        return -1;
    }
    cmsg = CMSG_FIRSTHDR(&message);
    if (cmsg == NULL || CMSG_NXTHDR(&message, cmsg) != NULL
            || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS
            || cmsg->cmsg_len != CMSG_LEN(sizeof(int))) return -1;
    memcpy(&received, CMSG_DATA(cmsg), sizeof received);
    return received;
}

static int print_result(ksec_result result) {
    if (result == KSEC_OK) printf("OK\n");
    else printf("ERROR %s\n", ksec_result_string(result));
    return fflush(stdout) == 0 ? (result == KSEC_OK ? 0 : 3) : 1;
}

static int open_output(const char *path) {
    int fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    if (lseek(fd, 0, SEEK_SET) != 0) {
        (void)close(fd);
        return -1;
    }
    return fd;
}

static int connect_unix(const char *path) {
    struct sockaddr_un address;
    size_t length;
    int fd;
    if (path == NULL) return -1;
    length = strlen(path);
    if (path[0] != '/' || length == 0U || length >= sizeof address.sun_path) {
        return -1;
    }
    fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    memset(&address, 0, sizeof address);
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, path, length + 1U);
    if (connect(fd, (struct sockaddr *)&address, sizeof address) != 0) {
        (void)close(fd);
        return -1;
    }
    return fd;
}

static uint64_t fresh_request_id(void) {
    uint64_t value = 0U;
    randombytes_buf(&value, sizeof value);
    return value == 0U ? 1U : value;
}

/* ksec_connect_at closes capability_fd. Callers must not close it again. */
static int run_create(const char *socket_path, const char *label,
                      int capability_fd) {
    ksec_client *client = NULL;
    uint8_t record_id[KSEC_RECORD_ID_BYTES];
    char hex[KSEC_RECORD_ID_BYTES * 2U + 1U];
    ksec_result result;
    memset(record_id, 0, sizeof record_id);
    memset(hex, 0, sizeof hex);
    result = ksec_connect_at(&client, socket_path, capability_fd);
    if (result == KSEC_OK) result = ksec_dataset_create(client, label, record_id);
    if (result == KSEC_OK) {
        ksec_hex_encode(record_id, sizeof record_id, hex);
        printf("OK %s\n", hex);
        if (fflush(stdout) != 0) result = KSEC_ERR_IO;
    }
    ksec_client_free(client);
    sodium_memzero(record_id, sizeof record_id);
    sodium_memzero(hex, sizeof hex);
    return result == KSEC_OK ? 0 : print_result(result);
}

static int run_seal(const char *socket_path,
                    const uint8_t record_id[KSEC_RECORD_ID_BYTES],
                    const char *name, uint64_t revision,
                    const char *input_path, const char *output_path,
                    int announce, int capability_fd) {
    ksec_client *client = NULL;
    int input_fd;
    int output_fd;
    ksec_result result;
    input_fd = open(input_path, O_RDONLY | O_CLOEXEC);
    output_fd = open_output(output_path);
    if (input_fd < 0 || output_fd < 0) {
        if (input_fd >= 0) (void)close(input_fd);
        if (output_fd >= 0) (void)close(output_fd);
        (void)close(capability_fd);
        return print_result(KSEC_ERR_IO);
    }
    result = ksec_connect_at(&client, socket_path, capability_fd);
    if (result == KSEC_OK && announce) {
        printf("SENDING\n");
        if (fflush(stdout) != 0) result = KSEC_ERR_IO;
    }
    if (result == KSEC_OK) {
        result = ksec_seal_fd(client, record_id, name, revision,
                              input_fd, output_fd);
    }
    (void)close(input_fd);
    (void)close(output_fd);
    ksec_client_free(client);
    return print_result(result);
}

static int run_unseal(const char *socket_path,
                      const uint8_t record_id[KSEC_RECORD_ID_BYTES],
                      const char *name, const char *input_path,
                      const char *output_path, int capability_fd) {
    ksec_client *client = NULL;
    uint64_t revision = 0U;
    int input_fd;
    int output_fd;
    ksec_result result;
    input_fd = open(input_path, O_RDONLY | O_CLOEXEC);
    output_fd = open_output(output_path);
    if (input_fd < 0 || output_fd < 0) {
        if (input_fd >= 0) (void)close(input_fd);
        if (output_fd >= 0) (void)close(output_fd);
        (void)close(capability_fd);
        return print_result(KSEC_ERR_IO);
    }
    result = ksec_connect_at(&client, socket_path, capability_fd);
    if (result == KSEC_OK) {
        result = ksec_unseal_fd(client, record_id, name, input_fd, output_fd,
                                &revision);
    }
    (void)close(input_fd);
    (void)close(output_fd);
    ksec_client_free(client);
    if (result == KSEC_OK) {
        printf("OK %llu\n", (unsigned long long)revision);
        if (fflush(stdout) != 0) return 1;
        return 0;
    }
    return print_result(result);
}

static int run_replace(const char *socket_path, const char *app_id,
                       const uint8_t record_id[KSEC_RECORD_ID_BYTES],
                       int capability_fd) {
    ksec_client *client = NULL;
    ksec_field field;
    ksec_record record;
    uint8_t value[4] = {'w', 'x', 'y', 'z'};
    ksec_result result;
    memset(&field, 0, sizeof field);
    memset(&record, 0, sizeof record);
    result = ksec_connect_at(&client, socket_path, capability_fd);
    if (result == KSEC_OK) {
        field.name = "value";
        field.value = value;
        field.value_len = sizeof value;
        record.owner = app_id;
        record.type = "opaque";
        record.label = "replacement";
        record.fields = &field;
        record.field_count = 1U;
        result = ksec_replace(client, record_id, &record);
    }
    ksec_client_free(client);
    sodium_memzero(value, sizeof value);
    return print_result(result);
}

static int run_put_type(const char *socket_path, const char *app_id,
                        int capability_fd) {
    ksec_client *client = NULL;
    ksec_field field;
    ksec_record record;
    uint8_t value[KSEC_DATASET_KEY_BYTES];
    uint8_t record_id[KSEC_RECORD_ID_BYTES];
    ksec_result result;
    memset(value, 'A', sizeof value);
    memset(record_id, 0, sizeof record_id);
    memset(&field, 0, sizeof field);
    memset(&record, 0, sizeof record);
    result = ksec_connect_at(&client, socket_path, capability_fd);
    if (result == KSEC_OK) {
        field.name = KSEC_DATASET_KEY_FIELD;
        field.value = value;
        field.value_len = sizeof value;
        record.owner = app_id;
        record.type = KSEC_DATASET_KEY_TYPE;
        record.label = "not-a-dataset-key";
        record.fields = &field;
        record.field_count = 1U;
        result = ksec_put(client, &record, record_id);
    }
    ksec_client_free(client);
    sodium_memzero(value, sizeof value);
    sodium_memzero(record_id, sizeof record_id);
    return print_result(result);
}

static int run_fill(const char *socket_path, int capability_fd) {
    ksec_client *client = NULL;
    uint8_t record_id[KSEC_RECORD_ID_BYTES];
    size_t created = 0U;
    ksec_result result;
    memset(record_id, 0, sizeof record_id);
    result = ksec_connect_at(&client, socket_path, capability_fd);
    while (result == KSEC_OK && created < (size_t)KSEC_MAX_RECORDS + 1U) {
        result = ksec_dataset_create(client, "fill-key", record_id);
        sodium_memzero(record_id, sizeof record_id);
        if (result == KSEC_OK) created++;
    }
    ksec_client_free(client);
    if (result == KSEC_ERR_LIMIT && created == (size_t)KSEC_MAX_RECORDS) {
        printf("LIMIT %zu\n", created);
        return fflush(stdout) == 0 ? 0 : 1;
    }
    printf("COUNT %zu\n", created);
    if (fflush(stdout) != 0) return 1;
    return print_result(result == KSEC_OK ? KSEC_ERR_LIMIT : result);
}

static int make_memfd(const void *prefix, size_t prefix_len, off_t size,
                      int seal_it) {
    int fd = memfd_create("ksec-dataset-raw", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (fd < 0) return -1;
    if (prefix_len > 0U && ksec_write_all(fd, prefix, prefix_len) != 0) {
        (void)close(fd);
        return -1;
    }
    if (size >= 0 && ftruncate(fd, size) != 0) {
        (void)close(fd);
        return -1;
    }
    if (lseek(fd, 0, SEEK_SET) != 0) {
        (void)close(fd);
        return -1;
    }
    if (seal_it && fcntl(fd, F_ADD_SEALS,
                         F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW
                             | F_SEAL_WRITE) != 0) {
        (void)close(fd);
        return -1;
    }
    return fd;
}

static int prepare_raw_fd(const char *kind, const char *path, int sealing,
                          int *out_fd) {
    static const char hello[] = "hello";
    uint64_t maximum = 0U;
    off_t big;
    int pipes[2] = {-1, -1};
    int fd;
    *out_fd = -1;
    if (strcmp(kind, "missing") == 0) return 0;
    if (strcmp(kind, "unsealed") == 0) {
        fd = make_memfd(hello, sizeof hello - 1U, -1, 0);
        if (fd < 0) return -1;
        *out_fd = fd;
        return 0;
    }
    if (strcmp(kind, "pipe") == 0) {
        if (pipe2(pipes, O_CLOEXEC) != 0) return -1;
        if (ksec_write_all(pipes[1], hello, sizeof hello - 1U) != 0) {
            (void)close(pipes[0]);
            (void)close(pipes[1]);
            return -1;
        }
        (void)close(pipes[1]);
        *out_fd = pipes[0];
        return 0;
    }
    if (strcmp(kind, "regular") == 0) {
        if (path == NULL) return -1;
        fd = open(path, O_RDWR | O_CLOEXEC);
        if (fd < 0) return -1;
        *out_fd = fd;
        return 0;
    }
    if (strcmp(kind, "oversize") == 0 || strcmp(kind, "unsealed-big") == 0) {
        int seal_it = strcmp(kind, "oversize") == 0;
        if (sealing) {
            big = (off_t)KSEC_MAX_DATASET_BYTES + 1;
        } else {
            ksec_result result = ksec_dataset_sealed_length(
                    KSEC_MAX_DATASET_BYTES,
                    (size_t)KSEC_DATASET_PREFIX_FIXED_BYTES
                        + (size_t)KSEC_MAX_APP_ID
                        + (size_t)KSEC_MAX_DATASET_NAME,
                    &maximum);
            if (result != KSEC_OK || maximum >= (uint64_t)INT64_MAX) {
                return result == KSEC_OK ? -1 : (int)result;
            }
            big = (off_t)maximum + 1;
        }
        fd = make_memfd(NULL, 0U, big, seal_it);
        if (fd < 0) return -1;
        *out_fd = fd;
        return 0;
    }
    return -1;
}

static int run_raw(const char *socket_path,
                   const uint8_t record_id[KSEC_RECORD_ID_BYTES],
                   const char *name, uint64_t revision, int sealing,
                   const char *kind, const char *path, int capability_fd) {
    ksec_packet_header request;
    ksec_packet_header reply;
    uint8_t body[KSEC_RECORD_ID_BYTES + 10U + KSEC_MAX_DATASET_NAME];
    uint8_t reply_body[64];
    size_t name_len;
    size_t body_len;
    int sock = -1;
    int passed = -1;
    int received = -1;
    int prepared;
    ksec_result result;
    uint32_t code;
    memset(&request, 0, sizeof request);
    memset(&reply, 0, sizeof reply);
    memset(body, 0, sizeof body);
    memset(reply_body, 0, sizeof reply_body);
    name_len = strlen(name);
    if (name_len > KSEC_MAX_DATASET_NAME) {
        (void)close(capability_fd);
        return print_result(KSEC_ERR_INVALID);
    }
    prepared = prepare_raw_fd(kind, path, sealing, &passed);
    if (prepared != 0) {
        (void)close(capability_fd);
        if (prepared > 0) return print_result((ksec_result)prepared);
        return print_result(KSEC_ERR_IO);
    }
    sock = connect_unix(socket_path);
    if (sock < 0) {
        if (passed >= 0) (void)close(passed);
        (void)close(capability_fd);
        return print_result(KSEC_ERR_IO);
    }
    request.version = KSEC_PROTOCOL_VERSION;
    request.operation = (uint16_t)KSEC_OP_ACTIVATE;
    request.request_id = fresh_request_id();
    result = ksec_send_packet(sock, &request, NULL, capability_fd);
    (void)close(capability_fd);
    capability_fd = -1;
    if (result != KSEC_OK) goto out;
    result = ksec_recv_packet(sock, &reply, reply_body, sizeof reply_body,
                              &received);
    if (received >= 0) {
        (void)close(received);
        received = -1;
    }
    if (result != KSEC_OK) goto out;
    if (reply.operation != (uint16_t)KSEC_OP_ACTIVATE
            || reply.request_id != request.request_id
            || reply.payload_len != 4U) {
        result = KSEC_ERR_PROTOCOL;
        goto out;
    }
    code = ksec_get_u32(reply_body);
    if (code > (uint32_t)KSEC_ERR_CONFLICT) {
        result = KSEC_ERR_PROTOCOL;
        goto out;
    }
    result = (ksec_result)code;
    if (result != KSEC_OK) goto out;
    memcpy(body, record_id, KSEC_RECORD_ID_BYTES);
    if (sealing) {
        ksec_put_u64(body + KSEC_RECORD_ID_BYTES, revision);
        ksec_put_u16(body + KSEC_RECORD_ID_BYTES + 8U, (uint16_t)name_len);
        memcpy(body + KSEC_RECORD_ID_BYTES + 10U, name, name_len);
        body_len = KSEC_RECORD_ID_BYTES + 10U + name_len;
        request.operation = (uint16_t)KSEC_OP_SEAL;
    } else {
        ksec_put_u16(body + KSEC_RECORD_ID_BYTES, (uint16_t)name_len);
        memcpy(body + KSEC_RECORD_ID_BYTES + 2U, name, name_len);
        body_len = KSEC_RECORD_ID_BYTES + 2U + name_len;
        request.operation = (uint16_t)KSEC_OP_UNSEAL;
    }
    request.request_id = fresh_request_id();
    request.payload_len = (uint32_t)body_len;
    result = ksec_send_packet(sock, &request, body, passed);
    if (passed >= 0) {
        (void)close(passed);
        passed = -1;
    }
    if (result != KSEC_OK) goto out;
    result = ksec_recv_packet(sock, &reply, reply_body, sizeof reply_body,
                              &received);
    if (received >= 0) {
        (void)close(received);
        received = -1;
    }
    if (result != KSEC_OK) goto out;
    if (reply.operation != request.operation
            || reply.request_id != request.request_id
            || reply.payload_len < 4U
            || reply.payload_len > sizeof reply_body) {
        result = KSEC_ERR_PROTOCOL;
        goto out;
    }
    code = ksec_get_u32(reply_body);
    if (code > (uint32_t)KSEC_ERR_CONFLICT) {
        result = KSEC_ERR_PROTOCOL;
        goto out;
    }
    result = (ksec_result)code;
out:
    if (passed >= 0) (void)close(passed);
    if (sock >= 0) (void)close(sock);
    sodium_memzero(body, sizeof body);
    sodium_memzero(reply_body, sizeof reply_body);
    return print_result(result);
}

static int parse_revision(const char *text, uint64_t *out) {
    char *end = NULL;
    unsigned long long value;
    errno = 0;
    value = strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0') return -1;
    *out = (uint64_t)value;
    return 0;
}

/* Requests sent with the replies left unread. Matches the B-3 probe. */
#define PIPELINE_FLOOD_COUNT 4000U

static int activate_raw(int sock, int capability_fd, ksec_result *out) {
    ksec_packet_header request;
    ksec_packet_header reply;
    uint8_t reply_body[64];
    int received = -1;
    ksec_result result;
    uint32_t code;
    memset(&request, 0, sizeof request);
    memset(&reply, 0, sizeof reply);
    memset(reply_body, 0, sizeof reply_body);
    request.version = KSEC_PROTOCOL_VERSION;
    request.operation = (uint16_t)KSEC_OP_ACTIVATE;
    request.request_id = fresh_request_id();
    result = ksec_send_packet(sock, &request, NULL, capability_fd);
    (void)close(capability_fd);
    if (result != KSEC_OK) {
        *out = result;
        return -1;
    }
    result = ksec_recv_packet(sock, &reply, reply_body, sizeof reply_body,
                              &received);
    if (received >= 0) (void)close(received);
    if (result != KSEC_OK) {
        *out = result;
        return -1;
    }
    if (reply.operation != (uint16_t)KSEC_OP_ACTIVATE
            || reply.request_id != request.request_id
            || reply.payload_len != 4U) {
        *out = KSEC_ERR_PROTOCOL;
        return -1;
    }
    code = ksec_get_u32(reply_body);
    if (code > (uint32_t)KSEC_ERR_CONFLICT) {
        *out = KSEC_ERR_PROTOCOL;
        return -1;
    }
    *out = (ksec_result)code;
    sodium_memzero(reply_body, sizeof reply_body);
    return *out == KSEC_OK ? 0 : -1;
}

static int sealed_memfd_from_file(const char *path) {
    size_t copied = 0U;
    int input;
    int output;
    input = open(path, O_RDONLY | O_CLOEXEC);
    if (input < 0) return -1;
    output = memfd_create("ksec-dataset-pipe", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (output < 0) {
        (void)close(input);
        return -1;
    }
    if (ksec_copy_fd(input, output, 1024U * 1024U, &copied) != 0
            || copied == 0U
            || lseek(output, 0, SEEK_SET) != 0
            || fcntl(output, F_ADD_SEALS,
                     F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE) != 0) {
        (void)close(input);
        (void)close(output);
        return -1;
    }
    (void)close(input);
    return output;
}

static size_t write_dataset_body(uint8_t *body,
                                 const uint8_t record_id[KSEC_RECORD_ID_BYTES],
                                 int sealing, uint64_t revision, const char *name) {
    size_t name_len = strlen(name);
    memcpy(body, record_id, KSEC_RECORD_ID_BYTES);
    if (sealing) {
        ksec_put_u64(body + KSEC_RECORD_ID_BYTES, revision);
        ksec_put_u16(body + KSEC_RECORD_ID_BYTES + 8U, (uint16_t)name_len);
        memcpy(body + KSEC_RECORD_ID_BYTES + 10U, name, name_len);
        return KSEC_RECORD_ID_BYTES + 10U + name_len;
    }
    ksec_put_u16(body + KSEC_RECORD_ID_BYTES, (uint16_t)name_len);
    memcpy(body + KSEC_RECORD_ID_BYTES + 2U, name, name_len);
    return KSEC_RECORD_ID_BYTES + 2U + name_len;
}

static const char *reply_word(ksec_result result) {
    if (result == KSEC_OK) return "OK";
    if (result == KSEC_ERR_BUSY) return "BUSY";
    return NULL;
}

/* Reads one reply. Closes a received descriptor. Returns 0, or -1 at EOF. */
static int read_dataset_reply(int sock, uint16_t operation, uint64_t request_id,
                              ksec_result *result_out, int *has_fd) {
    ksec_packet_header reply;
    uint8_t reply_body[64];
    int received = -1;
    ksec_result result;
    uint32_t code;
    memset(&reply, 0, sizeof reply);
    memset(reply_body, 0, sizeof reply_body);
    *has_fd = 0;
    result = ksec_recv_packet(sock, &reply, reply_body, sizeof reply_body,
                              &received);
    if (received >= 0) {
        *has_fd = 1;
        (void)close(received);
    }
    if (result != KSEC_OK) return -1;
    if (reply.operation != operation || reply.request_id != request_id
            || reply.payload_len < 4U || reply.payload_len > sizeof reply_body) {
        return -1;
    }
    code = ksec_get_u32(reply_body);
    sodium_memzero(reply_body, sizeof reply_body);
    if (code > (uint32_t)KSEC_ERR_CONFLICT) return -1;
    *result_out = (ksec_result)code;
    return 0;
}

static int send_dataset_op(int sock, uint16_t operation,
                           const uint8_t *body, size_t body_len, int passed,
                           uint64_t *request_id_out) {
    ksec_packet_header request;
    memset(&request, 0, sizeof request);
    request.version = KSEC_PROTOCOL_VERSION;
    request.operation = operation;
    request.request_id = fresh_request_id();
    request.payload_len = (uint32_t)body_len;
    *request_id_out = request.request_id;
    return ksec_send_packet(sock, &request, body, passed) == KSEC_OK ? 0 : -1;
}

/*
 * The first reply can arrive before this process reads it. Stay out of
 * recv after that, long enough for the daemon to handle the request that
 * was already sent. Reading immediately races the daemon and hides the
 * unread reply.
 */
static int pause_after_first_reply(int sock) {
    struct pollfd wait_fd;
    struct timespec delay;
    int ready;
    wait_fd.fd = sock;
    wait_fd.events = POLLIN;
    do {
        wait_fd.revents = 0;
        ready = poll(&wait_fd, 1, 10000);
    } while (ready < 0 && errno == EINTR);
    if (ready <= 0) return -1;
    delay.tv_sec = 1;
    delay.tv_nsec = 0;
    while (nanosleep(&delay, &delay) != 0) {
        if (errno != EINTR) return -1;
    }
    return 0;
}

/* Do not read while the daemon is still answering. It closes on a full queue. */
static int wait_for_hangup(int sock) {
    struct pollfd wait_fd;
    int left = 10000;
    wait_fd.fd = sock;
    wait_fd.events = POLLHUP;
    while (left > 0) {
        int slice = left > 200 ? 200 : left;
        int ready;
        wait_fd.revents = 0;
        ready = poll(&wait_fd, 1, slice);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) return -1;
        if ((wait_fd.revents & (POLLHUP | POLLERR)) != 0) return 0;
        left -= slice;
    }
    return 0;
}

static int print_tagged(const char *label, ksec_result result, int has_fd) {
    const char *word = reply_word(result);
    if (word != NULL) {
        printf("%s %s %s\n", label, word, has_fd ? "FD" : "NOFD");
    } else {
        printf("%s ERROR %s %s\n", label, ksec_result_string(result),
               has_fd ? "FD" : "NOFD");
    }
    return fflush(stdout) == 0 ? 0 : -1;
}

/*
 * Two requests with neither reply read, then one more after both replies
 * have been read. The second must be busy and carry no descriptor. The
 * third must succeed: the connection no longer has an unread reply.
 */
static int run_pipeline(const char *socket_path,
                        const uint8_t record_id[KSEC_RECORD_ID_BYTES],
                        const char *name, int sealing, const char *path,
                        int capability_fd) {
    uint8_t body[KSEC_RECORD_ID_BYTES + 10U + KSEC_MAX_DATASET_NAME];
    uint64_t ids[3];
    size_t body_len;
    int sock = -1;
    int passed = -1;
    int has_fd = 0;
    ksec_result result = KSEC_ERR_IO;
    uint16_t operation = (uint16_t)(sealing ? KSEC_OP_SEAL : KSEC_OP_UNSEAL);
    memset(body, 0, sizeof body);
    memset(ids, 0, sizeof ids);
    passed = sealing ? make_memfd(NULL, 0U, 0, 1) : sealed_memfd_from_file(path);
    if (passed < 0) {
        (void)close(capability_fd);
        return print_result(KSEC_ERR_IO);
    }
    sock = connect_unix(socket_path);
    if (sock < 0 || activate_raw(sock, capability_fd, &result) != 0) {
        if (sock < 0) (void)close(capability_fd);
        if (sock >= 0) (void)close(sock);
        (void)close(passed);
        return print_result(result);
    }
    capability_fd = -1;
    body_len = write_dataset_body(body, record_id, sealing, 7U, name);
    if (send_dataset_op(sock, operation, body, body_len, passed, &ids[0]) != 0
            || send_dataset_op(sock, operation, body, body_len, passed, &ids[1]) != 0
            || pause_after_first_reply(sock) != 0
            || read_dataset_reply(sock, operation, ids[0], &result, &has_fd) != 0
            || print_tagged("FIRST", result, has_fd) != 0
            || read_dataset_reply(sock, operation, ids[1], &result, &has_fd) != 0
            || print_tagged("SECOND", result, has_fd) != 0
            || send_dataset_op(sock, operation, body, body_len, passed, &ids[2]) != 0
            || read_dataset_reply(sock, operation, ids[2], &result, &has_fd) != 0
            || print_tagged("NEXT", result, has_fd) != 0) {
        (void)close(sock);
        (void)close(passed);
        sodium_memzero(body, sizeof body);
        return 1;
    }
    (void)close(sock);
    (void)close(passed);
    sodium_memzero(body, sizeof body);
    return 0;
}

/*
 * Send PIPELINE_FLOOD_COUNT zero-byte seals without reading any reply, the
 * same shape as the B-3 reproducer at --size-mib 0 --count 4000. Reading
 * starts only after the send loop stops, so a reply stays queued while the
 * later requests are handled.
 */
static int run_flood(const char *socket_path,
                     const uint8_t record_id[KSEC_RECORD_ID_BYTES],
                     const char *name, int capability_fd) {
    uint8_t body[KSEC_RECORD_ID_BYTES + 10U + KSEC_MAX_DATASET_NAME];
    uint64_t request_ids[PIPELINE_FLOOD_COUNT];
    size_t body_len;
    size_t sent = 0U;
    size_t ok_count = 0U;
    size_t busy_count = 0U;
    size_t descriptors = 0U;
    size_t index;
    int sock = -1;
    int passed = -1;
    ksec_result result = KSEC_ERR_IO;
    memset(body, 0, sizeof body);
    memset(request_ids, 0, sizeof request_ids);
    passed = make_memfd(NULL, 0U, 0, 1);
    if (passed < 0) {
        (void)close(capability_fd);
        return print_result(KSEC_ERR_IO);
    }
    sock = connect_unix(socket_path);
    if (sock < 0 || activate_raw(sock, capability_fd, &result) != 0) {
        if (sock < 0) (void)close(capability_fd);
        if (sock >= 0) (void)close(sock);
        (void)close(passed);
        return print_result(result);
    }
    capability_fd = -1;
    body_len = write_dataset_body(body, record_id, 1, 0U, name);
    for (index = 0; index < PIPELINE_FLOOD_COUNT; index++) {
        if (send_dataset_op(sock, (uint16_t)KSEC_OP_SEAL, body, body_len, passed,
                            &request_ids[index]) != 0) {
            break;
        }
        sent++;
    }
    /*
     * Replies stay unread until the daemon stops sending. With the default
     * socket buffer it closes; the wait also covers a buffer that holds
     * every busy reply.
     */
    if (wait_for_hangup(sock) != 0) {
        (void)close(sock);
        (void)close(passed);
        sodium_memzero(body, sizeof body);
        return 1;
    }
    for (index = 0; index < sent; index++) {
        int has_fd = 0;
        if (read_dataset_reply(sock, (uint16_t)KSEC_OP_SEAL, request_ids[index],
                               &result, &has_fd) != 0) break;
        if (has_fd) descriptors++;
        if (result == KSEC_OK) ok_count++;
        else if (result == KSEC_ERR_BUSY) busy_count++;
    }
    printf("SENT %zu\nOK %zu\nBUSY %zu\nDESCRIPTORS %zu\n",
           sent, ok_count, busy_count, descriptors);
    (void)close(sock);
    (void)close(passed);
    sodium_memzero(body, sizeof body);
    return fflush(stdout) == 0 ? 0 : 1;
}

static int launch(char **argv, const char *socket_path, const char *app_id,
                  uint32_t verbs, const uint8_t *scope) {
    int control[2] = {-1, -1};
    int status = 0;
    pid_t child;
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
        if (strcmp(argv[1], "create") == 0) {
            result = run_create(socket_path, argv[4], capability_fd);
        } else if (strcmp(argv[1], "fill") == 0) {
            result = run_fill(socket_path, capability_fd);
        } else if (strcmp(argv[1], "put-type") == 0) {
            result = run_put_type(socket_path, app_id, capability_fd);
        } else if (strcmp(argv[1], "replace") == 0) {
            uint8_t record_id[KSEC_RECORD_ID_BYTES];
            if (ksec_hex_decode(argv[4], record_id, sizeof record_id) != 0) {
                (void)close(capability_fd);
                _exit(2);
            }
            result = run_replace(socket_path, app_id, record_id, capability_fd);
            sodium_memzero(record_id, sizeof record_id);
        } else if (strcmp(argv[1], "seal") == 0
                || strcmp(argv[1], "seal-scoped") == 0) {
            uint8_t record_id[KSEC_RECORD_ID_BYTES];
            uint64_t revision = 0U;
            int announce = strcmp(argv[1], "seal") == 0 && argv[9] != NULL
                && strcmp(argv[9], "announce") == 0;
            if (ksec_hex_decode(argv[4], record_id, sizeof record_id) != 0
                    || parse_revision(argv[6], &revision) != 0) {
                (void)close(capability_fd);
                _exit(2);
            }
            result = run_seal(socket_path, record_id, argv[5], revision,
                              argv[7], argv[8], announce, capability_fd);
            sodium_memzero(record_id, sizeof record_id);
        } else if (strcmp(argv[1], "unseal") == 0
                || strcmp(argv[1], "unseal-scoped") == 0) {
            uint8_t record_id[KSEC_RECORD_ID_BYTES];
            if (ksec_hex_decode(argv[4], record_id, sizeof record_id) != 0) {
                (void)close(capability_fd);
                _exit(2);
            }
            result = run_unseal(socket_path, record_id, argv[5], argv[6],
                                argv[7], capability_fd);
            sodium_memzero(record_id, sizeof record_id);
        } else if (strcmp(argv[1], "raw") == 0) {
            uint8_t record_id[KSEC_RECORD_ID_BYTES];
            uint64_t revision = 0U;
            int sealing = strcmp(argv[4], "seal") == 0;
            const char *path = argv[9];
            if (ksec_hex_decode(argv[5], record_id, sizeof record_id) != 0
                    || parse_revision(argv[7], &revision) != 0) {
                (void)close(capability_fd);
                _exit(2);
            }
            result = run_raw(socket_path, record_id, argv[6], revision, sealing,
                             argv[8], path, capability_fd);
            sodium_memzero(record_id, sizeof record_id);
        } else if (strcmp(argv[1], "pipeline") == 0) {
            uint8_t record_id[KSEC_RECORD_ID_BYTES];
            int sealing = strcmp(argv[4], "seal") == 0;
            if (ksec_hex_decode(argv[5], record_id, sizeof record_id) != 0) {
                (void)close(capability_fd);
                _exit(2);
            }
            result = run_pipeline(socket_path, record_id, argv[6], sealing,
                                  sealing ? NULL : argv[7], capability_fd);
            sodium_memzero(record_id, sizeof record_id);
        } else if (strcmp(argv[1], "flood") == 0) {
            uint8_t record_id[KSEC_RECORD_ID_BYTES];
            if (ksec_hex_decode(argv[4], record_id, sizeof record_id) != 0) {
                (void)close(capability_fd);
                _exit(2);
            }
            result = run_flood(socket_path, record_id, argv[5], capability_fd);
            sodium_memzero(record_id, sizeof record_id);
        } else {
            (void)close(capability_fd);
            result = 2;
        }
        _exit(result);
    }
    (void)close(control[1]);
    {
        int capability_fd = -1;
        ksec_result result;
        if (scope == NULL) {
            result = ksec_supervisor_mint(socket_path, child, app_id, verbs,
                                          300U, &capability_fd);
        } else {
            result = ksec_supervisor_mint_scoped(socket_path, child, app_id,
                                                 verbs, scope, 300U,
                                                 &capability_fd);
        }
        if (result != KSEC_OK || capability_fd < 0
                || send_fd(control[0], capability_fd) != 0) {
            (void)kill(child, SIGTERM);
        }
        if (capability_fd >= 0) (void)close(capability_fd);
    }
    (void)close(control[0]);
    if (waitpid(child, &status, 0) != child) return 1;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return 1;
}

int main(int argc, char **argv) {
    uint8_t scope[KSEC_RECORD_ID_BYTES];
    const uint8_t *scope_ptr = NULL;
    uint32_t verbs = 0U;
    int scoped = 0;
    if (setvbuf(stdout, NULL, _IOLBF, 0) != 0) return 1;
    if (ksec_crypto_initialize() != KSEC_OK || signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        return 1;
    }
    if (argc < 4) return 2;
    memset(scope, 0, sizeof scope);
    if (strcmp(argv[1], "create") == 0) {
        if (argc != 5 || ksec_validate_app_id(argv[3]) != 0
                || ksec_validate_name(argv[4], KSEC_MAX_LABEL) != 0) return 2;
        verbs = KSEC_VERB_CREATE;
    } else if (strcmp(argv[1], "fill") == 0) {
        if (argc != 4 || ksec_validate_app_id(argv[3]) != 0) return 2;
        verbs = KSEC_VERB_CREATE;
    } else if (strcmp(argv[1], "put-type") == 0) {
        if (argc != 4 || ksec_validate_app_id(argv[3]) != 0) return 2;
        verbs = KSEC_VERB_CREATE;
    } else if (strcmp(argv[1], "replace") == 0) {
        if (argc != 5 || ksec_validate_app_id(argv[3]) != 0
                || ksec_hex_decode(argv[4], scope, sizeof scope) != 0) return 2;
        verbs = KSEC_VERB_REPLACE;
    } else if (strcmp(argv[1], "seal") == 0) {
        uint64_t revision = 0U;
        if ((argc != 9 && argc != 10) || ksec_validate_app_id(argv[3]) != 0
                || ksec_hex_decode(argv[4], scope, sizeof scope) != 0
                || ksec_validate_name(argv[5], KSEC_MAX_DATASET_NAME) != 0
                || parse_revision(argv[6], &revision) != 0
                || (argc == 10 && strcmp(argv[9], "announce") != 0)) return 2;
        (void)revision;
        verbs = KSEC_VERB_USE;
    } else if (strcmp(argv[1], "unseal") == 0) {
        if (argc != 8 || ksec_validate_app_id(argv[3]) != 0
                || ksec_hex_decode(argv[4], scope, sizeof scope) != 0
                || ksec_validate_name(argv[5], KSEC_MAX_DATASET_NAME) != 0) {
            return 2;
        }
        verbs = KSEC_VERB_USE;
    } else if (strcmp(argv[1], "seal-scoped") == 0) {
        uint64_t revision = 0U;
        if (argc != 10 || ksec_validate_app_id(argv[3]) != 0
                || ksec_hex_decode(argv[4], scope, sizeof scope) != 0
                || ksec_validate_name(argv[5], KSEC_MAX_DATASET_NAME) != 0
                || parse_revision(argv[6], &revision) != 0
                || ksec_hex_decode(argv[9], scope, sizeof scope) != 0) return 2;
        (void)revision;
        verbs = KSEC_VERB_USE;
        scoped = 1;
    } else if (strcmp(argv[1], "unseal-scoped") == 0) {
        if (argc != 9 || ksec_validate_app_id(argv[3]) != 0
                || ksec_hex_decode(argv[4], scope, sizeof scope) != 0
                || ksec_validate_name(argv[5], KSEC_MAX_DATASET_NAME) != 0
                || ksec_hex_decode(argv[8], scope, sizeof scope) != 0) return 2;
        verbs = KSEC_VERB_USE;
        scoped = 1;
    } else if (strcmp(argv[1], "raw") == 0) {
        uint64_t revision = 0U;
        if ((argc != 9 && argc != 10) || ksec_validate_app_id(argv[3]) != 0
                || (strcmp(argv[4], "seal") != 0 && strcmp(argv[4], "unseal") != 0)
                || ksec_hex_decode(argv[5], scope, sizeof scope) != 0
                || ksec_validate_name(argv[6], KSEC_MAX_DATASET_NAME) != 0
                || parse_revision(argv[7], &revision) != 0) return 2;
        (void)revision;
        if (strcmp(argv[8], "regular") == 0) {
            if (argc != 10) return 2;
        } else if (argc != 9
                || (strcmp(argv[8], "unsealed") != 0
                    && strcmp(argv[8], "pipe") != 0
                    && strcmp(argv[8], "missing") != 0
                    && strcmp(argv[8], "oversize") != 0
                    && strcmp(argv[8], "unsealed-big") != 0)) {
            return 2;
        }
        verbs = KSEC_VERB_USE;
    } else if (strcmp(argv[1], "pipeline") == 0) {
        int sealing;
        if (argc < 7 || ksec_validate_app_id(argv[3]) != 0
                || (strcmp(argv[4], "seal") != 0 && strcmp(argv[4], "unseal") != 0)
                || ksec_hex_decode(argv[5], scope, sizeof scope) != 0
                || ksec_validate_name(argv[6], KSEC_MAX_DATASET_NAME) != 0) {
            return 2;
        }
        sealing = strcmp(argv[4], "seal") == 0;
        if (sealing) {
            if (argc != 7) return 2;
        } else if (argc != 8) {
            return 2;
        }
        verbs = KSEC_VERB_USE;
    } else if (strcmp(argv[1], "flood") == 0) {
        if (argc != 6 || ksec_validate_app_id(argv[3]) != 0
                || ksec_hex_decode(argv[4], scope, sizeof scope) != 0
                || ksec_validate_name(argv[5], KSEC_MAX_DATASET_NAME) != 0) {
            return 2;
        }
        verbs = KSEC_VERB_USE;
    } else {
        return 2;
    }
    if (scoped) scope_ptr = scope;
    else memset(scope, 0, sizeof scope);
    {
        int code = launch(argv, argv[2], argv[3], verbs, scope_ptr);
        sodium_memzero(scope, sizeof scope);
        return code;
    }
}
