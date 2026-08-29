#define _GNU_SOURCE

#include "internal.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/un.h>
#include <unistd.h>

struct ksec_client {
    int fd;
    uint64_t next_request;
};

static ksec_result connect_socket(const char *path, int *out_fd) {
    struct sockaddr_un address;
    int fd;
    size_t length;
    if (path == NULL || out_fd == NULL) return KSEC_ERR_INVALID;
    length = strlen(path);
    if (path[0] != '/' || length == 0 || length >= sizeof address.sun_path) {
        return KSEC_ERR_INVALID;
    }
    fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (fd < 0) return KSEC_ERR_IO;
    memset(&address, 0, sizeof address);
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, path, length + 1U);
    if (connect(fd, (struct sockaddr *)&address, sizeof address) != 0) {
        int saved = errno;
        (void)close(fd);
        errno = saved;
        return KSEC_ERR_IO;
    }
    *out_fd = fd;
    return KSEC_OK;
}

static ksec_result exchange(ksec_client *client, uint16_t operation,
                            const uint8_t *payload, uint32_t payload_len,
                            int send_fd, uint8_t *response,
                            size_t response_size, size_t *response_len,
                            int *response_fd) {
    ksec_packet_header request;
    ksec_packet_header reply;
    uint8_t reply_payload[KSEC_PROTOCOL_MAX_PAYLOAD];
    int received = -1;
    ksec_result result;
    if (client == NULL || client->fd < 0 || response_len == NULL
            || response_fd == NULL || payload_len > KSEC_PROTOCOL_MAX_PAYLOAD) {
        return KSEC_ERR_INVALID;
    }
    memset(&request, 0, sizeof request);
    request.version = KSEC_PROTOCOL_VERSION;
    request.operation = operation;
    request.request_id = client->next_request++;
    request.payload_len = payload_len;
    result = ksec_send_packet(client->fd, &request, payload, send_fd);
    if (result != KSEC_OK) return result;
    result = ksec_recv_packet(client->fd, &reply, reply_payload,
                              sizeof reply_payload, &received);
    if (result != KSEC_OK) return result;
    if (reply.operation != operation || reply.request_id != request.request_id
            || reply.payload_len < 4U) {
        if (received >= 0) (void)close(received);
        return KSEC_ERR_PROTOCOL;
    }
    result = (ksec_result)ksec_get_u32(reply_payload);
    if (result < KSEC_OK || result > KSEC_ERR_MEMORY) {
        if (received >= 0) (void)close(received);
        return KSEC_ERR_PROTOCOL;
    }
    if (result != KSEC_OK) {
        if (received >= 0) (void)close(received);
        return result;
    }
    if ((size_t)reply.payload_len - 4U > response_size) {
        if (received >= 0) (void)close(received);
        return KSEC_ERR_LIMIT;
    }
    if (reply.payload_len > 4U && response != NULL) {
        memcpy(response, reply_payload + 4U, reply.payload_len - 4U);
    }
    *response_len = reply.payload_len - 4U;
    *response_fd = received;
    return KSEC_OK;
}

static ksec_result pipe_from_bytes(const uint8_t *data, size_t length, int *out_fd) {
    int fd;
    if (data == NULL || length == 0 || out_fd == NULL) return KSEC_ERR_INVALID;
    fd = memfd_create("ksec-sensitive-request", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (fd < 0) return KSEC_ERR_IO;
    if (ksec_write_all(fd, data, length) != 0 || lseek(fd, 0, SEEK_SET) != 0
            || fcntl(fd, F_ADD_SEALS,
                     F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE) != 0) {
        int saved = errno;
        (void)close(fd);
        errno = saved;
        return KSEC_ERR_IO;
    }
    *out_fd = fd;
    return KSEC_OK;
}

ksec_result ksec_connect_at(ksec_client **out, const char *socket_path,
                            int capability_fd) {
    ksec_client *client;
    uint8_t response[1];
    size_t response_len = 0;
    int response_fd = -1;
    ksec_result result;
    if (out == NULL || socket_path == NULL || capability_fd < 0) return KSEC_ERR_INVALID;
    if (ksec_set_cloexec(capability_fd, true) != 0) {
        (void)close(capability_fd);
        return KSEC_ERR_IO;
    }
    client = calloc(1U, sizeof *client);
    if (client == NULL) return KSEC_ERR_MEMORY;
    client->fd = -1;
    randombytes_buf(&client->next_request, sizeof client->next_request);
    if (client->next_request == 0) client->next_request = 1U;
    result = connect_socket(socket_path, &client->fd);
    if (result != KSEC_OK) goto fail;
    result = exchange(client, KSEC_OP_ACTIVATE, NULL, 0U, capability_fd,
                      response, sizeof response, &response_len, &response_fd);
    (void)close(capability_fd);
    capability_fd = -1;
    if (response_fd >= 0) (void)close(response_fd);
    if (result != KSEC_OK || response_len != 0U) {
        if (result == KSEC_OK) result = KSEC_ERR_PROTOCOL;
        goto fail;
    }
    *out = client;
    return KSEC_OK;
fail:
    if (capability_fd >= 0) (void)close(capability_fd);
    if (client->fd >= 0) (void)close(client->fd);
    free(client);
    return result;
}

ksec_result ksec_connect(ksec_client **out) {
    const char *runtime = getenv("XDG_RUNTIME_DIR");
    const char *socket_override = getenv("KILIX_SECRETS_SOCKET");
    const char *fd_text = getenv("KILIX_SECRETS_CAP_FD");
    char socket_path[4096];
    char *end = NULL;
    long fd_value;
    int count;
    if (runtime == NULL || fd_text == NULL) return KSEC_ERR_INVALID;
    errno = 0;
    fd_value = strtol(fd_text, &end, 10);
    if (errno != 0 || end == fd_text || *end != '\0' || fd_value < 0
            || fd_value > INT_MAX) return KSEC_ERR_INVALID;
    if (socket_override != NULL) {
        if (strlen(socket_override) >= sizeof socket_path) return KSEC_ERR_LIMIT;
        memcpy(socket_path, socket_override, strlen(socket_override) + 1U);
    } else {
        count = snprintf(socket_path, sizeof socket_path,
                         "%s/kilix-secrets/control.sock", runtime);
        if (count < 0 || (size_t)count >= sizeof socket_path) return KSEC_ERR_LIMIT;
    }
    return ksec_connect_at(out, socket_path, (int)fd_value);
}

void ksec_client_free(ksec_client *client) {
    if (client == NULL) return;
    if (client->fd >= 0) (void)close(client->fd);
    sodium_memzero(client, sizeof *client);
    free(client);
}

static ksec_result supervisor_mint(const char *socket_path, pid_t child_pid,
                                   const char *application_id,
                                   uint32_t verb_mask, const uint8_t *record_id,
                                   uint32_t lifetime_seconds,
                                   int *out_capability_fd) {
    ksec_client temporary;
    uint8_t payload[16U + KSEC_RECORD_ID_BYTES + KSEC_MAX_APP_ID];
    uint8_t response[1];
    size_t app_len;
    size_t response_len = 0;
    int response_fd = -1;
    ksec_result result;
    if (socket_path == NULL || application_id == NULL || out_capability_fd == NULL
            || child_pid <= 0 || ksec_validate_app_id(application_id) != 0
            || verb_mask == 0U || (verb_mask & ~(uint32_t)KSEC_VERB_ALL) != 0U
            || lifetime_seconds == 0U || lifetime_seconds > 300U) return KSEC_ERR_INVALID;
    app_len = strlen(application_id);
    memset(&temporary, 0, sizeof temporary);
    temporary.fd = -1;
    randombytes_buf(&temporary.next_request, sizeof temporary.next_request);
    result = connect_socket(socket_path, &temporary.fd);
    if (result != KSEC_OK) return result;
    ksec_put_u32(payload, (uint32_t)child_pid);
    ksec_put_u32(payload + 4U, verb_mask);
    ksec_put_u32(payload + 8U, lifetime_seconds);
    ksec_put_u16(payload + 12U, (uint16_t)app_len);
    ksec_put_u16(payload + 14U, (uint16_t)(record_id == NULL ? 0U : 1U));
    if (record_id != NULL) memcpy(payload + 16U, record_id, KSEC_RECORD_ID_BYTES);
    memcpy(payload + (record_id == NULL ? 16U : 32U), application_id, app_len);
    result = exchange(&temporary, KSEC_OP_MINT, payload,
                      (uint32_t)((record_id == NULL ? 16U : 32U) + app_len),
                      -1, response, sizeof response, &response_len, &response_fd);
    (void)close(temporary.fd);
    if (result != KSEC_OK) return result;
    if (response_len != 0U || response_fd < 0) {
        if (response_fd >= 0) (void)close(response_fd);
        return KSEC_ERR_PROTOCOL;
    }
    *out_capability_fd = response_fd;
    return KSEC_OK;
}

ksec_result ksec_supervisor_mint(const char *socket_path, pid_t child_pid,
                                 const char *application_id,
                                 uint32_t verb_mask, uint32_t lifetime_seconds,
                                 int *out_capability_fd) {
    return supervisor_mint(socket_path, child_pid, application_id, verb_mask,
                           NULL, lifetime_seconds, out_capability_fd);
}

ksec_result ksec_supervisor_mint_scoped(
        const char *socket_path, pid_t child_pid, const char *application_id,
        uint32_t verb_mask,
        const uint8_t record_id[KSEC_RECORD_ID_BYTES],
        uint32_t lifetime_seconds, int *out_capability_fd) {
    if (record_id == NULL) return KSEC_ERR_INVALID;
    return supervisor_mint(socket_path, child_pid, application_id, verb_mask,
                           record_id, lifetime_seconds, out_capability_fd);
}

static ksec_result lifecycle_with_input(ksec_client *client, uint16_t operation,
                                        uint32_t selector, int input_fd,
                                        int output_fd) {
    uint8_t payload[4];
    uint8_t response[1];
    size_t response_len = 0;
    int response_fd = -1;
    ksec_result result;
    ksec_put_u32(payload, selector);
    result = exchange(client, operation, payload, sizeof payload, input_fd,
                      response, sizeof response, &response_len, &response_fd);
    if (result != KSEC_OK) return result;
    if (response_len != 0U) {
        if (response_fd >= 0) (void)close(response_fd);
        return KSEC_ERR_PROTOCOL;
    }
    if (output_fd >= 0) {
        if (response_fd < 0 || ksec_copy_fd(response_fd, output_fd, 4096U, NULL) != 0) {
            if (response_fd >= 0) (void)close(response_fd);
            return KSEC_ERR_IO;
        }
    } else if (response_fd >= 0) {
        (void)close(response_fd);
        return KSEC_ERR_PROTOCOL;
    }
    if (response_fd >= 0 && close(response_fd) != 0) return KSEC_ERR_IO;
    return KSEC_OK;
}

ksec_result ksec_vault_init(ksec_client *client, int passphrase_fd,
                            int recovery_output_fd) {
    if (passphrase_fd < 0 || recovery_output_fd < 0) return KSEC_ERR_INVALID;
    return lifecycle_with_input(client, KSEC_OP_INIT, 0U, passphrase_fd,
                                recovery_output_fd);
}

ksec_result ksec_unlock(ksec_client *client, ksec_slot_type slot_type,
                        int secret_input_fd) {
    if (secret_input_fd < 0 || (slot_type != KSEC_SLOT_PASSPHRASE
            && slot_type != KSEC_SLOT_RECOVERY)) return KSEC_ERR_INVALID;
    return lifecycle_with_input(client, KSEC_OP_UNLOCK, (uint32_t)slot_type,
                                secret_input_fd, -1);
}

static ksec_result simple_request(ksec_client *client, uint16_t operation,
                                  const uint8_t *payload, uint32_t payload_len,
                                  int *returned_fd, uint8_t *response,
                                  size_t response_size, size_t *response_len) {
    int fd = -1;
    ksec_result result = exchange(client, operation, payload, payload_len, -1,
                                  response, response_size, response_len, &fd);
    if (result != KSEC_OK) return result;
    if (returned_fd != NULL) *returned_fd = fd;
    else if (fd >= 0) { (void)close(fd); return KSEC_ERR_PROTOCOL; }
    return KSEC_OK;
}

ksec_result ksec_lock(ksec_client *client) {
    uint8_t response[1];
    size_t length = 0;
    ksec_result result = simple_request(client, KSEC_OP_LOCK, NULL, 0U, NULL,
                                        response, sizeof response, &length);
    return result == KSEC_OK && length != 0U ? KSEC_ERR_PROTOCOL : result;
}

static ksec_result send_record(ksec_client *client, uint16_t operation,
                               const uint8_t *record_id, const ksec_record *record,
                               uint8_t output_id[KSEC_RECORD_ID_BYTES]) {
    ksec_secure_buffer encoded = {0};
    uint8_t payload[20U + KSEC_MAX_APP_ID];
    uint8_t response[KSEC_RECORD_ID_BYTES];
    size_t encoded_len = 0;
    size_t response_len = 0;
    size_t owner_len;
    uint16_t object_type;
    int data_fd = -1;
    int response_fd = -1;
    ksec_result result;
    if (client == NULL || record == NULL || output_id == NULL
            || ksec_validate_app_id(record->owner) != 0) return KSEC_ERR_INVALID;
    result = ksec_secure_alloc(&encoded, KSEC_MAX_RECORD_PLAINTEXT);
    if (result != KSEC_OK) return result;
    result = ksec_record_serialize(record, encoded.data, encoded.len, &encoded_len);
    if (result != KSEC_OK) goto out;
    encoded.len = encoded_len;
    result = pipe_from_bytes(encoded.data, encoded.len, &data_fd);
    if (result != KSEC_OK) goto out;
    owner_len = strlen(record->owner);
    object_type = strcmp(record->type, "device-identity") == 0
        ? KSEC_OBJECT_DEVICE_IDENTITY : KSEC_OBJECT_SECRET;
    if (record_id != NULL) memcpy(payload, record_id, KSEC_RECORD_ID_BYTES);
    ksec_put_u16(payload + (record_id != NULL ? 16U : 0U), object_type);
    ksec_put_u16(payload + (record_id != NULL ? 18U : 2U), (uint16_t)owner_len);
    memcpy(payload + (record_id != NULL ? 20U : 4U), record->owner, owner_len);
    result = exchange(client, operation, payload,
                      (uint32_t)((record_id != NULL ? 20U : 4U) + owner_len),
                      data_fd, response, sizeof response, &response_len, &response_fd);
    (void)close(data_fd);
    data_fd = -1;
    if (response_fd >= 0) { (void)close(response_fd); result = KSEC_ERR_PROTOCOL; }
    if (result == KSEC_OK && response_len == KSEC_RECORD_ID_BYTES) {
        memcpy(output_id, response, KSEC_RECORD_ID_BYTES);
    } else if (result == KSEC_OK) result = KSEC_ERR_PROTOCOL;
out:
    if (data_fd >= 0) (void)close(data_fd);
    ksec_secure_free(&encoded);
    sodium_memzero(response, sizeof response);
    return result;
}

ksec_result ksec_put(ksec_client *client, const ksec_record *record,
                     uint8_t record_id[KSEC_RECORD_ID_BYTES]) {
    return send_record(client, KSEC_OP_PUT, NULL, record, record_id);
}

ksec_result ksec_replace(ksec_client *client,
                         const uint8_t record_id[KSEC_RECORD_ID_BYTES],
                         const ksec_record *record) {
    uint8_t returned[KSEC_RECORD_ID_BYTES];
    ksec_result result;
    if (record_id == NULL) return KSEC_ERR_INVALID;
    result = send_record(client, KSEC_OP_REPLACE, record_id, record, returned);
    if (result == KSEC_OK && sodium_memcmp(record_id, returned, KSEC_RECORD_ID_BYTES) != 0) {
        result = KSEC_ERR_PROTOCOL;
    }
    sodium_memzero(returned, sizeof returned);
    return result;
}

ksec_result ksec_get_to_fd(ksec_client *client,
                           const uint8_t record_id[KSEC_RECORD_ID_BYTES],
                           const char *field, int output_fd) {
    uint8_t payload[18U + KSEC_MAX_FIELD_NAME];
    uint8_t response[1];
    size_t field_len;
    size_t response_len = 0;
    int secret_fd = -1;
    ksec_result result;
    if (client == NULL || record_id == NULL || output_fd < 0
            || ksec_validate_name(field, KSEC_MAX_FIELD_NAME) != 0) return KSEC_ERR_INVALID;
    field_len = strlen(field);
    memcpy(payload, record_id, KSEC_RECORD_ID_BYTES);
    ksec_put_u16(payload + 16U, (uint16_t)field_len);
    memcpy(payload + 18U, field, field_len);
    result = simple_request(client, KSEC_OP_GET, payload, (uint32_t)(18U + field_len),
                            &secret_fd, response, sizeof response, &response_len);
    if (result != KSEC_OK) return result;
    if (response_len != 0U || secret_fd < 0
            || ksec_copy_fd(secret_fd, output_fd, KSEC_MAX_SECRET_BYTES, NULL) != 0
            || close(secret_fd) != 0) return KSEC_ERR_IO;
    return KSEC_OK;
}

ksec_result ksec_get_buf(ksec_client *client,
                         const uint8_t record_id[KSEC_RECORD_ID_BYTES],
                         const char *field, uint8_t *buf, size_t buf_len,
                         size_t *out_len) {
    int fd;
    ksec_result result;
    size_t total = 0;
    if (buf == NULL || out_len == NULL || buf_len == 0) {
        return KSEC_ERR_INVALID;
    }
    fd = memfd_create("ksec-sensitive-response", MFD_CLOEXEC);
    if (fd < 0) return KSEC_ERR_IO;
    result = ksec_get_to_fd(client, record_id, field, fd);
    if (result == KSEC_OK && lseek(fd, 0, SEEK_SET) != 0) result = KSEC_ERR_IO;
    if (result == KSEC_OK) {
        for (;;) {
            ssize_t count;
            if (total == buf_len) {
                uint8_t extra;
                count = read(fd, &extra, 1U);
                if (count != 0) result = KSEC_ERR_LIMIT;
                sodium_memzero(&extra, sizeof extra);
                break;
            }
            count = read(fd, buf + total, buf_len - total);
            if (count < 0 && errno == EINTR) continue;
            if (count < 0) { result = KSEC_ERR_IO; break; }
            if (count == 0) break;
            total += (size_t)count;
        }
    }
    (void)close(fd);
    if (result != KSEC_OK) sodium_memzero(buf, buf_len);
    else *out_len = total;
    return result;
}

ksec_result ksec_delete(ksec_client *client,
                        const uint8_t record_id[KSEC_RECORD_ID_BYTES]) {
    uint8_t response[1];
    size_t length = 0;
    if (record_id == NULL) return KSEC_ERR_INVALID;
    {
        ksec_result result = simple_request(client, KSEC_OP_DELETE, record_id,
                                            KSEC_RECORD_ID_BYTES, NULL, response,
                                            sizeof response, &length);
        return result == KSEC_OK && length != 0U ? KSEC_ERR_PROTOCOL : result;
    }
}

static ksec_result request_output(ksec_client *client, uint16_t operation,
                                  int output_fd) {
    uint8_t response[1];
    size_t response_len = 0;
    int returned_fd = -1;
    ksec_result result;
    if (output_fd < 0) return KSEC_ERR_INVALID;
    result = simple_request(client, operation, NULL, 0U, &returned_fd, response,
                            sizeof response, &response_len);
    if (result != KSEC_OK) return result;
    if (response_len != 0U || returned_fd < 0
            || ksec_copy_fd(returned_fd, output_fd, KSEC_MAX_RECORD_PLAINTEXT, NULL) != 0
            || close(returned_fd) != 0) return KSEC_ERR_IO;
    return KSEC_OK;
}

ksec_result ksec_list_to_fd(ksec_client *client, int output_fd) {
    return request_output(client, KSEC_OP_LIST, output_fd);
}

ksec_result ksec_doctor_to_fd(ksec_client *client, int output_fd) {
    return request_output(client, KSEC_OP_DOCTOR, output_fd);
}

ksec_result ksec_compact(ksec_client *client) {
    uint8_t response[1];
    size_t length = 0;
    ksec_result result = simple_request(client, KSEC_OP_COMPACT, NULL, 0U, NULL,
                                        response, sizeof response, &length);
    return result == KSEC_OK && length != 0U ? KSEC_ERR_PROTOCOL : result;
}
