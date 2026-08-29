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
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

struct ksec_client {
    int fd;
    uint64_t next_request;
};

_Static_assert(sizeof(ksec_identity_info) == 112U,
               "ksec_identity_info ABI size changed");

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
    if (result < KSEC_OK || result > KSEC_ERR_CONFLICT) {
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

static ksec_result read_client_secret(int fd, size_t minimum,
                                      ksec_secure_buffer *buffer) {
    size_t total = 0U;
    ksec_result result;
    if (fd < 0 || minimum == 0U || minimum > 1024U || buffer == NULL) {
        return KSEC_ERR_INVALID;
    }
    result = ksec_secure_alloc(buffer, 1024U);
    if (result != KSEC_OK) return result;
    for (;;) {
        ssize_t count;
        if (total == buffer->len) {
            uint8_t extra = 0U;
            do {
                count = read(fd, &extra, 1U);
            } while (count < 0 && errno == EINTR);
            sodium_memzero(&extra, sizeof extra);
            if (count < 0) result = KSEC_ERR_IO;
            else if (count != 0) result = KSEC_ERR_LIMIT;
            break;
        }
        count = read(fd, buffer->data + total, buffer->len - total);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) { result = KSEC_ERR_IO; break; }
        if (count == 0) break;
        total += (size_t)count;
    }
    while (result == KSEC_OK && total > 0U
            && (buffer->data[total - 1U] == (uint8_t)'\n'
                || buffer->data[total - 1U] == (uint8_t)'\r')) total--;
    if (result == KSEC_OK && total < minimum) result = KSEC_ERR_INVALID;
    if (result != KSEC_OK) {
        ksec_secure_free(buffer);
        return result;
    }
    buffer->len = total;
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

static ksec_result lifecycle_with_payload_input(
        ksec_client *client, uint16_t operation, const uint8_t *payload,
        uint32_t payload_len, int input_fd, int output_fd) {
    uint8_t response[1];
    size_t response_len = 0;
    int response_fd = -1;
    ksec_result result;
    result = exchange(client, operation, payload, payload_len, input_fd,
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

static ksec_result lifecycle_with_input(ksec_client *client, uint16_t operation,
                                        uint32_t selector, int input_fd,
                                        int output_fd) {
    uint8_t payload[4];
    ksec_put_u32(payload, selector);
    return lifecycle_with_payload_input(client, operation, payload,
                                        sizeof payload, input_fd, output_fd);
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

ksec_result ksec_change_passphrase(ksec_client *client,
                                   int new_passphrase_fd) {
    if (new_passphrase_fd < 0) return KSEC_ERR_INVALID;
    return lifecycle_with_input(client, KSEC_OP_CHANGE_PASSPHRASE, 0U,
                                new_passphrase_fd, -1);
}

ksec_result ksec_rotate_master(ksec_client *client, int passphrase_fd,
                               int recovery_fd) {
    ksec_secure_buffer passphrase = {0};
    ksec_secure_buffer recovery = {0};
    ksec_secure_buffer framed = {0};
    int framed_fd = -1;
    ksec_result result;
    if (client == NULL || passphrase_fd < 0 || recovery_fd < 0) {
        return KSEC_ERR_INVALID;
    }
    result = read_client_secret(passphrase_fd, 8U, &passphrase);
    if (result != KSEC_OK) goto out;
    result = read_client_secret(recovery_fd, 32U, &recovery);
    if (result != KSEC_OK) goto out;
    result = ksec_secure_alloc(&framed, 8U + passphrase.len + recovery.len);
    if (result != KSEC_OK) goto out;
    ksec_put_u32(framed.data, (uint32_t)passphrase.len);
    ksec_put_u32(framed.data + 4U, (uint32_t)recovery.len);
    memcpy(framed.data + 8U, passphrase.data, passphrase.len);
    memcpy(framed.data + 8U + passphrase.len, recovery.data, recovery.len);
    result = pipe_from_bytes(framed.data, framed.len, &framed_fd);
    if (result != KSEC_OK) goto out;
    result = lifecycle_with_input(client, KSEC_OP_ROTATE_MASTER, 0U,
                                  framed_fd, -1);
out:
    if (framed_fd >= 0) (void)close(framed_fd);
    ksec_secure_free(&framed);
    ksec_secure_free(&recovery);
    ksec_secure_free(&passphrase);
    return result;
}

static ksec_result validate_backup_file(int fd, bool output,
                                        size_t *remaining) {
    struct stat status;
    off_t offset;
    int flags;
    uint64_t available;
    if (fd < 0 || remaining == NULL || fstat(fd, &status) != 0
            || !S_ISREG(status.st_mode) || status.st_uid != getuid()
            || status.st_nlink != 1 || (status.st_mode & 0777U) != 0600U
            || status.st_size < 0) return KSEC_ERR_DENIED;
    flags = fcntl(fd, F_GETFL);
    offset = lseek(fd, 0, SEEK_CUR);
    if (flags < 0 || offset < 0 || status.st_size < offset) return KSEC_ERR_IO;
    if ((output && (flags & O_ACCMODE) == O_RDONLY)
            || (!output && (flags & O_ACCMODE) == O_WRONLY)) {
        return KSEC_ERR_DENIED;
    }
    available = (uint64_t)(status.st_size - offset);
    if (output) {
        if (offset != 0 || status.st_size != 0) return KSEC_ERR_EXISTS;
    } else if (available < 192U || available > KSEC_MAX_BACKUP_BYTES
            || available > SIZE_MAX) {
        return KSEC_ERR_LIMIT;
    }
    *remaining = (size_t)available;
    return KSEC_OK;
}

ksec_result ksec_export_backup(ksec_client *client, int passphrase_fd,
                               int output_fd) {
    ksec_secure_buffer passphrase = {0};
    uint8_t payload[4];
    uint8_t response[1];
    size_t ignored = 0U;
    size_t response_len = 0U;
    size_t copied = 0U;
    int passphrase_memfd = -1;
    int response_fd = -1;
    ksec_result result;
    if (client == NULL || passphrase_fd < 0 || output_fd < 0) {
        return KSEC_ERR_INVALID;
    }
    result = validate_backup_file(output_fd, true, &ignored);
    if (result != KSEC_OK) return result;
    result = read_client_secret(passphrase_fd, 8U, &passphrase);
    if (result != KSEC_OK) goto out;
    result = pipe_from_bytes(passphrase.data, passphrase.len,
                             &passphrase_memfd);
    if (result != KSEC_OK) goto out;
    ksec_put_u32(payload, 0U);
    result = exchange(client, KSEC_OP_EXPORT_BACKUP, payload, sizeof payload,
                      passphrase_memfd, response, sizeof response,
                      &response_len, &response_fd);
    if (result != KSEC_OK) goto out;
    if (response_len != 0U || response_fd < 0
            || ksec_copy_fd(response_fd, output_fd,
                            (size_t)KSEC_MAX_BACKUP_BYTES, &copied) != 0
            || copied < 192U || fsync(output_fd) != 0) {
        result = KSEC_ERR_IO;
        goto out;
    }
    result = KSEC_OK;
out:
    if (response_fd >= 0) (void)close(response_fd);
    if (passphrase_memfd >= 0) (void)close(passphrase_memfd);
    ksec_secure_free(&passphrase);
    return result;
}

ksec_result ksec_import_backup(ksec_client *client, int passphrase_fd,
                               int input_fd) {
    ksec_secure_buffer passphrase = {0};
    uint8_t length_prefix[4];
    size_t backup_len = 0U;
    size_t copied = 0U;
    int framed_fd = -1;
    ksec_result result;
    if (client == NULL || passphrase_fd < 0 || input_fd < 0) {
        return KSEC_ERR_INVALID;
    }
    result = validate_backup_file(input_fd, false, &backup_len);
    if (result != KSEC_OK) return result;
    result = read_client_secret(passphrase_fd, 8U, &passphrase);
    if (result != KSEC_OK) goto out;
    framed_fd = memfd_create("ksec-backup-import",
                             MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (framed_fd < 0) { result = KSEC_ERR_IO; goto out; }
    ksec_put_u32(length_prefix, (uint32_t)passphrase.len);
    if (ksec_write_all(framed_fd, length_prefix, sizeof length_prefix) != 0
            || ksec_write_all(framed_fd, passphrase.data, passphrase.len) != 0
            || ksec_copy_fd(input_fd, framed_fd,
                            (size_t)KSEC_MAX_BACKUP_BYTES, &copied) != 0
            || copied != backup_len || lseek(framed_fd, 0, SEEK_SET) != 0
            || fcntl(framed_fd, F_ADD_SEALS,
                     F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW
                         | F_SEAL_WRITE) != 0) {
        result = KSEC_ERR_IO;
        goto out;
    }
    result = lifecycle_with_input(client, KSEC_OP_IMPORT_BACKUP, 0U,
                                  framed_fd, -1);
out:
    if (framed_fd >= 0) (void)close(framed_fd);
    sodium_memzero(length_prefix, sizeof length_prefix);
    ksec_secure_free(&passphrase);
    return result;
}

ksec_result ksec_reset_vault(ksec_client *client, const char *confirmation,
                             int new_passphrase_fd, int recovery_output_fd) {
    static const uint8_t expected[] = KSEC_RESET_CONFIRMATION;
    if (client == NULL || confirmation == NULL
            || strcmp(confirmation, KSEC_RESET_CONFIRMATION) != 0
            || new_passphrase_fd < 0 || recovery_output_fd < 0) {
        return KSEC_ERR_INVALID;
    }
    return lifecycle_with_payload_input(
            client, KSEC_OP_RESET_VAULT, expected, sizeof expected - 1U,
            new_passphrase_fd, recovery_output_fd);
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

ksec_result ksec_identity_open(
        ksec_client *client,
        const uint8_t record_id[KSEC_RECORD_ID_BYTES],
        const uint8_t expected_anchor[KSEC_IDENTITY_ANCHOR_BYTES],
        uint8_t private_key[KSEC_IDENTITY_KEY_BYTES],
        ksec_identity_info *info, int *lease_fd) {
    uint8_t payload[KSEC_RECORD_ID_BYTES + KSEC_IDENTITY_ANCHOR_BYTES];
    ksec_secure_buffer frame = {0};
    uint8_t derived_public[KSEC_IDENTITY_KEY_BYTES];
    uint8_t derived_anchor[KSEC_IDENTITY_ANCHOR_BYTES];
    uint8_t response[1];
    size_t payload_len = KSEC_RECORD_ID_BYTES;
    size_t response_len = 0U;
    int fd = -1;
    int flags;
    ssize_t count;
    ksec_result result;
    if (private_key == NULL || info == NULL || lease_fd == NULL) {
        return KSEC_ERR_INVALID;
    }
    sodium_memzero(private_key, KSEC_IDENTITY_KEY_BYTES);
    memset(info, 0, sizeof *info);
    *lease_fd = -1;
    if (client == NULL || record_id == NULL) return KSEC_ERR_INVALID;
    memset(payload, 0, sizeof payload);
    memset(derived_public, 0, sizeof derived_public);
    memset(derived_anchor, 0, sizeof derived_anchor);
    memcpy(payload, record_id, KSEC_RECORD_ID_BYTES);
    if (expected_anchor != NULL) {
        memcpy(payload + KSEC_RECORD_ID_BYTES, expected_anchor,
               KSEC_IDENTITY_ANCHOR_BYTES);
        payload_len = sizeof payload;
    }
    result = ksec_secure_alloc(&frame, KSEC_IDENTITY_FRAME_BYTES);
    if (result != KSEC_OK) goto out;
    result = simple_request(client, KSEC_OP_IDENTITY_OPEN, payload,
                            (uint32_t)payload_len, &fd, response,
                            sizeof response, &response_len);
    if (result != KSEC_OK) goto out;
    if (response_len != 0U || fd < 0
            || ksec_read_exact(fd, frame.data, frame.len) != 0
            || ksec_get_u32(frame.data) != KSEC_IDENTITY_FRAME_MAGIC
            || ksec_get_u16(frame.data + 4U) != KSEC_IDENTITY_FRAME_VERSION
            || ksec_get_u16(frame.data + 6U) != KSEC_IDENTITY_FRAME_BYTES
            || sodium_memcmp(frame.data + 24U, record_id,
                             KSEC_RECORD_ID_BYTES) != 0
            || ksec_get_u64(frame.data + 40U) == 0U) {
        result = KSEC_ERR_PROTOCOL;
        goto out;
    }
    if (crypto_scalarmult_curve25519_base(derived_public,
                                          frame.data + 112U) != 0
            || sodium_memcmp(derived_public, frame.data + 48U,
                             KSEC_IDENTITY_KEY_BYTES) != 0) {
        result = KSEC_ERR_CRYPTO;
        goto out;
    }
    result = ksec_identity_anchor(frame.data + 8U, frame.data + 24U,
                                  ksec_get_u64(frame.data + 40U),
                                  frame.data + 48U, derived_anchor);
    if (result != KSEC_OK) goto out;
    if (sodium_memcmp(derived_anchor, frame.data + 80U,
                      KSEC_IDENTITY_ANCHOR_BYTES) != 0) {
        result = KSEC_ERR_CRYPTO;
        goto out;
    }
    if (expected_anchor != NULL
            && sodium_memcmp(expected_anchor, derived_anchor,
                             KSEC_IDENTITY_ANCHOR_BYTES) != 0) {
        result = KSEC_ERR_CONFLICT;
        goto out;
    }
    flags = fcntl(fd, F_GETFL);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        result = KSEC_ERR_IO;
        goto out;
    }
    do {
        uint8_t extra = 0U;
        count = read(fd, &extra, 1U);
        sodium_memzero(&extra, sizeof extra);
    } while (count < 0 && errno == EINTR);
    if (count == 0) {
        result = KSEC_ERR_CONFLICT;
        goto out;
    }
    if (count > 0) {
        result = KSEC_ERR_PROTOCOL;
        goto out;
    }
    if (errno != EAGAIN && errno != EWOULDBLOCK) {
        result = KSEC_ERR_IO;
        goto out;
    }
    info->version = KSEC_IDENTITY_INFO_VERSION;
    memcpy(info->vault_uuid, frame.data + 8U, sizeof info->vault_uuid);
    memcpy(info->record_id, frame.data + 24U, sizeof info->record_id);
    info->record_revision = ksec_get_u64(frame.data + 40U);
    memcpy(info->public_key, frame.data + 48U, sizeof info->public_key);
    memcpy(info->anchor, frame.data + 80U, sizeof info->anchor);
    memcpy(private_key, frame.data + 112U, KSEC_IDENTITY_KEY_BYTES);
    *lease_fd = fd;
    fd = -1;
    result = KSEC_OK;
out:
    if (fd >= 0) (void)close(fd);
    if (result != KSEC_OK) {
        sodium_memzero(private_key, KSEC_IDENTITY_KEY_BYTES);
        sodium_memzero(info, sizeof *info);
    }
    sodium_memzero(payload, sizeof payload);
    ksec_secure_free(&frame);
    sodium_memzero(derived_public, sizeof derived_public);
    sodium_memzero(derived_anchor, sizeof derived_anchor);
    return result;
}

ksec_result ksec_identity_info_get(
        ksec_client *client,
        const uint8_t record_id[KSEC_RECORD_ID_BYTES],
        const uint8_t expected_anchor[KSEC_IDENTITY_ANCHOR_BYTES],
        ksec_identity_info *info) {
    uint8_t payload[KSEC_RECORD_ID_BYTES + KSEC_IDENTITY_ANCHOR_BYTES];
    uint8_t frame[KSEC_IDENTITY_INFO_FRAME_BYTES];
    uint8_t derived_anchor[KSEC_IDENTITY_ANCHOR_BYTES];
    uint8_t response[1];
    uint8_t extra = 0U;
    size_t payload_len = KSEC_RECORD_ID_BYTES;
    size_t response_len = 0U;
    int fd = -1;
    ssize_t count;
    ksec_result result;
    if (info == NULL) return KSEC_ERR_INVALID;
    memset(info, 0, sizeof *info);
    if (client == NULL || record_id == NULL) return KSEC_ERR_INVALID;
    memset(payload, 0, sizeof payload);
    memset(frame, 0, sizeof frame);
    memset(derived_anchor, 0, sizeof derived_anchor);
    memcpy(payload, record_id, KSEC_RECORD_ID_BYTES);
    if (expected_anchor != NULL) {
        memcpy(payload + KSEC_RECORD_ID_BYTES, expected_anchor,
               KSEC_IDENTITY_ANCHOR_BYTES);
        payload_len = sizeof payload;
    }
    result = simple_request(client, KSEC_OP_IDENTITY_INFO, payload,
                            (uint32_t)payload_len, &fd, response,
                            sizeof response, &response_len);
    if (result != KSEC_OK) goto out;
    if (response_len != 0U || fd < 0
            || ksec_read_exact(fd, frame, sizeof frame) != 0) {
        result = KSEC_ERR_PROTOCOL;
        goto out;
    }
    do {
        count = read(fd, &extra, 1U);
    } while (count < 0 && errno == EINTR);
    sodium_memzero(&extra, sizeof extra);
    if (count != 0
            || ksec_get_u32(frame) != KSEC_IDENTITY_INFO_FRAME_MAGIC
            || ksec_get_u16(frame + 4U) != KSEC_IDENTITY_FRAME_VERSION
            || ksec_get_u16(frame + 6U) != KSEC_IDENTITY_INFO_FRAME_BYTES
            || sodium_memcmp(frame + 24U, record_id,
                             KSEC_RECORD_ID_BYTES) != 0
            || ksec_get_u64(frame + 40U) == 0U) {
        result = KSEC_ERR_PROTOCOL;
        goto out;
    }
    result = ksec_identity_anchor(frame + 8U, frame + 24U,
                                  ksec_get_u64(frame + 40U), frame + 48U,
                                  derived_anchor);
    if (result != KSEC_OK) goto out;
    if (sodium_memcmp(derived_anchor, frame + 80U,
                      KSEC_IDENTITY_ANCHOR_BYTES) != 0) {
        result = KSEC_ERR_CRYPTO;
        goto out;
    }
    if (expected_anchor != NULL
            && sodium_memcmp(expected_anchor, derived_anchor,
                             KSEC_IDENTITY_ANCHOR_BYTES) != 0) {
        result = KSEC_ERR_CONFLICT;
        goto out;
    }
    info->version = KSEC_IDENTITY_INFO_VERSION;
    memcpy(info->vault_uuid, frame + 8U, sizeof info->vault_uuid);
    memcpy(info->record_id, frame + 24U, sizeof info->record_id);
    info->record_revision = ksec_get_u64(frame + 40U);
    memcpy(info->public_key, frame + 48U, sizeof info->public_key);
    memcpy(info->anchor, frame + 80U, sizeof info->anchor);
    result = KSEC_OK;
out:
    if (fd >= 0 && close(fd) != 0 && result == KSEC_OK) result = KSEC_ERR_IO;
    if (result != KSEC_OK) memset(info, 0, sizeof *info);
    sodium_memzero(payload, sizeof payload);
    sodium_memzero(frame, sizeof frame);
    sodium_memzero(derived_anchor, sizeof derived_anchor);
    return result;
}

ksec_result ksec_delete(ksec_client *client,
                        const uint8_t record_id[KSEC_RECORD_ID_BYTES]) {
    uint8_t payload[KSEC_RECORD_ID_BYTES * 2U];
    uint8_t response[1];
    size_t length = 0;
    if (record_id == NULL) return KSEC_ERR_INVALID;
    memcpy(payload, record_id, KSEC_RECORD_ID_BYTES);
    memcpy(payload + KSEC_RECORD_ID_BYTES, record_id, KSEC_RECORD_ID_BYTES);
    {
        ksec_result result = simple_request(client, KSEC_OP_DELETE, payload,
                                            sizeof payload, NULL, response,
                                            sizeof response, &length);
        sodium_memzero(payload, sizeof payload);
        return result == KSEC_OK && length != 0U ? KSEC_ERR_PROTOCOL : result;
    }
}

static ksec_result request_output_payload(ksec_client *client,
                                          uint16_t operation,
                                          const uint8_t *payload,
                                          uint32_t payload_len,
                                          int output_fd) {
    uint8_t response[1];
    size_t response_len = 0;
    int returned_fd = -1;
    ksec_result result;
    if (output_fd < 0) return KSEC_ERR_INVALID;
    result = simple_request(client, operation, payload, payload_len, &returned_fd,
                            response, sizeof response, &response_len);
    if (result != KSEC_OK) return result;
    if (response_len != 0U || returned_fd < 0
            || ksec_copy_fd(returned_fd, output_fd, KSEC_MAX_RECORD_PLAINTEXT, NULL) != 0
            || close(returned_fd) != 0) return KSEC_ERR_IO;
    return KSEC_OK;
}

ksec_result ksec_list_to_fd(ksec_client *client, int output_fd) {
    return request_output_payload(client, KSEC_OP_LIST, NULL, 0U, output_fd);
}

ksec_result ksec_show_to_fd(ksec_client *client,
                            const uint8_t record_id[KSEC_RECORD_ID_BYTES],
                            int output_fd) {
    if (record_id == NULL) return KSEC_ERR_INVALID;
    return request_output_payload(client, KSEC_OP_SHOW, record_id,
                                  KSEC_RECORD_ID_BYTES, output_fd);
}

static ksec_result change_grant(ksec_client *client, uint16_t operation,
                                const uint8_t record_id[KSEC_RECORD_ID_BYTES],
                                const char *application_id, uint32_t verbs) {
    uint8_t payload[KSEC_RECORD_ID_BYTES + 6U + KSEC_MAX_APP_ID];
    uint8_t response[1];
    size_t response_len = 0U;
    size_t app_len;
    ksec_result result;
    if (client == NULL || record_id == NULL
            || ksec_validate_app_id(application_id) != 0
            || (operation != KSEC_OP_GRANT && operation != KSEC_OP_REVOKE)) {
        return KSEC_ERR_INVALID;
    }
    if (operation == KSEC_OP_GRANT) {
        if (verbs == 0U || (verbs & ~KSEC_GRANTABLE_VERBS) != 0U) {
            return KSEC_ERR_INVALID;
        }
    } else if (verbs != 0U) {
        return KSEC_ERR_INVALID;
    }
    app_len = strlen(application_id);
    memcpy(payload, record_id, KSEC_RECORD_ID_BYTES);
    if (operation == KSEC_OP_GRANT) {
        ksec_put_u32(payload + KSEC_RECORD_ID_BYTES, verbs);
        ksec_put_u16(payload + KSEC_RECORD_ID_BYTES + 4U, (uint16_t)app_len);
        memcpy(payload + KSEC_RECORD_ID_BYTES + 6U, application_id, app_len);
        result = simple_request(client, operation, payload,
                                (uint32_t)(KSEC_RECORD_ID_BYTES + 6U + app_len),
                                NULL, response, sizeof response, &response_len);
    } else {
        ksec_put_u16(payload + KSEC_RECORD_ID_BYTES, (uint16_t)app_len);
        memcpy(payload + KSEC_RECORD_ID_BYTES + 2U, application_id, app_len);
        result = simple_request(client, operation, payload,
                                (uint32_t)(KSEC_RECORD_ID_BYTES + 2U + app_len),
                                NULL, response, sizeof response, &response_len);
    }
    return result == KSEC_OK && response_len != 0U ? KSEC_ERR_PROTOCOL : result;
}

ksec_result ksec_grant_record(
        ksec_client *client,
        const uint8_t record_id[KSEC_RECORD_ID_BYTES],
        const char *application_id, uint32_t verbs) {
    return change_grant(client, KSEC_OP_GRANT, record_id, application_id, verbs);
}

ksec_result ksec_revoke_record(
        ksec_client *client,
        const uint8_t record_id[KSEC_RECORD_ID_BYTES],
        const char *application_id) {
    return change_grant(client, KSEC_OP_REVOKE, record_id, application_id, 0U);
}

ksec_result ksec_doctor_to_fd(ksec_client *client, int output_fd) {
    return request_output_payload(client, KSEC_OP_DOCTOR, NULL, 0U, output_fd);
}

ksec_result ksec_compact(ksec_client *client) {
    uint8_t response[1];
    size_t length = 0;
    ksec_result result = simple_request(client, KSEC_OP_COMPACT, NULL, 0U, NULL,
                                        response, sizeof response, &length);
    return result == KSEC_OK && length != 0U ? KSEC_ERR_PROTOCOL : result;
}
