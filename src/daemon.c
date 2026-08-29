#define _GNU_SOURCE

#include "internal.h"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

typedef struct {
    int fd;
    uid_t uid;
    pid_t pid;
    ksec_capability *capability;
} daemon_connection;

typedef struct {
    ksec_store store;
    ksec_vault_header header;
    ksec_secure_buffer master;
    ksec_policy policy;
    int audit_fd;
    bool audit_degraded;
    bool initialized;
    bool unlocked;
    bool kdf_configured;
    uint32_t argon_ops;
    uint64_t argon_mem;
    uint32_t failed_unlocks;
    uint64_t retry_after;
    uint64_t idle_timeout;
    uint64_t last_authorized_use;
} daemon_state;

static volatile sig_atomic_t stop_requested = 0;

static ksec_result audit_state_event(daemon_state *state, const char *event,
                                     const char *outcome, uid_t uid, pid_t pid,
                                     const char *app_id,
                                     const uint8_t *record_id) {
    ksec_result result;
    if (state == NULL) return KSEC_ERR_INVALID;
    result = ksec_audit_event(state->audit_fd, event, outcome, uid, pid, app_id,
                              record_id);
    if (result != KSEC_OK) state->audit_degraded = true;
    return result;
}

static void handle_signal(int signal_number) {
    (void)signal_number;
    stop_requested = 1;
}

static int close_unneeded_descriptors(bool preserve_systemd_socket) {
    unsigned int first = preserve_systemd_socket ? 4U : 3U;
    struct rlimit limit;
    rlim_t descriptor;
    rlim_t maximum;
    if (close_range(first, UINT_MAX, 0) == 0) return 0;
    if (errno != ENOSYS && errno != EINVAL) return -1;
    if (getrlimit(RLIMIT_NOFILE, &limit) != 0) return -1;
    maximum = limit.rlim_cur;
    if (maximum == RLIM_INFINITY || maximum > UINT64_C(1048576)) {
        maximum = UINT64_C(1048576);
    }
    for (descriptor = first; descriptor < maximum; descriptor++) {
        if (close((int)descriptor) != 0 && errno != EBADF) return -1;
    }
    return 0;
}

static int systemd_environment_matches(void) {
    const char *listen_pid = getenv("LISTEN_PID");
    const char *listen_fds = getenv("LISTEN_FDS");
    char pid_text[32];
    int count = snprintf(pid_text, sizeof pid_text, "%ld", (long)getpid());
    return count >= 0 && listen_pid != NULL && listen_fds != NULL
        && strcmp(listen_pid, pid_text) == 0 && strcmp(listen_fds, "1") == 0;
}

static int validate_systemd_listener(int fd) {
    struct stat status;
    struct sockaddr_un address;
    socklen_t address_len = sizeof address;
    socklen_t option_len;
    int socket_type = 0;
    int accepting = 0;
    option_len = sizeof socket_type;
    if (fstat(fd, &status) != 0 || !S_ISSOCK(status.st_mode)
            || getsockopt(fd, SOL_SOCKET, SO_TYPE, &socket_type, &option_len) != 0
            || option_len != sizeof socket_type || socket_type != SOCK_SEQPACKET) {
        return -1;
    }
    option_len = sizeof accepting;
    if (getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &accepting, &option_len) != 0
            || option_len != sizeof accepting || accepting != 1) return -1;
    memset(&address, 0, sizeof address);
    if (getsockname(fd, (struct sockaddr *)&address, &address_len) != 0
            || address_len < sizeof address.sun_family
            || address.sun_family != AF_UNIX || address.sun_path[0] == '\0') return -1;
    return ksec_set_cloexec(fd, true);
}

static ksec_result sensitive_fd_from_bytes(const uint8_t *data, size_t length,
                                           int *out_fd) {
    int fd;
    if (data == NULL || length == 0 || out_fd == NULL) return KSEC_ERR_INVALID;
    fd = memfd_create("ksec-sensitive-reply", MFD_CLOEXEC | MFD_ALLOW_SEALING);
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

static ksec_result read_sensitive_fd(int fd, size_t minimum, size_t maximum,
                                     ksec_secure_buffer *buffer) {
    size_t total = 0;
    ksec_result result;
    if (fd < 0 || buffer == NULL || minimum == 0 || maximum < minimum
            || maximum > KSEC_MAX_RECORD_PLAINTEXT) return KSEC_ERR_INVALID;
    result = ksec_secure_alloc(buffer, maximum);
    if (result != KSEC_OK) return result;
    for (;;) {
        ssize_t count = read(fd, buffer->data + total, maximum - total);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) { result = KSEC_ERR_IO; goto fail; }
        if (count == 0) break;
        total += (size_t)count;
        if (total == maximum) {
            uint8_t extra = 0U;
            do {
                count = read(fd, &extra, 1U);
            } while (count < 0 && errno == EINTR);
            sodium_memzero(&extra, sizeof extra);
            if (count < 0) { result = KSEC_ERR_IO; goto fail; }
            if (count != 0) { result = KSEC_ERR_LIMIT; goto fail; }
            break;
        }
    }
    while (total > 0U && (buffer->data[total - 1U] == (uint8_t)'\n'
            || buffer->data[total - 1U] == (uint8_t)'\r')) total--;
    if (total < minimum) { result = KSEC_ERR_INVALID; goto fail; }
    buffer->len = total;
    return KSEC_OK;
fail:
    ksec_secure_free(buffer);
    return result;
}

static void lock_state(daemon_state *state) {
    if (state == NULL) return;
    ksec_secure_free(&state->master);
    ksec_store_clear_records(&state->store);
    ksec_policy_clear(&state->policy);
    ksec_policy_init(&state->policy);
    state->unlocked = false;
    state->last_authorized_use = 0;
}

static ksec_result send_reply(daemon_connection *connection,
                              const ksec_packet_header *request,
                              ksec_result result, const uint8_t *extra,
                              size_t extra_len, int passed_fd) {
    uint8_t payload[4U + KSEC_RECORD_ID_BYTES];
    ksec_packet_header reply;
    if (connection == NULL || request == NULL || extra_len > KSEC_RECORD_ID_BYTES
            || (extra_len > 0U && extra == NULL)) return KSEC_ERR_INVALID;
    memset(&reply, 0, sizeof reply);
    reply.version = KSEC_PROTOCOL_VERSION;
    reply.operation = request->operation;
    reply.request_id = request->request_id;
    reply.payload_len = (uint32_t)(4U + extra_len);
    ksec_put_u32(payload, (uint32_t)result);
    if (extra_len > 0U) memcpy(payload + 4U, extra, extra_len);
    return ksec_send_packet(connection->fd, &reply, payload, passed_fd);
}

static ksec_result authorize(daemon_state *state, daemon_connection *connection,
                             uint32_t verb, const char *owner,
                             const uint8_t *record_id) {
    ksec_result result;
    if (state == NULL || connection == NULL || connection->capability == NULL) {
        return KSEC_ERR_DENIED;
    }
    result = ksec_policy_authorize(connection->capability, verb, owner, record_id);
    if (result == KSEC_OK) state->last_authorized_use = ksec_now_seconds();
    else {
        (void)audit_state_event(state, "authorize", "denied", connection->uid,
                                connection->pid,
                                connection->capability->app_id, record_id);
    }
    return result;
}

static ksec_result handle_mint(daemon_state *state, daemon_connection *connection,
                               const uint8_t *payload, size_t payload_len,
                               int received_fd, int *reply_fd) {
    uint32_t target;
    uint32_t verbs;
    uint32_t lifetime;
    uint16_t app_len;
    uint16_t scope_kind;
    size_t app_offset;
    const uint8_t *record_id = NULL;
    char app[KSEC_MAX_APP_ID + 1U];
    if (received_fd >= 0 || payload == NULL || payload_len < 17U) return KSEC_ERR_PROTOCOL;
    target = ksec_get_u32(payload);
    verbs = ksec_get_u32(payload + 4U);
    lifetime = ksec_get_u32(payload + 8U);
    app_len = ksec_get_u16(payload + 12U);
    scope_kind = ksec_get_u16(payload + 14U);
    if (scope_kind == 0U) app_offset = 16U;
    else if (scope_kind == 1U) {
        app_offset = 16U + KSEC_RECORD_ID_BYTES;
        record_id = payload + 16U;
    } else return KSEC_ERR_INVALID;
    if (app_len == 0 || app_len > KSEC_MAX_APP_ID
            || payload_len != app_offset + app_len
            || target > INT32_MAX) return KSEC_ERR_INVALID;
    if (ksec_validate_app_id_bytes(payload + app_offset, app_len) != 0) {
        return KSEC_ERR_INVALID;
    }
    memcpy(app, payload + app_offset, app_len);
    app[app_len] = '\0';
    (void)audit_state_event(state, "capability", "begin", connection->uid,
                            connection->pid, app, record_id);
    return ksec_policy_mint(&state->policy, connection->pid, (pid_t)target, app,
                            verbs, record_id, lifetime, reply_fd);
}

static ksec_result handle_activate(daemon_state *state,
                                   daemon_connection *connection,
                                   size_t payload_len, int received_fd) {
    uint8_t token[KSEC_CAPABILITY_BYTES];
    uint8_t extra;
    ssize_t extra_count;
    ksec_result result;
    if (payload_len != 0U || received_fd < 0 || connection->capability != NULL) {
        return KSEC_ERR_PROTOCOL;
    }
    if (ksec_read_exact(received_fd, token, sizeof token) != 0) {
        sodium_memzero(token, sizeof token);
        return KSEC_ERR_INVALID;
    }
    do {
        extra_count = read(received_fd, &extra, 1U);
    } while (extra_count < 0 && errno == EINTR);
    if (extra_count != 0) {
        sodium_memzero(token, sizeof token);
        sodium_memzero(&extra, sizeof extra);
        return KSEC_ERR_INVALID;
    }
    result = ksec_policy_activate(&state->policy, connection->fd, connection->pid,
                                  token, sizeof token, &connection->capability);
    sodium_memzero(token, sizeof token);
    sodium_memzero(&extra, sizeof extra);
    return result;
}

static ksec_result handle_init(daemon_state *state, daemon_connection *connection,
                               const uint8_t *payload, size_t payload_len,
                               int received_fd, int *reply_fd) {
    ksec_secure_buffer passphrase = {0};
    ksec_secure_buffer master = {0};
    uint8_t recovery_raw[32];
    char recovery_hex[65];
    uint32_t selector;
    ksec_result result;
    if (payload == NULL || payload_len != 4U || received_fd < 0) return KSEC_ERR_PROTOCOL;
    selector = ksec_get_u32(payload);
    if (selector != 0U || state->initialized) return KSEC_ERR_EXISTS;
    result = authorize(state, connection, KSEC_VERB_CREATE,
                       connection->capability->app_id, NULL);
    if (result != KSEC_OK) return result;
    if (!state->kdf_configured) return KSEC_ERR_INVALID;
    result = read_sensitive_fd(received_fd, 8U, 1024U, &passphrase);
    if (result != KSEC_OK) return result;
    result = ksec_secure_alloc(&master, KSEC_MASTER_KEY_BYTES);
    if (result != KSEC_OK) goto out;
    randombytes_buf(recovery_raw, sizeof recovery_raw);
    ksec_hex_encode(recovery_raw, sizeof recovery_raw, recovery_hex);
    result = audit_state_event(state, "init", "begin", connection->uid,
                               connection->pid, connection->capability->app_id,
                               NULL);
    if (result != KSEC_OK) goto out;
    result = ksec_header_create(&state->header, passphrase.data, passphrase.len,
                                (const uint8_t *)recovery_hex, 64U,
                                state->argon_ops, state->argon_mem, master.data);
    if (result != KSEC_OK) goto out;
    result = ksec_store_write_header(&state->store, &state->header);
    if (result != KSEC_OK) goto out;
    state->initialized = true;
    result = sensitive_fd_from_bytes((const uint8_t *)recovery_hex, 64U, reply_fd);
out:
    sodium_memzero(recovery_raw, sizeof recovery_raw);
    sodium_memzero(recovery_hex, sizeof recovery_hex);
    ksec_secure_free(&master);
    ksec_secure_free(&passphrase);
    return result;
}

static ksec_result handle_unlock(daemon_state *state, daemon_connection *connection,
                                 const uint8_t *payload, size_t payload_len,
                                 int received_fd) {
    ksec_secure_buffer secret = {0};
    ksec_secure_buffer master = {0};
    ksec_slot_type slot_type;
    uint64_t now = ksec_now_seconds();
    ksec_result result;
    if (payload == NULL || payload_len != 4U || received_fd < 0) return KSEC_ERR_PROTOCOL;
    if (!state->initialized) return KSEC_ERR_NOT_FOUND;
    if (state->unlocked) return KSEC_ERR_EXISTS;
    if (now < state->retry_after) return KSEC_ERR_BUSY;
    slot_type = (ksec_slot_type)ksec_get_u32(payload);
    if (slot_type != KSEC_SLOT_PASSPHRASE && slot_type != KSEC_SLOT_RECOVERY) {
        return KSEC_ERR_INVALID;
    }
    result = authorize(state, connection, KSEC_VERB_READ,
                       connection->capability->app_id, NULL);
    if (result != KSEC_OK) return result;
    if ((state->header.flags & KSEC_HEADER_FLAG_RECOVERY_CONFIRMED) == 0U
            && slot_type != KSEC_SLOT_RECOVERY) {
        (void)audit_state_event(state, "recovery", "required", connection->uid,
                                connection->pid,
                                connection->capability->app_id, NULL);
        return KSEC_ERR_DENIED;
    }
    result = read_sensitive_fd(received_fd, slot_type == KSEC_SLOT_RECOVERY ? 64U : 8U,
                               1024U, &secret);
    if (result != KSEC_OK) return result;
    result = ksec_secure_alloc(&master, KSEC_MASTER_KEY_BYTES);
    if (result != KSEC_OK) goto out;
    result = ksec_header_unlock(&state->header, slot_type, secret.data, secret.len,
                                master.data);
    if (result != KSEC_OK) {
        uint32_t shift = state->failed_unlocks < 3U ? state->failed_unlocks : 3U;
        state->failed_unlocks++;
        state->retry_after = now + (UINT64_C(1) << shift);
        (void)audit_state_event(state, "unlock", "denied", connection->uid,
                                connection->pid,
                                connection->capability->app_id, NULL);
        goto out;
    }
    result = ksec_store_load(&state->store, &state->header, master.data);
    if (result != KSEC_OK) goto out;
    if ((state->header.flags & KSEC_HEADER_FLAG_RECOVERY_CONFIRMED) == 0U) {
        ksec_vault_header confirmed = state->header;
        result = audit_state_event(state, "recovery", "begin", connection->uid,
                                   connection->pid,
                                   connection->capability->app_id, NULL);
        if (result != KSEC_OK) goto out;
        result = ksec_header_confirm_recovery(&confirmed, master.data);
        if (result != KSEC_OK) goto out;
        result = ksec_store_write_header(&state->store, &confirmed);
        if (result != KSEC_OK) goto out;
        state->header = confirmed;
        (void)audit_state_event(state, "recovery", "confirmed", connection->uid,
                                connection->pid,
                                connection->capability->app_id, NULL);
    }
    state->master = master;
    memset(&master, 0, sizeof master);
    state->unlocked = true;
    state->failed_unlocks = 0;
    state->retry_after = 0;
    state->last_authorized_use = now;
    (void)audit_state_event(state, "unlock", "ok", connection->uid,
                            connection->pid, connection->capability->app_id,
                            NULL);
out:
    ksec_secure_free(&master);
    ksec_secure_free(&secret);
    return result;
}

static ksec_result parse_record_request(const uint8_t *payload, size_t payload_len,
                                        bool replacement, uint16_t *object_type,
                                        uint8_t record_id[KSEC_RECORD_ID_BYTES],
                                        char owner[KSEC_MAX_APP_ID + 1U]) {
    size_t base = replacement ? 20U : 4U;
    uint16_t owner_len;
    if (payload == NULL || object_type == NULL || owner == NULL || payload_len < base + 1U) {
        return KSEC_ERR_PROTOCOL;
    }
    if (replacement) memcpy(record_id, payload, KSEC_RECORD_ID_BYTES);
    *object_type = ksec_get_u16(payload + (replacement ? 16U : 0U));
    owner_len = ksec_get_u16(payload + (replacement ? 18U : 2U));
    if ((*object_type != KSEC_OBJECT_SECRET
            && *object_type != KSEC_OBJECT_DEVICE_IDENTITY)
            || owner_len == 0 || owner_len > KSEC_MAX_APP_ID
            || payload_len != base + owner_len) return KSEC_ERR_INVALID;
    if (ksec_validate_app_id_bytes(payload + base, owner_len) != 0) {
        return KSEC_ERR_INVALID;
    }
    memcpy(owner, payload + base, owner_len);
    owner[owner_len] = '\0';
    return KSEC_OK;
}

static ksec_result handle_put(daemon_state *state, daemon_connection *connection,
                              const uint8_t *payload, size_t payload_len,
                              int received_fd, bool replacement,
                              uint8_t response_id[KSEC_RECORD_ID_BYTES]) {
    uint16_t object_type = 0;
    uint8_t requested_id[KSEC_RECORD_ID_BYTES];
    char owner[KSEC_MAX_APP_ID + 1U];
    ksec_secure_buffer encoded = {0};
    ksec_owned_record record;
    ksec_owned_record *existing = NULL;
    ksec_result result;
    memset(&record, 0, sizeof record);
    memset(requested_id, 0, sizeof requested_id);
    if (!state->unlocked) return KSEC_ERR_LOCKED;
    if (received_fd < 0) return KSEC_ERR_PROTOCOL;
    result = parse_record_request(payload, payload_len, replacement, &object_type,
                                  requested_id, owner);
    if (result != KSEC_OK) return result;
    result = authorize(state, connection,
                       replacement ? KSEC_VERB_REPLACE : KSEC_VERB_CREATE, owner,
                       replacement ? requested_id : NULL);
    if (result != KSEC_OK) return result;
    if (replacement) {
        existing = ksec_store_find(&state->store, requested_id);
        if (existing == NULL || existing->deleted) return KSEC_ERR_NOT_FOUND;
        if (strcmp(existing->owner, owner) != 0) return KSEC_ERR_DENIED;
    }
    result = read_sensitive_fd(received_fd, 1U, KSEC_MAX_RECORD_PLAINTEXT, &encoded);
    if (result != KSEC_OK) return result;
    result = ksec_record_parse(encoded.data, encoded.len, &record);
    if (result != KSEC_OK) goto out;
    memcpy(record.owner, owner, strlen(owner) + 1U);
    record.object_type = object_type;
    if (replacement) memcpy(record.id, requested_id, KSEC_RECORD_ID_BYTES);
    else {
        do {
            randombytes_buf(record.id, KSEC_RECORD_ID_BYTES);
        } while (ksec_store_find(&state->store, record.id) != NULL);
    }
    memcpy(response_id, record.id, KSEC_RECORD_ID_BYTES);
    result = audit_state_event(state, replacement ? "replace" : "create",
                               "begin", connection->uid, connection->pid,
                               connection->capability->app_id, record.id);
    if (result != KSEC_OK) goto out;
    result = ksec_store_append(&state->store, &state->header, state->master.data,
                               &record, false);
out:
    ksec_owned_record_clear(&record);
    ksec_secure_free(&encoded);
    return result;
}

static ksec_result handle_get(daemon_state *state, daemon_connection *connection,
                              const uint8_t *payload, size_t payload_len,
                              int received_fd, int *reply_fd) {
    uint16_t field_len;
    char field[KSEC_MAX_FIELD_NAME + 1U];
    ksec_owned_record *record;
    size_t index;
    ksec_result result;
    if (!state->unlocked) return KSEC_ERR_LOCKED;
    if (received_fd >= 0 || payload == NULL || payload_len < 19U) return KSEC_ERR_PROTOCOL;
    field_len = ksec_get_u16(payload + KSEC_RECORD_ID_BYTES);
    if (field_len == 0 || field_len > KSEC_MAX_FIELD_NAME
            || payload_len != 18U + field_len) return KSEC_ERR_INVALID;
    memcpy(field, payload + 18U, field_len);
    field[field_len] = '\0';
    if (ksec_validate_name(field, KSEC_MAX_FIELD_NAME) != 0) return KSEC_ERR_INVALID;
    record = ksec_store_find(&state->store, payload);
    if (record == NULL || record->deleted) return KSEC_ERR_NOT_FOUND;
    result = authorize(state, connection, KSEC_VERB_USE, record->owner, record->id);
    if (result != KSEC_OK) {
        result = authorize(state, connection, KSEC_VERB_READ, record->owner,
                           record->id);
    }
    if (result != KSEC_OK) return result;
    if (record->expires_at != 0U && record->expires_at <= ksec_now_seconds()) {
        return KSEC_ERR_EXPIRED;
    }
    for (index = 0; index < record->field_count; index++) {
        if (strcmp(record->fields[index].name, field) == 0) {
            result = sensitive_fd_from_bytes(record->fields[index].value.data,
                                             record->fields[index].value.len, reply_fd);
            if (result == KSEC_OK) {
                (void)audit_state_event(state, "use", "ok", connection->uid,
                                        connection->pid,
                                        connection->capability->app_id,
                                        record->id);
            }
            return result;
        }
    }
    return KSEC_ERR_NOT_FOUND;
}

static ksec_result handle_delete(daemon_state *state, daemon_connection *connection,
                                 const uint8_t *payload, size_t payload_len,
                                 int received_fd) {
    ksec_owned_record *existing;
    ksec_owned_record tombstone;
    ksec_result result;
    if (!state->unlocked) return KSEC_ERR_LOCKED;
    if (received_fd >= 0 || payload == NULL || payload_len != KSEC_RECORD_ID_BYTES) {
        return KSEC_ERR_PROTOCOL;
    }
    existing = ksec_store_find(&state->store, payload);
    if (existing == NULL || existing->deleted) return KSEC_ERR_NOT_FOUND;
    result = authorize(state, connection, KSEC_VERB_DELETE, existing->owner,
                       existing->id);
    if (result != KSEC_OK) return result;
    result = audit_state_event(state, "delete", "begin", connection->uid,
                               connection->pid,
                               connection->capability->app_id, existing->id);
    if (result != KSEC_OK) return result;
    memset(&tombstone, 0, sizeof tombstone);
    memcpy(tombstone.id, existing->id, KSEC_RECORD_ID_BYTES);
    memcpy(tombstone.owner, existing->owner, strlen(existing->owner) + 1U);
    tombstone.object_type = existing->object_type;
    result = ksec_store_append(&state->store, &state->header, state->master.data,
                               &tombstone, true);
    ksec_owned_record_clear(&tombstone);
    return result;
}

static ksec_result handle_list(daemon_state *state, daemon_connection *connection,
                               size_t payload_len, int received_fd, int *reply_fd) {
    uint8_t *listing;
    size_t used = 0;
    size_t index;
    ksec_result result;
    if (!state->unlocked) return KSEC_ERR_LOCKED;
    if (payload_len != 0U || received_fd >= 0) return KSEC_ERR_PROTOCOL;
    result = authorize(state, connection, KSEC_VERB_LIST_OWN,
                       connection->capability->app_id, NULL);
    if (result != KSEC_OK) return result;
    listing = calloc(1U, KSEC_MAX_RECORD_PLAINTEXT);
    if (listing == NULL) return KSEC_ERR_MEMORY;
    for (index = 0; index < state->store.record_count; index++) {
        ksec_owned_record *record = &state->store.records[index];
        char id_hex[KSEC_RECORD_ID_BYTES * 2U + 1U];
        int count;
        if (record->deleted || strcmp(record->owner, connection->capability->app_id) != 0) continue;
        ksec_hex_encode(record->id, KSEC_RECORD_ID_BYTES, id_hex);
        count = snprintf((char *)listing + used, KSEC_MAX_RECORD_PLAINTEXT - used,
                         "%s\t%s\t%s\t%llu\n", id_hex, record->type, record->label,
                         (unsigned long long)record->expires_at);
        if (count < 0 || (size_t)count >= KSEC_MAX_RECORD_PLAINTEXT - used) {
            sodium_memzero(listing, KSEC_MAX_RECORD_PLAINTEXT);
            free(listing);
            return KSEC_ERR_LIMIT;
        }
        used += (size_t)count;
    }
    if (used == 0U) {
        listing[0] = (uint8_t)'\n';
        used = 1U;
    }
    result = sensitive_fd_from_bytes(listing, used, reply_fd);
    sodium_memzero(listing, KSEC_MAX_RECORD_PLAINTEXT);
    free(listing);
    return result;
}

static ksec_result handle_doctor(daemon_state *state, daemon_connection *connection,
                                 size_t payload_len, int received_fd, int *reply_fd) {
    char report[512];
    int count;
    ksec_result result;
    if (payload_len != 0U || received_fd >= 0) return KSEC_ERR_PROTOCOL;
    result = authorize(state, connection, KSEC_VERB_DOCTOR,
                       connection->capability->app_id, NULL);
    if (result != KSEC_OK) return result;
    count = snprintf(report, sizeof report,
                     "format=1\ninitialized=%s\nstate=%s\nrecovery=%s\nkdf_point=%s\nrecords=%zu/%u\ntorn_tail=%s\naudit=%s\n",
                     state->initialized ? "yes" : "no",
                     state->unlocked ? "unlocked" : "locked",
                     !state->initialized ? "not-initialized"
                         : (state->header.flags & KSEC_HEADER_FLAG_RECOVERY_CONFIRMED) != 0U
                             ? "confirmed" : "confirmation-required",
                     state->kdf_configured ? "development-configured" : "unselected",
                     state->unlocked ? state->store.record_count : 0U,
                     KSEC_MAX_RECORDS,
                     state->store.torn_tail ? "yes" : "no",
                     state->audit_degraded ? "degraded" : "available");
    if (count < 0 || (size_t)count >= sizeof report) return KSEC_ERR_LIMIT;
    return sensitive_fd_from_bytes((const uint8_t *)report, (size_t)count, reply_fd);
}

static ksec_result dispatch_request(daemon_state *state, daemon_connection *connection,
                                    const ksec_packet_header *request,
                                    const uint8_t *payload, int received_fd,
                                    uint8_t response_id[KSEC_RECORD_ID_BYTES],
                                    size_t *response_len, int *reply_fd) {
    ksec_result result;
    *response_len = 0U;
    *reply_fd = -1;
    if (connection->uid != getuid()) return KSEC_ERR_DENIED;
    switch (request->operation) {
        case KSEC_OP_MINT:
            return handle_mint(state, connection, payload, request->payload_len,
                               received_fd, reply_fd);
        case KSEC_OP_ACTIVATE:
            return handle_activate(state, connection, request->payload_len, received_fd);
        default:
            if (connection->capability == NULL) return KSEC_ERR_DENIED;
            break;
    }
    switch (request->operation) {
        case KSEC_OP_INIT:
            return handle_init(state, connection, payload, request->payload_len,
                               received_fd, reply_fd);
        case KSEC_OP_UNLOCK:
            return handle_unlock(state, connection, payload, request->payload_len,
                                 received_fd);
        case KSEC_OP_LOCK:
            if (request->payload_len != 0U || received_fd >= 0) return KSEC_ERR_PROTOCOL;
            result = authorize(state, connection, KSEC_VERB_READ,
                               connection->capability->app_id, NULL);
            if (result != KSEC_OK) return result;
            (void)audit_state_event(state, "lock", "ok", connection->uid,
                                    connection->pid,
                                    connection->capability->app_id, NULL);
            lock_state(state);
            connection->capability = NULL;
            return KSEC_OK;
        case KSEC_OP_PUT:
            result = handle_put(state, connection, payload, request->payload_len,
                                received_fd, false, response_id);
            if (result == KSEC_OK) *response_len = KSEC_RECORD_ID_BYTES;
            return result;
        case KSEC_OP_REPLACE:
            result = handle_put(state, connection, payload, request->payload_len,
                                received_fd, true, response_id);
            if (result == KSEC_OK) *response_len = KSEC_RECORD_ID_BYTES;
            return result;
        case KSEC_OP_GET:
            return handle_get(state, connection, payload, request->payload_len,
                              received_fd, reply_fd);
        case KSEC_OP_DELETE:
            return handle_delete(state, connection, payload, request->payload_len,
                                 received_fd);
        case KSEC_OP_LIST:
            return handle_list(state, connection, request->payload_len, received_fd,
                               reply_fd);
        case KSEC_OP_DOCTOR:
            return handle_doctor(state, connection, request->payload_len, received_fd,
                                 reply_fd);
        case KSEC_OP_COMPACT:
            if (!state->unlocked) return KSEC_ERR_LOCKED;
            if (request->payload_len != 0U || received_fd >= 0) return KSEC_ERR_PROTOCOL;
            result = authorize(state, connection, KSEC_VERB_REPLACE,
                               connection->capability->app_id, NULL);
            if (result != KSEC_OK) return result;
            result = audit_state_event(state, "compact", "begin",
                                       connection->uid, connection->pid,
                                       connection->capability->app_id, NULL);
            if (result != KSEC_OK) return result;
            return ksec_store_compact(&state->store, &state->header,
                                      state->master.data);
        default:
            return KSEC_ERR_PROTOCOL;
    }
}

static int create_listener(const char *socket_path) {
    struct sockaddr_un address;
    char directory[4096];
    char parent[4096];
    char *slash;
    struct stat status;
    int fd;
    size_t path_len;
    if (socket_path == NULL || socket_path[0] != '/') return -1;
    path_len = strlen(socket_path);
    if (path_len >= sizeof address.sun_path || path_len >= sizeof directory) return -1;
    memcpy(directory, socket_path, path_len + 1U);
    slash = strrchr(directory, '/');
    if (slash == NULL || slash == directory) return -1;
    *slash = '\0';
    if (lstat(directory, &status) != 0) {
        if (errno != ENOENT
                || ksec_parent_directory(directory, parent, sizeof parent) != 0
                || ksec_validate_secure_directory(parent, true) != 0
                || mkdir(directory, 0700) != 0
                || ksec_sync_directory(parent) != 0) return -1;
    }
    if (ksec_validate_secure_directory(directory, true) != 0) return -1;
    if (lstat(socket_path, &status) == 0) {
        if (!S_ISSOCK(status.st_mode) || status.st_uid != getuid()
                || unlink(socket_path) != 0) return -1;
    } else if (errno != ENOENT) return -1;
    fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) return -1;
    memset(&address, 0, sizeof address);
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, socket_path, path_len + 1U);
    if (bind(fd, (struct sockaddr *)&address, sizeof address) != 0
            || chmod(socket_path, 0600) != 0 || listen(fd, 32) != 0) {
        int saved = errno;
        (void)close(fd);
        (void)unlink(socket_path);
        errno = saved;
        return -1;
    }
    return fd;
}

static int accept_connection(int listener, daemon_connection *connection) {
    struct ucred credentials;
    socklen_t length = sizeof credentials;
    int fd = accept4(listener, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
    if (fd < 0) return -1;
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &length) != 0
            || length != sizeof credentials) {
        (void)close(fd);
        return -1;
    }
    memset(connection, 0, sizeof *connection);
    connection->fd = fd;
    connection->uid = credentials.uid;
    connection->pid = credentials.pid;
    return 0;
}

static void close_connection(daemon_state *state, daemon_connection *connection) {
    if (connection->fd >= 0) {
        ksec_policy_disconnect(&state->policy, connection->fd);
        (void)close(connection->fd);
    }
    memset(connection, 0, sizeof *connection);
    connection->fd = -1;
}

static int serve(int listener, daemon_state *state) {
    daemon_connection connections[KSEC_MAX_CONNECTIONS];
    struct pollfd pollfds[KSEC_MAX_CONNECTIONS + 1U];
    size_t index;
    for (index = 0; index < KSEC_MAX_CONNECTIONS; index++) connections[index].fd = -1;
    while (!stop_requested) {
        int ready;
        pollfds[0].fd = listener;
        pollfds[0].events = POLLIN;
        pollfds[0].revents = 0;
        for (index = 0; index < KSEC_MAX_CONNECTIONS; index++) {
            pollfds[index + 1U].fd = connections[index].fd;
            pollfds[index + 1U].events = POLLIN;
            pollfds[index + 1U].revents = 0;
        }
        ready = poll(pollfds, KSEC_MAX_CONNECTIONS + 1U, 1000);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) return -1;
        if (state->unlocked && state->idle_timeout > 0U
                && ksec_now_seconds() - state->last_authorized_use >= state->idle_timeout) {
            lock_state(state);
            for (index = 0; index < KSEC_MAX_CONNECTIONS; index++) {
                connections[index].capability = NULL;
            }
        }
        if ((pollfds[0].revents & POLLIN) != 0) {
            daemon_connection incoming;
            bool placed = false;
            if (accept_connection(listener, &incoming) == 0) {
                for (index = 0; index < KSEC_MAX_CONNECTIONS; index++) {
                    if (connections[index].fd < 0) {
                        connections[index] = incoming;
                        placed = true;
                        break;
                    }
                }
                if (!placed) (void)close(incoming.fd);
            }
        }
        for (index = 0; index < KSEC_MAX_CONNECTIONS; index++) {
            daemon_connection *connection = &connections[index];
            short events = pollfds[index + 1U].revents;
            if (connection->fd < 0 || events == 0) continue;
            if ((events & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
                close_connection(state, connection);
                continue;
            }
            if ((events & POLLIN) != 0) {
                ksec_packet_header request;
                uint8_t payload[KSEC_PROTOCOL_MAX_PAYLOAD];
                uint8_t response_id[KSEC_RECORD_ID_BYTES];
                size_t response_len = 0;
                int received_fd = -1;
                int reply_fd = -1;
                ksec_result result = ksec_recv_packet(connection->fd, &request,
                                                       payload, sizeof payload,
                                                       &received_fd);
                if (result == KSEC_ERR_NOT_FOUND) {
                    close_connection(state, connection);
                    continue;
                }
                if (result != KSEC_OK) {
                    if (received_fd >= 0) (void)close(received_fd);
                    close_connection(state, connection);
                    continue;
                }
                result = dispatch_request(state, connection, &request, payload,
                                          received_fd, response_id, &response_len,
                                          &reply_fd);
                if (received_fd >= 0) (void)close(received_fd);
                if (send_reply(connection, &request, result,
                               response_len > 0U ? response_id : NULL,
                               response_len, result == KSEC_OK ? reply_fd : -1) != KSEC_OK) {
                    if (reply_fd >= 0) (void)close(reply_fd);
                    close_connection(state, connection);
                    continue;
                }
                if (reply_fd >= 0) (void)close(reply_fd);
                sodium_memzero(payload, sizeof payload);
                sodium_memzero(response_id, sizeof response_id);
            }
        }
    }
    for (index = 0; index < KSEC_MAX_CONNECTIONS; index++) {
        if (connections[index].fd >= 0) close_connection(state, &connections[index]);
    }
    return 0;
}

static int parse_u32(const char *text, uint32_t *out) {
    char *end = NULL;
    unsigned long value;
    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value > UINT32_MAX) return -1;
    *out = (uint32_t)value;
    return 0;
}

static void usage(FILE *stream) {
    fprintf(stream,
            "usage: kilix-secretsd [--systemd | --socket PATH] --data-dir PATH\n"
            "       [--development-kdf-ops 3..6 --development-kdf-mem-mib 256..512]\n"
            "       [--idle-seconds N]\n");
}

int main(int argc, char **argv) {
    static const struct option options[] = {
        {"systemd", no_argument, NULL, 'S'},
        {"socket", required_argument, NULL, 's'},
        {"data-dir", required_argument, NULL, 'd'},
        {"development-kdf-ops", required_argument, NULL, 'o'},
        {"development-kdf-mem-mib", required_argument, NULL, 'm'},
        {"idle-seconds", required_argument, NULL, 'i'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };
    const char *socket_path = NULL;
    const char *data_dir = NULL;
    bool systemd_mode = false;
    bool systemd_environment_valid = false;
    bool ops_set = false;
    bool mem_set = false;
    uint32_t mem_mib = 0;
    int listener = -1;
    int option;
    int exit_code = 1;
    daemon_state state;
    struct rlimit core_limit = {0, 0};
    struct sigaction action;
    memset(&state, 0, sizeof state);
    state.store.lock_fd = -1;
    state.audit_fd = -1;
    state.idle_timeout = 900U;
    while ((option = getopt_long(argc, argv, "Ss:d:o:m:i:h", options, NULL)) != -1) {
        switch (option) {
            case 'S': systemd_mode = true; break;
            case 's': socket_path = optarg; break;
            case 'd': data_dir = optarg; break;
            case 'o':
                if (parse_u32(optarg, &state.argon_ops) != 0) { usage(stderr); return 2; }
                ops_set = true;
                break;
            case 'm':
                if (parse_u32(optarg, &mem_mib) != 0) { usage(stderr); return 2; }
                mem_set = true;
                break;
            case 'i': {
                uint32_t idle;
                if (parse_u32(optarg, &idle) != 0) { usage(stderr); return 2; }
                state.idle_timeout = idle;
                break;
            }
            case 'h': usage(stdout); return 0;
            default: usage(stderr); return 2;
        }
    }
    if (optind != argc || data_dir == NULL || data_dir[0] != '/'
            || systemd_mode == (socket_path != NULL) || ops_set != mem_set) {
        usage(stderr);
        return 2;
    }
    if (systemd_mode) {
        systemd_environment_valid = systemd_environment_matches() != 0;
        if (!systemd_environment_valid) return 2;
    }
    if (ops_set) {
        state.argon_mem = (uint64_t)mem_mib * UINT64_C(1024) * UINT64_C(1024);
        if (state.argon_ops < KSEC_ARGON_OPS_MIN || state.argon_ops > KSEC_ARGON_OPS_MAX
                || state.argon_mem < KSEC_ARGON_MEM_MIN || state.argon_mem > KSEC_ARGON_MEM_MAX) {
            usage(stderr);
            return 2;
        }
        state.kdf_configured = true;
    }
    umask(0077);
    if (clearenv() != 0 || close_unneeded_descriptors(systemd_mode) != 0) return 1;
    if (setrlimit(RLIMIT_CORE, &core_limit) != 0 || prctl(PR_SET_DUMPABLE, 0) != 0
            || ksec_crypto_initialize() != KSEC_OK) return 1;
    memset(&action, 0, sizeof action);
    action.sa_handler = handle_signal;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) != 0 || sigaction(SIGINT, &action, NULL) != 0
            || signal(SIGPIPE, SIG_IGN) == SIG_ERR) return 1;
    ksec_policy_init(&state.policy);
    if (ksec_store_open(&state.store, data_dir, true) != KSEC_OK) goto cleanup;
    {
        ksec_result header_result = ksec_store_read_header(&state.store, &state.header);
        if (header_result == KSEC_OK) state.initialized = true;
        else if (header_result != KSEC_ERR_NOT_FOUND) goto cleanup;
    }
    if (ksec_audit_open(data_dir, &state.audit_fd) != KSEC_OK) goto cleanup;
    if (systemd_mode) {
        listener = 3;
        if (!systemd_environment_valid || validate_systemd_listener(listener) != 0) goto cleanup;
    } else {
        listener = create_listener(socket_path);
        if (listener < 0) goto cleanup;
    }
    exit_code = serve(listener, &state) == 0 ? 0 : 1;
cleanup:
    lock_state(&state);
    if (listener >= 0 && (!systemd_mode || listener != 3)) (void)close(listener);
    if (!systemd_mode && socket_path != NULL) (void)unlink(socket_path);
    if (state.audit_fd >= 0) (void)close(state.audit_fd);
    ksec_store_close(&state.store);
    ksec_policy_clear(&state.policy);
    sodium_memzero(&state.header, sizeof state.header);
    return exit_code;
}
