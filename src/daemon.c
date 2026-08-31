#define _GNU_SOURCE

#include "internal.h"
#include "session.h"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
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
    bool active;
    int writer_fd;
    int connection_fd;
    ksec_capability *capability;
    uint8_t record_id[KSEC_RECORD_ID_BYTES];
    uint64_t record_revision;
} identity_lease;

typedef struct {
    ksec_store store;
    ksec_vault_header header;
    ksec_secure_buffer master;
    ksec_policy policy;
    int audit_fd;
    bool audit_degraded;
    bool initialized;
    bool header_damaged;
    bool unlocked;
    bool kdf_configured;
    uint32_t argon_ops;
    uint64_t argon_mem;
    uint32_t failed_unlocks;
    uint64_t retry_after;
    uint64_t idle_timeout;
    uint64_t last_authorized_use;
    ksec_session_monitor *session_monitor;
    identity_lease identity_leases[KSEC_MAX_IDENTITY_LEASES];
} daemon_state;

static volatile sig_atomic_t stop_requested = 0;
static volatile sig_atomic_t lock_requested = 0;

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
    if (signal_number == SIGUSR1) lock_requested = 1;
    else stop_requested = 1;
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
    /*
     * The event loop drains the accept queue until accept4() reports EAGAIN,
     * so a blocking listener would sleep inside accept4() and stall the single
     * daemon thread. A self-created listener gets SOCK_NONBLOCK at creation;
     * an inherited one carries whatever the activator chose, so establish the
     * property here rather than depending on it.
     */
    if (ksec_set_nonblock(fd, true) != 0) return -1;
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

static ksec_result validate_identity_record(const ksec_owned_record *record) {
    if (record == NULL || record->deleted
            || record->object_type != KSEC_OBJECT_DEVICE_IDENTITY
            || strcmp(record->owner, KSEC_IDENTITY_OWNER) != 0
            || strcmp(record->type, KSEC_IDENTITY_TYPE) != 0
            || record->expires_at != 0U || record->field_count != 1U
            || strcmp(record->fields[0].name,
                      KSEC_IDENTITY_PRIVATE_FIELD) != 0
            || record->fields[0].value.len != KSEC_IDENTITY_KEY_BYTES
            || record->grant_count != 0U) return KSEC_ERR_INVALID;
    return KSEC_OK;
}

static void close_identity_lease(identity_lease *lease) {
    if (lease == NULL || !lease->active) return;
    if (lease->writer_fd >= 0) (void)close(lease->writer_fd);
    sodium_memzero(lease, sizeof *lease);
}

static void invalidate_all_identity_leases(daemon_state *state) {
    size_t index;
    if (state == NULL) return;
    for (index = 0U; index < KSEC_MAX_IDENTITY_LEASES; index++) {
        close_identity_lease(&state->identity_leases[index]);
    }
}

static void invalidate_record_identity_leases(
        daemon_state *state,
        const uint8_t record_id[KSEC_RECORD_ID_BYTES]) {
    size_t index;
    if (state == NULL || record_id == NULL) return;
    for (index = 0U; index < KSEC_MAX_IDENTITY_LEASES; index++) {
        identity_lease *lease = &state->identity_leases[index];
        if (lease->active
                && sodium_memcmp(lease->record_id, record_id,
                                 KSEC_RECORD_ID_BYTES) == 0) {
            close_identity_lease(lease);
        }
    }
}

static void invalidate_connection_identity_leases(daemon_state *state,
                                                   int connection_fd) {
    size_t index;
    if (state == NULL || connection_fd < 0) return;
    for (index = 0U; index < KSEC_MAX_IDENTITY_LEASES; index++) {
        identity_lease *lease = &state->identity_leases[index];
        if (lease->active && lease->connection_fd == connection_fd) {
            close_identity_lease(lease);
        }
    }
}

static size_t identity_lease_count(const daemon_state *state) {
    size_t index;
    size_t count = 0U;
    if (state == NULL) return 0U;
    for (index = 0U; index < KSEC_MAX_IDENTITY_LEASES; index++) {
        if (state->identity_leases[index].active) count++;
    }
    return count;
}

static void expire_identity_leases(daemon_state *state) {
    size_t index;
    if (state == NULL) return;
    for (index = 0U; index < KSEC_MAX_IDENTITY_LEASES; index++) {
        identity_lease *lease = &state->identity_leases[index];
        ksec_owned_record *record;
        struct pollfd descriptor;
        if (!lease->active) continue;
        descriptor.fd = lease->writer_fd;
        descriptor.events = POLLOUT;
        descriptor.revents = 0;
        {
            int ready = poll(&descriptor, 1U, 0);
            if ((ready > 0
                    && (descriptor.revents
                        & (POLLERR | POLLHUP | POLLNVAL)) != 0)
                    || (ready < 0 && errno != EINTR)) {
                close_identity_lease(lease);
                continue;
            }
        }
        record = state->unlocked
            ? ksec_store_find(&state->store, lease->record_id) : NULL;
        if (record == NULL || validate_identity_record(record) != KSEC_OK
                || record->revision != lease->record_revision
                || ksec_policy_authorize(lease->capability, KSEC_VERB_USE,
                                         KSEC_IDENTITY_OWNER,
                                         lease->record_id) != KSEC_OK) {
            close_identity_lease(lease);
        }
    }
}

static void lock_state(daemon_state *state) {
    if (state == NULL) return;
    invalidate_all_identity_leases(state);
    ksec_secure_free(&state->master);
    ksec_store_clear_records(&state->store);
    ksec_policy_clear(&state->policy);
    ksec_policy_init(&state->policy);
    state->unlocked = false;
    state->last_authorized_use = 0;
}

static ksec_result finish_store_mutation(daemon_state *state,
                                         ksec_result result) {
    if (state != NULL && result != KSEC_OK) {
        ksec_vault_header observed;
        memset(&observed, 0, sizeof observed);
        ksec_result observed_result =
            ksec_store_read_header(&state->store, &observed);
        if (observed_result == KSEC_OK) {
            state->header = observed;
            state->initialized = true;
            state->header_damaged = false;
        } else {
            state->initialized = false;
            state->header_damaged = observed_result != KSEC_ERR_NOT_FOUND;
        }
        sodium_memzero(&observed, sizeof observed);
        lock_state(state);
    }
    return result;
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

static bool record_grants_verb(const ksec_owned_record *record,
                               const char *application_id, uint32_t verb) {
    size_t index;
    if (record == NULL || application_id == NULL) return false;
    for (index = 0U; index < record->grant_count; index++) {
        if (strcmp(record->grants[index].application_id, application_id) == 0) {
            return (record->grants[index].verbs & verb) == verb;
        }
    }
    return false;
}

static ksec_result authorize_record_raw(daemon_connection *connection,
                                        uint32_t verb,
                                        const ksec_owned_record *record) {
    ksec_result result;
    if (connection == NULL || connection->capability == NULL || record == NULL) {
        return KSEC_ERR_DENIED;
    }
    result = ksec_policy_authorize(connection->capability, verb, record->owner,
                                   record->id);
    if (result != KSEC_OK
            && record_grants_verb(record, connection->capability->app_id, verb)) {
        result = ksec_policy_authorize(connection->capability, verb, NULL,
                                       record->id);
    }
    return result;
}

static ksec_result authorize_record(daemon_state *state,
                                    daemon_connection *connection,
                                    uint32_t verb,
                                    const ksec_owned_record *record) {
    ksec_result result;
    if (state == NULL) return KSEC_ERR_DENIED;
    result = authorize_record_raw(connection, verb, record);
    if (result == KSEC_OK) {
        state->last_authorized_use = ksec_now_seconds();
    } else {
        (void)audit_state_event(state, "authorize", "denied", connection->uid,
                                connection->pid,
                                connection->capability->app_id, record->id);
    }
    return result;
}

static ksec_result clone_owned_record(const ksec_owned_record *source,
                                      ksec_owned_record *destination) {
    size_t index;
    ksec_result result;
    if (source == NULL || destination == NULL || source->deleted
            || source->field_count == 0U
            || source->field_count > KSEC_MAX_FIELDS
            || source->grant_count > KSEC_MAX_GRANTS) return KSEC_ERR_INVALID;
    memset(destination, 0, sizeof *destination);
    memcpy(destination->id, source->id, KSEC_RECORD_ID_BYTES);
    memcpy(destination->owner, source->owner, strlen(source->owner) + 1U);
    memcpy(destination->type, source->type, strlen(source->type) + 1U);
    memcpy(destination->label, source->label, strlen(source->label) + 1U);
    destination->object_type = source->object_type;
    destination->revision = source->revision;
    destination->expires_at = source->expires_at;
    destination->grant_count = source->grant_count;
    memcpy(destination->grants, source->grants,
           source->grant_count * sizeof source->grants[0]);
    for (index = 0U; index < source->field_count; index++) {
        memcpy(destination->fields[index].name, source->fields[index].name,
               strlen(source->fields[index].name) + 1U);
        result = ksec_secure_alloc(&destination->fields[index].value,
                                   source->fields[index].value.len);
        if (result != KSEC_OK) {
            ksec_owned_record_clear(destination);
            return result;
        }
        memcpy(destination->fields[index].value.data,
               source->fields[index].value.data,
               source->fields[index].value.len);
        destination->field_count++;
    }
    return KSEC_OK;
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
    ksec_vault_header candidate;
    uint8_t recovery_raw[32];
    char recovery_hex[65];
    uint32_t selector;
    uint32_t opslimit = 0;
    uint64_t memlimit = 0;
    bool retry_unconfirmed;
    ksec_result result;
    memset(&candidate, 0, sizeof candidate);
    if (payload == NULL || payload_len != 4U || received_fd < 0) return KSEC_ERR_PROTOCOL;
    selector = ksec_get_u32(payload);
    if (selector != 0U) return KSEC_ERR_INVALID;
    retry_unconfirmed = state->initialized
        && (state->header.flags & KSEC_HEADER_FLAG_RECOVERY_CONFIRMED) == 0U;
    if (state->header_damaged) return KSEC_ERR_INVALID;
    if (state->initialized && !retry_unconfirmed) return KSEC_ERR_EXISTS;
    if (retry_unconfirmed && ksec_now_seconds() < state->retry_after) {
        return KSEC_ERR_BUSY;
    }
    result = authorize(state, connection, KSEC_VERB_CREATE,
                       connection->capability->app_id, NULL);
    if (result != KSEC_OK) return result;
    if (!retry_unconfirmed && !state->kdf_configured) return KSEC_ERR_INVALID;
    result = read_sensitive_fd(received_fd, 8U, 1024U, &passphrase);
    if (result != KSEC_OK) return result;
    result = ksec_secure_alloc(&master, KSEC_MASTER_KEY_BYTES);
    if (result != KSEC_OK) goto out;
    randombytes_buf(recovery_raw, sizeof recovery_raw);
    ksec_hex_encode(recovery_raw, sizeof recovery_raw, recovery_hex);
    if (retry_unconfirmed) {
        size_t index;
        result = ksec_header_unlock(&state->header, KSEC_SLOT_PASSPHRASE,
                                    passphrase.data, passphrase.len, master.data);
        if (result != KSEC_OK) {
            uint64_t now = ksec_now_seconds();
            uint32_t shift = state->failed_unlocks < 3U
                ? state->failed_unlocks : 3U;
            state->failed_unlocks++;
            state->retry_after = now + (UINT64_C(1) << shift);
            (void)audit_state_event(state, "recovery", "denied",
                                    connection->uid, connection->pid,
                                    connection->capability->app_id, NULL);
            goto out;
        }
        for (index = 0U; index < state->header.slot_count; index++) {
            if (state->header.slots[index].slot_type
                    == KSEC_SLOT_RECOVERY) {
                opslimit = state->header.slots[index].opslimit;
                memlimit = state->header.slots[index].memlimit;
            }
        }
        candidate = state->header;
        result = ksec_header_rewrap_slot(
                &candidate, KSEC_SLOT_RECOVERY,
                (const uint8_t *)recovery_hex, 64U, opslimit, memlimit,
                master.data);
    } else {
        result = ksec_header_create(&candidate, passphrase.data, passphrase.len,
                                    (const uint8_t *)recovery_hex, 64U,
                                    state->argon_ops, state->argon_mem,
                                    master.data);
    }
    if (result != KSEC_OK) goto out;
    result = sensitive_fd_from_bytes((const uint8_t *)recovery_hex, 64U,
                                     reply_fd);
    if (result != KSEC_OK) goto out;
    result = audit_state_event(state, retry_unconfirmed ? "recovery" : "init",
                               "begin", connection->uid, connection->pid,
                               connection->capability->app_id, NULL);
    if (result != KSEC_OK) goto out;
    result = ksec_store_write_header(&state->store, &candidate);
    if (result != KSEC_OK) {
        ksec_vault_header observed;
        if (*reply_fd >= 0) {
            (void)close(*reply_fd);
            *reply_fd = -1;
        }
        if (ksec_store_read_header(&state->store, &observed) == KSEC_OK) {
            state->header = observed;
            state->initialized = true;
            sodium_memzero(&observed, sizeof observed);
        }
        (void)finish_store_mutation(state, result);
        goto out;
    }
    state->header = candidate;
    state->initialized = true;
    state->failed_unlocks = 0U;
    state->retry_after = 0U;
    (void)audit_state_event(state, retry_unconfirmed ? "recovery" : "init",
                            "ok", connection->uid, connection->pid,
                            connection->capability->app_id, NULL);
out:
    if (result != KSEC_OK && *reply_fd >= 0) {
        (void)close(*reply_fd);
        *reply_fd = -1;
    }
    sodium_memzero(recovery_raw, sizeof recovery_raw);
    sodium_memzero(recovery_hex, sizeof recovery_hex);
    sodium_memzero(&candidate, sizeof candidate);
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
        if (result != KSEC_OK) {
            (void)finish_store_mutation(state, result);
            goto out;
        }
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

static ksec_result handle_change_passphrase(
        daemon_state *state, daemon_connection *connection,
        const uint8_t *payload, size_t payload_len, int received_fd) {
    ksec_secure_buffer passphrase = {0};
    ksec_vault_header candidate;
    uint32_t selector;
    uint32_t opslimit = 0U;
    uint64_t memlimit = 0U;
    size_t index;
    ksec_result result;
    memset(&candidate, 0, sizeof candidate);
    if (payload == NULL || payload_len != 4U || received_fd < 0) {
        return KSEC_ERR_PROTOCOL;
    }
    selector = ksec_get_u32(payload);
    if (selector != 0U) return KSEC_ERR_INVALID;
    if (!state->unlocked) return KSEC_ERR_LOCKED;
    result = authorize(state, connection, KSEC_VERB_REPLACE,
                       connection->capability->app_id, NULL);
    if (result != KSEC_OK) return result;
    result = read_sensitive_fd(received_fd, 8U, 1024U, &passphrase);
    if (result != KSEC_OK) return result;
    for (index = 0U; index < state->header.slot_count; index++) {
        if (state->header.slots[index].slot_type == KSEC_SLOT_PASSPHRASE) {
            opslimit = state->header.slots[index].opslimit;
            memlimit = state->header.slots[index].memlimit;
        }
    }
    result = audit_state_event(state, "passphrase-change", "begin",
                               connection->uid, connection->pid,
                               connection->capability->app_id, NULL);
    if (result != KSEC_OK) goto out;
    candidate = state->header;
    result = ksec_header_rewrap_slot(&candidate, KSEC_SLOT_PASSPHRASE,
                                     passphrase.data, passphrase.len,
                                     opslimit, memlimit, state->master.data);
    if (result != KSEC_OK) goto out;
    result = ksec_store_write_header(&state->store, &candidate);
    if (result != KSEC_OK) {
        result = finish_store_mutation(state, result);
        goto out;
    }
    state->header = candidate;
    (void)audit_state_event(state, "passphrase-change", "ok",
                            connection->uid, connection->pid,
                            connection->capability->app_id, NULL);
out:
    sodium_memzero(&candidate, sizeof candidate);
    ksec_secure_free(&passphrase);
    return result;
}

static ksec_result handle_rotate_master(
        daemon_state *state, daemon_connection *connection,
        const uint8_t *payload, size_t payload_len, int received_fd) {
    ksec_secure_buffer framed = {0};
    ksec_secure_buffer verified = {0};
    ksec_secure_buffer new_master = {0};
    ksec_vault_header candidate;
    uint32_t passphrase_len;
    uint32_t recovery_len;
    uint32_t opslimit = 0U;
    uint64_t memlimit = 0U;
    uint32_t selector;
    size_t index;
    char app_id[KSEC_MAX_APP_ID + 1U];
    ksec_result result;
    memset(&candidate, 0, sizeof candidate);
    memset(app_id, 0, sizeof app_id);
    if (payload == NULL || payload_len != 4U || received_fd < 0) {
        return KSEC_ERR_PROTOCOL;
    }
    selector = ksec_get_u32(payload);
    if (selector != 0U) return KSEC_ERR_INVALID;
    if (!state->unlocked) return KSEC_ERR_LOCKED;
    result = authorize(state, connection, KSEC_VERB_REPLACE,
                       connection->capability->app_id, NULL);
    if (result != KSEC_OK) return result;
    memcpy(app_id, connection->capability->app_id,
           strlen(connection->capability->app_id) + 1U);
    result = read_sensitive_fd(received_fd, 48U, 2056U, &framed);
    if (result != KSEC_OK) goto out;
    if (framed.len < 8U) { result = KSEC_ERR_INVALID; goto out; }
    passphrase_len = ksec_get_u32(framed.data);
    recovery_len = ksec_get_u32(framed.data + 4U);
    if (passphrase_len < 8U || passphrase_len > 1024U
            || recovery_len < 32U || recovery_len > 1024U
            || framed.len != 8U + (size_t)passphrase_len
                              + (size_t)recovery_len) {
        result = KSEC_ERR_INVALID;
        goto out;
    }
    result = ksec_secure_alloc(&verified, KSEC_MASTER_KEY_BYTES);
    if (result != KSEC_OK) goto out;
    result = ksec_header_unlock(&state->header, KSEC_SLOT_PASSPHRASE,
                                framed.data + 8U, passphrase_len,
                                verified.data);
    if (result != KSEC_OK || !ksec_safe_equal(verified.data,
                                               state->master.data,
                                               KSEC_MASTER_KEY_BYTES)) {
        result = KSEC_ERR_CRYPTO;
        goto credential_failure;
    }
    sodium_memzero(verified.data, verified.len);
    result = ksec_header_unlock(&state->header, KSEC_SLOT_RECOVERY,
                                framed.data + 8U + passphrase_len,
                                recovery_len, verified.data);
    if (result != KSEC_OK || !ksec_safe_equal(verified.data,
                                               state->master.data,
                                               KSEC_MASTER_KEY_BYTES)) {
        result = KSEC_ERR_CRYPTO;
        goto credential_failure;
    }
    for (index = 0U; index < state->header.slot_count; index++) {
        if (state->header.slots[index].opslimit > opslimit) {
            opslimit = state->header.slots[index].opslimit;
        }
        if (state->header.slots[index].memlimit > memlimit) {
            memlimit = state->header.slots[index].memlimit;
        }
    }
    result = audit_state_event(state, "master-rotation", "begin",
                               connection->uid, connection->pid, app_id, NULL);
    if (result != KSEC_OK) goto out;
    result = ksec_secure_alloc(&new_master, KSEC_MASTER_KEY_BYTES);
    if (result != KSEC_OK) goto out;
    randombytes_buf(new_master.data, new_master.len);
    candidate = state->header;
    result = ksec_header_rotate_master(
            &candidate, state->master.data, new_master.data,
            framed.data + 8U, passphrase_len,
            framed.data + 8U + passphrase_len, recovery_len,
            opslimit, memlimit);
    if (result != KSEC_OK) goto out;
    result = ksec_store_rotate_generation(&state->store, &candidate,
                                          new_master.data);
    if (result != KSEC_OK) {
        result = finish_store_mutation(state, result);
        goto out;
    }
    state->header = candidate;
    ksec_secure_free(&state->master);
    state->master = new_master;
    memset(&new_master, 0, sizeof new_master);
    invalidate_all_identity_leases(state);
    (void)audit_state_event(state, "master-rotation", "ok",
                            connection->uid, connection->pid, app_id, NULL);
    ksec_policy_clear(&state->policy);
    ksec_policy_init(&state->policy);
    connection->capability = NULL;
    state->last_authorized_use = ksec_now_seconds();
    result = KSEC_OK;
    goto out;

credential_failure:
    (void)audit_state_event(state, "master-rotation", "denied",
                            connection->uid, connection->pid, app_id, NULL);
out:
    sodium_memzero(app_id, sizeof app_id);
    sodium_memzero(&candidate, sizeof candidate);
    ksec_secure_free(&new_master);
    ksec_secure_free(&verified);
    ksec_secure_free(&framed);
    return result;
}

static ksec_result handle_export_backup(
        daemon_state *state, daemon_connection *connection,
        const uint8_t *payload, size_t payload_len, int received_fd,
        int *reply_fd) {
    ksec_secure_buffer passphrase = {0};
    uint32_t selector;
    ksec_result result;
    if (payload == NULL || payload_len != 4U || received_fd < 0
            || reply_fd == NULL) return KSEC_ERR_PROTOCOL;
    selector = ksec_get_u32(payload);
    if (selector != 0U) return KSEC_ERR_INVALID;
    if (!state->unlocked) return KSEC_ERR_LOCKED;
    result = authorize(state, connection, KSEC_VERB_READ,
                       connection->capability->app_id, NULL);
    if (result != KSEC_OK) return result;
    result = read_sensitive_fd(received_fd, 8U, 1024U, &passphrase);
    if (result != KSEC_OK) goto out;
    result = audit_state_event(state, "export", "begin", connection->uid,
                               connection->pid,
                               connection->capability->app_id, NULL);
    if (result != KSEC_OK) goto out;
    *reply_fd = memfd_create("ksec-encrypted-backup",
                             MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (*reply_fd < 0) { result = KSEC_ERR_IO; goto out; }
    result = ksec_backup_create(&state->store, &state->header,
                                state->master.data, passphrase.data,
                                passphrase.len, *reply_fd);
    if (result != KSEC_OK || lseek(*reply_fd, 0, SEEK_SET) != 0
            || fcntl(*reply_fd, F_ADD_SEALS,
                     F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW
                         | F_SEAL_WRITE) != 0) {
        if (result == KSEC_OK) result = KSEC_ERR_IO;
        goto out;
    }
    result = audit_state_event(state, "export", "ok", connection->uid,
                               connection->pid,
                               connection->capability->app_id, NULL);
out:
    if (result != KSEC_OK && *reply_fd >= 0) {
        (void)close(*reply_fd);
        *reply_fd = -1;
    }
    ksec_secure_free(&passphrase);
    return result;
}

static ksec_result handle_import_backup(
        daemon_state *state, daemon_connection *connection,
        const uint8_t *payload, size_t payload_len, int received_fd) {
    ksec_secure_buffer passphrase = {0};
    ksec_backup_image image;
    uint8_t length_prefix[4];
    char app_id[KSEC_MAX_APP_ID + 1U];
    uint32_t selector;
    uint32_t passphrase_len;
    ksec_result result;
    memset(&image, 0, sizeof image);
    memset(length_prefix, 0, sizeof length_prefix);
    memset(app_id, 0, sizeof app_id);
    if (payload == NULL || payload_len != 4U || received_fd < 0) {
        return KSEC_ERR_PROTOCOL;
    }
    selector = ksec_get_u32(payload);
    if (selector != 0U) return KSEC_ERR_INVALID;
    result = authorize(state, connection, KSEC_VERB_REPLACE,
                       connection->capability->app_id, NULL);
    if (result != KSEC_OK) return result;
    memcpy(app_id, connection->capability->app_id,
           strlen(connection->capability->app_id) + 1U);
    if (ksec_read_exact(received_fd, length_prefix,
                        sizeof length_prefix) != 0) {
        result = KSEC_ERR_IO;
        goto out;
    }
    passphrase_len = ksec_get_u32(length_prefix);
    if (passphrase_len < 8U || passphrase_len > 1024U) {
        result = KSEC_ERR_INVALID;
        goto out;
    }
    result = ksec_secure_alloc(&passphrase, passphrase_len);
    if (result != KSEC_OK) goto out;
    if (ksec_read_exact(received_fd, passphrase.data,
                        passphrase_len) != 0) {
        result = KSEC_ERR_IO;
        goto out;
    }
    result = ksec_backup_open(received_fd, passphrase.data, passphrase.len,
                              &image);
    if (result != KSEC_OK) {
        (void)audit_state_event(state, "import", "denied", connection->uid,
                                connection->pid, app_id, NULL);
        goto out;
    }
    result = audit_state_event(state, "import", "begin", connection->uid,
                               connection->pid, app_id, NULL);
    if (result != KSEC_OK) goto out;
    result = ksec_store_import_generation(&state->store, &image);
    if (result != KSEC_OK) {
        result = finish_store_mutation(state, result);
        connection->capability = NULL;
        goto out;
    }
    state->header = image.header;
    state->initialized = true;
    state->header_damaged = false;
    lock_state(state);
    connection->capability = NULL;
    (void)audit_state_event(state, "import", "ok", connection->uid,
                            connection->pid, app_id, NULL);
    result = KSEC_OK;
out:
    sodium_memzero(length_prefix, sizeof length_prefix);
    sodium_memzero(app_id, sizeof app_id);
    ksec_backup_image_clear(&image);
    ksec_secure_free(&passphrase);
    return result;
}

static ksec_result handle_reset_vault(
        daemon_state *state, daemon_connection *connection,
        const uint8_t *payload, size_t payload_len, int received_fd,
        int *reply_fd) {
    static const uint8_t confirmation[] = KSEC_RESET_CONFIRMATION;
    ksec_secure_buffer passphrase = {0};
    ksec_secure_buffer new_master = {0};
    ksec_vault_header candidate;
    uint8_t recovery_raw[32];
    char recovery_hex[65];
    char app_id[KSEC_MAX_APP_ID + 1U];
    ksec_result result;
    memset(&candidate, 0, sizeof candidate);
    memset(recovery_raw, 0, sizeof recovery_raw);
    memset(recovery_hex, 0, sizeof recovery_hex);
    memset(app_id, 0, sizeof app_id);
    if (payload == NULL || payload_len != sizeof confirmation - 1U
            || received_fd < 0 || reply_fd == NULL) {
        return KSEC_ERR_PROTOCOL;
    }
    if (!ksec_safe_equal(payload, confirmation, sizeof confirmation - 1U)) {
        return KSEC_ERR_INVALID;
    }
    if (!state->initialized && !state->header_damaged) {
        return KSEC_ERR_NOT_FOUND;
    }
    if (!state->kdf_configured) return KSEC_ERR_INVALID;
    result = authorize(state, connection, KSEC_VERB_REPLACE,
                       connection->capability->app_id, NULL);
    if (result != KSEC_OK) return result;
    memcpy(app_id, connection->capability->app_id,
           strlen(connection->capability->app_id) + 1U);
    result = read_sensitive_fd(received_fd, 8U, 1024U, &passphrase);
    if (result != KSEC_OK) goto out;
    result = ksec_secure_alloc(&new_master, KSEC_MASTER_KEY_BYTES);
    if (result != KSEC_OK) goto out;
    randombytes_buf(recovery_raw, sizeof recovery_raw);
    ksec_hex_encode(recovery_raw, sizeof recovery_raw, recovery_hex);
    result = ksec_header_create(&candidate, passphrase.data, passphrase.len,
                                (const uint8_t *)recovery_hex, 64U,
                                state->argon_ops, state->argon_mem,
                                new_master.data);
    if (result != KSEC_OK) goto out;
    result = sensitive_fd_from_bytes((const uint8_t *)recovery_hex, 64U,
                                     reply_fd);
    if (result != KSEC_OK) goto out;
    result = audit_state_event(state, "vault-reset", "begin",
                               connection->uid, connection->pid, app_id, NULL);
    if (result != KSEC_OK) goto out;
    result = ksec_store_reset_generation(&state->store, &candidate,
                                         new_master.data);
    if (result != KSEC_OK) {
        result = finish_store_mutation(state, result);
        connection->capability = NULL;
        goto out;
    }
    state->header = candidate;
    state->initialized = true;
    state->header_damaged = false;
    state->failed_unlocks = 0U;
    state->retry_after = 0U;
    lock_state(state);
    connection->capability = NULL;
    (void)audit_state_event(state, "vault-reset", "ok",
                            connection->uid, connection->pid, app_id, NULL);
    result = KSEC_OK;
out:
    if (result != KSEC_OK && *reply_fd >= 0) {
        (void)close(*reply_fd);
        *reply_fd = -1;
    }
    sodium_memzero(app_id, sizeof app_id);
    sodium_memzero(recovery_raw, sizeof recovery_raw);
    sodium_memzero(recovery_hex, sizeof recovery_hex);
    sodium_memzero(&candidate, sizeof candidate);
    ksec_secure_free(&new_master);
    ksec_secure_free(&passphrase);
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
    if (replacement) {
        existing = ksec_store_find(&state->store, requested_id);
        if (existing == NULL || existing->deleted) return KSEC_ERR_NOT_FOUND;
        if (strcmp(existing->owner, owner) != 0) return KSEC_ERR_DENIED;
        result = authorize_record(state, connection, KSEC_VERB_REPLACE,
                                  existing);
    } else {
        result = authorize(state, connection, KSEC_VERB_CREATE, owner, NULL);
    }
    if (result != KSEC_OK) return result;
    result = read_sensitive_fd(received_fd, 1U, KSEC_MAX_RECORD_PLAINTEXT, &encoded);
    if (result != KSEC_OK) return result;
    result = ksec_record_parse(encoded.data, encoded.len, &record);
    if (result != KSEC_OK) goto out;
    if (record.grant_count != 0U) {
        result = KSEC_ERR_DENIED;
        goto out;
    }
    memcpy(record.owner, owner, strlen(owner) + 1U);
    record.object_type = object_type;
    if (replacement) {
        memcpy(record.id, requested_id, KSEC_RECORD_ID_BYTES);
        record.grant_count = existing->grant_count;
        memcpy(record.grants, existing->grants,
               existing->grant_count * sizeof existing->grants[0]);
    }
    else {
        do {
            randombytes_buf(record.id, KSEC_RECORD_ID_BYTES);
        } while (ksec_store_find(&state->store, record.id) != NULL);
    }
    if (object_type == KSEC_OBJECT_DEVICE_IDENTITY
            || (replacement
                && existing->object_type == KSEC_OBJECT_DEVICE_IDENTITY)) {
        if (object_type != KSEC_OBJECT_DEVICE_IDENTITY
                || validate_identity_record(&record) != KSEC_OK) {
            result = KSEC_ERR_INVALID;
            goto out;
        }
    }
    memcpy(response_id, record.id, KSEC_RECORD_ID_BYTES);
    result = audit_state_event(state, replacement ? "replace" : "create",
                               "begin", connection->uid, connection->pid,
                               connection->capability->app_id, record.id);
    if (result != KSEC_OK) goto out;
    result = ksec_store_append(&state->store, &state->header, state->master.data,
                               &record, false);
    result = finish_store_mutation(state, result);
    if (result == KSEC_OK) {
        if (replacement) {
            invalidate_record_identity_leases(state, response_id);
        }
        (void)audit_state_event(state, replacement ? "replace" : "create", "ok",
                                connection->uid, connection->pid,
                                connection->capability->app_id, response_id);
    }
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
    if (record->object_type == KSEC_OBJECT_DEVICE_IDENTITY) {
        return KSEC_ERR_DENIED;
    }
    result = authorize_record_raw(connection, KSEC_VERB_USE, record);
    if (result != KSEC_OK) {
        result = authorize_record_raw(connection, KSEC_VERB_READ, record);
    }
    if (result != KSEC_OK) {
        (void)audit_state_event(state, "authorize", "denied", connection->uid,
                                connection->pid,
                                connection->capability->app_id, record->id);
        return result;
    }
    state->last_authorized_use = ksec_now_seconds();
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

static ksec_result handle_identity_open(
        daemon_state *state, daemon_connection *connection,
        const uint8_t *payload, size_t payload_len, int received_fd,
        int *reply_fd) {
    ksec_secure_buffer frame = {0};
    uint8_t public_key[KSEC_IDENTITY_KEY_BYTES];
    uint8_t anchor[KSEC_IDENTITY_ANCHOR_BYTES];
    ksec_owned_record *record;
    identity_lease *lease = NULL;
    int pipe_fds[2] = {-1, -1};
    size_t index;
    ksec_result result;
    memset(public_key, 0, sizeof public_key);
    memset(anchor, 0, sizeof anchor);
    if (!state->unlocked) return KSEC_ERR_LOCKED;
    if (payload == NULL
            || (payload_len != KSEC_RECORD_ID_BYTES
                && payload_len != KSEC_RECORD_ID_BYTES
                                  + KSEC_IDENTITY_ANCHOR_BYTES)
            || received_fd >= 0 || reply_fd == NULL) {
        return KSEC_ERR_PROTOCOL;
    }
    record = ksec_store_find(&state->store, payload);
    if (record == NULL || record->deleted) return KSEC_ERR_NOT_FOUND;
    if (validate_identity_record(record) != KSEC_OK) return KSEC_ERR_INVALID;
    result = authorize_record(state, connection, KSEC_VERB_USE, record);
    if (result != KSEC_OK) return result;
    if (crypto_scalarmult_curve25519_base(
            public_key, record->fields[0].value.data) != 0) {
        result = KSEC_ERR_CRYPTO;
        goto out;
    }
    result = ksec_identity_anchor(state->header.vault_uuid, record->id,
                                  record->revision, public_key, anchor);
    if (result != KSEC_OK) goto out;
    if (payload_len == KSEC_RECORD_ID_BYTES + KSEC_IDENTITY_ANCHOR_BYTES
            && sodium_memcmp(payload + KSEC_RECORD_ID_BYTES, anchor,
                             KSEC_IDENTITY_ANCHOR_BYTES) != 0) {
        result = KSEC_ERR_CONFLICT;
        goto out;
    }
    for (index = 0U; index < KSEC_MAX_IDENTITY_LEASES; index++) {
        if (!state->identity_leases[index].active) {
            lease = &state->identity_leases[index];
            break;
        }
    }
    if (lease == NULL) {
        result = KSEC_ERR_LIMIT;
        goto out;
    }
    result = ksec_secure_alloc(&frame, KSEC_IDENTITY_FRAME_BYTES);
    if (result != KSEC_OK) goto out;
    if (pipe2(pipe_fds, O_CLOEXEC) != 0) {
        result = KSEC_ERR_IO;
        goto out;
    }
    ksec_put_u32(frame.data, KSEC_IDENTITY_FRAME_MAGIC);
    ksec_put_u16(frame.data + 4U, KSEC_IDENTITY_FRAME_VERSION);
    ksec_put_u16(frame.data + 6U, (uint16_t)KSEC_IDENTITY_FRAME_BYTES);
    memcpy(frame.data + 8U, state->header.vault_uuid, KSEC_UUID_BYTES);
    memcpy(frame.data + 24U, record->id, KSEC_RECORD_ID_BYTES);
    ksec_put_u64(frame.data + 40U, record->revision);
    memcpy(frame.data + 48U, public_key, KSEC_IDENTITY_KEY_BYTES);
    memcpy(frame.data + 80U, anchor, KSEC_IDENTITY_ANCHOR_BYTES);
    memcpy(frame.data + 112U, record->fields[0].value.data,
           KSEC_IDENTITY_KEY_BYTES);
    if (ksec_write_all(pipe_fds[1], frame.data, frame.len) != 0) {
        result = KSEC_ERR_IO;
        goto out;
    }
    memset(lease, 0, sizeof *lease);
    lease->active = true;
    lease->writer_fd = pipe_fds[1];
    pipe_fds[1] = -1;
    lease->connection_fd = connection->fd;
    lease->capability = connection->capability;
    memcpy(lease->record_id, record->id, KSEC_RECORD_ID_BYTES);
    lease->record_revision = record->revision;
    *reply_fd = pipe_fds[0];
    pipe_fds[0] = -1;
    (void)audit_state_event(state, "identity-open", "ok", connection->uid,
                            connection->pid,
                            connection->capability->app_id, record->id);
    result = KSEC_OK;
out:
    if (pipe_fds[0] >= 0) (void)close(pipe_fds[0]);
    if (pipe_fds[1] >= 0) (void)close(pipe_fds[1]);
    ksec_secure_free(&frame);
    sodium_memzero(public_key, sizeof public_key);
    sodium_memzero(anchor, sizeof anchor);
    return result;
}

static ksec_result handle_identity_info(
        daemon_state *state, daemon_connection *connection,
        const uint8_t *payload, size_t payload_len, int received_fd,
        int *reply_fd) {
    uint8_t frame[KSEC_IDENTITY_INFO_FRAME_BYTES];
    uint8_t public_key[KSEC_IDENTITY_KEY_BYTES];
    uint8_t anchor[KSEC_IDENTITY_ANCHOR_BYTES];
    ksec_owned_record *record;
    ksec_result result;
    memset(frame, 0, sizeof frame);
    memset(public_key, 0, sizeof public_key);
    memset(anchor, 0, sizeof anchor);
    if (!state->unlocked) return KSEC_ERR_LOCKED;
    if (payload == NULL
            || (payload_len != KSEC_RECORD_ID_BYTES
                && payload_len != KSEC_RECORD_ID_BYTES
                                  + KSEC_IDENTITY_ANCHOR_BYTES)
            || received_fd >= 0 || reply_fd == NULL) {
        return KSEC_ERR_PROTOCOL;
    }
    record = ksec_store_find(&state->store, payload);
    if (record == NULL || record->deleted) return KSEC_ERR_NOT_FOUND;
    if (validate_identity_record(record) != KSEC_OK) return KSEC_ERR_INVALID;
    result = authorize_record(state, connection, KSEC_VERB_USE, record);
    if (result != KSEC_OK) return result;
    if (crypto_scalarmult_curve25519_base(
            public_key, record->fields[0].value.data) != 0) {
        result = KSEC_ERR_CRYPTO;
        goto out;
    }
    result = ksec_identity_anchor(state->header.vault_uuid, record->id,
                                  record->revision, public_key, anchor);
    if (result != KSEC_OK) goto out;
    if (payload_len == KSEC_RECORD_ID_BYTES + KSEC_IDENTITY_ANCHOR_BYTES
            && sodium_memcmp(payload + KSEC_RECORD_ID_BYTES, anchor,
                             KSEC_IDENTITY_ANCHOR_BYTES) != 0) {
        result = KSEC_ERR_CONFLICT;
        goto out;
    }
    ksec_put_u32(frame, KSEC_IDENTITY_INFO_FRAME_MAGIC);
    ksec_put_u16(frame + 4U, KSEC_IDENTITY_FRAME_VERSION);
    ksec_put_u16(frame + 6U, (uint16_t)KSEC_IDENTITY_INFO_FRAME_BYTES);
    memcpy(frame + 8U, state->header.vault_uuid, KSEC_UUID_BYTES);
    memcpy(frame + 24U, record->id, KSEC_RECORD_ID_BYTES);
    ksec_put_u64(frame + 40U, record->revision);
    memcpy(frame + 48U, public_key, KSEC_IDENTITY_KEY_BYTES);
    memcpy(frame + 80U, anchor, KSEC_IDENTITY_ANCHOR_BYTES);
    result = sensitive_fd_from_bytes(frame, sizeof frame, reply_fd);
    if (result == KSEC_OK) {
        (void)audit_state_event(state, "identity-info", "ok",
                                connection->uid, connection->pid,
                                connection->capability->app_id, record->id);
    }
out:
    sodium_memzero(frame, sizeof frame);
    sodium_memzero(public_key, sizeof public_key);
    sodium_memzero(anchor, sizeof anchor);
    return result;
}

static ksec_result handle_delete(daemon_state *state, daemon_connection *connection,
                                 const uint8_t *payload, size_t payload_len,
                                 int received_fd) {
    ksec_owned_record *existing;
    ksec_owned_record tombstone;
    ksec_result result;
    if (!state->unlocked) return KSEC_ERR_LOCKED;
    if (received_fd >= 0 || payload == NULL
            || payload_len != KSEC_RECORD_ID_BYTES * 2U) {
        return KSEC_ERR_PROTOCOL;
    }
    if (!ksec_safe_equal(payload, payload + KSEC_RECORD_ID_BYTES,
                         KSEC_RECORD_ID_BYTES)) return KSEC_ERR_INVALID;
    existing = ksec_store_find(&state->store, payload);
    if (existing == NULL || existing->deleted) return KSEC_ERR_NOT_FOUND;
    result = authorize_record(state, connection, KSEC_VERB_DELETE, existing);
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
    result = finish_store_mutation(state, result);
    if (result == KSEC_OK) {
        invalidate_record_identity_leases(state, payload);
        (void)audit_state_event(state, "delete", "ok", connection->uid,
                                connection->pid,
                                connection->capability->app_id, payload);
    }
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
        if (record->deleted
                || (strcmp(record->owner, connection->capability->app_id) != 0
                    && !record_grants_verb(record,
                                           connection->capability->app_id,
                                           KSEC_VERB_LIST_OWN))) continue;
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

static int append_report(char *report, size_t report_size, size_t *used,
                         const char *format, ...) {
    va_list arguments;
    int count;
    if (report == NULL || used == NULL || format == NULL || *used >= report_size) {
        return -1;
    }
    va_start(arguments, format);
    count = vsnprintf(report + *used, report_size - *used, format, arguments);
    va_end(arguments);
    if (count < 0 || (size_t)count >= report_size - *used) return -1;
    *used += (size_t)count;
    return 0;
}

static int format_grant_verbs(uint32_t verbs, char *output,
                              size_t output_size) {
    static const struct {
        uint32_t verb;
        const char *name;
    } names[] = {
        {KSEC_VERB_READ, "read"},
        {KSEC_VERB_REPLACE, "replace"},
        {KSEC_VERB_DELETE, "delete"},
        {KSEC_VERB_LIST_OWN, "list-own"},
        {KSEC_VERB_USE, "use"}
    };
    size_t used = 0U;
    size_t index;
    if (output == NULL || output_size == 0U || verbs == 0U
            || (verbs & ~KSEC_GRANTABLE_VERBS) != 0U) return -1;
    for (index = 0U; index < sizeof names / sizeof names[0]; index++) {
        if ((verbs & names[index].verb) != 0U) {
            int count = snprintf(output + used, output_size - used, "%s%s",
                                 used == 0U ? "" : ",", names[index].name);
            if (count < 0 || (size_t)count >= output_size - used) return -1;
            used += (size_t)count;
        }
    }
    return used == 0U ? -1 : 0;
}

static ksec_result handle_show(daemon_state *state,
                               daemon_connection *connection,
                               const uint8_t *payload, size_t payload_len,
                               int received_fd, int *reply_fd) {
    ksec_owned_record *record;
    char report[4096];
    char id_hex[KSEC_RECORD_ID_BYTES * 2U + 1U];
    size_t used = 0U;
    size_t index;
    ksec_result result;
    memset(report, 0, sizeof report);
    if (!state->unlocked) return KSEC_ERR_LOCKED;
    if (payload == NULL || payload_len != KSEC_RECORD_ID_BYTES
            || received_fd >= 0 || reply_fd == NULL) return KSEC_ERR_PROTOCOL;
    record = ksec_store_find(&state->store, payload);
    if (record == NULL || record->deleted) return KSEC_ERR_NOT_FOUND;
    result = authorize_record(state, connection, KSEC_VERB_LIST_OWN, record);
    if (result != KSEC_OK) return result;
    ksec_hex_encode(record->id, KSEC_RECORD_ID_BYTES, id_hex);
    if (append_report(report, sizeof report, &used,
                      "id=%s\nowner=%s\ntype=%s\nlabel=%s\nrevision=%llu\n"
                      "expires_at=%llu\nexpired=%s\nfields=%zu/%u\n",
                      id_hex, record->owner, record->type, record->label,
                      (unsigned long long)record->revision,
                      (unsigned long long)record->expires_at,
                      record->expires_at != 0U
                          && record->expires_at <= ksec_now_seconds()
                              ? "yes" : "no",
                      record->field_count, KSEC_MAX_FIELDS) != 0) {
        return KSEC_ERR_LIMIT;
    }
    for (index = 0U; index < record->field_count; index++) {
        if (append_report(report, sizeof report, &used, "field=%s\n",
                          record->fields[index].name) != 0) {
            return KSEC_ERR_LIMIT;
        }
    }
    if (append_report(report, sizeof report, &used, "grants=%zu/%u\n",
                      record->grant_count, KSEC_MAX_GRANTS) != 0) {
        return KSEC_ERR_LIMIT;
    }
    for (index = 0U; index < record->grant_count; index++) {
        char verbs[64];
        if (format_grant_verbs(record->grants[index].verbs, verbs,
                               sizeof verbs) != 0
                || append_report(report, sizeof report, &used,
                                 "grant=%s\tverbs=%s\n",
                                 record->grants[index].application_id,
                                 verbs) != 0) {
            sodium_memzero(verbs, sizeof verbs);
            return KSEC_ERR_LIMIT;
        }
        sodium_memzero(verbs, sizeof verbs);
    }
    result = sensitive_fd_from_bytes((const uint8_t *)report, used, reply_fd);
    sodium_memzero(report, sizeof report);
    sodium_memzero(id_hex, sizeof id_hex);
    return result;
}

static ksec_result handle_change_grant(
        daemon_state *state, daemon_connection *connection,
        const uint8_t *payload, size_t payload_len, int received_fd,
        bool revoke) {
    size_t fixed = revoke ? KSEC_RECORD_ID_BYTES + 2U
                          : KSEC_RECORD_ID_BYTES + 6U;
    size_t app_offset = revoke ? KSEC_RECORD_ID_BYTES + 2U
                               : KSEC_RECORD_ID_BYTES + 6U;
    uint16_t app_len;
    uint32_t verbs = 0U;
    char application_id[KSEC_MAX_APP_ID + 1U];
    ksec_owned_record *existing;
    ksec_owned_record candidate;
    size_t position = 0U;
    bool found = false;
    ksec_result result;
    memset(application_id, 0, sizeof application_id);
    memset(&candidate, 0, sizeof candidate);
    if (!state->unlocked) return KSEC_ERR_LOCKED;
    if (payload == NULL || payload_len < fixed + 1U || received_fd >= 0) {
        return KSEC_ERR_PROTOCOL;
    }
    if (revoke) {
        app_len = ksec_get_u16(payload + KSEC_RECORD_ID_BYTES);
    } else {
        verbs = ksec_get_u32(payload + KSEC_RECORD_ID_BYTES);
        app_len = ksec_get_u16(payload + KSEC_RECORD_ID_BYTES + 4U);
        if (verbs == 0U || (verbs & ~KSEC_GRANTABLE_VERBS) != 0U) {
            return KSEC_ERR_INVALID;
        }
    }
    if (app_len == 0U || app_len > KSEC_MAX_APP_ID
            || payload_len != fixed + app_len
            || ksec_validate_app_id_bytes(payload + app_offset, app_len) != 0) {
        return KSEC_ERR_INVALID;
    }
    memcpy(application_id, payload + app_offset, app_len);
    application_id[app_len] = '\0';
    existing = ksec_store_find(&state->store, payload);
    if (existing == NULL || existing->deleted) return KSEC_ERR_NOT_FOUND;
    if (strcmp(existing->owner, application_id) == 0) return KSEC_ERR_INVALID;
    result = authorize(state, connection, KSEC_VERB_REPLACE, existing->owner,
                       existing->id);
    if (result != KSEC_OK) return result;
    if (existing->object_type == KSEC_OBJECT_DEVICE_IDENTITY) {
        return KSEC_ERR_DENIED;
    }
    while (position < existing->grant_count) {
        int comparison = strcmp(existing->grants[position].application_id,
                                application_id);
        if (comparison >= 0) {
            found = comparison == 0;
            break;
        }
        position++;
    }
    if (revoke && !found) return KSEC_ERR_NOT_FOUND;
    if (!revoke && found && existing->grants[position].verbs == verbs) {
        return KSEC_ERR_EXISTS;
    }
    if (!revoke && !found && existing->grant_count >= KSEC_MAX_GRANTS) {
        return KSEC_ERR_LIMIT;
    }
    result = clone_owned_record(existing, &candidate);
    if (result != KSEC_OK) return result;
    if (revoke) {
        if (position + 1U < candidate.grant_count) {
            memmove(&candidate.grants[position],
                    &candidate.grants[position + 1U],
                    (candidate.grant_count - position - 1U)
                        * sizeof candidate.grants[0]);
        }
        candidate.grant_count--;
        sodium_memzero(&candidate.grants[candidate.grant_count],
                       sizeof candidate.grants[0]);
    } else if (found) {
        candidate.grants[position].verbs = verbs;
    } else {
        if (position < candidate.grant_count) {
            memmove(&candidate.grants[position + 1U],
                    &candidate.grants[position],
                    (candidate.grant_count - position)
                        * sizeof candidate.grants[0]);
        }
        memset(&candidate.grants[position], 0, sizeof candidate.grants[0]);
        memcpy(candidate.grants[position].application_id, application_id,
               app_len + 1U);
        candidate.grants[position].verbs = verbs;
        candidate.grant_count++;
    }
    result = audit_state_event(state, revoke ? "revoke" : "grant", "begin",
                               connection->uid, connection->pid,
                               connection->capability->app_id, existing->id);
    if (result != KSEC_OK) goto out;
    result = ksec_store_append(&state->store, &state->header, state->master.data,
                               &candidate, false);
    result = finish_store_mutation(state, result);
    if (result == KSEC_OK) {
        invalidate_record_identity_leases(state, payload);
        (void)audit_state_event(state, revoke ? "revoke" : "grant", "ok",
                                connection->uid, connection->pid,
                                connection->capability->app_id, payload);
    }
out:
    ksec_owned_record_clear(&candidate);
    sodium_memzero(application_id, sizeof application_id);
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
                     "format=1\ninitialized=%s\nstorage=%s\nstate=%s\nrecovery=%s\nkdf_point=%s\nrecords=%zu/%u\nidentity_leases=%zu/%u\ntorn_tail=%s\naudit=%s\nsession_monitor=active\ngraphical_sessions=%zu/%u\n",
                     state->initialized ? "yes" : "no",
                     state->header_damaged ? "damaged" : "readable",
                     state->unlocked ? "unlocked" : "locked",
                     state->header_damaged ? "unavailable"
                         : !state->initialized ? "not-initialized"
                         : (state->header.flags & KSEC_HEADER_FLAG_RECOVERY_CONFIRMED) != 0U
                             ? "confirmed" : "confirmation-required",
                     state->kdf_configured ? "development-configured" : "unselected",
                     state->unlocked ? state->store.record_count : 0U,
                     KSEC_MAX_RECORDS,
                     identity_lease_count(state), KSEC_MAX_IDENTITY_LEASES,
                     state->store.torn_tail ? "yes" : "no",
                     state->audit_degraded ? "degraded" : "available",
                     ksec_session_monitor_tracked(state->session_monitor),
                     KSEC_MAX_GRAPHICAL_SESSIONS);
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
            return finish_store_mutation(
                    state, ksec_store_compact(&state->store, &state->header,
                                              state->master.data));
        case KSEC_OP_CHANGE_PASSPHRASE:
            return handle_change_passphrase(state, connection, payload,
                                            request->payload_len, received_fd);
        case KSEC_OP_ROTATE_MASTER:
            return handle_rotate_master(state, connection, payload,
                                        request->payload_len, received_fd);
        case KSEC_OP_EXPORT_BACKUP:
            return handle_export_backup(state, connection, payload,
                                        request->payload_len, received_fd,
                                        reply_fd);
        case KSEC_OP_IMPORT_BACKUP:
            return handle_import_backup(state, connection, payload,
                                        request->payload_len, received_fd);
        case KSEC_OP_SHOW:
            return handle_show(state, connection, payload,
                               request->payload_len, received_fd, reply_fd);
        case KSEC_OP_GRANT:
            return handle_change_grant(state, connection, payload,
                                       request->payload_len, received_fd,
                                       false);
        case KSEC_OP_REVOKE:
            return handle_change_grant(state, connection, payload,
                                       request->payload_len, received_fd,
                                       true);
        case KSEC_OP_RESET_VAULT:
            return handle_reset_vault(state, connection, payload,
                                      request->payload_len, received_fd,
                                      reply_fd);
        case KSEC_OP_IDENTITY_OPEN:
            return handle_identity_open(state, connection, payload,
                                        request->payload_len, received_fd,
                                        reply_fd);
        case KSEC_OP_IDENTITY_INFO:
            return handle_identity_info(state, connection, payload,
                                        request->payload_len, received_fd,
                                        reply_fd);
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
            || chmod(socket_path, 0600) != 0
            || listen(fd, (int)KSEC_MAX_CONNECTIONS) != 0) {
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
        invalidate_connection_identity_leases(state, connection->fd);
        ksec_policy_disconnect(&state->policy, connection->fd);
        (void)close(connection->fd);
    }
    memset(connection, 0, sizeof *connection);
    connection->fd = -1;
}

static int serve(int listener, daemon_state *state) {
    daemon_connection connections[KSEC_MAX_CONNECTIONS];
    struct pollfd pollfds[KSEC_MAX_CONNECTIONS + 2U];
    size_t index;
    /*
     * The accept-drain loop below stops on EAGAIN, so a blocking listener would
     * sleep inside accept4() and stall this single thread indefinitely. Both
     * listener paths establish O_NONBLOCK -- create_listener() at creation and
     * validate_systemd_listener() on the inherited descriptor -- but the
     * dependence lives here, so enforce it here as well and fail closed on a
     * blocking descriptor and on an unusable one alike. A future third listener
     * path then cannot reintroduce the hang silently.
     */
    if (ksec_fd_is_nonblocking(listener) != 1) return -1;
    for (index = 0; index < KSEC_MAX_CONNECTIONS; index++) connections[index].fd = -1;
    while (!stop_requested) {
        int ready;
        pollfds[0].fd = listener;
        pollfds[0].events = POLLIN;
        pollfds[0].revents = 0;
        pollfds[1].fd = ksec_session_monitor_fd(state->session_monitor);
        pollfds[1].events = ksec_session_monitor_events(state->session_monitor);
        pollfds[1].revents = 0;
        if (pollfds[1].fd < 0 || pollfds[1].events == 0) {
            fprintf(stderr,
                    "kilix-secretsd: session monitor poll setup failed (fd=%d events=%d)\n",
                    pollfds[1].fd, (int)pollfds[1].events);
            return -1;
        }
        for (index = 0; index < KSEC_MAX_CONNECTIONS; index++) {
            pollfds[index + 2U].fd = connections[index].fd;
            pollfds[index + 2U].events = POLLIN;
            pollfds[index + 2U].revents = 0;
        }
        ready = poll(pollfds, KSEC_MAX_CONNECTIONS + 2U, 1000);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) return -1;
        expire_identity_leases(state);
        if ((pollfds[1].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0
                || ksec_session_monitor_process(state->session_monitor) != 0) {
            lock_state(state);
            fprintf(stderr, "kilix-secretsd: session monitor processing failed\n");
            return -1;
        }
        if (lock_requested != 0
                || ksec_session_monitor_take_lock(state->session_monitor)) {
            const char *event = lock_requested != 0
                ? "signal-lock" : "session-lock";
            lock_requested = 0;
            (void)audit_state_event(state, event, "ok", getuid(), getpid(),
                                    "session-monitor", NULL);
            lock_state(state);
            for (index = 0; index < KSEC_MAX_CONNECTIONS; index++) {
                connections[index].capability = NULL;
            }
        }
        if (state->unlocked && state->idle_timeout > 0U
                && ksec_now_seconds() - state->last_authorized_use >= state->idle_timeout) {
            lock_state(state);
            for (index = 0; index < KSEC_MAX_CONNECTIONS; index++) {
                connections[index].capability = NULL;
            }
        }
        if ((pollfds[0].revents & POLLIN) != 0) {
            size_t admitted;
            for (admitted = 0; admitted < KSEC_MAX_CONNECTIONS; admitted++) {
                daemon_connection incoming;
                bool placed = false;
                if (accept_connection(listener, &incoming) != 0) break;
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
            short events = pollfds[index + 2U].revents;
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
            || sigaction(SIGUSR1, &action, NULL) != 0
            || signal(SIGPIPE, SIG_IGN) == SIG_ERR) return 1;
    ksec_policy_init(&state.policy);
    if (ksec_store_open(&state.store, data_dir, true) != KSEC_OK) goto cleanup;
    {
        ksec_result header_result = ksec_store_read_header(&state.store, &state.header);
        if (header_result == KSEC_OK) state.initialized = true;
        else if (header_result != KSEC_ERR_NOT_FOUND) state.header_damaged = true;
    }
    if (ksec_audit_open(data_dir, &state.audit_fd) != KSEC_OK) goto cleanup;
    if (ksec_session_monitor_open(&state.session_monitor, getuid()) != 0) {
        goto cleanup;
    }
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
    ksec_session_monitor_close(state.session_monitor);
    state.session_monitor = NULL;
    ksec_store_close(&state.store);
    ksec_policy_clear(&state.policy);
    sodium_memzero(&state.header, sizeof state.header);
    return exit_code;
}
