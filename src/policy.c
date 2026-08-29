#define _GNU_SOURCE

#include "internal.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int process_identity(pid_t pid, pid_t *parent, uint64_t *start_time) {
    char path[64];
    char buffer[4096];
    char *tail;
    char *token;
    char *save = NULL;
    unsigned int field = 3U;
    int fd;
    ssize_t count;
    long parsed_parent = -1;
    unsigned long long parsed_start = 0;
    int written = snprintf(path, sizeof path, "/proc/%ld/stat", (long)pid);
    if (written < 0 || (size_t)written >= sizeof path) return -1;
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    count = read(fd, buffer, sizeof buffer - 1U);
    if (count <= 0) { (void)close(fd); return -1; }
    if (close(fd) != 0) return -1;
    buffer[(size_t)count] = '\0';
    tail = strrchr(buffer, ')');
    if (tail == NULL || tail[1] != ' ') return -1;
    token = strtok_r(tail + 2, " ", &save);
    while (token != NULL) {
        if (field == 4U) {
            char *end = NULL;
            errno = 0;
            parsed_parent = strtol(token, &end, 10);
            if (errno != 0 || end == token || *end != '\0') return -1;
        }
        if (field == 22U) {
            char *end = NULL;
            errno = 0;
            parsed_start = strtoull(token, &end, 10);
            if (errno != 0 || end == token || *end != '\0') return -1;
            break;
        }
        field++;
        token = strtok_r(NULL, " ", &save);
    }
    if (field != 22U || parsed_parent <= 0 || parsed_start == 0) return -1;
    if (parent != NULL) *parent = (pid_t)parsed_parent;
    if (start_time != NULL) *start_time = (uint64_t)parsed_start;
    return 0;
}

void ksec_policy_init(ksec_policy *policy) {
    if (policy != NULL) memset(policy, 0, sizeof *policy);
}

void ksec_policy_clear(ksec_policy *policy) {
    if (policy != NULL) sodium_memzero(policy, sizeof *policy);
}

ksec_result ksec_policy_mint(ksec_policy *policy, pid_t supervisor_pid,
                             pid_t target_pid, const char *app_id,
                             uint32_t verbs, const uint8_t *record_id,
                             uint32_t lifetime_seconds, int *out_fd) {
    ksec_capability *entry = NULL;
    pid_t parent = 0;
    uint64_t target_start = 0;
    uint64_t supervisor_start = 0;
    int pipe_fds[2] = {-1, -1};
    size_t index;
    uint64_t now = ksec_now_seconds();
    if (policy == NULL || app_id == NULL || out_fd == NULL
            || supervisor_pid <= 0 || target_pid <= 0
            || ksec_validate_app_id(app_id) != 0 || verbs == 0
            || (verbs & ~(uint32_t)KSEC_VERB_ALL) != 0U || lifetime_seconds == 0
            || lifetime_seconds > 300U) return KSEC_ERR_INVALID;
    if (process_identity(target_pid, &parent, &target_start) != 0
            || parent != supervisor_pid
            || process_identity(supervisor_pid, NULL, &supervisor_start) != 0) {
        return KSEC_ERR_DENIED;
    }
    for (index = 0; index < KSEC_MAX_CAPABILITIES; index++) {
        ksec_capability *candidate = &policy->entries[index];
        uint64_t current_target = 0;
        uint64_t current_supervisor = 0;
        if (candidate->active && (candidate->expires_at <= now
                || ksec_process_start_time(candidate->target_pid,
                                           &current_target) != 0
                || ksec_process_start_time(candidate->supervisor_pid,
                                           &current_supervisor) != 0
                || current_target != candidate->target_start_time
                || current_supervisor != candidate->supervisor_start_time)) {
            sodium_memzero(candidate, sizeof *candidate);
        }
        if (!candidate->active && entry == NULL) entry = candidate;
    }
    if (entry == NULL) return KSEC_ERR_LIMIT;
    if (pipe2(pipe_fds, O_CLOEXEC) != 0) return KSEC_ERR_IO;
    memset(entry, 0, sizeof *entry);
    randombytes_buf(entry->token, KSEC_CAPABILITY_BYTES);
    entry->active = true;
    entry->target_pid = target_pid;
    entry->target_start_time = target_start;
    entry->supervisor_pid = supervisor_pid;
    entry->supervisor_start_time = supervisor_start;
    entry->verbs = verbs;
    entry->record_scoped = record_id != NULL;
    if (record_id != NULL) memcpy(entry->record_id, record_id, KSEC_RECORD_ID_BYTES);
    entry->expires_at = now + lifetime_seconds;
    entry->connection_fd = -1;
    memcpy(entry->app_id, app_id, strlen(app_id) + 1U);
    if (ksec_write_all(pipe_fds[1], entry->token, KSEC_CAPABILITY_BYTES) != 0) {
        int saved = errno;
        (void)close(pipe_fds[0]);
        (void)close(pipe_fds[1]);
        sodium_memzero(entry, sizeof *entry);
        errno = saved;
        return KSEC_ERR_IO;
    }
    if (close(pipe_fds[1]) != 0) {
        int saved = errno;
        pipe_fds[1] = -1;
        (void)close(pipe_fds[0]);
        sodium_memzero(entry, sizeof *entry);
        errno = saved;
        return KSEC_ERR_IO;
    }
    *out_fd = pipe_fds[0];
    return KSEC_OK;
}

ksec_result ksec_policy_activate(ksec_policy *policy, int connection_fd,
                                 pid_t peer_pid, const uint8_t *token,
                                 size_t token_len, ksec_capability **out) {
    size_t index;
    uint64_t peer_start = 0;
    if (policy == NULL || connection_fd < 0 || peer_pid <= 0 || token == NULL
            || token_len != KSEC_CAPABILITY_BYTES || out == NULL
            || ksec_process_start_time(peer_pid, &peer_start) != 0) {
        return KSEC_ERR_INVALID;
    }
    for (index = 0; index < KSEC_MAX_CAPABILITIES; index++) {
        ksec_capability *entry = &policy->entries[index];
        if (!entry->active || entry->activated
                || !ksec_safe_equal(entry->token, token, token_len)) continue;
        if (entry->target_pid != peer_pid || entry->target_start_time != peer_start
                || entry->expires_at <= ksec_now_seconds()) return KSEC_ERR_DENIED;
        entry->activated = true;
        entry->connection_fd = connection_fd;
        sodium_memzero(entry->token, sizeof entry->token);
        *out = entry;
        return KSEC_OK;
    }
    return KSEC_ERR_DENIED;
}

void ksec_policy_disconnect(ksec_policy *policy, int connection_fd) {
    size_t index;
    if (policy == NULL) return;
    for (index = 0; index < KSEC_MAX_CAPABILITIES; index++) {
        if (policy->entries[index].active
                && policy->entries[index].connection_fd == connection_fd) {
            sodium_memzero(&policy->entries[index], sizeof policy->entries[index]);
        }
    }
}

ksec_result ksec_policy_authorize(ksec_capability *capability, uint32_t verb,
                                  const char *owner, const uint8_t *record_id) {
    uint64_t target_start = 0;
    uint64_t supervisor_start = 0;
    if (capability == NULL || !capability->active || !capability->activated
            || capability->connection_fd < 0 || verb == 0
            || (capability->verbs & verb) != verb
            || capability->expires_at <= ksec_now_seconds()) return KSEC_ERR_DENIED;
    if (ksec_process_start_time(capability->target_pid, &target_start) != 0
            || ksec_process_start_time(capability->supervisor_pid,
                                       &supervisor_start) != 0
            || target_start != capability->target_start_time
            || supervisor_start != capability->supervisor_start_time) {
        return KSEC_ERR_DENIED;
    }
    if (owner != NULL && strcmp(owner, capability->app_id) != 0) return KSEC_ERR_DENIED;
    if (capability->record_scoped && (record_id == NULL
            || sodium_memcmp(record_id, capability->record_id,
                             KSEC_RECORD_ID_BYTES) != 0)) return KSEC_ERR_DENIED;
    return KSEC_OK;
}
