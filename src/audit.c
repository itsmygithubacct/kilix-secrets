#define _GNU_SOURCE

#include "internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int safe_word(const char *value, size_t maximum) {
    size_t index;
    size_t length;
    if (value == NULL) return -1;
    length = strlen(value);
    if (length == 0 || length > maximum) return -1;
    for (index = 0; index < length; index++) {
        unsigned char ch = (unsigned char)value[index];
        if (!((ch >= (unsigned char)'a' && ch <= (unsigned char)'z')
                || (ch >= (unsigned char)'A' && ch <= (unsigned char)'Z')
                || (ch >= (unsigned char)'0' && ch <= (unsigned char)'9')
                || ch == (unsigned char)'-' || ch == (unsigned char)'_')) return -1;
    }
    return 0;
}

ksec_result ksec_audit_open(const char *data_dir, int *out_fd) {
    char path[4096];
    char rotated[4096];
    struct stat status;
    int stat_result;
    int count;
    int fd;
    if (data_dir == NULL || out_fd == NULL) return KSEC_ERR_INVALID;
    count = snprintf(path, sizeof path, "%s/audit.log", data_dir);
    if (count < 0 || (size_t)count >= sizeof path) return KSEC_ERR_LIMIT;
    count = snprintf(rotated, sizeof rotated, "%s/audit.log.1", data_dir);
    if (count < 0 || (size_t)count >= sizeof rotated) return KSEC_ERR_LIMIT;
    errno = 0;
    stat_result = lstat(path, &status);
    if (stat_result == 0 && (uint64_t)status.st_size >= KSEC_MAX_AUDIT_BYTES) {
        if (!S_ISREG(status.st_mode) || status.st_uid != getuid()
                || status.st_nlink != 1 || (status.st_mode & 0777U) != 0600U
                || rename(path, rotated) != 0 || ksec_sync_directory(data_dir) != 0) {
            return KSEC_ERR_AUDIT;
        }
    } else if (stat_result != 0 && errno != ENOENT) {
        return KSEC_ERR_AUDIT;
    }
    fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0 || fstat(fd, &status) != 0 || !S_ISREG(status.st_mode)
            || status.st_uid != getuid() || status.st_nlink != 1
            || (status.st_mode & 0777U) != 0600U) {
        if (fd >= 0) (void)close(fd);
        return KSEC_ERR_AUDIT;
    }
    *out_fd = fd;
    return KSEC_OK;
}

ksec_result ksec_audit_event(int fd, const char *event, const char *outcome,
                             uid_t uid, pid_t pid, const char *app_id,
                             const uint8_t *record_id) {
    char line[512];
    char id_hex[KSEC_RECORD_ID_BYTES * 2U + 1U];
    struct stat status;
    int count;
    if (fd < 0 || safe_word(event, 48U) != 0 || safe_word(outcome, 24U) != 0
            || ksec_validate_app_id(app_id) != 0) return KSEC_ERR_INVALID;
    if (record_id != NULL) ksec_hex_encode(record_id, KSEC_RECORD_ID_BYTES, id_hex);
    else memcpy(id_hex, "-", 2U);
    count = snprintf(line, sizeof line,
                     "time=%llu event=%s outcome=%s uid=%lu pid=%ld app=%s record=%s\n",
                     (unsigned long long)ksec_now_seconds(), event, outcome,
                     (unsigned long)uid, (long)pid, app_id, id_hex);
    if (count < 0 || (size_t)count >= sizeof line) return KSEC_ERR_LIMIT;
    if (fstat(fd, &status) != 0 || !S_ISREG(status.st_mode)
            || status.st_uid != getuid() || status.st_nlink != 1
            || (status.st_mode & 0777U) != 0600U || status.st_size < 0
            || (uint64_t)status.st_size > KSEC_MAX_AUDIT_BYTES
            || (uint64_t)count > KSEC_MAX_AUDIT_BYTES - (uint64_t)status.st_size) {
        return KSEC_ERR_AUDIT;
    }
    if (ksec_write_all(fd, line, (size_t)count) != 0 || fsync(fd) != 0) {
        return KSEC_ERR_AUDIT;
    }
    return KSEC_OK;
}
