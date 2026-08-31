#define _GNU_SOURCE

#include "internal.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

void ksec_put_u16(uint8_t out[2], uint16_t value) {
    out[0] = (uint8_t)(value >> 8);
    out[1] = (uint8_t)value;
}

void ksec_put_u32(uint8_t out[4], uint32_t value) {
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

void ksec_put_u64(uint8_t out[8], uint64_t value) {
    size_t index;
    for (index = 0; index < 8U; index++) {
        unsigned int shift = (unsigned int)((7U - index) * 8U);
        out[index] = (uint8_t)(value >> shift);
    }
}

uint16_t ksec_get_u16(const uint8_t in[2]) {
    return (uint16_t)(((uint16_t)in[0] << 8) | (uint16_t)in[1]);
}

uint32_t ksec_get_u32(const uint8_t in[4]) {
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16)
        | ((uint32_t)in[2] << 8) | (uint32_t)in[3];
}

uint64_t ksec_get_u64(const uint8_t in[8]) {
    uint64_t value = 0;
    size_t index;
    for (index = 0; index < 8U; index++) {
        value = (value << 8) | (uint64_t)in[index];
    }
    return value;
}

int ksec_write_all(int fd, const void *data, size_t length) {
    const uint8_t *bytes = data;
    size_t offset = 0;
    while (offset < length) {
        ssize_t count = write(fd, bytes + offset, length - offset);
        if (count < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (count == 0) return -1;
        offset += (size_t)count;
    }
    return 0;
}

int ksec_read_exact(int fd, void *data, size_t length) {
    uint8_t *bytes = data;
    size_t offset = 0;
    while (offset < length) {
        ssize_t count = read(fd, bytes + offset, length - offset);
        if (count < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (count == 0) return 1;
        offset += (size_t)count;
    }
    return 0;
}

int ksec_copy_fd(int input_fd, int output_fd, size_t limit, size_t *copied) {
    uint8_t buffer[4096];
    size_t total = 0;
    for (;;) {
        ssize_t count = read(input_fd, buffer, sizeof buffer);
        if (count < 0) {
            if (errno == EINTR) continue;
            sodium_memzero(buffer, sizeof buffer);
            return -1;
        }
        if (count == 0) break;
        if ((size_t)count > limit - total) {
            sodium_memzero(buffer, sizeof buffer);
            errno = EFBIG;
            return -1;
        }
        if (ksec_write_all(output_fd, buffer, (size_t)count) != 0) {
            sodium_memzero(buffer, sizeof buffer);
            return -1;
        }
        total += (size_t)count;
    }
    sodium_memzero(buffer, sizeof buffer);
    if (copied != NULL) *copied = total;
    return 0;
}

int ksec_set_cloexec(int fd, bool enabled) {
    int flags = fcntl(fd, F_GETFD);
    if (flags < 0) return -1;
    if (enabled) flags |= FD_CLOEXEC;
    else flags &= ~FD_CLOEXEC;
    return fcntl(fd, F_SETFD, flags);
}

/*
 * 1 = non-blocking, 0 = blocking, -1 = unusable descriptor. Callers that depend
 * on non-blocking semantics must treat anything other than 1 as fatal, so the
 * error case never reads as "probably fine".
 */
int ksec_fd_is_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0) return -1;
    return (flags & O_NONBLOCK) != 0 ? 1 : 0;
}

int ksec_set_nonblock(int fd, bool enabled) {
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0) return -1;
    if (enabled) flags |= O_NONBLOCK;
    else flags &= ~O_NONBLOCK;
    return fcntl(fd, F_SETFL, flags);
}

int ksec_sync_directory(const char *path) {
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    int saved;
    if (fd < 0) return -1;
    if (fsync(fd) != 0) {
        saved = errno;
        (void)close(fd);
        errno = saved;
        return -1;
    }
    return close(fd);
}

int ksec_parent_directory(const char *path, char *output, size_t output_size) {
    char *separator;
    size_t length;
    if (path == NULL || output == NULL || output_size == 0U || path[0] != '/') {
        return -1;
    }
    length = strlen(path);
    if (length == 0U || length >= output_size || (length > 1U && path[length - 1U] == '/')) {
        return -1;
    }
    memcpy(output, path, length + 1U);
    separator = strrchr(output, '/');
    if (separator == NULL) return -1;
    if (separator == output) separator[1] = '\0';
    else *separator = '\0';
    return 0;
}

int ksec_validate_secure_directory(const char *path, bool require_user_leaf) {
    char current[4096];
    size_t length;
    size_t index;
    size_t segment_start = 1U;
    if (path == NULL || path[0] != '/') return -1;
    length = strlen(path);
    if (length <= 1U || length >= sizeof current || path[length - 1U] == '/') return -1;
    memcpy(current, path, length + 1U);
    for (index = 1U; index <= length; index++) {
        bool final = index == length;
        struct stat status;
        char saved;
        if (!final && current[index] != '/') continue;
        if (index == segment_start
                || (index - segment_start == 1U && current[segment_start] == '.')
                || (index - segment_start == 2U && current[segment_start] == '.'
                    && current[segment_start + 1U] == '.')) return -1;
        saved = current[index];
        current[index] = '\0';
        if (lstat(current, &status) != 0 || !S_ISDIR(status.st_mode)
                || S_ISLNK(status.st_mode)
                || (status.st_uid != 0U && status.st_uid != getuid())) return -1;
        if ((status.st_mode & 0022U) != 0U
                && !(status.st_uid == 0U && (status.st_mode & S_ISVTX) != 0U)) {
            return -1;
        }
        if (final && require_user_leaf
                && (status.st_uid != getuid() || (status.st_mode & 0077U) != 0U)) {
            return -1;
        }
        current[index] = saved;
        segment_start = index + 1U;
    }
    return 0;
}

int ksec_validate_app_id_bytes(const uint8_t *value, size_t length) {
    size_t index;
    if (value == NULL) return -1;
    if (length == 0 || length > KSEC_MAX_APP_ID) return -1;
    for (index = 0; index < length; index++) {
        uint8_t ch = value[index];
        if (!((ch >= (unsigned char)'a' && ch <= (unsigned char)'z')
                || (ch >= (unsigned char)'0' && ch <= (unsigned char)'9')
                || ch == (unsigned char)'.' || ch == (unsigned char)'-')) {
            return -1;
        }
    }
    return 0;
}

int ksec_validate_app_id(const char *value) {
    if (value == NULL) return -1;
    return ksec_validate_app_id_bytes((const uint8_t *)value, strlen(value));
}

int ksec_validate_text_bytes(const uint8_t *value, size_t length,
                             size_t max_length) {
    size_t index = 0;
    if (value == NULL) return -1;
    if (length == 0 || length > max_length) return -1;
    while (index < length) {
        uint8_t first = value[index];
        if (first < 0x80U) {
            if (first < 0x20U || first == 0x7fU) return -1;
            index++;
        } else if (first >= 0xc2U && first <= 0xdfU) {
            if (index + 1U >= length || (value[index + 1U] & 0xc0U) != 0x80U) return -1;
            index += 2U;
        } else if (first >= 0xe0U && first <= 0xefU) {
            uint8_t second;
            if (index + 2U >= length) return -1;
            second = value[index + 1U];
            if ((value[index + 2U] & 0xc0U) != 0x80U
                    || (first == 0xe0U && (second < 0xa0U || second > 0xbfU))
                    || (first == 0xedU && (second < 0x80U || second > 0x9fU))
                    || (first != 0xe0U && first != 0xedU
                        && (second & 0xc0U) != 0x80U)) return -1;
            index += 3U;
        } else if (first >= 0xf0U && first <= 0xf4U) {
            uint8_t second;
            if (index + 3U >= length) return -1;
            second = value[index + 1U];
            if ((value[index + 2U] & 0xc0U) != 0x80U
                    || (value[index + 3U] & 0xc0U) != 0x80U
                    || (first == 0xf0U && (second < 0x90U || second > 0xbfU))
                    || (first == 0xf4U && (second < 0x80U || second > 0x8fU))
                    || (first != 0xf0U && first != 0xf4U
                        && (second & 0xc0U) != 0x80U)) return -1;
            index += 4U;
        } else {
            return -1;
        }
    }
    return 0;
}

int ksec_validate_name(const char *value, size_t max_length) {
    if (value == NULL) return -1;
    return ksec_validate_text_bytes((const uint8_t *)value, strlen(value),
                                    max_length);
}

uint64_t ksec_now_seconds(void) {
    time_t now = time(NULL);
    return now < 0 ? 0U : (uint64_t)now;
}

int ksec_process_start_time(pid_t pid, uint64_t *out) {
    char path[64];
    char buffer[4096];
    char *tail;
    char *field;
    char *save = NULL;
    int fd;
    ssize_t count;
    unsigned int index = 3U;
    unsigned long long value;
    if (out == NULL || pid <= 0) return -1;
    if (snprintf(path, sizeof path, "/proc/%ld/stat", (long)pid) < 0) return -1;
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    count = read(fd, buffer, sizeof buffer - 1U);
    if (count <= 0) {
        int saved = errno;
        (void)close(fd);
        errno = saved;
        return -1;
    }
    if (close(fd) != 0) return -1;
    buffer[(size_t)count] = '\0';
    tail = strrchr(buffer, ')');
    if (tail == NULL || tail[1] != ' ') return -1;
    field = strtok_r(tail + 2, " ", &save);
    while (field != NULL && index < 22U) {
        field = strtok_r(NULL, " ", &save);
        index++;
    }
    if (field == NULL || index != 22U) return -1;
    errno = 0;
    {
        char *end = NULL;
        value = strtoull(field, &end, 10);
        if (errno != 0 || end == field || *end != '\0') return -1;
    }
    *out = (uint64_t)value;
    return 0;
}

int ksec_safe_equal(const uint8_t *left, const uint8_t *right, size_t length) {
    if (left == NULL || right == NULL || length == 0) return 0;
    return sodium_memcmp(left, right, length) == 0;
}

void ksec_hex_encode(const uint8_t *input, size_t length, char *output) {
    static const char digits[] = "0123456789abcdef";
    size_t index;
    for (index = 0; index < length; index++) {
        output[index * 2U] = digits[input[index] >> 4];
        output[index * 2U + 1U] = digits[input[index] & 0x0fU];
    }
    output[length * 2U] = '\0';
}

int ksec_hex_decode(const char *input, uint8_t *output, size_t output_length) {
    size_t index;
    if (input == NULL || output == NULL || strlen(input) != output_length * 2U) return -1;
    for (index = 0; index < output_length; index++) {
        int high;
        int low;
        unsigned char a = (unsigned char)input[index * 2U];
        unsigned char b = (unsigned char)input[index * 2U + 1U];
        high = isdigit(a) ? (int)(a - (unsigned char)'0')
            : (a >= (unsigned char)'a' && a <= (unsigned char)'f') ? (int)(a - (unsigned char)'a') + 10 : -1;
        low = isdigit(b) ? (int)(b - (unsigned char)'0')
            : (b >= (unsigned char)'a' && b <= (unsigned char)'f') ? (int)(b - (unsigned char)'a') + 10 : -1;
        if (high < 0 || low < 0) return -1;
        output[index] = (uint8_t)((unsigned int)high << 4) | (uint8_t)low;
    }
    return 0;
}

const char *ksec_result_string(ksec_result result) {
    switch (result) {
        case KSEC_OK: return "ok";
        case KSEC_ERR_LOCKED: return "vault locked";
        case KSEC_ERR_DENIED: return "denied";
        case KSEC_ERR_NOT_FOUND: return "not found";
        case KSEC_ERR_EXPIRED: return "expired";
        case KSEC_ERR_INVALID: return "invalid input";
        case KSEC_ERR_LIMIT: return "limit exceeded";
        case KSEC_ERR_IO: return "I/O failure";
        case KSEC_ERR_CRYPTO: return "authentication failure";
        case KSEC_ERR_PROTOCOL: return "protocol failure";
        case KSEC_ERR_BUSY: return "busy";
        case KSEC_ERR_EXISTS: return "already exists";
        case KSEC_ERR_AUDIT: return "audit unavailable";
        case KSEC_ERR_MEMORY: return "secure memory unavailable";
        case KSEC_ERR_CONFLICT: return "identity generation conflict";
    }
    return "unknown result";
}
