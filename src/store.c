#define _GNU_SOURCE

#include "internal.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/fs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

enum {
    JOURNAL_PREFIX_BYTES = 12,
    JOURNAL_BODY_FIXED_BYTES = 58,
    JOURNAL_FLAG_DELETE = 1,
    HEADER_MAX_BYTES = 1024
};

static const uint8_t JOURNAL_MAGIC[8] = {'K','S','V','J','R','0','0','1'};

#ifdef KSEC_TESTING
typedef struct {
    bool active;
    ksec_test_store_point point;
    unsigned int occurrence;
    unsigned int seen;
    int value;
    size_t partial_write_bytes;
} store_test_fault;

static store_test_fault crash_fault;
static store_test_fault error_fault;

void ksec_test_store_fault_reset(void) {
    memset(&crash_fault, 0, sizeof crash_fault);
    memset(&error_fault, 0, sizeof error_fault);
}

void ksec_test_store_crash_after(ksec_test_store_point point,
                                 unsigned int occurrence, int exit_status) {
    memset(&crash_fault, 0, sizeof crash_fault);
    crash_fault.active = true;
    crash_fault.point = point;
    crash_fault.occurrence = occurrence;
    crash_fault.value = exit_status;
}

void ksec_test_store_fail_at(ksec_test_store_point point,
                             unsigned int occurrence, int error_number,
                             size_t partial_write_bytes) {
    memset(&error_fault, 0, sizeof error_fault);
    error_fault.active = true;
    error_fault.point = point;
    error_fault.occurrence = occurrence;
    error_fault.value = error_number;
    error_fault.partial_write_bytes = partial_write_bytes;
}

static bool test_fault_matches(store_test_fault *fault,
                               ksec_test_store_point point) {
    if (!fault->active || fault->point != point) return false;
    fault->seen++;
    if (fault->seen != fault->occurrence) return false;
    fault->active = false;
    return true;
}

static int store_test_before(ksec_test_store_point point, int fd,
                             const void *data, size_t length) {
    if (!test_fault_matches(&error_fault, point)) return 0;
    if (error_fault.partial_write_bytes > 0U && fd >= 0 && data != NULL
            && length > 0U) {
        size_t partial = error_fault.partial_write_bytes;
        if (partial > length) partial = length;
        if (ksec_write_all(fd, data, partial) != 0) return -1;
    }
    errno = error_fault.value;
    return -1;
}

static void store_test_after(ksec_test_store_point point) {
    if (test_fault_matches(&crash_fault, point)) {
        _exit(crash_fault.value);
    }
}
#else
static int store_test_before(int point, int fd, const void *data, size_t length) {
    (void)point;
    (void)fd;
    (void)data;
    (void)length;
    return 0;
}

static void store_test_after(int point) {
    (void)point;
}
#endif

static int store_write_all(int fd, const void *data, size_t length, int point) {
    if (store_test_before(point, fd, data, length) != 0
            || ksec_write_all(fd, data, length) != 0) return -1;
    store_test_after(point);
    return 0;
}

static int store_fsync(int fd, int point) {
    if (store_test_before(point, fd, NULL, 0U) != 0 || fsync(fd) != 0) return -1;
    store_test_after(point);
    return 0;
}

static int store_close(int fd, int point) {
    if (store_test_before(point, fd, NULL, 0U) != 0 || close(fd) != 0) return -1;
    store_test_after(point);
    return 0;
}

static int store_rename(const char *old_path, const char *new_path, int point) {
    if (store_test_before(point, -1, NULL, 0U) != 0
            || rename(old_path, new_path) != 0) return -1;
    store_test_after(point);
    return 0;
}

static int store_directory_sync(const char *path, int point) {
    if (store_test_before(point, -1, NULL, 0U) != 0
            || ksec_sync_directory(path) != 0) return -1;
    store_test_after(point);
    return 0;
}

static int safe_regular_fd(int fd, mode_t required_mode) {
    struct stat status;
    if (fstat(fd, &status) != 0 || !S_ISREG(status.st_mode)
            || status.st_uid != getuid() || status.st_nlink != 1
            || (status.st_mode & 0777U) != required_mode) return -1;
    return 0;
}

static int make_path(char *output, size_t output_size, const char *directory,
                     const char *leaf) {
    int count = snprintf(output, output_size, "%s/%s", directory, leaf);
    return count < 0 || (size_t)count >= output_size ? -1 : 0;
}

static int open_unique_temporary(const char *directory, const char *stem,
                                 char *path, size_t path_size, int point) {
    unsigned int attempt;
    if (store_test_before(point, -1, NULL, 0U) != 0) return -1;
    for (attempt = 0U; attempt < 32U; attempt++) {
        uint8_t suffix[8];
        char suffix_hex[17];
        int count;
        int fd;
        randombytes_buf(suffix, sizeof suffix);
        ksec_hex_encode(suffix, sizeof suffix, suffix_hex);
        sodium_memzero(suffix, sizeof suffix);
        count = snprintf(path, path_size, "%s/.%s.tmp.%ld.%s", directory,
                         stem, (long)getpid(), suffix_hex);
        sodium_memzero(suffix_hex, sizeof suffix_hex);
        if (count < 0 || (size_t)count >= path_size) {
            errno = ENAMETOOLONG;
            return -1;
        }
        fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                  0600);
        if (fd >= 0) {
            store_test_after(point);
            return fd;
        }
        if (errno != EEXIST) return -1;
    }
    errno = EEXIST;
    return -1;
}

static int create_unique_directory(const char *root, const char *stem,
                                   char *path, size_t path_size, int point) {
    unsigned int attempt;
    if (store_test_before(point, -1, NULL, 0U) != 0) return -1;
    for (attempt = 0U; attempt < 32U; attempt++) {
        uint8_t suffix[8];
        char suffix_hex[17];
        int count;
        randombytes_buf(suffix, sizeof suffix);
        ksec_hex_encode(suffix, sizeof suffix, suffix_hex);
        sodium_memzero(suffix, sizeof suffix);
        count = snprintf(path, path_size, "%s/.%s.%ld.%s", root, stem,
                         (long)getpid(), suffix_hex);
        sodium_memzero(suffix_hex, sizeof suffix_hex);
        if (count < 0 || (size_t)count >= path_size) {
            errno = ENAMETOOLONG;
            return -1;
        }
        if (mkdir(path, 0700) == 0) {
            store_test_after(point);
            return 0;
        }
        if (errno != EEXIST) return -1;
    }
    errno = EEXIST;
    return -1;
}

static int store_exchange_directories(const char *left, const char *right,
                                      int point) {
    if (store_test_before(point, -1, NULL, 0U) != 0) return -1;
    if (syscall(SYS_renameat2, AT_FDCWD, left, AT_FDCWD, right,
                RENAME_EXCHANGE) != 0) return -1;
    store_test_after(point);
    return 0;
}

static int sync_parent_directory(const char *path) {
    char parent[4096];
    if (ksec_parent_directory(path, parent, sizeof parent) != 0) return -1;
    return ksec_sync_directory(parent);
}

static void clear_records(ksec_store *store) {
    size_t index;
    if (store == NULL || store->records == NULL) return;
    for (index = 0; index < store->record_count; index++) {
        ksec_owned_record_clear(&store->records[index]);
    }
    free(store->records);
    store->records = NULL;
    store->record_count = 0;
}

void ksec_store_clear_records(ksec_store *store) {
    clear_records(store);
    if (store != NULL) {
        store->last_revision = 0;
        store->torn_tail = false;
    }
}

static ksec_result ensure_record_capacity(ksec_store *store, size_t needed) {
    ksec_owned_record *resized;
    size_t old_count;
    if (needed > KSEC_MAX_RECORDS) return KSEC_ERR_LIMIT;
    if (needed <= store->record_count) return KSEC_OK;
    old_count = store->record_count;
    resized = realloc(store->records, needed * sizeof *resized);
    if (resized == NULL) return KSEC_ERR_MEMORY;
    store->records = resized;
    memset(&store->records[old_count], 0, (needed - old_count) * sizeof *resized);
    return KSEC_OK;
}

static void move_record(ksec_owned_record *destination, ksec_owned_record *source) {
    *destination = *source;
    memset(source, 0, sizeof *source);
}

static ksec_result apply_loaded_record(ksec_store *store, ksec_owned_record *record,
                                       bool deletion) {
    ksec_owned_record *existing = ksec_store_find(store, record->id);
    if (deletion) {
        if (existing != NULL) {
            size_t index = (size_t)(existing - store->records);
            ksec_owned_record_clear(existing);
            if (index + 1U < store->record_count) {
                memmove(existing, existing + 1U,
                        (store->record_count - index - 1U) * sizeof *existing);
            }
            store->record_count--;
            memset(&store->records[store->record_count], 0,
                   sizeof store->records[store->record_count]);
        }
        return KSEC_OK;
    }
    if (existing != NULL) {
        ksec_owned_record_clear(existing);
        move_record(existing, record);
        return KSEC_OK;
    }
    if (store->record_count >= KSEC_MAX_RECORDS) return KSEC_ERR_LIMIT;
    {
        size_t new_count = store->record_count + 1U;
        ksec_result result = ensure_record_capacity(store, new_count);
        if (result != KSEC_OK) return result;
        move_record(&store->records[store->record_count], record);
        store->record_count = new_count;
    }
    return KSEC_OK;
}

static ksec_result owned_record_plaintext(const ksec_owned_record *record,
                                          ksec_secure_buffer *plaintext) {
    ksec_field fields[KSEC_MAX_FIELDS];
    ksec_grant grants[KSEC_MAX_GRANTS];
    ksec_record public_record;
    size_t index;
    size_t output_len = 0;
    ksec_result result;
    result = ksec_secure_alloc(plaintext, KSEC_MAX_RECORD_PLAINTEXT);
    if (result != KSEC_OK) return result;
    for (index = 0; index < record->field_count; index++) {
        fields[index].name = record->fields[index].name;
        fields[index].value = record->fields[index].value.data;
        fields[index].value_len = record->fields[index].value.len;
    }
    for (index = 0; index < record->grant_count; index++) {
        grants[index].application_id = record->grants[index].application_id;
        grants[index].verbs = record->grants[index].verbs;
    }
    public_record.owner = record->owner;
    public_record.type = record->type;
    public_record.label = record->label;
    public_record.expires_at = record->expires_at;
    public_record.fields = fields;
    public_record.field_count = record->field_count;
    public_record.grants = record->grant_count > 0U ? grants : NULL;
    public_record.grant_count = record->grant_count;
    result = ksec_record_serialize(&public_record, plaintext->data, plaintext->len,
                                   &output_len);
    if (result != KSEC_OK) {
        ksec_secure_free(plaintext);
        return result;
    }
    plaintext->len = output_len;
    return KSEC_OK;
}

static ksec_result make_entry(const ksec_vault_header *header,
                              const uint8_t master_key[KSEC_MASTER_KEY_BYTES],
                              const ksec_owned_record *record, bool deletion,
                              uint8_t **output, size_t *output_len) {
    ksec_secure_buffer plaintext = {0};
    uint8_t tombstone = 0U;
    const uint8_t *plain_data;
    size_t plain_len;
    uint8_t nonce[KSEC_NONCE_BYTES];
    uint8_t *ciphertext = NULL;
    size_t ciphertext_len = 0;
    size_t owner_len;
    size_t body_len;
    size_t total_len;
    size_t offset = 0;
    ksec_result result;
    if (header == NULL || master_key == NULL || record == NULL || output == NULL
            || output_len == NULL || record->revision == 0
            || ksec_validate_app_id(record->owner) != 0) return KSEC_ERR_INVALID;
    if (deletion) {
        plain_data = &tombstone;
        plain_len = 1U;
    } else {
        result = owned_record_plaintext(record, &plaintext);
        if (result != KSEC_OK) return result;
        plain_data = plaintext.data;
        plain_len = plaintext.len;
    }
    ciphertext = malloc(plain_len + KSEC_TAG_BYTES);
    if (ciphertext == NULL) {
        result = KSEC_ERR_MEMORY;
        goto out;
    }
    result = ksec_record_encrypt(master_key, record->object_type, header->vault_uuid,
                                 record->id, record->revision, record->owner,
                                 plain_data, plain_len, nonce, ciphertext,
                                 plain_len + KSEC_TAG_BYTES, &ciphertext_len);
    if (result != KSEC_OK) goto out;
    owner_len = strlen(record->owner);
    body_len = JOURNAL_BODY_FIXED_BYTES + owner_len + ciphertext_len;
    total_len = JOURNAL_PREFIX_BYTES + body_len;
    if (body_len > UINT32_MAX || total_len > KSEC_MAX_RECORD_PLAINTEXT + 4096U) {
        result = KSEC_ERR_LIMIT;
        goto out;
    }
    *output = malloc(total_len);
    if (*output == NULL) {
        result = KSEC_ERR_MEMORY;
        goto out;
    }
    memcpy(*output + offset, JOURNAL_MAGIC, sizeof JOURNAL_MAGIC); offset += 8U;
    ksec_put_u32(*output + offset, (uint32_t)body_len); offset += 4U;
    ksec_put_u16(*output + offset, record->object_type); offset += 2U;
    ksec_put_u16(*output + offset, deletion ? JOURNAL_FLAG_DELETE : 0U); offset += 2U;
    ksec_put_u64(*output + offset, record->revision); offset += 8U;
    memcpy(*output + offset, record->id, KSEC_RECORD_ID_BYTES); offset += KSEC_RECORD_ID_BYTES;
    ksec_put_u16(*output + offset, (uint16_t)owner_len); offset += 2U;
    ksec_put_u32(*output + offset, (uint32_t)plain_len); offset += 4U;
    memcpy(*output + offset, nonce, KSEC_NONCE_BYTES); offset += KSEC_NONCE_BYTES;
    memcpy(*output + offset, record->owner, owner_len); offset += owner_len;
    memcpy(*output + offset, ciphertext, ciphertext_len); offset += ciphertext_len;
    if (offset != total_len) {
        free(*output);
        *output = NULL;
        result = KSEC_ERR_INVALID;
        goto out;
    }
    *output_len = total_len;
    result = KSEC_OK;
out:
    if (ciphertext != NULL) {
        sodium_memzero(ciphertext, plain_len + KSEC_TAG_BYTES);
        free(ciphertext);
    }
    ksec_secure_free(&plaintext);
    return result;
}

ksec_result ksec_store_open(ksec_store *store, const char *data_dir, bool create) {
    char parent[4096];
    char current[4096];
    struct stat status;
    int fd;
    if (store == NULL || data_dir == NULL || data_dir[0] != '/') return KSEC_ERR_INVALID;
    memset(store, 0, sizeof *store);
    store->lock_fd = -1;
    if (strlen(data_dir) >= sizeof store->root_dir) return KSEC_ERR_LIMIT;
    memcpy(store->root_dir, data_dir, strlen(data_dir) + 1U);
    if (lstat(data_dir, &status) != 0) {
        if (!create || errno != ENOENT
                || ksec_parent_directory(data_dir, parent, sizeof parent) != 0
                || ksec_validate_secure_directory(parent, false) != 0
                || mkdir(data_dir, 0700) != 0) return KSEC_ERR_IO;
        if (sync_parent_directory(data_dir) != 0 && errno != EINVAL) return KSEC_ERR_IO;
    }
    if (ksec_validate_secure_directory(data_dir, true) != 0) return KSEC_ERR_DENIED;
    if (make_path(current, sizeof current, data_dir, "vault-current") != 0) {
        return KSEC_ERR_LIMIT;
    }
    if (lstat(current, &status) != 0) {
        if (errno != ENOENT || mkdir(current, 0700) != 0
                || ksec_sync_directory(data_dir) != 0) return KSEC_ERR_IO;
    }
    if (ksec_validate_secure_directory(current, true) != 0
            || strlen(current) >= sizeof store->data_dir) return KSEC_ERR_DENIED;
    memcpy(store->data_dir, current, strlen(current) + 1U);
    if (make_path(store->vault_path, sizeof store->vault_path, current, "vault.ksv") != 0
            || make_path(store->journal_path, sizeof store->journal_path, current, "journal.ksj") != 0
            || make_path(store->lock_path, sizeof store->lock_path, data_dir, "writer.lock") != 0) {
        return KSEC_ERR_LIMIT;
    }
    fd = open(store->lock_path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0 || safe_regular_fd(fd, 0600) != 0) {
        if (fd >= 0) (void)close(fd);
        return KSEC_ERR_DENIED;
    }
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        (void)close(fd);
        return errno == EWOULDBLOCK ? KSEC_ERR_BUSY : KSEC_ERR_IO;
    }
    store->lock_fd = fd;
    return KSEC_OK;
}

void ksec_store_close(ksec_store *store) {
    if (store == NULL) return;
    clear_records(store);
    if (store->lock_fd >= 0) {
        (void)flock(store->lock_fd, LOCK_UN);
        (void)close(store->lock_fd);
    }
    sodium_memzero(store, sizeof *store);
    store->lock_fd = -1;
}

ksec_result ksec_store_write_header(ksec_store *store,
                                    const ksec_vault_header *header) {
    uint8_t encoded[HEADER_MAX_BYTES];
    size_t encoded_len = 0;
    char temporary[4096];
    int fd = -1;
    ksec_result result;
    if (store == NULL || header == NULL) return KSEC_ERR_INVALID;
    result = ksec_header_encode(header, encoded, sizeof encoded, &encoded_len);
    if (result != KSEC_OK) return result;
    fd = open_unique_temporary(store->data_dir, "vault.ksv", temporary,
                               sizeof temporary, KSEC_TEST_STORE_HEADER_OPEN);
    if (fd < 0) {
        sodium_memzero(encoded, sizeof encoded);
        return KSEC_ERR_IO;
    }
    if (safe_regular_fd(fd, 0600) != 0
            || store_write_all(fd, encoded, encoded_len,
                               KSEC_TEST_STORE_HEADER_WRITE) != 0
            || store_fsync(fd, KSEC_TEST_STORE_HEADER_FSYNC) != 0) {
        int saved = errno;
        (void)close(fd);
        (void)unlink(temporary);
        sodium_memzero(encoded, sizeof encoded);
        errno = saved;
        return KSEC_ERR_IO;
    }
    if (store_close(fd, KSEC_TEST_STORE_HEADER_CLOSE) != 0) {
        int saved = errno;
        fd = -1;
        (void)unlink(temporary);
        sodium_memzero(encoded, sizeof encoded);
        errno = saved;
        return KSEC_ERR_IO;
    }
    fd = -1;
    if (store_rename(temporary, store->vault_path,
                     KSEC_TEST_STORE_HEADER_RENAME) != 0
            || store_directory_sync(store->data_dir,
                                    KSEC_TEST_STORE_HEADER_DIRSYNC) != 0) {
        int saved = errno;
        (void)unlink(temporary);
        sodium_memzero(encoded, sizeof encoded);
        errno = saved;
        return KSEC_ERR_IO;
    }
    sodium_memzero(encoded, sizeof encoded);
    return KSEC_OK;
}

ksec_result ksec_store_read_header(ksec_store *store, ksec_vault_header *header) {
    uint8_t encoded[HEADER_MAX_BYTES];
    struct stat status;
    int fd;
    int read_result;
    ksec_result result;
    if (store == NULL || header == NULL) return KSEC_ERR_INVALID;
    fd = open(store->vault_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return errno == ENOENT ? KSEC_ERR_NOT_FOUND : KSEC_ERR_IO;
    if (safe_regular_fd(fd, 0600) != 0 || fstat(fd, &status) != 0
            || status.st_size <= 0 || status.st_size > (off_t)sizeof encoded) {
        (void)close(fd);
        return KSEC_ERR_DENIED;
    }
    read_result = ksec_read_exact(fd, encoded, (size_t)status.st_size);
    if (read_result != 0 || close(fd) != 0) {
        sodium_memzero(encoded, sizeof encoded);
        return KSEC_ERR_IO;
    }
    result = ksec_header_decode(encoded, (size_t)status.st_size, header);
    sodium_memzero(encoded, sizeof encoded);
    return result;
}

ksec_owned_record *ksec_store_find(ksec_store *store,
                                   const uint8_t id[KSEC_RECORD_ID_BYTES]) {
    size_t index;
    if (store == NULL || id == NULL) return NULL;
    for (index = 0; index < store->record_count; index++) {
        if (sodium_memcmp(store->records[index].id, id, KSEC_RECORD_ID_BYTES) == 0) {
            return &store->records[index];
        }
    }
    return NULL;
}

ksec_result ksec_store_load(ksec_store *store,
                            const ksec_vault_header *header,
                            const uint8_t master_key[KSEC_MASTER_KEY_BYTES]) {
    struct stat status;
    int fd;
    uint64_t last_revision = 0;
    ksec_result result = KSEC_OK;
    if (store == NULL || header == NULL || master_key == NULL) return KSEC_ERR_INVALID;
    clear_records(store);
    store->last_revision = 0;
    store->torn_tail = false;
    fd = open(store->journal_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return errno == ENOENT ? KSEC_OK : KSEC_ERR_IO;
    if (safe_regular_fd(fd, 0600) != 0 || fstat(fd, &status) != 0
            || status.st_size < 0 || (uint64_t)status.st_size > KSEC_MAX_JOURNAL_BYTES) {
        (void)close(fd);
        return KSEC_ERR_DENIED;
    }
    for (;;) {
        uint8_t prefix[JOURNAL_PREFIX_BYTES];
        ssize_t prefix_count;
        uint32_t body_len;
        uint8_t *body = NULL;
        uint16_t object_type;
        uint16_t flags;
        uint64_t revision;
        uint16_t owner_len;
        uint32_t plain_len;
        const uint8_t *object_id;
        const uint8_t *nonce;
        const uint8_t *ciphertext;
        char owner[KSEC_MAX_APP_ID + 1U];
        size_t ciphertext_len;
        ksec_secure_buffer plaintext = {0};
        ksec_owned_record record;
        memset(&record, 0, sizeof record);
        do {
            prefix_count = read(fd, prefix, sizeof prefix);
        } while (prefix_count < 0 && errno == EINTR);
        if (prefix_count < 0) { result = KSEC_ERR_IO; break; }
        if (prefix_count == 0) break;
        if ((size_t)prefix_count != sizeof prefix) {
            store->torn_tail = true;
            break;
        }
        if (memcmp(prefix, JOURNAL_MAGIC, sizeof JOURNAL_MAGIC) != 0) {
            result = KSEC_ERR_INVALID;
            break;
        }
        body_len = ksec_get_u32(prefix + 8U);
        if (body_len < JOURNAL_BODY_FIXED_BYTES + 1U + KSEC_TAG_BYTES
                || body_len > KSEC_MAX_RECORD_PLAINTEXT + 4096U) {
            result = KSEC_ERR_LIMIT;
            break;
        }
        body = malloc(body_len);
        if (body == NULL) { result = KSEC_ERR_MEMORY; break; }
        {
            int exact = ksec_read_exact(fd, body, body_len);
            if (exact == 1) {
                store->torn_tail = true;
                free(body);
                break;
            }
            if (exact != 0) {
                free(body);
                result = KSEC_ERR_IO;
                break;
            }
        }
        object_type = ksec_get_u16(body);
        flags = ksec_get_u16(body + 2U);
        revision = ksec_get_u64(body + 4U);
        object_id = body + 12U;
        owner_len = ksec_get_u16(body + 28U);
        plain_len = ksec_get_u32(body + 30U);
        nonce = body + 34U;
        if ((flags & (uint16_t)~JOURNAL_FLAG_DELETE) != 0U || revision <= last_revision
                || owner_len == 0 || owner_len > KSEC_MAX_APP_ID || plain_len == 0
                || plain_len > KSEC_MAX_RECORD_PLAINTEXT
                || body_len != JOURNAL_BODY_FIXED_BYTES + owner_len + plain_len + KSEC_TAG_BYTES) {
            free(body);
            result = KSEC_ERR_INVALID;
            break;
        }
        if (ksec_validate_app_id_bytes(body + JOURNAL_BODY_FIXED_BYTES,
                                       owner_len) != 0) {
            free(body);
            result = KSEC_ERR_INVALID;
            break;
        }
        memcpy(owner, body + JOURNAL_BODY_FIXED_BYTES, owner_len);
        owner[owner_len] = '\0';
        ciphertext = body + JOURNAL_BODY_FIXED_BYTES + owner_len;
        ciphertext_len = (size_t)plain_len + KSEC_TAG_BYTES;
        result = ksec_secure_alloc(&plaintext, plain_len);
        if (result != KSEC_OK) { free(body); break; }
        result = ksec_record_decrypt(master_key, object_type, header->vault_uuid,
                                     object_id, revision, owner, nonce, ciphertext,
                                     ciphertext_len, plaintext.data, plaintext.len,
                                     &plaintext.len);
        if (result != KSEC_OK) {
            ksec_secure_free(&plaintext);
            free(body);
            break;
        }
        memcpy(record.id, object_id, KSEC_RECORD_ID_BYTES);
        memcpy(record.owner, owner, owner_len + 1U);
        record.object_type = object_type;
        record.revision = revision;
        if ((flags & JOURNAL_FLAG_DELETE) != 0U) {
            if (plaintext.len != 1U || plaintext.data[0] != 0U) result = KSEC_ERR_INVALID;
        } else {
            ksec_owned_record parsed;
            memset(&parsed, 0, sizeof parsed);
            result = ksec_record_parse(plaintext.data, plaintext.len, &parsed);
            if (result == KSEC_OK) {
                memcpy(parsed.id, object_id, KSEC_RECORD_ID_BYTES);
                memcpy(parsed.owner, owner, owner_len + 1U);
                parsed.object_type = object_type;
                parsed.revision = revision;
                move_record(&record, &parsed);
            }
        }
        ksec_secure_free(&plaintext);
        free(body);
        if (result != KSEC_OK) {
            ksec_owned_record_clear(&record);
            break;
        }
        result = apply_loaded_record(store, &record,
                                     (flags & JOURNAL_FLAG_DELETE) != 0U);
        ksec_owned_record_clear(&record);
        if (result != KSEC_OK) break;
        last_revision = revision;
    }
    if (close(fd) != 0 && result == KSEC_OK) result = KSEC_ERR_IO;
    if (result != KSEC_OK) {
        clear_records(store);
        store->last_revision = 0;
        return result;
    }
    store->last_revision = last_revision;
    return KSEC_OK;
}

ksec_result ksec_store_append(ksec_store *store,
                              const ksec_vault_header *header,
                              const uint8_t master_key[KSEC_MASTER_KEY_BYTES],
                              ksec_owned_record *record, bool deletion) {
    uint8_t *entry = NULL;
    size_t entry_len = 0;
    bool created = false;
    bool write_attempted = false;
    int fd;
    ksec_result result;
    if (store == NULL || header == NULL || master_key == NULL || record == NULL
            || store->torn_tail) return KSEC_ERR_INVALID;
    record->revision = store->last_revision + 1U;
    if (record->revision == 0) return KSEC_ERR_LIMIT;
    result = make_entry(header, master_key, record, deletion, &entry, &entry_len);
    if (result != KSEC_OK) return result;
    if (store_test_before(KSEC_TEST_STORE_APPEND_OPEN, -1, NULL, 0U) != 0) {
        fd = -1;
    } else {
        fd = open(store->journal_path,
                  O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0 && errno == ENOENT) {
            fd = open(store->journal_path,
                      O_WRONLY | O_APPEND | O_CREAT | O_EXCL | O_CLOEXEC
                          | O_NOFOLLOW,
                      0600);
            created = fd >= 0;
        }
        if (fd >= 0) store_test_after(KSEC_TEST_STORE_APPEND_OPEN);
    }
    if (fd < 0 || safe_regular_fd(fd, 0600) != 0) {
        int saved = errno;
        if (fd >= 0) (void)close(fd);
        sodium_memzero(entry, entry_len);
        free(entry);
        errno = saved;
        return KSEC_ERR_IO;
    }
    write_attempted = true;
    if (store_write_all(fd, entry, entry_len, KSEC_TEST_STORE_APPEND_WRITE) != 0
            || store_fsync(fd, KSEC_TEST_STORE_APPEND_FSYNC) != 0) {
        int saved = errno;
        (void)close(fd);
        sodium_memzero(entry, entry_len);
        free(entry);
        store->torn_tail = write_attempted;
        errno = saved;
        return KSEC_ERR_IO;
    }
    if (store_close(fd, KSEC_TEST_STORE_APPEND_CLOSE) != 0) {
        int saved = errno;
        (void)close(fd);
        sodium_memzero(entry, entry_len);
        free(entry);
        store->torn_tail = write_attempted;
        errno = saved;
        return KSEC_ERR_IO;
    }
    fd = -1;
    if (created && store_directory_sync(store->data_dir,
                                       KSEC_TEST_STORE_APPEND_DIRSYNC) != 0) {
        int saved = errno;
        sodium_memzero(entry, entry_len);
        free(entry);
        store->torn_tail = write_attempted;
        errno = saved;
        return KSEC_ERR_IO;
    }
    sodium_memzero(entry, entry_len);
    free(entry);
    store->last_revision = record->revision;
    return apply_loaded_record(store, record, deletion);
}

static int compare_record_revision(const void *left, const void *right) {
    const ksec_owned_record *const *a = left;
    const ksec_owned_record *const *b = right;
    if ((*a)->revision < (*b)->revision) return -1;
    if ((*a)->revision > (*b)->revision) return 1;
    return 0;
}

ksec_result ksec_store_compact(ksec_store *store,
                               const ksec_vault_header *header,
                               const uint8_t master_key[KSEC_MASTER_KEY_BYTES]) {
    ksec_owned_record **ordered = NULL;
    size_t live = 0;
    size_t index;
    char temporary[4096];
    int fd = -1;
    ksec_result result = KSEC_OK;
    if (store == NULL || header == NULL || master_key == NULL || store->torn_tail) {
        return KSEC_ERR_INVALID;
    }
    ordered = calloc(store->record_count == 0 ? 1U : store->record_count,
                     sizeof *ordered);
    if (ordered == NULL) return KSEC_ERR_MEMORY;
    for (index = 0; index < store->record_count; index++) {
        if (!store->records[index].deleted) ordered[live++] = &store->records[index];
    }
    qsort(ordered, live, sizeof *ordered, compare_record_revision);
    fd = open_unique_temporary(store->data_dir, "journal.ksj", temporary,
                               sizeof temporary, KSEC_TEST_STORE_COMPACT_OPEN);
    if (fd < 0) { free(ordered); return KSEC_ERR_IO; }
    for (index = 0; index < live; index++) {
        uint8_t *entry = NULL;
        size_t entry_len = 0;
        result = make_entry(header, master_key, ordered[index], false, &entry, &entry_len);
        if (result != KSEC_OK || store_write_all(fd, entry, entry_len,
                                                 KSEC_TEST_STORE_COMPACT_WRITE) != 0) {
            if (result == KSEC_OK) result = KSEC_ERR_IO;
            if (entry != NULL) {
                sodium_memzero(entry, entry_len);
                free(entry);
            }
            break;
        }
        sodium_memzero(entry, entry_len);
        free(entry);
    }
    if (result == KSEC_OK && store->last_revision > 0U && (live == 0U
            || ordered[live - 1U]->revision < store->last_revision)) {
        ksec_owned_record checkpoint;
        uint8_t *entry = NULL;
        size_t entry_len = 0;
        memset(&checkpoint, 0, sizeof checkpoint);
        memcpy(checkpoint.owner, "kilix-secrets", sizeof "kilix-secrets");
        checkpoint.object_type = KSEC_OBJECT_SECRET;
        checkpoint.revision = store->last_revision;
        result = make_entry(header, master_key, &checkpoint, true, &entry, &entry_len);
        if (result == KSEC_OK && store_write_all(
                fd, entry, entry_len, KSEC_TEST_STORE_COMPACT_WRITE) != 0) {
            result = KSEC_ERR_IO;
        }
        if (entry != NULL) {
            sodium_memzero(entry, entry_len);
            free(entry);
        }
    }
    if (result == KSEC_OK
            && store_fsync(fd, KSEC_TEST_STORE_COMPACT_FSYNC) != 0) {
        result = KSEC_ERR_IO;
    }
    if (result == KSEC_OK) {
        if (store_close(fd, KSEC_TEST_STORE_COMPACT_CLOSE) != 0) {
            result = KSEC_ERR_IO;
            (void)close(fd);
        }
    } else {
        (void)close(fd);
    }
    fd = -1;
    if (result == KSEC_OK && store_rename(
            temporary, store->journal_path, KSEC_TEST_STORE_COMPACT_RENAME) != 0) {
        result = KSEC_ERR_IO;
    }
    if (result == KSEC_OK && store_directory_sync(
            store->data_dir, KSEC_TEST_STORE_COMPACT_DIRSYNC) != 0) {
        result = KSEC_ERR_IO;
    }
    if (result != KSEC_OK) (void)unlink(temporary);
    free(ordered);
    return result;
}

static bool records_equal(const ksec_owned_record *left,
                          const ksec_owned_record *right) {
    size_t index;
    if (left == NULL || right == NULL
            || sodium_memcmp(left->id, right->id, KSEC_RECORD_ID_BYTES) != 0
            || strcmp(left->owner, right->owner) != 0
            || strcmp(left->type, right->type) != 0
            || strcmp(left->label, right->label) != 0
            || left->object_type != right->object_type
            || left->revision != right->revision
            || left->expires_at != right->expires_at
            || left->field_count != right->field_count
            || left->grant_count != right->grant_count
            || left->deleted != right->deleted) return false;
    for (index = 0U; index < left->field_count; index++) {
        if (strcmp(left->fields[index].name, right->fields[index].name) != 0
                || left->fields[index].value.len
                    != right->fields[index].value.len
                || sodium_memcmp(left->fields[index].value.data,
                                 right->fields[index].value.data,
                                 left->fields[index].value.len) != 0) {
            return false;
        }
    }
    for (index = 0U; index < left->grant_count; index++) {
        if (strcmp(left->grants[index].application_id,
                   right->grants[index].application_id) != 0
                || left->grants[index].verbs != right->grants[index].verbs) {
            return false;
        }
    }
    return true;
}

static bool stores_equal(const ksec_store *left, const ksec_store *right) {
    size_t index;
    if (left == NULL || right == NULL
            || left->record_count != right->record_count
            || left->last_revision != right->last_revision
            || right->torn_tail) return false;
    for (index = 0U; index < left->record_count; index++) {
        size_t other;
        bool found = false;
        for (other = 0U; other < right->record_count; other++) {
            if (sodium_memcmp(left->records[index].id,
                              right->records[other].id,
                              KSEC_RECORD_ID_BYTES) == 0) {
                found = records_equal(&left->records[index],
                                      &right->records[other]);
                break;
            }
        }
        if (!found) return false;
    }
    return true;
}

static int initialize_generation_store(ksec_store *generation,
                                       const char *root,
                                       const char *directory) {
    if (generation == NULL || root == NULL || directory == NULL
            || strlen(root) >= sizeof generation->root_dir
            || strlen(directory) >= sizeof generation->data_dir) return -1;
    memset(generation, 0, sizeof *generation);
    generation->lock_fd = -1;
    memcpy(generation->root_dir, root, strlen(root) + 1U);
    memcpy(generation->data_dir, directory, strlen(directory) + 1U);
    if (make_path(generation->vault_path, sizeof generation->vault_path,
                  directory, "vault.ksv") != 0
            || make_path(generation->journal_path,
                         sizeof generation->journal_path, directory,
                         "journal.ksj") != 0) return -1;
    return 0;
}

static int complete_rotation_stage(int point) {
    if (store_test_before(point, -1, NULL, 0U) != 0) return -1;
    store_test_after(point);
    return 0;
}

static ksec_result write_generation_file(const char *directory,
                                         const char *path,
                                         const uint8_t *bytes, size_t length,
                                         int point) {
    int fd;
    if (directory == NULL || path == NULL
            || (bytes == NULL && length > 0U)) return KSEC_ERR_INVALID;
    fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
              0600);
    if (fd < 0) return KSEC_ERR_IO;
    if (safe_regular_fd(fd, 0600) != 0
            || store_test_before(point, fd, bytes, length) != 0
            || ksec_write_all(fd, bytes, length) != 0
            || fsync(fd) != 0) {
        int saved = errno;
        (void)close(fd);
        errno = saved;
        return KSEC_ERR_IO;
    }
    if (close(fd) != 0) return KSEC_ERR_IO;
    if (ksec_sync_directory(directory) != 0) return KSEC_ERR_IO;
    store_test_after(point);
    return KSEC_OK;
}

ksec_result ksec_store_rotate_generation(
        ksec_store *store, const ksec_vault_header *new_header,
        const uint8_t new_master_key[KSEC_MASTER_KEY_BYTES]) {
    ksec_store staged;
    ksec_store verification;
    ksec_vault_header old_header;
    ksec_vault_header verified_header;
    uint8_t expected_header[1024];
    uint8_t observed_header[1024];
    size_t expected_header_len = 0U;
    size_t observed_header_len = 0U;
    char staging_path[4096];
    char retained_path[4096];
    const char *suffix;
    int count;
    bool exchanged = false;
    ksec_result result;
    memset(&staged, 0, sizeof staged);
    memset(&verification, 0, sizeof verification);
    memset(&old_header, 0, sizeof old_header);
    memset(&verified_header, 0, sizeof verified_header);
    if (store == NULL || new_header == NULL || new_master_key == NULL
            || store->lock_fd < 0 || store->root_dir[0] != '/'
            || store->data_dir[0] != '/' || store->torn_tail) {
        return KSEC_ERR_INVALID;
    }
    result = ksec_store_read_header(store, &old_header);
    if (result != KSEC_OK) goto out;
    if (new_header->format_version != old_header.format_version
            || sodium_memcmp(new_header->vault_uuid, old_header.vault_uuid,
                             KSEC_UUID_BYTES) != 0
            || old_header.generation == UINT64_MAX
            || new_header->generation != old_header.generation + 1U
            || (new_header->flags & KSEC_HEADER_FLAG_RECOVERY_CONFIRMED) == 0U) {
        result = KSEC_ERR_INVALID;
        goto out;
    }
    result = ksec_header_verify_master(new_header, new_master_key);
    if (result != KSEC_OK) goto out;
    if (create_unique_directory(store->root_dir, "vault-rotation",
                                staging_path, sizeof staging_path,
                                KSEC_TEST_STORE_ROTATE_DIRECTORY) != 0
            || initialize_generation_store(&staged, store->root_dir,
                                           staging_path) != 0) {
        result = KSEC_ERR_IO;
        goto out;
    }
    staged.records = store->records;
    staged.record_count = store->record_count;
    staged.last_revision = store->last_revision;
    result = ksec_store_write_header(&staged, new_header);
    if (result != KSEC_OK
            || complete_rotation_stage(KSEC_TEST_STORE_ROTATE_HEADER) != 0) {
        if (result == KSEC_OK) result = KSEC_ERR_IO;
        goto out;
    }
    result = ksec_store_compact(&staged, new_header, new_master_key);
    if (result != KSEC_OK
            || complete_rotation_stage(KSEC_TEST_STORE_ROTATE_JOURNAL) != 0) {
        if (result == KSEC_OK) result = KSEC_ERR_IO;
        goto out;
    }
    if (initialize_generation_store(&verification, store->root_dir,
                                    staging_path) != 0) {
        result = KSEC_ERR_IO;
        goto out;
    }
    result = ksec_store_read_header(&verification, &verified_header);
    if (result == KSEC_OK) {
        result = ksec_header_verify_master(&verified_header, new_master_key);
    }
    if (result == KSEC_OK) {
        result = ksec_header_encode(new_header, expected_header,
                                    sizeof expected_header,
                                    &expected_header_len);
    }
    if (result == KSEC_OK) {
        result = ksec_header_encode(&verified_header, observed_header,
                                    sizeof observed_header,
                                    &observed_header_len);
    }
    if (result == KSEC_OK && (expected_header_len != observed_header_len
            || sodium_memcmp(expected_header, observed_header,
                             expected_header_len) != 0)) {
        result = KSEC_ERR_CRYPTO;
    }
    if (result == KSEC_OK) {
        result = ksec_store_load(&verification, &verified_header,
                                 new_master_key);
    }
    if (result == KSEC_OK && !stores_equal(store, &verification)) {
        result = KSEC_ERR_CRYPTO;
    }
    if (result != KSEC_OK
            || complete_rotation_stage(KSEC_TEST_STORE_ROTATE_VERIFY) != 0) {
        if (result == KSEC_OK) result = KSEC_ERR_IO;
        goto out;
    }
    if (store_directory_sync(store->root_dir,
                             KSEC_TEST_STORE_ROTATE_PRESYNC) != 0) {
        result = KSEC_ERR_IO;
        goto out;
    }
    if (store_exchange_directories(store->data_dir, staging_path,
                                   KSEC_TEST_STORE_ROTATE_EXCHANGE) != 0) {
        result = KSEC_ERR_IO;
        goto out;
    }
    exchanged = true;
    if (store_directory_sync(store->root_dir,
                             KSEC_TEST_STORE_ROTATE_POSTSYNC) != 0) {
        result = KSEC_ERR_IO;
        goto out;
    }
    suffix = strrchr(staging_path, '.');
    if (suffix == NULL) {
        result = KSEC_ERR_IO;
        goto out;
    }
    count = snprintf(retained_path, sizeof retained_path,
                     "%s/.vault-previous-%llu.%ld%s", store->root_dir,
                     (unsigned long long)old_header.generation,
                     (long)getpid(), suffix);
    if (count < 0 || (size_t)count >= sizeof retained_path
            || store_rename(staging_path, retained_path,
                            KSEC_TEST_STORE_ROTATE_RETAIN) != 0
            || store_directory_sync(store->root_dir,
                                    KSEC_TEST_STORE_ROTATE_RETAIN_SYNC) != 0) {
        result = KSEC_ERR_IO;
        goto out;
    }
    result = KSEC_OK;
out:
    if (exchanged && result != KSEC_OK) {
        store->torn_tail = true;
    }
    clear_records(&verification);
    verification.lock_fd = -1;
    staged.records = NULL;
    staged.record_count = 0U;
    sodium_memzero(&staged, sizeof staged);
    sodium_memzero(&verification, sizeof verification);
    sodium_memzero(&old_header, sizeof old_header);
    sodium_memzero(&verified_header, sizeof verified_header);
    sodium_memzero(expected_header, sizeof expected_header);
    sodium_memzero(observed_header, sizeof observed_header);
    return result;
}

typedef struct {
    const char *staging_name;
    const char *retained_name;
    int directory;
    int vault;
    int journal;
    int verify;
    int presync;
    int exchange;
    int postsync;
    int retain;
    int retain_sync;
    bool require_confirmed;
    bool require_new_identity;
} generation_install_policy;

static ksec_result install_generation(
        ksec_store *store, const ksec_vault_header *header,
        const uint8_t master_key[KSEC_MASTER_KEY_BYTES],
        const uint8_t *vault, size_t vault_len,
        const uint8_t *journal, size_t journal_len,
        const generation_install_policy *policy) {
    ksec_store staged;
    ksec_store verification;
    ksec_vault_header old_header;
    ksec_vault_header verified_header;
    uint8_t expected_header[HEADER_MAX_BYTES];
    uint8_t observed_header[HEADER_MAX_BYTES];
    size_t expected_header_len = 0U;
    size_t observed_header_len = 0U;
    char staging_path[4096];
    char retained_path[4096];
    const char *suffix;
    int count;
    bool exchanged = false;
    bool old_header_known = false;
    ksec_result result = KSEC_ERR_INVALID;
    memset(&staged, 0, sizeof staged);
    memset(&verification, 0, sizeof verification);
    memset(&old_header, 0, sizeof old_header);
    memset(&verified_header, 0, sizeof verified_header);
    memset(expected_header, 0, sizeof expected_header);
    memset(observed_header, 0, sizeof observed_header);
    if (store == NULL || header == NULL || master_key == NULL
            || vault == NULL || policy == NULL || store->lock_fd < 0
            || store->root_dir[0] != '/' || store->data_dir[0] != '/'
            || store->torn_tail || vault_len == 0U
            || vault_len > sizeof expected_header
            || (journal == NULL && journal_len > 0U)
            || journal_len > KSEC_MAX_JOURNAL_BYTES
            || policy->staging_name == NULL || policy->retained_name == NULL
            || (policy->require_confirmed
                && (header->flags & KSEC_HEADER_FLAG_RECOVERY_CONFIRMED) == 0U)
            || (!policy->require_confirmed
                && (header->flags != 0U || header->generation != 1U))) {
        return KSEC_ERR_INVALID;
    }
    result = ksec_header_verify_master(header, master_key);
    if (result != KSEC_OK) goto out;
    result = ksec_header_encode(header, expected_header,
                                sizeof expected_header, &expected_header_len);
    if (result != KSEC_OK) goto out;
    if (expected_header_len != vault_len
            || sodium_memcmp(expected_header, vault,
                             expected_header_len) != 0) {
        result = KSEC_ERR_CRYPTO;
        goto out;
    }
    result = ksec_store_read_header(store, &old_header);
    if (result == KSEC_OK) old_header_known = true;
    else result = KSEC_OK;
    if (policy->require_new_identity && old_header_known
            && sodium_memcmp(old_header.vault_uuid, header->vault_uuid,
                             KSEC_UUID_BYTES) == 0) {
        result = KSEC_ERR_INVALID;
        goto out;
    }
    if (create_unique_directory(store->root_dir, policy->staging_name,
                                staging_path, sizeof staging_path,
                                policy->directory) != 0
            || initialize_generation_store(&staged, store->root_dir,
                                           staging_path) != 0) {
        result = KSEC_ERR_IO;
        goto out;
    }
    result = write_generation_file(staging_path, staged.vault_path,
                                   vault, vault_len, policy->vault);
    if (result != KSEC_OK) goto out;
    result = write_generation_file(staging_path, staged.journal_path,
                                   journal, journal_len, policy->journal);
    if (result != KSEC_OK) goto out;
    if (initialize_generation_store(&verification, store->root_dir,
                                    staging_path) != 0) {
        result = KSEC_ERR_IO;
        goto out;
    }
    result = ksec_store_read_header(&verification, &verified_header);
    if (result == KSEC_OK) {
        result = ksec_header_verify_master(&verified_header, master_key);
    }
    if (result == KSEC_OK) {
        result = ksec_header_encode(&verified_header, observed_header,
                                    sizeof observed_header,
                                    &observed_header_len);
    }
    if (result == KSEC_OK && (observed_header_len != vault_len
            || sodium_memcmp(observed_header, vault,
                             observed_header_len) != 0)) {
        result = KSEC_ERR_CRYPTO;
    }
    if (result == KSEC_OK) {
        result = ksec_store_load(&verification, &verified_header,
                                 master_key);
    }
    if (result == KSEC_OK && (verification.torn_tail
            || (policy->require_new_identity
                && verification.record_count != 0U))) {
        result = KSEC_ERR_INVALID;
    }
    if (result != KSEC_OK
            || complete_rotation_stage(policy->verify) != 0) {
        if (result == KSEC_OK) result = KSEC_ERR_IO;
        goto out;
    }
    if (store_directory_sync(store->root_dir, policy->presync) != 0) {
        result = KSEC_ERR_IO;
        goto out;
    }
    if (store_exchange_directories(store->data_dir, staging_path,
                                   policy->exchange) != 0) {
        result = KSEC_ERR_IO;
        goto out;
    }
    exchanged = true;
    if (store_directory_sync(store->root_dir, policy->postsync) != 0) {
        result = KSEC_ERR_IO;
        goto out;
    }
    suffix = strrchr(staging_path, '.');
    if (suffix == NULL) {
        result = KSEC_ERR_IO;
        goto out;
    }
    if (old_header_known) {
        count = snprintf(retained_path, sizeof retained_path,
                         "%s/.%s-%llu.%ld%s", store->root_dir,
                         policy->retained_name,
                         (unsigned long long)old_header.generation,
                         (long)getpid(), suffix);
    } else {
        count = snprintf(retained_path, sizeof retained_path,
                         "%s/.%s-unknown.%ld%s", store->root_dir,
                         policy->retained_name,
                         (long)getpid(), suffix);
    }
    if (count < 0 || (size_t)count >= sizeof retained_path
            || store_rename(staging_path, retained_path, policy->retain) != 0
            || store_directory_sync(store->root_dir, policy->retain_sync) != 0) {
        result = KSEC_ERR_IO;
        goto out;
    }
    clear_records(store);
    store->last_revision = 0U;
    store->torn_tail = false;
    result = KSEC_OK;
out:
    if (exchanged && result != KSEC_OK) store->torn_tail = true;
    clear_records(&verification);
    verification.lock_fd = -1;
    sodium_memzero(&staged, sizeof staged);
    sodium_memzero(&verification, sizeof verification);
    sodium_memzero(&old_header, sizeof old_header);
    sodium_memzero(&verified_header, sizeof verified_header);
    sodium_memzero(expected_header, sizeof expected_header);
    sodium_memzero(observed_header, sizeof observed_header);
    return result;
}

ksec_result ksec_store_import_generation(ksec_store *store,
                                         const ksec_backup_image *image) {
    static const generation_install_policy policy = {
        "vault-import", "vault-previous",
        KSEC_TEST_STORE_IMPORT_DIRECTORY,
        KSEC_TEST_STORE_IMPORT_VAULT,
        KSEC_TEST_STORE_IMPORT_JOURNAL,
        KSEC_TEST_STORE_IMPORT_VERIFY,
        KSEC_TEST_STORE_IMPORT_PRESYNC,
        KSEC_TEST_STORE_IMPORT_EXCHANGE,
        KSEC_TEST_STORE_IMPORT_POSTSYNC,
        KSEC_TEST_STORE_IMPORT_RETAIN,
        KSEC_TEST_STORE_IMPORT_RETAIN_SYNC,
        true, false
    };
    if (image == NULL || image->master.data == NULL
            || image->master.len != KSEC_MASTER_KEY_BYTES) {
        return KSEC_ERR_INVALID;
    }
    return install_generation(store, &image->header, image->master.data,
                              image->vault, image->vault_len,
                              image->journal, image->journal_len, &policy);
}

ksec_result ksec_store_reset_generation(
        ksec_store *store, const ksec_vault_header *new_header,
        const uint8_t new_master_key[KSEC_MASTER_KEY_BYTES]) {
    static const generation_install_policy policy = {
        "vault-reset", "vault-reset-retained",
        KSEC_TEST_STORE_RESET_DIRECTORY,
        KSEC_TEST_STORE_RESET_VAULT,
        KSEC_TEST_STORE_RESET_JOURNAL,
        KSEC_TEST_STORE_RESET_VERIFY,
        KSEC_TEST_STORE_RESET_PRESYNC,
        KSEC_TEST_STORE_RESET_EXCHANGE,
        KSEC_TEST_STORE_RESET_POSTSYNC,
        KSEC_TEST_STORE_RESET_RETAIN,
        KSEC_TEST_STORE_RESET_RETAIN_SYNC,
        false, true
    };
    uint8_t encoded[HEADER_MAX_BYTES];
    size_t encoded_len = 0U;
    ksec_result result;
    memset(encoded, 0, sizeof encoded);
    if (new_header == NULL || new_master_key == NULL) {
        return KSEC_ERR_INVALID;
    }
    result = ksec_header_encode(new_header, encoded, sizeof encoded,
                                &encoded_len);
    if (result == KSEC_OK) {
        result = install_generation(store, new_header, new_master_key,
                                    encoded, encoded_len, NULL, 0U, &policy);
    }
    sodium_memzero(encoded, sizeof encoded);
    return result;
}
