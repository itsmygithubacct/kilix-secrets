#define _GNU_SOURCE

#include "internal.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

enum {
    JOURNAL_PREFIX_BYTES = 12,
    JOURNAL_BODY_FIXED_BYTES = 58,
    JOURNAL_FLAG_DELETE = 1,
    HEADER_MAX_BYTES = 1024
};

static const uint8_t JOURNAL_MAGIC[8] = {'K','S','V','J','R','0','0','1'};

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
    public_record.owner = record->owner;
    public_record.type = record->type;
    public_record.label = record->label;
    public_record.expires_at = record->expires_at;
    public_record.fields = fields;
    public_record.field_count = record->field_count;
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
    int fd;
    if (store == NULL || data_dir == NULL || data_dir[0] != '/') return KSEC_ERR_INVALID;
    memset(store, 0, sizeof *store);
    store->lock_fd = -1;
    if (strlen(data_dir) >= sizeof store->data_dir) return KSEC_ERR_LIMIT;
    memcpy(store->data_dir, data_dir, strlen(data_dir) + 1U);
    if (lstat(data_dir, &(struct stat){0}) != 0) {
        if (!create || errno != ENOENT
                || ksec_parent_directory(data_dir, parent, sizeof parent) != 0
                || ksec_validate_secure_directory(parent, false) != 0
                || mkdir(data_dir, 0700) != 0) return KSEC_ERR_IO;
        if (sync_parent_directory(data_dir) != 0 && errno != EINVAL) return KSEC_ERR_IO;
    }
    if (ksec_validate_secure_directory(data_dir, true) != 0) return KSEC_ERR_DENIED;
    if (make_path(store->vault_path, sizeof store->vault_path, data_dir, "vault.ksv") != 0
            || make_path(store->journal_path, sizeof store->journal_path, data_dir, "journal.ksj") != 0
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
    int count;
    ksec_result result;
    if (store == NULL || header == NULL) return KSEC_ERR_INVALID;
    result = ksec_header_encode(header, encoded, sizeof encoded, &encoded_len);
    if (result != KSEC_OK) return result;
    count = snprintf(temporary, sizeof temporary, "%s/.vault.ksv.tmp.%ld",
                     store->data_dir, (long)getpid());
    if (count < 0 || (size_t)count >= sizeof temporary) return KSEC_ERR_LIMIT;
    fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return KSEC_ERR_IO;
    if (safe_regular_fd(fd, 0600) != 0 || ksec_write_all(fd, encoded, encoded_len) != 0
            || fsync(fd) != 0) {
        int saved = errno;
        (void)close(fd);
        (void)unlink(temporary);
        sodium_memzero(encoded, sizeof encoded);
        errno = saved;
        return KSEC_ERR_IO;
    }
    if (close(fd) != 0) {
        int saved = errno;
        fd = -1;
        (void)unlink(temporary);
        sodium_memzero(encoded, sizeof encoded);
        errno = saved;
        return KSEC_ERR_IO;
    }
    fd = -1;
    if (rename(temporary, store->vault_path) != 0
            || ksec_sync_directory(store->data_dir) != 0) {
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
    int fd;
    ksec_result result;
    if (store == NULL || header == NULL || master_key == NULL || record == NULL
            || store->torn_tail) return KSEC_ERR_INVALID;
    record->revision = store->last_revision + 1U;
    if (record->revision == 0) return KSEC_ERR_LIMIT;
    result = make_entry(header, master_key, record, deletion, &entry, &entry_len);
    if (result != KSEC_OK) return result;
    fd = open(store->journal_path, O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 && errno == ENOENT) {
        fd = open(store->journal_path,
                  O_WRONLY | O_APPEND | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                  0600);
        created = fd >= 0;
    }
    if (fd < 0 || safe_regular_fd(fd, 0600) != 0
            || ksec_write_all(fd, entry, entry_len) != 0 || fsync(fd) != 0) {
        int saved = errno;
        if (fd >= 0) (void)close(fd);
        sodium_memzero(entry, entry_len);
        free(entry);
        errno = saved;
        return KSEC_ERR_IO;
    }
    if (close(fd) != 0) {
        int saved = errno;
        sodium_memzero(entry, entry_len);
        free(entry);
        errno = saved;
        return KSEC_ERR_IO;
    }
    fd = -1;
    if (created && ksec_sync_directory(store->data_dir) != 0) {
        int saved = errno;
        sodium_memzero(entry, entry_len);
        free(entry);
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
    int count;
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
    count = snprintf(temporary, sizeof temporary, "%s/.journal.ksj.tmp.%ld",
                     store->data_dir, (long)getpid());
    if (count < 0 || (size_t)count >= sizeof temporary) {
        free(ordered);
        return KSEC_ERR_LIMIT;
    }
    fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) { free(ordered); return KSEC_ERR_IO; }
    for (index = 0; index < live; index++) {
        uint8_t *entry = NULL;
        size_t entry_len = 0;
        result = make_entry(header, master_key, ordered[index], false, &entry, &entry_len);
        if (result != KSEC_OK || ksec_write_all(fd, entry, entry_len) != 0) {
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
        if (result == KSEC_OK && ksec_write_all(fd, entry, entry_len) != 0) {
            result = KSEC_ERR_IO;
        }
        if (entry != NULL) {
            sodium_memzero(entry, entry_len);
            free(entry);
        }
    }
    if (result == KSEC_OK && fsync(fd) != 0) result = KSEC_ERR_IO;
    if (close(fd) != 0 && result == KSEC_OK) result = KSEC_ERR_IO;
    fd = -1;
    if (result == KSEC_OK && rename(temporary, store->journal_path) != 0) {
        result = KSEC_ERR_IO;
    }
    if (result == KSEC_OK && ksec_sync_directory(store->data_dir) != 0) {
        result = KSEC_ERR_IO;
    }
    if (result != KSEC_OK) (void)unlink(temporary);
    free(ordered);
    return result;
}
