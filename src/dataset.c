/*
 * Sealed dataset file v1, dataset-key record schema and request parsers.
 * docs/SEALED-DATASETS.md sections 2, 3 and 4.
 */
#include "internal.h"

#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

_Static_assert(KSEC_DATASET_STREAM_HEADER_BYTES
                   == crypto_secretstream_xchacha20poly1305_HEADERBYTES,
               "secretstream header size");
_Static_assert(KSEC_DATASET_CHUNK_OVERHEAD
                   == crypto_secretstream_xchacha20poly1305_ABYTES,
               "secretstream chunk overhead");
_Static_assert(KSEC_DATASET_KEY_BYTES == crypto_kdf_KEYBYTES,
               "dataset key size");
_Static_assert(sizeof KSEC_DATASET_KDF_CONTEXT - 1U == crypto_kdf_CONTEXTBYTES,
               "dataset KDF context size");

static const uint8_t DATASET_MAGIC[8] = {
    'K', 'S', 'D', 'S', 'E', 'T', '0', '1'
};

enum {
    KSEC_DATASET_PREFIX_MIN =
        KSEC_DATASET_PREFIX_FIXED_BYTES + 1U + 1U,
    KSEC_DATASET_PREFIX_MAX =
        KSEC_DATASET_PREFIX_FIXED_BYTES + KSEC_MAX_APP_ID
        + KSEC_MAX_DATASET_NAME,
    KSEC_DATASET_CIPHER_CHUNK =
        KSEC_DATASET_CHUNK_BYTES + KSEC_DATASET_CHUNK_OVERHEAD
};

static int chunk_count(uint64_t plaintext_length, uint64_t *chunks) {
    if (chunks == NULL || plaintext_length > KSEC_MAX_DATASET_BYTES) return -1;
    if (plaintext_length == 0U) {
        *chunks = 1U;
        return 0;
    }
    *chunks = (plaintext_length + (uint64_t)KSEC_DATASET_CHUNK_BYTES - 1U)
        / (uint64_t)KSEC_DATASET_CHUNK_BYTES;
    return 0;
}

static int prefix_length_ok(size_t prefix_length) {
    return prefix_length >= KSEC_DATASET_PREFIX_MIN
        && prefix_length <= KSEC_DATASET_PREFIX_MAX;
}

/* 0 exact, 1 short, -1 error. A zero-length read is exact. */
static int pread_exact(int fd, void *data, size_t length, off_t offset) {
    uint8_t *bytes = data;
    size_t got = 0U;
    if (length == 0U) return 0;
    if (data == NULL || offset < 0) return -1;
    while (got < length) {
        ssize_t count = pread(fd, bytes + got, length - got,
                               offset + (off_t)got);
        if (count < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (count == 0) return 1;
        got += (size_t)count;
    }
    return 0;
}

static int regular_size(int fd, uint64_t *size) {
    struct stat status;
    if (size == NULL || fd < 0 || fstat(fd, &status) != 0) return -1;
    if (!S_ISREG(status.st_mode) || status.st_size < 0) return 1;
    *size = (uint64_t)status.st_size;
    return 0;
}

static ksec_result derive_stream_key(const uint8_t key[KSEC_DATASET_KEY_BYTES],
                                     uint8_t out[KSEC_DATASET_KEY_BYTES]) {
    if (key == NULL || out == NULL) return KSEC_ERR_INVALID;
    if (crypto_kdf_derive_from_key(
            out, KSEC_DATASET_KEY_BYTES,
            (uint64_t)KSEC_DATASET_KDF_SUBKEY_ID,
            KSEC_DATASET_KDF_CONTEXT, key) != 0) {
        sodium_memzero(out, KSEC_DATASET_KEY_BYTES);
        return KSEC_ERR_CRYPTO;
    }
    return KSEC_OK;
}

static int identity_matches(const ksec_dataset_header_info *parsed,
                            const ksec_dataset_header_info *expected) {
    size_t owner_len;
    size_t name_len;
    size_t expected_owner;
    size_t expected_name;
    if (parsed == NULL || expected == NULL) return 0;
    if (sodium_memcmp(parsed->vault_uuid, expected->vault_uuid,
                      KSEC_UUID_BYTES) != 0) return 0;
    if (sodium_memcmp(parsed->key_record_id, expected->key_record_id,
                      KSEC_RECORD_ID_BYTES) != 0) return 0;
    expected_owner = strnlen(expected->owner, sizeof expected->owner);
    owner_len = strnlen(parsed->owner, sizeof parsed->owner);
    if (expected_owner == sizeof expected->owner || expected_owner != owner_len
            || owner_len == 0U
            || sodium_memcmp(parsed->owner, expected->owner, owner_len) != 0) {
        return 0;
    }
    expected_name = strnlen(expected->name, sizeof expected->name);
    name_len = strnlen(parsed->name, sizeof parsed->name);
    if (expected_name == sizeof expected->name || expected_name != name_len
            || name_len == 0U
            || sodium_memcmp(parsed->name, expected->name, name_len) != 0) {
        return 0;
    }
    return 1;
}

ksec_result ksec_dataset_encode_prefix(const ksec_dataset_header_info *info,
                                       uint8_t *output, size_t output_size,
                                       size_t *output_length) {
    size_t owner_len;
    size_t name_len;
    size_t prefix;
    size_t offset = 0U;
    if (info == NULL || output == NULL || output_length == NULL
            || info->plaintext_length > KSEC_MAX_DATASET_BYTES
            || ksec_validate_app_id(info->owner) != 0
            || ksec_validate_name(info->name, KSEC_MAX_DATASET_NAME) != 0) {
        return KSEC_ERR_INVALID;
    }
    owner_len = strlen(info->owner);
    name_len = strlen(info->name);
    prefix = KSEC_DATASET_PREFIX_FIXED_BYTES + owner_len + name_len;
    if (prefix > output_size) return KSEC_ERR_LIMIT;
    memcpy(output + offset, DATASET_MAGIC, sizeof DATASET_MAGIC);
    offset += sizeof DATASET_MAGIC;
    ksec_put_u16(output + offset, KSEC_DATASET_FORMAT_VERSION);
    offset += 2U;
    ksec_put_u16(output + offset, KSEC_DATASET_STREAM_ID);
    offset += 2U;
    ksec_put_u32(output + offset, KSEC_DATASET_CHUNK_BYTES);
    offset += 4U;
    memcpy(output + offset, info->vault_uuid, KSEC_UUID_BYTES);
    offset += KSEC_UUID_BYTES;
    memcpy(output + offset, info->key_record_id, KSEC_RECORD_ID_BYTES);
    offset += KSEC_RECORD_ID_BYTES;
    ksec_put_u64(output + offset, info->revision);
    offset += 8U;
    ksec_put_u64(output + offset, info->plaintext_length);
    offset += 8U;
    ksec_put_u16(output + offset, (uint16_t)owner_len);
    offset += 2U;
    memcpy(output + offset, info->owner, owner_len);
    offset += owner_len;
    ksec_put_u16(output + offset, (uint16_t)name_len);
    offset += 2U;
    memcpy(output + offset, info->name, name_len);
    offset += name_len;
    if (offset != prefix) return KSEC_ERR_INVALID;
    *output_length = prefix;
    return KSEC_OK;
}

ksec_result ksec_dataset_parse_prefix(const uint8_t *input, size_t input_length,
                                      ksec_dataset_header_info *info,
                                      size_t *prefix_length) {
    ksec_dataset_header_info parsed;
    uint16_t owner_len;
    uint16_t name_len;
    size_t prefix;
    uint64_t plaintext_length;
    memset(&parsed, 0, sizeof parsed);
    if (input == NULL || info == NULL || prefix_length == NULL
            || input_length < 66U) {
        return KSEC_ERR_INVALID;
    }
    if (memcmp(input, DATASET_MAGIC, sizeof DATASET_MAGIC) != 0
            || ksec_get_u16(input + 8U) != KSEC_DATASET_FORMAT_VERSION
            || ksec_get_u16(input + 10U) != KSEC_DATASET_STREAM_ID
            || ksec_get_u32(input + 12U) != (uint32_t)KSEC_DATASET_CHUNK_BYTES) {
        return KSEC_ERR_INVALID;
    }
    memcpy(parsed.vault_uuid, input + 16U, KSEC_UUID_BYTES);
    memcpy(parsed.key_record_id, input + 32U, KSEC_RECORD_ID_BYTES);
    parsed.revision = ksec_get_u64(input + 48U);
    plaintext_length = ksec_get_u64(input + 56U);
    if (plaintext_length > KSEC_MAX_DATASET_BYTES) return KSEC_ERR_INVALID;
    parsed.plaintext_length = plaintext_length;
    owner_len = ksec_get_u16(input + 64U);
    if (owner_len == 0U || owner_len > KSEC_MAX_APP_ID
            || input_length < 68U + (size_t)owner_len) {
        return KSEC_ERR_INVALID;
    }
    if (ksec_validate_app_id_bytes(input + 66U, owner_len) != 0) {
        return KSEC_ERR_INVALID;
    }
    name_len = ksec_get_u16(input + 66U + owner_len);
    if (name_len == 0U || name_len > KSEC_MAX_DATASET_NAME) {
        return KSEC_ERR_INVALID;
    }
    prefix = 68U + (size_t)owner_len + (size_t)name_len;
    if (input_length < prefix + KSEC_DATASET_STREAM_HEADER_BYTES
            || ksec_validate_text_bytes(input + 68U + owner_len, name_len,
                                        KSEC_MAX_DATASET_NAME) != 0) {
        return KSEC_ERR_INVALID;
    }
    memcpy(parsed.owner, input + 66U, owner_len);
    parsed.owner[owner_len] = '\0';
    memcpy(parsed.name, input + 68U + owner_len, name_len);
    parsed.name[name_len] = '\0';
    *info = parsed;
    *prefix_length = prefix;
    return KSEC_OK;
}

ksec_result ksec_dataset_sealed_length(uint64_t plaintext_length,
                                       size_t prefix_length,
                                       uint64_t *sealed_length) {
    uint64_t chunks = 0U;
    uint64_t total;
    uint64_t overhead;
    if (sealed_length == NULL || !prefix_length_ok(prefix_length)
            || chunk_count(plaintext_length, &chunks) != 0) {
        return KSEC_ERR_INVALID;
    }
    overhead = chunks * (uint64_t)KSEC_DATASET_CHUNK_OVERHEAD;
    total = (uint64_t)prefix_length
        + (uint64_t)KSEC_DATASET_STREAM_HEADER_BYTES;
    if (total > UINT64_MAX - plaintext_length
            || total + plaintext_length > UINT64_MAX - overhead) {
        return KSEC_ERR_LIMIT;
    }
    *sealed_length = total + plaintext_length + overhead;
    return KSEC_OK;
}

static ksec_result chunk_plain_len(uint64_t index, uint64_t chunks,
                                   uint64_t *remaining, size_t *plain_len,
                                   unsigned char *tag) {
    uint64_t length;
    if (remaining == NULL || plain_len == NULL || tag == NULL || chunks == 0U
            || index >= chunks) {
        return KSEC_ERR_INVALID;
    }
    if (index + 1U == chunks) {
        length = *remaining;
        *tag = crypto_secretstream_xchacha20poly1305_TAG_FINAL;
    } else {
        if (*remaining < (uint64_t)KSEC_DATASET_CHUNK_BYTES) {
            return KSEC_ERR_INVALID;
        }
        length = (uint64_t)KSEC_DATASET_CHUNK_BYTES;
        *tag = crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
    }
    if (length > (uint64_t)KSEC_DATASET_CHUNK_BYTES) return KSEC_ERR_INVALID;
    *plain_len = (size_t)length;
    *remaining -= length;
    return KSEC_OK;
}

ksec_result ksec_dataset_seal(const uint8_t key[KSEC_DATASET_KEY_BYTES],
                              const ksec_dataset_header_info *info,
                              int plaintext_fd, int output_fd) {
    uint8_t prefix[KSEC_DATASET_PREFIX_MAX];
    uint8_t header[KSEC_DATASET_STREAM_HEADER_BYTES];
    uint8_t framed[KSEC_DATASET_PREFIX_MAX + KSEC_DATASET_STREAM_HEADER_BYTES];
    crypto_secretstream_xchacha20poly1305_state state;
    ksec_secure_buffer stream_key = {0};
    ksec_secure_buffer plain = {0};
    ksec_secure_buffer cipher = {0};
    size_t prefix_len = 0U;
    uint64_t file_size = 0U;
    uint64_t chunks = 0U;
    uint64_t remaining;
    uint64_t index;
    off_t plain_offset = 0;
    ksec_result result = KSEC_ERR_INVALID;
    int sized;
    memset(&state, 0, sizeof state);
    memset(header, 0, sizeof header);
    if (key == NULL || info == NULL || plaintext_fd < 0 || output_fd < 0) {
        return KSEC_ERR_INVALID;
    }
    result = ksec_dataset_encode_prefix(info, prefix, sizeof prefix,
                                        &prefix_len);
    if (result != KSEC_OK) return result;
    sized = regular_size(plaintext_fd, &file_size);
    if (sized < 0) return KSEC_ERR_IO;
    if (sized > 0 || file_size != info->plaintext_length
            || chunk_count(info->plaintext_length, &chunks) != 0) {
        return KSEC_ERR_INVALID;
    }
    result = ksec_secure_alloc(&stream_key, KSEC_DATASET_KEY_BYTES);
    if (result != KSEC_OK) goto out;
    result = ksec_secure_alloc(&plain, KSEC_DATASET_CHUNK_BYTES);
    if (result != KSEC_OK) goto out;
    result = ksec_secure_alloc(&cipher, KSEC_DATASET_CIPHER_CHUNK);
    if (result != KSEC_OK) goto out;
    result = derive_stream_key(key, stream_key.data);
    if (result != KSEC_OK) goto out;
    if (crypto_secretstream_xchacha20poly1305_init_push(
            &state, header, stream_key.data) != 0) {
        result = KSEC_ERR_CRYPTO;
        goto out;
    }
    memcpy(framed, prefix, prefix_len);
    memcpy(framed + prefix_len, header, sizeof header);
    if (ksec_write_all(output_fd, framed, prefix_len + sizeof header) != 0) {
        result = KSEC_ERR_IO;
        goto out;
    }
    remaining = info->plaintext_length;
    for (index = 0U; index < chunks; index++) {
        size_t plain_len = 0U;
        unsigned char tag = 0U;
        unsigned long long cipher_len = 0U;
        int read_result;
        result = chunk_plain_len(index, chunks, &remaining, &plain_len, &tag);
        if (result != KSEC_OK) goto out;
        read_result = pread_exact(plaintext_fd, plain.data, plain_len,
                                   plain_offset);
        if (read_result < 0) {
            result = KSEC_ERR_IO;
            goto out;
        }
        if (read_result > 0) {
            result = KSEC_ERR_INVALID;
            goto out;
        }
        if (crypto_secretstream_xchacha20poly1305_push(
                &state, cipher.data, &cipher_len, plain.data,
                (unsigned long long)plain_len, prefix,
                (unsigned long long)prefix_len, tag) != 0
                || cipher_len != (unsigned long long)plain_len
                    + (unsigned long long)KSEC_DATASET_CHUNK_OVERHEAD) {
            result = KSEC_ERR_CRYPTO;
            goto out;
        }
        if (ksec_write_all(output_fd, cipher.data, (size_t)cipher_len) != 0) {
            result = KSEC_ERR_IO;
            goto out;
        }
        plain_offset += (off_t)plain_len;
        sodium_memzero(plain.data, plain.len);
        sodium_memzero(cipher.data, cipher.len);
    }
    if (remaining != 0U) {
        result = KSEC_ERR_INVALID;
        goto out;
    }
    result = KSEC_OK;
out:
    sodium_memzero(&state, sizeof state);
    sodium_memzero(header, sizeof header);
    sodium_memzero(framed, sizeof framed);
    sodium_memzero(prefix, sizeof prefix);
    ksec_secure_free(&stream_key);
    ksec_secure_free(&plain);
    ksec_secure_free(&cipher);
    return result;
}

ksec_result ksec_dataset_unseal(const uint8_t key[KSEC_DATASET_KEY_BYTES],
                                const ksec_dataset_header_info *expected,
                                int sealed_fd, int output_fd,
                                ksec_dataset_header_info *actual) {
    uint8_t head[KSEC_DATASET_PREFIX_MAX + KSEC_DATASET_STREAM_HEADER_BYTES];
    crypto_secretstream_xchacha20poly1305_state state;
    ksec_dataset_header_info parsed;
    ksec_secure_buffer stream_key = {0};
    ksec_secure_buffer plain = {0};
    ksec_secure_buffer cipher = {0};
    size_t prefix_len = 0U;
    size_t head_len;
    uint64_t file_size = 0U;
    uint64_t expected_size = 0U;
    uint64_t chunks = 0U;
    uint64_t remaining;
    uint64_t index;
    off_t cipher_offset;
    ksec_result result = KSEC_ERR_INVALID;
    int sized;
    int read_result;
    memset(&state, 0, sizeof state);
    memset(&parsed, 0, sizeof parsed);
    memset(head, 0, sizeof head);
    if (key == NULL || expected == NULL || actual == NULL || sealed_fd < 0
            || output_fd < 0) {
        return KSEC_ERR_INVALID;
    }
    sized = regular_size(sealed_fd, &file_size);
    if (sized < 0) return KSEC_ERR_IO;
    if (sized > 0) return KSEC_ERR_INVALID;
    head_len = file_size < (uint64_t)sizeof head
        ? (size_t)file_size : sizeof head;
    read_result = pread_exact(sealed_fd, head, head_len, 0);
    if (read_result < 0) return KSEC_ERR_IO;
    if (read_result > 0) return KSEC_ERR_INVALID;
    result = ksec_dataset_parse_prefix(head, head_len, &parsed, &prefix_len);
    if (result != KSEC_OK) {
        sodium_memzero(&parsed, sizeof parsed);
        sodium_memzero(head, sizeof head);
        return result;
    }
    if (!identity_matches(&parsed, expected)) {
        result = KSEC_ERR_CONFLICT;
        goto out;
    }
    result = ksec_dataset_sealed_length(parsed.plaintext_length, prefix_len,
                                        &expected_size);
    if (result != KSEC_OK) goto out;
    if (file_size != expected_size) {
        result = KSEC_ERR_INVALID;
        goto out;
    }
    if (chunk_count(parsed.plaintext_length, &chunks) != 0) {
        result = KSEC_ERR_INVALID;
        goto out;
    }
    result = ksec_secure_alloc(&stream_key, KSEC_DATASET_KEY_BYTES);
    if (result != KSEC_OK) goto out;
    result = ksec_secure_alloc(&plain, KSEC_DATASET_CHUNK_BYTES);
    if (result != KSEC_OK) goto out;
    result = ksec_secure_alloc(&cipher, KSEC_DATASET_CIPHER_CHUNK);
    if (result != KSEC_OK) goto out;
    result = derive_stream_key(key, stream_key.data);
    if (result != KSEC_OK) goto out;
    if (prefix_len > sizeof head - sizeof(uint8_t[KSEC_DATASET_STREAM_HEADER_BYTES])
            || crypto_secretstream_xchacha20poly1305_init_pull(
                &state, head + prefix_len, stream_key.data) != 0) {
        result = KSEC_ERR_CRYPTO;
        goto out;
    }
    remaining = parsed.plaintext_length;
    cipher_offset = (off_t)prefix_len
        + (off_t)KSEC_DATASET_STREAM_HEADER_BYTES;
    for (index = 0U; index < chunks; index++) {
        size_t plain_len = 0U;
        size_t cipher_len;
        unsigned char expect_tag = 0U;
        unsigned char got_tag = 0U;
        unsigned long long opened = 0U;
        result = chunk_plain_len(index, chunks, &remaining, &plain_len,
                                 &expect_tag);
        if (result != KSEC_OK) goto out;
        cipher_len = plain_len + KSEC_DATASET_CHUNK_OVERHEAD;
        read_result = pread_exact(sealed_fd, cipher.data, cipher_len,
                                   cipher_offset);
        if (read_result < 0) {
            result = KSEC_ERR_IO;
            goto out;
        }
        if (read_result > 0) {
            result = KSEC_ERR_INVALID;
            goto out;
        }
        if (crypto_secretstream_xchacha20poly1305_pull(
                &state, plain.data, &opened, &got_tag, cipher.data,
                (unsigned long long)cipher_len, head,
                (unsigned long long)prefix_len) != 0
                || opened != (unsigned long long)plain_len
                || got_tag != expect_tag) {
            result = KSEC_ERR_CRYPTO;
            goto out;
        }
        if (plain_len > 0U
                && ksec_write_all(output_fd, plain.data, plain_len) != 0) {
            result = KSEC_ERR_IO;
            goto out;
        }
        cipher_offset += (off_t)cipher_len;
        sodium_memzero(plain.data, plain.len);
        sodium_memzero(cipher.data, cipher.len);
    }
    if (remaining != 0U) {
        result = KSEC_ERR_INVALID;
        goto out;
    }
    *actual = parsed;
    result = KSEC_OK;
out:
    sodium_memzero(&state, sizeof state);
    sodium_memzero(&parsed, sizeof parsed);
    sodium_memzero(head, sizeof head);
    ksec_secure_free(&stream_key);
    ksec_secure_free(&plain);
    ksec_secure_free(&cipher);
    return result;
}

static ksec_result parse_counted_text(const uint8_t *payload,
                                      size_t payload_length,
                                      size_t length_offset, size_t max_length,
                                      char *output, size_t output_size) {
    uint16_t text_len;
    size_t fixed = length_offset + 2U;
    if (payload == NULL || output == NULL || output_size == 0U) {
        return KSEC_ERR_PROTOCOL;
    }
    output[0] = '\0';
    if (payload_length < fixed) return KSEC_ERR_PROTOCOL;
    text_len = ksec_get_u16(payload + length_offset);
    if ((size_t)text_len > SIZE_MAX - fixed
            || payload_length != fixed + (size_t)text_len) {
        return KSEC_ERR_PROTOCOL;
    }
    if (text_len == 0U || (size_t)text_len > max_length
            || (size_t)text_len >= output_size
            || ksec_validate_text_bytes(payload + fixed, text_len,
                                        max_length) != 0) {
        return KSEC_ERR_INVALID;
    }
    memcpy(output, payload + fixed, text_len);
    output[text_len] = '\0';
    return KSEC_OK;
}

ksec_result ksec_dataset_parse_create_request(const uint8_t *payload,
                                              size_t payload_length,
                                              char label[KSEC_MAX_LABEL + 1U]) {
    return parse_counted_text(payload, payload_length, 0U, KSEC_MAX_LABEL,
                              label, KSEC_MAX_LABEL + 1U);
}

ksec_result ksec_dataset_parse_seal_request(
        const uint8_t *payload, size_t payload_length,
        uint8_t record_id[KSEC_RECORD_ID_BYTES], uint64_t *revision,
        char name[KSEC_MAX_DATASET_NAME + 1U]) {
    ksec_result result;
    if (payload == NULL || record_id == NULL || revision == NULL || name == NULL) {
        return KSEC_ERR_PROTOCOL;
    }
    sodium_memzero(record_id, KSEC_RECORD_ID_BYTES);
    *revision = 0U;
    name[0] = '\0';
    if (payload_length < KSEC_RECORD_ID_BYTES + 8U + 2U) return KSEC_ERR_PROTOCOL;
    result = parse_counted_text(payload, payload_length,
                                KSEC_RECORD_ID_BYTES + 8U,
                                KSEC_MAX_DATASET_NAME, name,
                                KSEC_MAX_DATASET_NAME + 1U);
    if (result != KSEC_OK) return result;
    memcpy(record_id, payload, KSEC_RECORD_ID_BYTES);
    *revision = ksec_get_u64(payload + KSEC_RECORD_ID_BYTES);
    return KSEC_OK;
}

ksec_result ksec_dataset_parse_unseal_request(
        const uint8_t *payload, size_t payload_length,
        uint8_t record_id[KSEC_RECORD_ID_BYTES],
        char name[KSEC_MAX_DATASET_NAME + 1U]) {
    ksec_result result;
    if (payload == NULL || record_id == NULL || name == NULL) {
        return KSEC_ERR_PROTOCOL;
    }
    sodium_memzero(record_id, KSEC_RECORD_ID_BYTES);
    name[0] = '\0';
    if (payload_length < KSEC_RECORD_ID_BYTES + 2U) return KSEC_ERR_PROTOCOL;
    result = parse_counted_text(payload, payload_length, KSEC_RECORD_ID_BYTES,
                                KSEC_MAX_DATASET_NAME, name,
                                KSEC_MAX_DATASET_NAME + 1U);
    if (result != KSEC_OK) return result;
    memcpy(record_id, payload, KSEC_RECORD_ID_BYTES);
    return KSEC_OK;
}

ksec_result ksec_validate_dataset_key_record(const ksec_owned_record *record) {
    if (record == NULL || record->deleted
            || record->object_type != KSEC_OBJECT_DATASET_KEY
            || record->expires_at != 0U
            || record->field_count != 1U
            || record->grant_count != 0U
            || ksec_validate_app_id(record->owner) != 0
            || strcmp(record->type, KSEC_DATASET_KEY_TYPE) != 0
            || ksec_validate_name(record->label, KSEC_MAX_LABEL) != 0
            || strcmp(record->fields[0].name, KSEC_DATASET_KEY_FIELD) != 0
            || record->fields[0].value.data == NULL
            || record->fields[0].value.len != KSEC_DATASET_KEY_BYTES) {
        return KSEC_ERR_INVALID;
    }
    return KSEC_OK;
}
