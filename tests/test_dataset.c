/* Dataset format, seal/unseal, request parsers and object type 4. */
#include "internal.h"

#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static unsigned int checks_run;
static unsigned int checks_failed;

static void check_condition(int condition, const char *expression,
                            const char *file, int line) {
    checks_run++;
    if (!condition) {
        checks_failed++;
        fprintf(stderr, "FAIL %s:%d: %s\n", file, line, expression);
    }
}

#define CHECK(expression) \
    check_condition((expression) ? 1 : 0, #expression, __FILE__, __LINE__)

static void expect_result(ksec_result result, ksec_result want,
                          const char *scenario) {
    checks_run++;
    if (result == want) return;
    checks_failed++;
    if (result == KSEC_OK) {
        fprintf(stderr, "FAIL %s: unseal returned OK\n", scenario);
        return;
    }
    fprintf(stderr, "FAIL %s: got %s\n", scenario, ksec_result_string(result));
}

static void expect_not_ok(ksec_result result, const char *scenario) {
    checks_run++;
    if (result == KSEC_OK) {
        checks_failed++;
        fprintf(stderr, "FAIL %s: unseal returned OK\n", scenario);
    }
}

static void fill_sequence(uint8_t *bytes, size_t length, uint8_t first) {
    size_t index;
    for (index = 0U; index < length; index++) {
        bytes[index] = (uint8_t)(first + (uint8_t)index);
    }
}

static uint8_t pattern_byte(uint64_t index) {
    return (uint8_t)((index * UINT64_C(131) + UINT64_C(17)) & UINT64_C(0xff));
}

/* 92 + n + m + L + 17*k, with k = 1 when L is 0 and otherwise ceil(L/65536). */
static uint64_t sealed_formula(uint64_t length, size_t owner_len,
                               size_t name_len) {
    uint64_t chunks = length == 0U
        ? 1U
        : (length + UINT64_C(65535)) / UINT64_C(65536);
    return UINT64_C(92) + (uint64_t)owner_len + (uint64_t)name_len + length
        + UINT64_C(17) * chunks;
}

static int is_fill(const void *data, size_t length, uint8_t byte) {
    const uint8_t *bytes = data;
    size_t index;
    for (index = 0U; index < length; index++) {
        if (bytes[index] != byte) return 0;
    }
    return 1;
}

static int rewrite_fd(int fd, const uint8_t *data, size_t length) {
    if (ftruncate(fd, 0) != 0 || lseek(fd, 0, SEEK_SET) < 0) return -1;
    if (length > 0U && ksec_write_all(fd, data, length) != 0) return -1;
    return lseek(fd, 0, SEEK_SET) < 0 ? -1 : 0;
}

static int write_pattern(int fd, uint64_t length) {
    uint8_t block[4096];
    uint64_t offset = 0U;
    if (rewrite_fd(fd, NULL, 0U) != 0) return -1;
    while (offset < length) {
        size_t count = sizeof block;
        size_t index;
        if ((uint64_t)count > length - offset) count = (size_t)(length - offset);
        for (index = 0U; index < count; index++) {
            block[index] = pattern_byte(offset + (uint64_t)index);
        }
        if (ksec_write_all(fd, block, count) != 0) return -1;
        offset += (uint64_t)count;
    }
    sodium_memzero(block, sizeof block);
    return 0;
}

static int write_byte(int fd, uint64_t length, uint8_t byte) {
    uint8_t block[4096];
    uint64_t offset = 0U;
    if (rewrite_fd(fd, NULL, 0U) != 0) return -1;
    memset(block, byte, sizeof block);
    while (offset < length) {
        size_t count = sizeof block;
        if ((uint64_t)count > length - offset) count = (size_t)(length - offset);
        if (ksec_write_all(fd, block, count) != 0) return -1;
        offset += (uint64_t)count;
    }
    return 0;
}

static int output_matches(int fd, uint64_t length) {
    uint8_t block[4096];
    uint64_t offset = 0U;
    struct stat status;
    if (fstat(fd, &status) != 0 || status.st_size < 0
            || (uint64_t)status.st_size != length) {
        return 0;
    }
    while (offset < length) {
        size_t count = sizeof block;
        size_t index;
        ssize_t got;
        if ((uint64_t)count > length - offset) count = (size_t)(length - offset);
        got = pread(fd, block, count, (off_t)offset);
        if (got < 0 || (size_t)got != count) return 0;
        for (index = 0U; index < count; index++) {
            if (block[index] != pattern_byte(offset + (uint64_t)index)) return 0;
        }
        offset += (uint64_t)count;
    }
    return 1;
}

static int hash_fd(int fd, uint64_t length, uint8_t digest[32]) {
    crypto_hash_sha256_state hasher;
    uint8_t block[4096];
    uint64_t offset = 0U;
    struct stat status;
    if (fstat(fd, &status) != 0 || status.st_size < 0
            || (uint64_t)status.st_size != length) {
        return -1;
    }
    crypto_hash_sha256_init(&hasher);
    while (offset < length) {
        size_t count = sizeof block;
        ssize_t got;
        if ((uint64_t)count > length - offset) count = (size_t)(length - offset);
        got = pread(fd, block, count, (off_t)offset);
        if (got < 0 || (size_t)got != count) return -1;
        crypto_hash_sha256_update(&hasher, block, count);
        offset += (uint64_t)count;
    }
    crypto_hash_sha256_final(&hasher, digest);
    sodium_memzero(block, sizeof block);
    sodium_memzero(&hasher, sizeof hasher);
    return 0;
}

static void hash_pattern(uint64_t length, uint8_t digest[32]) {
    crypto_hash_sha256_state hasher;
    uint8_t block[4096];
    uint64_t offset = 0U;
    crypto_hash_sha256_init(&hasher);
    while (offset < length) {
        size_t count = sizeof block;
        size_t index;
        if ((uint64_t)count > length - offset) count = (size_t)(length - offset);
        for (index = 0U; index < count; index++) {
            block[index] = pattern_byte(offset + (uint64_t)index);
        }
        crypto_hash_sha256_update(&hasher, block, count);
        offset += (uint64_t)count;
    }
    crypto_hash_sha256_final(&hasher, digest);
    sodium_memzero(block, sizeof block);
    sodium_memzero(&hasher, sizeof hasher);
}

static int memfd_new(void) {
    return memfd_create("ksec-dataset-test", MFD_CLOEXEC);
}

static int slurp_fd(int fd, uint8_t **out, size_t *out_len) {
    struct stat status;
    uint8_t *buffer;
    ssize_t got;
    if (fstat(fd, &status) != 0 || status.st_size < 0) return -1;
    buffer = malloc((size_t)status.st_size + 1U);
    if (buffer == NULL) return -1;
    if (status.st_size > 0) {
        got = pread(fd, buffer, (size_t)status.st_size, 0);
        if (got < 0 || got != status.st_size) {
            free(buffer);
            return -1;
        }
    }
    *out = buffer;
    *out_len = (size_t)status.st_size;
    return 0;
}

static void fill_info(ksec_dataset_header_info *info, uint64_t length,
                      uint64_t revision, const char *owner, const char *name) {
    memset(info, 0, sizeof *info);
    fill_sequence(info->vault_uuid, sizeof info->vault_uuid, 0x10U);
    fill_sequence(info->key_record_id, sizeof info->key_record_id, 0x20U);
    info->revision = revision;
    info->plaintext_length = length;
    memcpy(info->owner, owner, strlen(owner) + 1U);
    memcpy(info->name, name, strlen(name) + 1U);
}

static void expect_info(const ksec_dataset_header_info *info,
                        const ksec_dataset_header_info *want) {
    CHECK(sodium_memcmp(info->vault_uuid, want->vault_uuid,
                        sizeof info->vault_uuid) == 0);
    CHECK(sodium_memcmp(info->key_record_id, want->key_record_id,
                        sizeof info->key_record_id) == 0);
    CHECK(info->revision == want->revision);
    CHECK(info->plaintext_length == want->plaintext_length);
    CHECK(strcmp(info->owner, want->owner) == 0);
    CHECK(strcmp(info->name, want->name) == 0);
}

static void round_trip(const uint8_t key[KSEC_DATASET_KEY_BYTES],
                       uint64_t length, uint64_t revision,
                       const char *owner, const char *name) {
    ksec_dataset_header_info info;
    ksec_dataset_header_info parsed;
    ksec_dataset_header_info actual;
    uint8_t prefix[KSEC_DATASET_PREFIX_FIXED_BYTES + KSEC_MAX_APP_ID
                   + KSEC_MAX_DATASET_NAME];
    uint8_t head[512];
    struct stat status;
    size_t prefix_len = 0U;
    uint64_t sealed_len = 0U;
    uint64_t formula;
    ssize_t got;
    int plain_fd = -1;
    int sealed_fd = -1;
    int out_fd = -1;
    fill_info(&info, length, revision, owner, name);
    formula = sealed_formula(length, strlen(owner), strlen(name));
    plain_fd = memfd_new();
    sealed_fd = memfd_new();
    out_fd = memfd_new();
    CHECK(plain_fd >= 0 && sealed_fd >= 0 && out_fd >= 0);
    if (plain_fd < 0 || sealed_fd < 0 || out_fd < 0) goto out;
    CHECK(ksec_dataset_encode_prefix(&info, prefix, sizeof prefix, &prefix_len)
          == KSEC_OK);
    CHECK(prefix_len == 68U + strlen(owner) + strlen(name));
    CHECK(ksec_dataset_sealed_length(length, prefix_len, &sealed_len) == KSEC_OK);
    CHECK(sealed_len == formula);
    CHECK(write_pattern(plain_fd, length) == 0);
    CHECK(ksec_dataset_seal(key, &info, plain_fd, sealed_fd) == KSEC_OK);
    CHECK(fstat(sealed_fd, &status) == 0);
    CHECK(status.st_size >= 0 && (uint64_t)status.st_size == formula);
    got = pread(sealed_fd, head, sizeof head, 0);
    CHECK(got >= (ssize_t)(prefix_len + 24U));
    if (got >= (ssize_t)(prefix_len + 24U)) {
        CHECK(ksec_dataset_parse_prefix(head, (size_t)got, &parsed, &prefix_len)
              == KSEC_OK);
        expect_info(&parsed, &info);
    }
    memset(&actual, 0, sizeof actual);
    CHECK(rewrite_fd(out_fd, NULL, 0U) == 0);
    CHECK(ksec_dataset_unseal(key, &info, sealed_fd, out_fd, &actual) == KSEC_OK);
    expect_info(&actual, &info);
    CHECK(output_matches(out_fd, length));
out:
    if (plain_fd >= 0) close(plain_fd);
    if (sealed_fd >= 0) close(sealed_fd);
    if (out_fd >= 0) close(out_fd);
    sodium_memzero(prefix, sizeof prefix);
    sodium_memzero(head, sizeof head);
    sodium_memzero(&info, sizeof info);
    sodium_memzero(&parsed, sizeof parsed);
    sodium_memzero(&actual, sizeof actual);
}

static void test_lengths_and_round_trips(void) {
    static const uint64_t lengths[] = {
        0U, 1U, 65535U, 65536U, 65537U, 196608U, 1048583U
    };
    uint8_t key[KSEC_DATASET_KEY_BYTES];
    char long_owner[KSEC_MAX_APP_ID + 1U];
    char long_name[KSEC_MAX_DATASET_NAME + 1U];
    ksec_dataset_header_info info;
    uint8_t prefix[8];
    size_t prefix_len = 0U;
    uint64_t sealed_len = 0U;
    uint64_t over = (uint64_t)KSEC_MAX_DATASET_BYTES + 1U;
    size_t index;
    int pipes[2] = {-1, -1};
    int plain_fd = -1;
    int sealed_fd = -1;
    int out_fd = -1;
    fill_sequence(key, sizeof key, 0xa0U);
    for (index = 0U; index < sizeof lengths / sizeof lengths[0]; index++) {
        round_trip(key, lengths[index], lengths[index] == 0U ? 0U : 1U,
                   "kilix-secrets.test", "ledger");
    }
    memset(long_owner, 'a', KSEC_MAX_APP_ID);
    long_owner[KSEC_MAX_APP_ID] = '\0';
    memset(long_name, 'b', KSEC_MAX_DATASET_NAME);
    long_name[KSEC_MAX_DATASET_NAME] = '\0';
    round_trip(key, 1U, 0U, long_owner, long_name);

    fill_info(&info, KSEC_MAX_DATASET_BYTES, 1U, "a", "b");
    CHECK(ksec_dataset_encode_prefix(&info, prefix, sizeof prefix, &prefix_len)
          == KSEC_ERR_LIMIT);
    CHECK(ksec_dataset_encode_prefix(&info, NULL, 0U, &prefix_len)
          == KSEC_ERR_INVALID);
    {
        uint8_t full[KSEC_DATASET_PREFIX_FIXED_BYTES + 2U];
        CHECK(ksec_dataset_encode_prefix(&info, full, sizeof full, &prefix_len)
              == KSEC_OK);
        CHECK(prefix_len == 70U);
        CHECK(ksec_dataset_sealed_length(KSEC_MAX_DATASET_BYTES, prefix_len,
                                        &sealed_len) == KSEC_OK);
        CHECK(sealed_len == sealed_formula(KSEC_MAX_DATASET_BYTES, 1U, 1U));
        sodium_memzero(full, sizeof full);
    }
    info.plaintext_length = over;
    CHECK(ksec_dataset_encode_prefix(&info, prefix, sizeof prefix, &prefix_len)
          == KSEC_ERR_INVALID);
    CHECK(ksec_dataset_sealed_length(over, 70U, &sealed_len) == KSEC_ERR_INVALID);
    CHECK(ksec_dataset_sealed_length(0U, 69U, &sealed_len) == KSEC_ERR_INVALID);
    CHECK(ksec_dataset_sealed_length(0U, 261U, &sealed_len) == KSEC_ERR_INVALID);
    CHECK(ksec_dataset_sealed_length(1U, 70U, &sealed_len) == KSEC_OK);
    CHECK(ksec_dataset_sealed_length(1U, 260U, &sealed_len) == KSEC_OK);
    memcpy(info.owner, "Bad", sizeof "Bad");
    info.plaintext_length = 1U;
    CHECK(ksec_dataset_encode_prefix(&info, prefix, sizeof prefix, &prefix_len)
          == KSEC_ERR_INVALID);

    fill_info(&info, 0U, 1U, "kilix-secrets.test", "ledger");
    CHECK(pipe(pipes) == 0);
    plain_fd = memfd_new();
    sealed_fd = memfd_new();
    out_fd = memfd_new();
    CHECK(plain_fd >= 0 && sealed_fd >= 0 && out_fd >= 0);
    if (pipes[0] >= 0) {
        CHECK(ksec_dataset_seal(key, &info, pipes[0], sealed_fd)
              == KSEC_ERR_INVALID);
        CHECK(ksec_dataset_unseal(key, &info, pipes[0], out_fd, &info)
              == KSEC_ERR_INVALID);
    }
    CHECK(ksec_dataset_seal(NULL, &info, plain_fd, sealed_fd) == KSEC_ERR_INVALID);
    CHECK(ksec_dataset_unseal(key, NULL, sealed_fd, out_fd, &info)
          == KSEC_ERR_INVALID);
    if (pipes[0] >= 0) close(pipes[0]);
    if (pipes[1] >= 0) close(pipes[1]);
    if (plain_fd >= 0) close(plain_fd);
    if (sealed_fd >= 0) close(sealed_fd);
    if (out_fd >= 0) close(out_fd);
    sodium_memzero(key, sizeof key);
    sodium_memzero(&info, sizeof info);
}

static int seal_to_buffer(const uint8_t key[KSEC_DATASET_KEY_BYTES],
                          const ksec_dataset_header_info *info,
                          int (*write_plain)(int fd, uint64_t length),
                          uint8_t **out, size_t *out_len) {
    int plain_fd = memfd_new();
    int sealed_fd = memfd_new();
    int result = -1;
    if (plain_fd < 0 || sealed_fd < 0) goto out;
    if (write_plain(plain_fd, info->plaintext_length) != 0) goto out;
    if (ksec_dataset_seal(key, info, plain_fd, sealed_fd) != KSEC_OK) goto out;
    if (slurp_fd(sealed_fd, out, out_len) != 0) goto out;
    result = 0;
out:
    if (plain_fd >= 0) close(plain_fd);
    if (sealed_fd >= 0) close(sealed_fd);
    return result;
}

static int write_pattern_cb(int fd, uint64_t length) {
    return write_pattern(fd, length);
}

static int write_two_chunk(int fd, const uint8_t stream_key[KSEC_DATASET_KEY_BYTES],
                           const ksec_dataset_header_info *info,
                           unsigned char first_tag, unsigned char second_tag) {
    uint8_t prefix[320];
    uint8_t header[KSEC_DATASET_STREAM_HEADER_BYTES];
    crypto_secretstream_xchacha20poly1305_state state;
    ksec_secure_buffer plain = {0};
    ksec_secure_buffer cipher = {0};
    size_t prefix_len = 0U;
    unsigned long long cipher_len = 0U;
    int result = -1;
    memset(&state, 0, sizeof state);
    if (ksec_dataset_encode_prefix(info, prefix, sizeof prefix, &prefix_len)
            != KSEC_OK) {
        return -1;
    }
    if (ksec_secure_alloc(&plain, KSEC_DATASET_CHUNK_BYTES) != KSEC_OK
            || ksec_secure_alloc(&cipher, KSEC_DATASET_CHUNK_BYTES + 17U)
                != KSEC_OK) {
        goto out;
    }
    memset(plain.data, 0x11, plain.len);
    if (crypto_secretstream_xchacha20poly1305_init_push(
            &state, header, stream_key) != 0) {
        goto out;
    }
    if (ksec_write_all(fd, prefix, prefix_len) != 0
            || ksec_write_all(fd, header, sizeof header) != 0) {
        goto out;
    }
    if (crypto_secretstream_xchacha20poly1305_push(
            &state, cipher.data, &cipher_len, plain.data, 65536ULL,
            prefix, (unsigned long long)prefix_len, first_tag) != 0
            || cipher_len != 65553ULL
            || ksec_write_all(fd, cipher.data, (size_t)cipher_len) != 0) {
        goto out;
    }
    if (crypto_secretstream_xchacha20poly1305_push(
            &state, cipher.data, &cipher_len, plain.data, 1ULL,
            prefix, (unsigned long long)prefix_len, second_tag) != 0
            || cipher_len != 18ULL
            || ksec_write_all(fd, cipher.data, (size_t)cipher_len) != 0) {
        goto out;
    }
    result = 0;
out:
    sodium_memzero(&state, sizeof state);
    sodium_memzero(header, sizeof header);
    sodium_memzero(prefix, sizeof prefix);
    ksec_secure_free(&plain);
    ksec_secure_free(&cipher);
    return result;
}

static void unseal_buffer(const uint8_t key[KSEC_DATASET_KEY_BYTES],
                          const ksec_dataset_header_info *expected,
                          int sealed_fd, int out_fd,
                          const uint8_t *bytes, size_t length,
                          ksec_result want, const char *scenario) {
    ksec_dataset_header_info actual;
    memset(&actual, 0x5a, sizeof actual);
    CHECK(rewrite_fd(sealed_fd, bytes, length) == 0);
    CHECK(rewrite_fd(out_fd, NULL, 0U) == 0);
    if (want == KSEC_OK) {
        CHECK(ksec_dataset_unseal(key, expected, sealed_fd, out_fd, &actual)
              == KSEC_OK);
        return;
    }
    expect_result(ksec_dataset_unseal(key, expected, sealed_fd, out_fd, &actual),
                  want, scenario);
    CHECK(is_fill(&actual, sizeof actual, 0x5aU));
}

static void test_damage(void) {
    uint8_t key[KSEC_DATASET_KEY_BYTES];
    uint8_t other_key[KSEC_DATASET_KEY_BYTES];
    uint8_t stream_key[KSEC_DATASET_KEY_BYTES];
    ksec_dataset_header_info info;
    ksec_dataset_header_info expected;
    uint8_t *small = NULL;
    uint8_t *wide_a = NULL;
    uint8_t *wide_b = NULL;
    uint8_t *extended = NULL;
    size_t small_len = 0U;
    size_t wide_len = 0U;
    size_t other_len = 0U;
    size_t prefix_len = 92U;
    size_t chunk_on_disk = 65536U + 17U;
    size_t offset;
    unsigned int bit;
    int sealed_fd = -1;
    int out_fd = -1;
    int attack_fd = -1;
    int plain_fd = -1;
    char scenario[80];
    fill_sequence(key, sizeof key, 0xa0U);
    fill_sequence(other_key, sizeof other_key, 0x50U);
    fill_info(&info, 100U, 1U, "kilix-secrets.test", "ledger");
    expected = info;
    sealed_fd = memfd_new();
    out_fd = memfd_new();
    attack_fd = memfd_new();
    plain_fd = memfd_new();
    CHECK(sealed_fd >= 0 && out_fd >= 0 && attack_fd >= 0 && plain_fd >= 0);
    CHECK(seal_to_buffer(key, &info, write_pattern_cb, &small, &small_len) == 0);
    CHECK(small_len == sealed_formula(100U, 18U, 6U));
    for (offset = 0U; offset < small_len; offset++) {
        for (bit = 0U; bit < 8U; bit++) {
            ksec_dataset_header_info actual;
            ksec_result result;
            small[offset] = (uint8_t)(small[offset] ^ (uint8_t)(1U << bit));
            snprintf(scenario, sizeof scenario,
                     "flip-bit offset %zu bit %u", offset, bit);
            memset(&actual, 0, sizeof actual);
            CHECK(rewrite_fd(sealed_fd, small, small_len) == 0);
            CHECK(rewrite_fd(out_fd, NULL, 0U) == 0);
            result = ksec_dataset_unseal(key, &expected, sealed_fd, out_fd,
                                         &actual);
            expect_not_ok(result, scenario);
            small[offset] = (uint8_t)(small[offset] ^ (uint8_t)(1U << bit));
        }
    }
    for (offset = 1U; offset <= 40U; offset++) {
        snprintf(scenario, sizeof scenario, "truncate-tail %zu", offset);
        unseal_buffer(key, &expected, sealed_fd, out_fd, small,
                      small_len - offset, KSEC_ERR_INVALID, scenario);
    }
    extended = malloc(small_len + 1U);
    CHECK(extended != NULL);
    if (extended != NULL) {
        memcpy(extended, small, small_len);
        extended[small_len] = 0x5aU;
        unseal_buffer(key, &expected, sealed_fd, out_fd, extended,
                      small_len + 1U, KSEC_ERR_INVALID, "extend-one");
        extended[prefix_len + 24U] ^= 0x01U;
        unseal_buffer(key, &expected, sealed_fd, out_fd, extended,
                      small_len + 1U, KSEC_ERR_INVALID,
                      "order-length-before-decrypt");
        free(extended);
    }
    memcpy(expected.name, "other", sizeof "other");
    unseal_buffer(key, &expected, sealed_fd, out_fd, small, small_len,
                  KSEC_ERR_CONFLICT, "name-mismatch");
    small[prefix_len + 24U] ^= 0x01U;
    unseal_buffer(key, &expected, sealed_fd, out_fd, small, small_len,
                  KSEC_ERR_CONFLICT, "order-name-before-decrypt");
    small[prefix_len + 24U] ^= 0x01U;
    expected = info;
    expected.vault_uuid[0] ^= 0x01U;
    unseal_buffer(key, &expected, sealed_fd, out_fd, small, small_len,
                  KSEC_ERR_CONFLICT, "uuid-mismatch");
    expected = info;
    expected.key_record_id[0] ^= 0x01U;
    unseal_buffer(key, &expected, sealed_fd, out_fd, small, small_len,
                  KSEC_ERR_CONFLICT, "id-mismatch");
    expected = info;
    memcpy(expected.owner, "kilix-secrets.other", sizeof "kilix-secrets.other");
    unseal_buffer(key, &expected, sealed_fd, out_fd, small, small_len,
                  KSEC_ERR_CONFLICT, "owner-mismatch");
    expected = info;
    unseal_buffer(other_key, &expected, sealed_fd, out_fd, small, small_len,
                  KSEC_ERR_CRYPTO, "wrong-key");
    memcpy(expected.name, "other", sizeof "other");
    unseal_buffer(key, &expected, sealed_fd, out_fd, small, 8U,
                  KSEC_ERR_INVALID, "order-parse-before-identity");
    expected = info;

    CHECK(write_pattern(plain_fd, 99U) == 0);
    CHECK(ksec_dataset_seal(key, &info, plain_fd, sealed_fd) == KSEC_ERR_INVALID);
    CHECK(write_pattern(plain_fd, 101U) == 0);
    CHECK(ksec_dataset_seal(key, &info, plain_fd, sealed_fd) == KSEC_ERR_INVALID);

    info.plaintext_length = 65537U;
    CHECK(seal_to_buffer(key, &info, write_pattern_cb, &wide_a, &wide_len) == 0);
    CHECK(wide_len == sealed_formula(65537U, 18U, 6U));
    unseal_buffer(key, &info, sealed_fd, out_fd, wide_a,
                  prefix_len + 24U, KSEC_ERR_INVALID, "truncate-boundary-header");
    unseal_buffer(key, &info, sealed_fd, out_fd, wide_a,
                  prefix_len + 24U + chunk_on_disk, KSEC_ERR_INVALID,
                  "drop-final");
    free(wide_a);
    wide_a = NULL;

    CHECK(crypto_kdf_derive_from_key(
              stream_key, sizeof stream_key,
              (uint64_t)KSEC_DATASET_KDF_SUBKEY_ID,
              KSEC_DATASET_KDF_CONTEXT, key) == 0);
    CHECK(rewrite_fd(attack_fd, NULL, 0U) == 0);
    CHECK(write_two_chunk(attack_fd, stream_key, &info,
                          crypto_secretstream_xchacha20poly1305_TAG_FINAL,
                          crypto_secretstream_xchacha20poly1305_TAG_MESSAGE)
          == 0);
    {
        uint8_t *attack = NULL;
        size_t attack_len = 0U;
        CHECK(slurp_fd(attack_fd, &attack, &attack_len) == 0);
        CHECK(attack_len == sealed_formula(65537U, 18U, 6U));
        unseal_buffer(key, &info, sealed_fd, out_fd, attack, attack_len,
                      KSEC_ERR_CRYPTO, "early-final");
        free(attack);
    }
    CHECK(rewrite_fd(attack_fd, NULL, 0U) == 0);
    CHECK(write_two_chunk(attack_fd, key, &info,
                          crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
                          crypto_secretstream_xchacha20poly1305_TAG_FINAL)
          == 0);
    {
        uint8_t *attack = NULL;
        size_t attack_len = 0U;
        CHECK(slurp_fd(attack_fd, &attack, &attack_len) == 0);
        CHECK(attack_len == sealed_formula(65537U, 18U, 6U));
        unseal_buffer(key, &info, sealed_fd, out_fd, attack, attack_len,
                      KSEC_ERR_CRYPTO, "raw-key");
        free(attack);
    }

    info.plaintext_length = 196608U;
    CHECK(seal_to_buffer(key, &info, write_pattern_cb, &wide_a, &wide_len) == 0);
    {
        int second = memfd_new();
        int plain_b = memfd_new();
        CHECK(second >= 0 && plain_b >= 0);
        CHECK(write_byte(plain_b, info.plaintext_length, 0x22U) == 0);
        CHECK(rewrite_fd(second, NULL, 0U) == 0);
        CHECK(ksec_dataset_seal(key, &info, plain_b, second) == KSEC_OK);
        CHECK(slurp_fd(second, &wide_b, &other_len) == 0);
        if (plain_b >= 0) close(plain_b);
        if (second >= 0) close(second);
    }
    CHECK(wide_len == other_len);
    CHECK(wide_len == sealed_formula(196608U, 18U, 6U));
    {
        size_t middle = prefix_len + 24U + chunk_on_disk;
        CHECK(middle + chunk_on_disk <= wide_len);
        CHECK(memcmp(wide_a + middle, wide_b + middle, chunk_on_disk) != 0);
        unseal_buffer(key, &info, sealed_fd, out_fd, wide_a,
                      prefix_len + 24U, KSEC_ERR_INVALID,
                      "truncate-boundary-0");
        unseal_buffer(key, &info, sealed_fd, out_fd, wide_a,
                      prefix_len + 24U + chunk_on_disk, KSEC_ERR_INVALID,
                      "truncate-boundary-1");
        unseal_buffer(key, &info, sealed_fd, out_fd, wide_a,
                      prefix_len + 24U + 2U * chunk_on_disk, KSEC_ERR_INVALID,
                      "truncate-boundary-2");
        memcpy(wide_a + middle, wide_b + middle, chunk_on_disk);
        unseal_buffer(key, &info, sealed_fd, out_fd, wide_a, wide_len,
                      KSEC_ERR_CRYPTO, "middle-swap");
    }
    free(small);
    free(wide_a);
    free(wide_b);
    if (sealed_fd >= 0) close(sealed_fd);
    if (out_fd >= 0) close(out_fd);
    if (attack_fd >= 0) close(attack_fd);
    if (plain_fd >= 0) close(plain_fd);
    sodium_memzero(key, sizeof key);
    sodium_memzero(other_key, sizeof other_key);
    sodium_memzero(stream_key, sizeof stream_key);
    sodium_memzero(&info, sizeof info);
    sodium_memzero(&expected, sizeof expected);
}

static size_t put_raw_prefix(uint8_t *out, size_t cap, const uint8_t magic[8],
                             uint16_t version, uint16_t stream, uint32_t chunk,
                             uint64_t revision, uint64_t length,
                             const uint8_t *owner, uint16_t owner_len,
                             const uint8_t *name, uint16_t name_len,
                             size_t extra) {
    size_t prefix = 68U + (size_t)owner_len + (size_t)name_len;
    size_t total = prefix + 24U + extra;
    if (total > cap) return 0U;
    memset(out, 0, total);
    memcpy(out, magic, 8U);
    ksec_put_u16(out + 8U, version);
    ksec_put_u16(out + 10U, stream);
    ksec_put_u32(out + 12U, chunk);
    ksec_put_u64(out + 48U, revision);
    ksec_put_u64(out + 56U, length);
    ksec_put_u16(out + 64U, owner_len);
    if (owner_len > 0U) memcpy(out + 66U, owner, owner_len);
    ksec_put_u16(out + 66U + owner_len, name_len);
    if (name_len > 0U) memcpy(out + 68U + owner_len, name, name_len);
    return total;
}

static void expect_parse(const uint8_t *bytes, size_t length, ksec_result want,
                         const char *scenario) {
    ksec_dataset_header_info info;
    size_t prefix_len = 0U;
    memset(&info, 0, sizeof info);
    expect_result(ksec_dataset_parse_prefix(bytes, length, &info, &prefix_len),
                  want, scenario);
}

static void test_header_grammar(void) {
    uint8_t raw[512];
    uint8_t magic[8] = {'K', 'S', 'D', 'S', 'E', 'T', '0', '1'};
    uint8_t owner65[65];
    uint8_t name129[129];
    const uint8_t owner[] = "kilix-secrets.test";
    const uint8_t name[] = "ledger";
    ksec_dataset_header_info info;
    size_t prefix_len = 0U;
    size_t total;
    memset(owner65, 'a', sizeof owner65);
    memset(name129, 'b', sizeof name129);
    total = put_raw_prefix(raw, sizeof raw, magic, 1U, 1U, 65536U, 0U, 0U,
                           owner, 18U, name, 6U, 0U);
    CHECK(total == 92U + 24U);
    CHECK(ksec_dataset_parse_prefix(raw, total, &info, &prefix_len) == KSEC_OK);
    CHECK(prefix_len == 92U);
    CHECK(info.revision == 0U && info.plaintext_length == 0U);
    CHECK(strcmp(info.owner, "kilix-secrets.test") == 0);
    CHECK(strcmp(info.name, "ledger") == 0);
    expect_parse(raw, prefix_len, KSEC_ERR_INVALID, "missing-stream-header");
    expect_parse(raw, prefix_len + 23U, KSEC_ERR_INVALID, "short-stream-header");
    expect_parse(raw, total + 0U, KSEC_OK, "prefix-plus-header");
    raw[total] = 0x11U;
    expect_parse(raw, total + 1U, KSEC_OK, "prefix-plus-header-extra");
    raw[0] ^= 0x01U;
    expect_parse(raw, total + 1U, KSEC_ERR_INVALID, "bad-magic");
    raw[0] ^= 0x01U;
    ksec_put_u16(raw + 8U, 2U);
    expect_parse(raw, total, KSEC_ERR_INVALID, "bad-version");
    ksec_put_u16(raw + 8U, 1U);
    ksec_put_u16(raw + 10U, 2U);
    expect_parse(raw, total, KSEC_ERR_INVALID, "bad-stream-id");
    ksec_put_u16(raw + 10U, 1U);
    ksec_put_u32(raw + 12U, 65535U);
    expect_parse(raw, total, KSEC_ERR_INVALID, "bad-chunk-size");
    ksec_put_u32(raw + 12U, 65536U);
    total = put_raw_prefix(raw, sizeof raw, magic, 1U, 1U, 65536U, 1U,
                           (uint64_t)KSEC_MAX_DATASET_BYTES + 1U,
                           owner, 18U, name, 6U, 0U);
    expect_parse(raw, total, KSEC_ERR_INVALID, "plaintext-over-max");
    total = put_raw_prefix(raw, sizeof raw, magic, 1U, 1U, 65536U, 1U, 0U,
                           owner, 0U, name, 6U, 0U);
    expect_parse(raw, total, KSEC_ERR_INVALID, "owner-length-0");
    total = put_raw_prefix(raw, sizeof raw, magic, 1U, 1U, 65536U, 1U, 0U,
                           owner65, 65U, name, 1U, 0U);
    expect_parse(raw, total, KSEC_ERR_INVALID, "owner-length-65");
    total = put_raw_prefix(raw, sizeof raw, magic, 1U, 1U, 65536U, 1U, 0U,
                           (const uint8_t *)"A", 1U, name, 6U, 0U);
    expect_parse(raw, total, KSEC_ERR_INVALID, "owner-uppercase");
    total = put_raw_prefix(raw, sizeof raw, magic, 1U, 1U, 65536U, 1U, 0U,
                           (const uint8_t *)"a_b", 3U, name, 6U, 0U);
    expect_parse(raw, total, KSEC_ERR_INVALID, "owner-bad-byte");
    total = put_raw_prefix(raw, sizeof raw, magic, 1U, 1U, 65536U, 1U, 0U,
                           owner, 18U, name, 0U, 0U);
    expect_parse(raw, total, KSEC_ERR_INVALID, "name-length-0");
    total = put_raw_prefix(raw, sizeof raw, magic, 1U, 1U, 65536U, 1U, 0U,
                           owner, 1U, name129, 129U, 0U);
    expect_parse(raw, total, KSEC_ERR_INVALID, "name-length-129");
    total = put_raw_prefix(raw, sizeof raw, magic, 1U, 1U, 65536U, 1U, 0U,
                           owner, 18U, (const uint8_t *)"\x01", 1U, 0U);
    expect_parse(raw, total, KSEC_ERR_INVALID, "name-control");
    total = put_raw_prefix(raw, sizeof raw, magic, 1U, 1U, 65536U, 1U, 0U,
                           owner, 18U, (const uint8_t *)"\x7f", 1U, 0U);
    expect_parse(raw, total, KSEC_ERR_INVALID, "name-delete");
    total = put_raw_prefix(raw, sizeof raw, magic, 1U, 1U, 65536U, 1U, 0U,
                           owner, 18U, (const uint8_t *)"\xff", 1U, 0U);
    expect_parse(raw, total, KSEC_ERR_INVALID, "name-invalid-utf8");
    expect_parse(raw, 10U, KSEC_ERR_INVALID, "truncated-prefix");
    expect_parse(NULL, total, KSEC_ERR_INVALID, "null-prefix");
}

/* Framing that does not match the declared body is PROTOCOL.
 * A framed length outside the grammar is INVALID. */
static void test_requests(void) {
    uint8_t buffer[256];
    char label[KSEC_MAX_LABEL + 1U];
    char name[KSEC_MAX_DATASET_NAME + 1U];
    uint8_t record_id[KSEC_RECORD_ID_BYTES];
    uint64_t revision = 1U;
    const uint8_t cafe[] = {0xc3U, 0xa9U};
    const uint8_t overlong[] = {0xc0U, 0xafU};

    expect_result(ksec_dataset_parse_create_request(NULL, 0U, label),
                  KSEC_ERR_PROTOCOL, "create-null");
    expect_result(ksec_dataset_parse_create_request(buffer, 2U, NULL),
                  KSEC_ERR_PROTOCOL, "create-null-out");
    buffer[0] = 0U;
    expect_result(ksec_dataset_parse_create_request(buffer, 1U, label),
                  KSEC_ERR_PROTOCOL, "create-short");
    ksec_put_u16(buffer, 0U);
    expect_result(ksec_dataset_parse_create_request(buffer, 2U, label),
                  KSEC_ERR_INVALID, "create-zero");
    ksec_put_u16(buffer, 2U);
    memcpy(buffer + 2U, "ok", 2U);
    CHECK(ksec_dataset_parse_create_request(buffer, 4U, label) == KSEC_OK);
    CHECK(strcmp(label, "ok") == 0);
    ksec_put_u16(buffer, 4U);
    memcpy(buffer + 2U, "ok", 2U);
    expect_result(ksec_dataset_parse_create_request(buffer, 4U, label),
                  KSEC_ERR_PROTOCOL, "create-declared-mismatch");
    ksec_put_u16(buffer, 1U);
    buffer[2] = 'z';
    buffer[3] = 'z';
    expect_result(ksec_dataset_parse_create_request(buffer, 4U, label),
                  KSEC_ERR_PROTOCOL, "create-trailing");
    ksec_put_u16(buffer, 128U);
    memset(buffer + 2U, 'm', 128U);
    CHECK(ksec_dataset_parse_create_request(buffer, 130U, label) == KSEC_OK);
    CHECK(strlen(label) == 128U);
    ksec_put_u16(buffer, 129U);
    memset(buffer + 2U, 'm', 129U);
    expect_result(ksec_dataset_parse_create_request(buffer, 131U, label),
                  KSEC_ERR_INVALID, "create-too-long");
    ksec_put_u16(buffer, 1U);
    buffer[2] = 0x01U;
    expect_result(ksec_dataset_parse_create_request(buffer, 3U, label),
                  KSEC_ERR_INVALID, "create-control");
    buffer[2] = 0x7fU;
    expect_result(ksec_dataset_parse_create_request(buffer, 3U, label),
                  KSEC_ERR_INVALID, "create-delete");
    ksec_put_u16(buffer, 2U);
    memcpy(buffer + 2U, overlong, sizeof overlong);
    expect_result(ksec_dataset_parse_create_request(buffer, 4U, label),
                  KSEC_ERR_INVALID, "create-overlong");
    memcpy(buffer + 2U, cafe, sizeof cafe);
    CHECK(ksec_dataset_parse_create_request(buffer, 4U, label) == KSEC_OK);
    CHECK((unsigned char)label[0] == 0xc3U && (unsigned char)label[1] == 0xa9U);
    ksec_put_u16(buffer, 3U);
    buffer[2] = 'a';
    buffer[3] = 0U;
    buffer[4] = 'b';
    expect_result(ksec_dataset_parse_create_request(buffer, 5U, label),
                  KSEC_ERR_INVALID, "create-nul");
    ksec_put_u16(buffer, 7U);
    memcpy(buffer + 2U, "led ger", 7U);
    CHECK(ksec_dataset_parse_create_request(buffer, 9U, label) == KSEC_OK);
    CHECK(strcmp(label, "led ger") == 0);

    memset(buffer, 0x21, sizeof buffer);
    expect_result(ksec_dataset_parse_seal_request(NULL, 0U, record_id, &revision,
                                                  name),
                  KSEC_ERR_PROTOCOL, "seal-null");
    expect_result(ksec_dataset_parse_seal_request(buffer, 26U, NULL, &revision,
                                                  name),
                  KSEC_ERR_PROTOCOL, "seal-null-id");
    expect_result(ksec_dataset_parse_seal_request(buffer, 25U, record_id,
                                                  &revision, name),
                  KSEC_ERR_PROTOCOL, "seal-short");
    ksec_put_u64(buffer + 16U, 0U);
    ksec_put_u16(buffer + 24U, 0U);
    expect_result(ksec_dataset_parse_seal_request(buffer, 26U, record_id,
                                                  &revision, name),
                  KSEC_ERR_INVALID, "seal-zero");
    ksec_put_u64(buffer + 16U, UINT64_MAX);
    ksec_put_u16(buffer + 24U, 6U);
    memcpy(buffer + 26U, "ledger", 6U);
    CHECK(ksec_dataset_parse_seal_request(buffer, 32U, record_id, &revision, name)
          == KSEC_OK);
    CHECK(revision == UINT64_MAX);
    CHECK(strcmp(name, "ledger") == 0);
    CHECK(record_id[0] == 0x21U);
    ksec_put_u16(buffer + 24U, 4U);
    expect_result(ksec_dataset_parse_seal_request(buffer, 32U, record_id,
                                                  &revision, name),
                  KSEC_ERR_PROTOCOL, "seal-declared-mismatch");
    ksec_put_u16(buffer + 24U, 6U);
    buffer[32] = 'x';
    expect_result(ksec_dataset_parse_seal_request(buffer, 33U, record_id,
                                                  &revision, name),
                  KSEC_ERR_PROTOCOL, "seal-trailing");
    ksec_put_u16(buffer + 24U, 128U);
    memset(buffer + 26U, 'n', 128U);
    CHECK(ksec_dataset_parse_seal_request(buffer, 154U, record_id, &revision,
                                          name) == KSEC_OK);
    CHECK(strlen(name) == 128U);
    ksec_put_u16(buffer + 24U, 129U);
    memset(buffer + 26U, 'n', 129U);
    expect_result(ksec_dataset_parse_seal_request(buffer, 155U, record_id,
                                                  &revision, name),
                  KSEC_ERR_INVALID, "seal-too-long");
    ksec_put_u64(buffer + 16U, 0U);
    ksec_put_u16(buffer + 24U, 1U);
    buffer[26] = 0x01U;
    expect_result(ksec_dataset_parse_seal_request(buffer, 27U, record_id,
                                                  &revision, name),
                  KSEC_ERR_INVALID, "seal-control");
    ksec_put_u16(buffer + 24U, 2U);
    memcpy(buffer + 26U, overlong, sizeof overlong);
    expect_result(ksec_dataset_parse_seal_request(buffer, 28U, record_id,
                                                  &revision, name),
                  KSEC_ERR_INVALID, "seal-overlong");
    memcpy(buffer + 26U, cafe, sizeof cafe);
    CHECK(ksec_dataset_parse_seal_request(buffer, 28U, record_id, &revision,
                                          name) == KSEC_OK);
    CHECK(revision == 0U);

    expect_result(ksec_dataset_parse_unseal_request(NULL, 0U, record_id, name),
                  KSEC_ERR_PROTOCOL, "unseal-null");
    expect_result(ksec_dataset_parse_unseal_request(buffer, 17U, record_id, name),
                  KSEC_ERR_PROTOCOL, "unseal-short");
    memset(buffer, 0x44, 16U);
    ksec_put_u16(buffer + 16U, 0U);
    expect_result(ksec_dataset_parse_unseal_request(buffer, 18U, record_id, name),
                  KSEC_ERR_INVALID, "unseal-zero");
    ksec_put_u16(buffer + 16U, 6U);
    memcpy(buffer + 18U, "ledger", 6U);
    CHECK(ksec_dataset_parse_unseal_request(buffer, 24U, record_id, name)
          == KSEC_OK);
    CHECK(strcmp(name, "ledger") == 0);
    CHECK(record_id[0] == 0x44U);
    buffer[24] = 'x';
    expect_result(ksec_dataset_parse_unseal_request(buffer, 25U, record_id, name),
                  KSEC_ERR_PROTOCOL, "unseal-trailing");
    ksec_put_u16(buffer + 16U, 5U);
    expect_result(ksec_dataset_parse_unseal_request(buffer, 24U, record_id, name),
                  KSEC_ERR_PROTOCOL, "unseal-declared-mismatch");
    ksec_put_u16(buffer + 16U, 128U);
    memset(buffer + 18U, 'u', 128U);
    CHECK(ksec_dataset_parse_unseal_request(buffer, 146U, record_id, name)
          == KSEC_OK);
    CHECK(strlen(name) == 128U);
    ksec_put_u16(buffer + 16U, 129U);
    memset(buffer + 18U, 'u', 129U);
    expect_result(ksec_dataset_parse_unseal_request(buffer, 147U, record_id,
                                                    name),
                  KSEC_ERR_INVALID, "unseal-too-long");
    ksec_put_u16(buffer + 16U, 1U);
    buffer[18] = 0x7fU;
    expect_result(ksec_dataset_parse_unseal_request(buffer, 19U, record_id, name),
                  KSEC_ERR_INVALID, "unseal-delete");
    ksec_put_u16(buffer + 16U, 2U);
    memcpy(buffer + 18U, overlong, sizeof overlong);
    expect_result(ksec_dataset_parse_unseal_request(buffer, 20U, record_id, name),
                  KSEC_ERR_INVALID, "unseal-overlong");
    sodium_memzero(buffer, sizeof buffer);
    sodium_memzero(record_id, sizeof record_id);
}

static ksec_result build_key_record(ksec_owned_record *owned, const char *type,
                                   const char *label, uint64_t expires,
                                   const ksec_field *fields, size_t field_count,
                                   const ksec_grant *grants, size_t grant_count) {
    ksec_record record;
    uint8_t encoded[2048];
    size_t encoded_len = 0U;
    ksec_result result;
    memset(&record, 0, sizeof record);
    record.owner = "kilix-secrets.test";
    record.type = type;
    record.label = label;
    record.expires_at = expires;
    record.fields = fields;
    record.field_count = field_count;
    record.grants = grants;
    record.grant_count = grant_count;
    result = ksec_record_serialize(&record, encoded, sizeof encoded, &encoded_len);
    if (result != KSEC_OK) {
        sodium_memzero(encoded, sizeof encoded);
        return result;
    }
    result = ksec_record_parse(encoded, encoded_len, owned);
    sodium_memzero(encoded, sizeof encoded);
    if (result != KSEC_OK) return result;
    memcpy(owned->owner, "kilix-secrets.test", sizeof "kilix-secrets.test");
    owned->object_type = KSEC_OBJECT_DATASET_KEY;
    fill_sequence(owned->id, sizeof owned->id, 0x30U);
    return KSEC_OK;
}

static void test_validate(void) {
    uint8_t key[KSEC_DATASET_KEY_BYTES];
    uint8_t short_key[31];
    uint8_t long_key[33];
    uint8_t extra_value[1] = {0x01U};
    ksec_owned_record owned;
    ksec_field fields[2];
    ksec_field one;
    ksec_grant grant;
    uint8_t *saved;
    fill_sequence(key, sizeof key, 0xa0U);
    memset(short_key, 0x11, sizeof short_key);
    memset(long_key, 0x22, sizeof long_key);
    memset(&owned, 0, sizeof owned);
    one.name = KSEC_DATASET_KEY_FIELD;
    one.value = key;
    one.value_len = sizeof key;
    CHECK(build_key_record(&owned, KSEC_DATASET_KEY_TYPE, "ledger", 0U,
                           &one, 1U, NULL, 0U) == KSEC_OK);
    CHECK(owned.revision == 0U);
    CHECK(ksec_validate_dataset_key_record(&owned) == KSEC_OK);
    owned.object_type = KSEC_OBJECT_SECRET;
    CHECK(ksec_validate_dataset_key_record(&owned) == KSEC_ERR_INVALID);
    owned.object_type = 5U;
    CHECK(ksec_validate_dataset_key_record(&owned) == KSEC_ERR_INVALID);
    owned.object_type = KSEC_OBJECT_DATASET_KEY;
    owned.deleted = true;
    CHECK(ksec_validate_dataset_key_record(&owned) == KSEC_ERR_INVALID);
    owned.deleted = false;
    memcpy(owned.owner, "BAD", sizeof "BAD");
    CHECK(ksec_validate_dataset_key_record(&owned) == KSEC_ERR_INVALID);
    memcpy(owned.owner, "kilix-secrets.test", sizeof "kilix-secrets.test");
    memcpy(owned.label, "bad\x01", sizeof "bad\x01");
    CHECK(ksec_validate_dataset_key_record(&owned) == KSEC_ERR_INVALID);
    saved = owned.fields[0].value.data;
    owned.fields[0].value.data = NULL;
    CHECK(ksec_validate_dataset_key_record(&owned) == KSEC_ERR_INVALID);
    owned.fields[0].value.data = saved;
    owned.grant_count = 1U;
    memcpy(owned.grants[0].application_id, "kilix-secrets.peer",
           sizeof "kilix-secrets.peer");
    owned.grants[0].verbs = KSEC_VERB_READ;
    CHECK(ksec_validate_dataset_key_record(&owned) == KSEC_ERR_INVALID);
    owned.grant_count = 0U;
    memcpy(owned.label, "ledger", sizeof "ledger");
    CHECK(ksec_validate_dataset_key_record(&owned) == KSEC_OK);
    ksec_owned_record_clear(&owned);
    CHECK(ksec_validate_dataset_key_record(NULL) == KSEC_ERR_INVALID);

    one.name = "value";
    CHECK(build_key_record(&owned, KSEC_DATASET_KEY_TYPE, "ledger", 0U,
                           &one, 1U, NULL, 0U) == KSEC_OK);
    CHECK(ksec_validate_dataset_key_record(&owned) == KSEC_ERR_INVALID);
    ksec_owned_record_clear(&owned);
    one.name = KSEC_DATASET_KEY_FIELD;
    CHECK(build_key_record(&owned, "opaque", "ledger", 0U, &one, 1U, NULL, 0U)
          == KSEC_OK);
    CHECK(ksec_validate_dataset_key_record(&owned) == KSEC_ERR_INVALID);
    ksec_owned_record_clear(&owned);
    CHECK(build_key_record(&owned, KSEC_DATASET_KEY_TYPE, "ledger", 1U,
                           &one, 1U, NULL, 0U) == KSEC_OK);
    CHECK(ksec_validate_dataset_key_record(&owned) == KSEC_ERR_INVALID);
    ksec_owned_record_clear(&owned);
    one.value = short_key;
    one.value_len = sizeof short_key;
    CHECK(build_key_record(&owned, KSEC_DATASET_KEY_TYPE, "ledger", 0U,
                           &one, 1U, NULL, 0U) == KSEC_OK);
    CHECK(ksec_validate_dataset_key_record(&owned) == KSEC_ERR_INVALID);
    ksec_owned_record_clear(&owned);
    one.value = long_key;
    one.value_len = sizeof long_key;
    CHECK(build_key_record(&owned, KSEC_DATASET_KEY_TYPE, "ledger", 0U,
                           &one, 1U, NULL, 0U) == KSEC_OK);
    CHECK(ksec_validate_dataset_key_record(&owned) == KSEC_ERR_INVALID);
    ksec_owned_record_clear(&owned);
    one.value = key;
    one.value_len = sizeof key;
    fields[0] = one;
    fields[1].name = "extra";
    fields[1].value = extra_value;
    fields[1].value_len = sizeof extra_value;
    CHECK(build_key_record(&owned, KSEC_DATASET_KEY_TYPE, "ledger", 0U,
                           fields, 2U, NULL, 0U) == KSEC_OK);
    CHECK(ksec_validate_dataset_key_record(&owned) == KSEC_ERR_INVALID);
    ksec_owned_record_clear(&owned);
    grant.application_id = "kilix-secrets.peer";
    grant.verbs = KSEC_VERB_READ;
    CHECK(build_key_record(&owned, KSEC_DATASET_KEY_TYPE, "ledger", 0U,
                           &one, 1U, &grant, 1U) == KSEC_OK);
    CHECK(ksec_validate_dataset_key_record(&owned) == KSEC_ERR_INVALID);
    ksec_owned_record_clear(&owned);
    CHECK(build_key_record(&owned, KSEC_DATASET_KEY_TYPE, "caf\xc3\xa9", 0U,
                           &one, 1U, NULL, 0U) == KSEC_OK);
    CHECK(ksec_validate_dataset_key_record(&owned) == KSEC_OK);
    ksec_owned_record_clear(&owned);
    sodium_memzero(key, sizeof key);
}

static void test_object_type_gate(void) {
    uint8_t ad[128];
    uint8_t uuid[KSEC_UUID_BYTES];
    uint8_t object_id[KSEC_RECORD_ID_BYTES];
    uint8_t parsed_uuid[KSEC_UUID_BYTES];
    uint8_t parsed_id[KSEC_RECORD_ID_BYTES];
    char owner[KSEC_MAX_APP_ID + 1U];
    uint16_t object_type = 0U;
    uint64_t revision = 0U;
    uint32_t plaintext_length = 0U;
    size_t ad_len = 0U;
    ksec_result formatted;
    ksec_result parsed;
    fill_sequence(uuid, sizeof uuid, 0x10U);
    fill_sequence(object_id, sizeof object_id, 0x20U);
    CHECK(ksec_format_record_ad(KSEC_OBJECT_SECRET, uuid, object_id, 1U, 32U,
                                "kilix-secrets.test", ad, sizeof ad, &ad_len)
          == KSEC_OK);
    CHECK(ksec_format_record_ad(KSEC_OBJECT_DATASET_KEY, uuid, object_id, 1U,
                                32U, "kilix-secrets.test", ad, sizeof ad, &ad_len)
          == KSEC_OK);
    CHECK(ad_len > 12U && ad[10] == 0U && ad[11] == KSEC_OBJECT_DATASET_KEY);
    CHECK(ksec_parse_record_ad(ad, ad_len, &object_type, parsed_uuid, parsed_id,
                               &revision, &plaintext_length, owner) == KSEC_OK);
    CHECK(object_type == KSEC_OBJECT_DATASET_KEY);
    CHECK(revision == 1U && plaintext_length == 32U);
    CHECK(strcmp(owner, "kilix-secrets.test") == 0);
    CHECK(ksec_format_record_ad(0U, uuid, object_id, 1U, 32U,
                                "kilix-secrets.test", ad, sizeof ad, &ad_len)
          == KSEC_ERR_INVALID);
    CHECK(ksec_format_record_ad(6U, uuid, object_id, 1U, 32U,
                                "kilix-secrets.test", ad, sizeof ad, &ad_len)
          == KSEC_ERR_INVALID);
    formatted = ksec_format_record_ad(5U, uuid, object_id, 1U, 32U,
                                      "kilix-secrets.test", ad, sizeof ad,
                                      &ad_len);
    CHECK(ksec_format_record_ad(KSEC_OBJECT_DATASET_KEY, uuid, object_id, 1U,
                                32U, "kilix-secrets.test", ad, sizeof ad, &ad_len)
          == KSEC_OK);
    ad[11] = 5U;
    parsed = ksec_parse_record_ad(ad, ad_len, &object_type, parsed_uuid, parsed_id,
                                  &revision, &plaintext_length, owner);
    checks_run++;
    if (formatted != KSEC_ERR_INVALID || parsed == KSEC_OK) {
        checks_failed++;
        fprintf(stderr, "FAIL object-type-5: accepted\n");
    }
}

static const char *expected_plaintext_sha(uint64_t length) {
    if (length == 0U) {
        return "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    }
    if (length == 100U) {
        return "3083a7bd9018ee33c186d0c31e4f8a4564efc5b60eefd256cb020a02c548846c";
    }
    if (length == 65537U) {
        return "65d80b2b0f0120bda1628b3749982090e058d2d9f4a5fad1bc70250b49bc4e96";
    }
    return NULL;
}

static int decode_hex_alloc(const char *hex, uint8_t **out, size_t *out_len) {
    size_t hex_len = strlen(hex);
    uint8_t *decoded;
    if (hex_len == 0U || (hex_len & 1U) != 0U) return -1;
    decoded = malloc(hex_len / 2U);
    if (decoded == NULL) return -1;
    if (ksec_hex_decode(hex, decoded, hex_len / 2U) != 0) {
        free(decoded);
        return -1;
    }
    *out = decoded;
    *out_len = hex_len / 2U;
    return 0;
}

static int copy_token(char *dest, size_t dest_size, const char *value) {
    size_t length = strlen(value);
    if (length + 1U > dest_size) return -1;
    memcpy(dest, value, length + 1U);
    return 0;
}

static void test_vectors(void) {
    static const char key_hex[] =
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf";
    static const char stream_hex[] =
        "e9c4b9e444407d435781d874d40d3aba0fcaacecc26c5c58ad5ee2f32b066523";
    static const char uuid_hex[] = "101112131415161718191a1b1c1d1e1f";
    static const char id_hex[] = "202122232425262728292a2b2c2d2e2f";
    struct vector_case {
        uint64_t length;
        int saw_length;
        int saw_sha;
        uint8_t *prefix;
        size_t prefix_len;
        uint8_t *sealed;
        size_t sealed_len;
    } cases[3];
    char file_key[80];
    char file_stream[80];
    char file_uuid[80];
    char file_id[80];
    char file_owner[80];
    char file_name[160];
    char file_revision[32];
    char file_format[80];
    char file_provider[80];
    char file_kdf[80];
    char file_subkey[32];
    char file_chunk[32];
    char derived_hex[65];
    uint8_t dataset_key[KSEC_DATASET_KEY_BYTES];
    uint8_t stream_key[KSEC_DATASET_KEY_BYTES];
    uint8_t uuid[KSEC_UUID_BYTES];
    uint8_t record_id[KSEC_RECORD_ID_BYTES];
    FILE *file;
    char *line = NULL;
    size_t cap = 0U;
    ssize_t nread;
    int current = -1;
    size_t index;
    memset(cases, 0, sizeof cases);
    file_key[0] = '\0';
    file_stream[0] = '\0';
    file_uuid[0] = '\0';
    file_id[0] = '\0';
    file_owner[0] = '\0';
    file_name[0] = '\0';
    file_revision[0] = '\0';
    file_format[0] = '\0';
    file_provider[0] = '\0';
    file_kdf[0] = '\0';
    file_subkey[0] = '\0';
    file_chunk[0] = '\0';
    file = fopen("tests/vectors/dataset-v1.txt", "r");
    CHECK(file != NULL);
    if (file == NULL) return;
    while ((nread = getline(&line, &cap, file)) != -1) {
        char *key;
        char *value;
        char *split;
        if (nread > 0 && line[nread - 1] == '\n') line[--nread] = '\0';
        split = strchr(line, '=');
        CHECK(split != NULL);
        if (split == NULL) continue;
        *split = '\0';
        key = line;
        value = split + 1;
        if (strcmp(key, "case") == 0) {
            current++;
            CHECK(current >= 0 && current < 3);
            if (current < 0 || current >= 3) break;
            if (strcmp(value, "L0") == 0) cases[current].length = 0U;
            else if (strcmp(value, "L100") == 0) cases[current].length = 100U;
            else if (strcmp(value, "L65537") == 0) cases[current].length = 65537U;
            else CHECK(0);
            continue;
        }
        if (current < 0) {
            int copied = -1;
            if (strcmp(key, "vector_format") == 0) {
                copied = copy_token(file_format, sizeof file_format, value);
            } else if (strcmp(key, "provider") == 0) {
                copied = copy_token(file_provider, sizeof file_provider, value);
            } else if (strcmp(key, "kdf_context") == 0) {
                copied = copy_token(file_kdf, sizeof file_kdf, value);
            } else if (strcmp(key, "kdf_subkey_id") == 0) {
                copied = copy_token(file_subkey, sizeof file_subkey, value);
            } else if (strcmp(key, "chunk_bytes") == 0) {
                copied = copy_token(file_chunk, sizeof file_chunk, value);
            } else if (strcmp(key, "dataset_key") == 0) {
                copied = copy_token(file_key, sizeof file_key, value);
            } else if (strcmp(key, "stream_key") == 0) {
                copied = copy_token(file_stream, sizeof file_stream, value);
            } else if (strcmp(key, "vault_uuid") == 0) {
                copied = copy_token(file_uuid, sizeof file_uuid, value);
            } else if (strcmp(key, "key_record_id") == 0) {
                copied = copy_token(file_id, sizeof file_id, value);
            } else if (strcmp(key, "owner") == 0) {
                copied = copy_token(file_owner, sizeof file_owner, value);
            } else if (strcmp(key, "name") == 0) {
                copied = copy_token(file_name, sizeof file_name, value);
            } else if (strcmp(key, "revision") == 0) {
                copied = copy_token(file_revision, sizeof file_revision, value);
            }
            CHECK(copied == 0);
            continue;
        }
        if (strcmp(key, "plaintext_length") == 0) {
            const char *want_len = "65537";
            if (current == 0) want_len = "0";
            else if (current == 1) want_len = "100";
            CHECK(strcmp(value, want_len) == 0);
            cases[current].saw_length = 1;
        } else if (strcmp(key, "plaintext_sha256") == 0) {
            const char *want = expected_plaintext_sha(cases[current].length);
            CHECK(want != NULL && strcmp(value, want) == 0);
            cases[current].saw_sha = 1;
        } else if (strcmp(key, "prefix_hex") == 0) {
            CHECK(decode_hex_alloc(value, &cases[current].prefix,
                                   &cases[current].prefix_len) == 0);
        } else if (strcmp(key, "sealed_hex") == 0) {
            CHECK(decode_hex_alloc(value, &cases[current].sealed,
                                   &cases[current].sealed_len) == 0);
        } else {
            CHECK(0);
        }
    }
    fclose(file);
    free(line);
    CHECK(current == 2);
    CHECK(strcmp(file_format, "KSEC-DATASET-V1") == 0);
    CHECK(strcmp(file_provider, "libsodium-1.0.18-1+deb13u1") == 0);
    CHECK(strcmp(file_kdf, "KSDSET01") == 0);
    CHECK(strcmp(file_subkey, "1") == 0);
    CHECK(strcmp(file_chunk, "65536") == 0);
    CHECK(strcmp(file_key, key_hex) == 0);
    CHECK(strcmp(file_stream, stream_hex) == 0);
    CHECK(strcmp(file_uuid, uuid_hex) == 0);
    CHECK(strcmp(file_id, id_hex) == 0);
    CHECK(strcmp(file_owner, "kilix-secrets.test") == 0);
    CHECK(strcmp(file_name, "ledger") == 0);
    CHECK(strcmp(file_revision, "1") == 0);
    CHECK(ksec_hex_decode(key_hex, dataset_key, sizeof dataset_key) == 0);
    CHECK(ksec_hex_decode(uuid_hex, uuid, sizeof uuid) == 0);
    CHECK(ksec_hex_decode(id_hex, record_id, sizeof record_id) == 0);
    CHECK(crypto_kdf_derive_from_key(
              stream_key, sizeof stream_key,
              (uint64_t)KSEC_DATASET_KDF_SUBKEY_ID,
              KSEC_DATASET_KDF_CONTEXT, dataset_key) == 0);
    ksec_hex_encode(stream_key, sizeof stream_key, derived_hex);
    CHECK(strcmp(derived_hex, stream_hex) == 0);
    for (index = 0U; index < 3U; index++) {
        ksec_dataset_header_info expected;
        ksec_dataset_header_info parsed;
        ksec_dataset_header_info actual;
        uint8_t digest[32];
        uint8_t pattern_digest[32];
        char digest_hex[65];
        char pattern_hex[65];
        size_t parsed_prefix = 0U;
        const char *want_sha;
        int sealed_fd = memfd_new();
        int out_fd = memfd_new();
        CHECK(cases[index].saw_length && cases[index].saw_sha);
        CHECK(cases[index].prefix != NULL && cases[index].sealed != NULL);
        CHECK(sealed_fd >= 0 && out_fd >= 0);
        want_sha = expected_plaintext_sha(cases[index].length);
        CHECK(cases[index].prefix_len == 92U);
        CHECK(cases[index].sealed_len
              == sealed_formula(cases[index].length, 18U, 6U));
        CHECK(memcmp(cases[index].sealed, cases[index].prefix,
                     cases[index].prefix_len) == 0);
        CHECK(ksec_dataset_parse_prefix(cases[index].sealed,
                                        cases[index].sealed_len, &parsed,
                                        &parsed_prefix) == KSEC_OK);
        CHECK(parsed_prefix == 92U);
        fill_info(&expected, cases[index].length, 1U, "kilix-secrets.test",
                  "ledger");
        memcpy(expected.vault_uuid, uuid, sizeof uuid);
        memcpy(expected.key_record_id, record_id, sizeof record_id);
        expect_info(&parsed, &expected);
        CHECK(rewrite_fd(sealed_fd, cases[index].sealed, cases[index].sealed_len)
              == 0);
        CHECK(rewrite_fd(out_fd, NULL, 0U) == 0);
        CHECK(ksec_dataset_unseal(dataset_key, &expected, sealed_fd, out_fd,
                                  &actual) == KSEC_OK);
        expect_info(&actual, &expected);
        CHECK(output_matches(out_fd, cases[index].length));
        CHECK(hash_fd(out_fd, cases[index].length, digest) == 0);
        hash_pattern(cases[index].length, pattern_digest);
        ksec_hex_encode(digest, sizeof digest, digest_hex);
        ksec_hex_encode(pattern_digest, sizeof pattern_digest, pattern_hex);
        CHECK(want_sha != NULL && strcmp(digest_hex, want_sha) == 0);
        CHECK(want_sha != NULL && strcmp(pattern_hex, want_sha) == 0);
        if (sealed_fd >= 0) close(sealed_fd);
        if (out_fd >= 0) close(out_fd);
        free(cases[index].prefix);
        free(cases[index].sealed);
        sodium_memzero(digest, sizeof digest);
        sodium_memzero(pattern_digest, sizeof pattern_digest);
        sodium_memzero(&expected, sizeof expected);
        sodium_memzero(&parsed, sizeof parsed);
        sodium_memzero(&actual, sizeof actual);
    }
    sodium_memzero(dataset_key, sizeof dataset_key);
    sodium_memzero(stream_key, sizeof stream_key);
    sodium_memzero(derived_hex, sizeof derived_hex);
}

static int remove_tree_entry(const char *path, const struct stat *status,
                             int type, struct FTW *info) {
    (void)status;
    (void)info;
    if (type == FTW_DP) (void)rmdir(path);
    else (void)unlink(path);
    return 0;
}

static int temp_tree_is_safe(const char *path) {
    const char *root = getenv("TMPDIR");
    struct stat status;
    size_t root_len;
    if (root == NULL || path == NULL || root[0] != '/' || path[0] != '/') return 0;
    root_len = strlen(root);
    if (root_len < 2U || strncmp(path, root, root_len) != 0 || path[root_len] != '/') {
        return 0;
    }
    if (strstr(path, "/../") != NULL || strstr(path, "ksec-dataset.") == NULL) {
        return 0;
    }
    if (lstat(path, &status) != 0 || !S_ISDIR(status.st_mode)
            || S_ISLNK(status.st_mode)) {
        return 0;
    }
    return 1;
}

static void cleanup_temp_tree(const char *path) {
    if (!temp_tree_is_safe(path)) {
        fprintf(stderr, "FAIL refusing to delete %s\n",
                path == NULL ? "(null)" : path);
        checks_run++;
        checks_failed++;
        return;
    }
    CHECK(nftw(path, remove_tree_entry, 16, FTW_DEPTH | FTW_PHYS) == 0);
    {
        struct stat gone;
        CHECK(lstat(path, &gone) != 0 && errno == ENOENT);
    }
}

static int make_temp_dir(char path[4096]) {
    const char *root = getenv("TMPDIR");
    struct stat status;
    int count;
    if (root == NULL || root[0] != '/' || lstat(root, &status) != 0
            || !S_ISDIR(status.st_mode) || S_ISLNK(status.st_mode)) {
        return -1;
    }
    count = snprintf(path, 4096U, "%s/ksec-dataset.XXXXXX", root);
    if (count < 0 || count >= 4096) return -1;
    return mkdtemp(path) == NULL ? -1 : 0;
}

static void expect_loaded_key(ksec_store *store,
                              const uint8_t id[KSEC_RECORD_ID_BYTES],
                              const uint8_t key[KSEC_DATASET_KEY_BYTES]) {
    ksec_owned_record *found = ksec_store_find(store, id);
    CHECK(found != NULL);
    if (found == NULL) return;
    CHECK(found->object_type == KSEC_OBJECT_DATASET_KEY);
    CHECK(!found->deleted);
    CHECK(strcmp(found->owner, "kilix-secrets.test") == 0);
    CHECK(ksec_validate_dataset_key_record(found) == KSEC_OK);
    CHECK(found->fields[0].value.len == KSEC_DATASET_KEY_BYTES);
    CHECK(sodium_memcmp(found->fields[0].value.data, key,
                        KSEC_DATASET_KEY_BYTES) == 0);
}

static void test_vault_lifecycle(void) {
    static const uint8_t passphrase[] = "synthetic-passphrase";
    static const uint8_t recovery[] =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    char directory[4096];
    ksec_store store;
    ksec_vault_header header;
    ksec_vault_header disk_header;
    ksec_owned_record owned;
    ksec_backup_image image;
    ksec_dataset_header_info info;
    ksec_dataset_header_info actual;
    ksec_field field;
    uint8_t master[KSEC_MASTER_KEY_BYTES];
    uint8_t new_master[KSEC_MASTER_KEY_BYTES];
    uint8_t dataset_key[KSEC_DATASET_KEY_BYTES];
    uint8_t record_id[KSEC_RECORD_ID_BYTES];
    uint64_t generation_before = 0U;
    int temp_ok;
    int opened = 0;
    int backup_fd = -1;
    int plain_fd = -1;
    int sealed_fd = -1;
    int out_fd = -1;
    memset(&store, 0, sizeof store);
    memset(&header, 0, sizeof header);
    memset(&disk_header, 0, sizeof disk_header);
    memset(&owned, 0, sizeof owned);
    memset(&image, 0, sizeof image);
    memset(&info, 0, sizeof info);
    store.lock_fd = -1;
    fill_sequence(dataset_key, sizeof dataset_key, 0xa0U);
    fill_sequence(record_id, sizeof record_id, 0x44U);
    temp_ok = make_temp_dir(directory) == 0;
    CHECK(temp_ok);
    if (!temp_ok) return;
    CHECK(ksec_header_create(&header, passphrase, sizeof passphrase - 1U,
                             recovery, sizeof recovery - 1U,
                             KSEC_ARGON_OPS_MIN, KSEC_ARGON_MEM_MIN, master)
          == KSEC_OK);
    CHECK(header.generation == 1U && header.flags == 0U);
    CHECK(ksec_header_confirm_recovery(&header, master) == KSEC_OK);
    CHECK(header.generation == 2U
          && (header.flags & KSEC_HEADER_FLAG_RECOVERY_CONFIRMED) != 0U);
    CHECK(ksec_store_open(&store, directory, false) == KSEC_OK);
    opened = 1;
    CHECK(ksec_store_write_header(&store, &header) == KSEC_OK);
    field.name = KSEC_DATASET_KEY_FIELD;
    field.value = dataset_key;
    field.value_len = sizeof dataset_key;
    CHECK(build_key_record(&owned, KSEC_DATASET_KEY_TYPE, "ledger", 0U,
                           &field, 1U, NULL, 0U) == KSEC_OK);
    memcpy(owned.id, record_id, sizeof record_id);
    CHECK(ksec_validate_dataset_key_record(&owned) == KSEC_OK);
    CHECK(ksec_store_append(&store, &header, master, &owned, false) == KSEC_OK);
    ksec_store_close(&store);
    opened = 0;
    CHECK(ksec_store_open(&store, directory, false) == KSEC_OK);
    opened = 1;
    CHECK(ksec_store_load(&store, &header, master) == KSEC_OK);
    expect_loaded_key(&store, record_id, dataset_key);
    CHECK(ksec_store_compact(&store, &header, master) == KSEC_OK);
    ksec_store_close(&store);
    opened = 0;
    CHECK(ksec_store_open(&store, directory, false) == KSEC_OK);
    opened = 1;
    CHECK(ksec_store_load(&store, &header, master) == KSEC_OK);
    expect_loaded_key(&store, record_id, dataset_key);
    randombytes_buf(new_master, sizeof new_master);
    CHECK(sodium_memcmp(master, new_master, sizeof master) != 0);
    generation_before = header.generation;
    CHECK(ksec_header_rotate_master(&header, master, new_master, passphrase,
                                   sizeof passphrase - 1U, recovery,
                                   sizeof recovery - 1U, KSEC_ARGON_OPS_MIN,
                                   KSEC_ARGON_MEM_MIN) == KSEC_OK);
    CHECK(header.generation == generation_before + 1U);
    CHECK(ksec_store_rotate_generation(&store, &header, new_master) == KSEC_OK);
    backup_fd = memfd_new();
    CHECK(backup_fd >= 0);
    CHECK(ksec_backup_create(&store, &header, new_master, passphrase,
                             sizeof passphrase - 1U, backup_fd) == KSEC_OK);
    ksec_store_close(&store);
    opened = 0;
    CHECK(ksec_store_open(&store, directory, false) == KSEC_OK);
    opened = 1;
    CHECK(ksec_store_read_header(&store, &disk_header) == KSEC_OK);
    CHECK(disk_header.generation == header.generation);
    CHECK(sodium_memcmp(disk_header.vault_uuid, header.vault_uuid,
                        sizeof header.vault_uuid) == 0);
    CHECK(ksec_store_load(&store, &header, new_master) == KSEC_OK);
    expect_loaded_key(&store, record_id, dataset_key);
    CHECK(lseek(backup_fd, 0, SEEK_SET) == 0);
    CHECK(ksec_backup_open(backup_fd, passphrase, sizeof passphrase - 1U, &image)
          == KSEC_OK);
    CHECK(image.master.data != NULL
          && sodium_memcmp(image.master.data, new_master, sizeof new_master) == 0);
    CHECK(ksec_store_import_generation(&store, &image) == KSEC_OK);
    CHECK(ksec_store_load(&store, &image.header, image.master.data) == KSEC_OK);
    expect_loaded_key(&store, record_id, dataset_key);
    fill_info(&info, 1U, 1U, "kilix-secrets.test", "ledger");
    memcpy(info.vault_uuid, header.vault_uuid, sizeof info.vault_uuid);
    memcpy(info.key_record_id, record_id, sizeof record_id);
    plain_fd = memfd_new();
    sealed_fd = memfd_new();
    out_fd = memfd_new();
    CHECK(plain_fd >= 0 && sealed_fd >= 0 && out_fd >= 0);
    CHECK(write_pattern(plain_fd, 1U) == 0);
    CHECK(ksec_dataset_seal(dataset_key, &info, plain_fd, sealed_fd) == KSEC_OK);
    CHECK(ksec_dataset_unseal(dataset_key, &info, sealed_fd, out_fd, &actual)
          == KSEC_OK);
    CHECK(output_matches(out_fd, 1U));
    ksec_store_close(&store);
    opened = 0;
    ksec_backup_image_clear(&image);
    if (backup_fd >= 0) close(backup_fd);
    if (plain_fd >= 0) close(plain_fd);
    if (sealed_fd >= 0) close(sealed_fd);
    if (out_fd >= 0) close(out_fd);
    ksec_owned_record_clear(&owned);
    sodium_memzero(master, sizeof master);
    sodium_memzero(new_master, sizeof new_master);
    sodium_memzero(dataset_key, sizeof dataset_key);
    sodium_memzero(&header, sizeof header);
    sodium_memzero(&disk_header, sizeof disk_header);
    sodium_memzero(&info, sizeof info);
    sodium_memzero(&actual, sizeof actual);
    if (opened) ksec_store_close(&store);
    cleanup_temp_tree(directory);
}

int main(void) {
    if (ksec_crypto_initialize() != KSEC_OK) {
        fprintf(stderr, "FAIL crypto initialize\n");
        return 1;
    }
    test_lengths_and_round_trips();
    test_damage();
    test_header_grammar();
    test_requests();
    test_validate();
    test_object_type_gate();
    test_vectors();
    test_vault_lifecycle();
    printf("dataset checks: %u/%u passed\n",
           checks_run - checks_failed, checks_run);
    return checks_failed == 0U ? 0 : 1;
}
