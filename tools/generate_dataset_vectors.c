/*
 * Deterministic sealed-dataset v1 vectors.
 *
 * randombytes is replaced only in this process. The seed is the 32-byte
 * string "kilix-secrets-dset-v1-seed-2026". Each draw is
 * randombytes_buf_deterministic of the current seed; the seed then becomes
 * SHA-256 of itself so successive secretstream headers differ.
 */
#include "internal.h"

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static uint8_t det_seed[randombytes_SEEDBYTES] = {
    'k', 'i', 'l', 'i', 'x', '-', 's', 'e',
    'c', 'r', 'e', 't', 's', '-', 'd', 's',
    'e', 't', '-', 'v', '1', '-', 's', 'e',
    'e', 'd', '-', '2', '0', '2', '6'
};

static void det_buf(void * const buf, const size_t size) {
    randombytes_buf_deterministic(buf, size, det_seed);
    crypto_hash_sha256(det_seed, det_seed, sizeof det_seed);
}

static uint32_t det_random(void) {
    uint32_t value = 0U;
    det_buf(&value, sizeof value);
    return value;
}

static const char *det_name(void) {
    return "dataset-v1-deterministic";
}

static randombytes_implementation det_impl = {
    det_name, det_random, NULL, NULL, det_buf, NULL
};

static void fill_sequence(uint8_t *output, size_t length, uint8_t first) {
    size_t index;
    for (index = 0U; index < length; index++) {
        output[index] = (uint8_t)(first + (uint8_t)index);
    }
}

static void print_hex(const char *name, const uint8_t *bytes, size_t length) {
    size_t index;
    printf("%s=", name);
    for (index = 0U; index < length; index++) printf("%02x", bytes[index]);
    putchar('\n');
}

static uint8_t pattern_byte(uint64_t index) {
    return (uint8_t)((index * UINT64_C(131) + UINT64_C(17)) & UINT64_C(0xff));
}

static int write_pattern(int fd, uint64_t length, uint8_t digest[32]) {
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
        if (ksec_write_all(fd, block, count) != 0) return -1;
        offset += (uint64_t)count;
    }
    crypto_hash_sha256_final(&hasher, digest);
    sodium_memzero(block, sizeof block);
    sodium_memzero(&hasher, sizeof hasher);
    return 0;
}

static int emit_case(const uint8_t key[KSEC_DATASET_KEY_BYTES],
                     const ksec_dataset_header_info *base, uint64_t length) {
    ksec_dataset_header_info info = *base;
    uint8_t prefix[KSEC_DATASET_PREFIX_FIXED_BYTES + KSEC_MAX_APP_ID
                   + KSEC_MAX_DATASET_NAME];
    uint8_t digest[32];
    uint8_t *sealed = NULL;
    size_t prefix_len = 0U;
    uint64_t sealed_len = 0U;
    struct stat status;
    int plain_fd = -1;
    int sealed_fd = -1;
    int result = -1;
    info.plaintext_length = length;
    plain_fd = memfd_create("ksec-dataset-vector-plain", MFD_CLOEXEC);
    sealed_fd = memfd_create("ksec-dataset-vector-sealed", MFD_CLOEXEC);
    if (plain_fd < 0 || sealed_fd < 0) goto out;
    if (write_pattern(plain_fd, length, digest) != 0) goto out;
    if (ksec_dataset_encode_prefix(&info, prefix, sizeof prefix, &prefix_len)
                != KSEC_OK
            || ksec_dataset_seal(key, &info, plain_fd, sealed_fd) != KSEC_OK
            || fstat(sealed_fd, &status) != 0 || status.st_size < 0) {
        goto out;
    }
    sealed_len = (uint64_t)status.st_size;
    sealed = malloc(sealed_len == 0U ? 1U : (size_t)sealed_len);
    if (sealed == NULL) goto out;
    if (sealed_len > 0U) {
        ssize_t count = pread(sealed_fd, sealed, (size_t)sealed_len, 0);
        if (count < 0 || (uint64_t)count != sealed_len) goto out;
    }
    printf("case=L%llu\n", (unsigned long long)length);
    printf("plaintext_length=%llu\n", (unsigned long long)length);
    print_hex("plaintext_sha256", digest, sizeof digest);
    print_hex("prefix_hex", prefix, prefix_len);
    print_hex("sealed_hex", sealed, (size_t)sealed_len);
    result = 0;
out:
    if (plain_fd >= 0) close(plain_fd);
    if (sealed_fd >= 0) close(sealed_fd);
    if (sealed != NULL) {
        sodium_memzero(sealed, (size_t)sealed_len);
        free(sealed);
    }
    sodium_memzero(prefix, sizeof prefix);
    sodium_memzero(digest, sizeof digest);
    sodium_memzero(&info, sizeof info);
    return result;
}

int main(void) {
    ksec_dataset_header_info info;
    uint8_t dataset_key[KSEC_DATASET_KEY_BYTES];
    uint8_t stream_key[KSEC_DATASET_KEY_BYTES];
    int result = 1;
    if (ksec_crypto_initialize() != KSEC_OK) return 1;
    if (randombytes_set_implementation(&det_impl) != 0) return 1;
    memset(&info, 0, sizeof info);
    fill_sequence(dataset_key, sizeof dataset_key, 0xa0U);
    fill_sequence(info.vault_uuid, sizeof info.vault_uuid, 0x10U);
    fill_sequence(info.key_record_id, sizeof info.key_record_id, 0x20U);
    info.revision = 1U;
    memcpy(info.owner, "kilix-secrets.test", sizeof "kilix-secrets.test");
    memcpy(info.name, "ledger", sizeof "ledger");
    if (crypto_kdf_derive_from_key(
            stream_key, sizeof stream_key,
            (uint64_t)KSEC_DATASET_KDF_SUBKEY_ID,
            KSEC_DATASET_KDF_CONTEXT, dataset_key) != 0) {
        goto out;
    }
    puts("vector_format=KSEC-DATASET-V1");
    puts("provider=libsodium-1.0.18-1+deb13u1");
    puts("kdf_context=KSDSET01");
    puts("kdf_subkey_id=1");
    puts("chunk_bytes=65536");
    print_hex("dataset_key", dataset_key, sizeof dataset_key);
    print_hex("stream_key", stream_key, sizeof stream_key);
    print_hex("vault_uuid", info.vault_uuid, sizeof info.vault_uuid);
    print_hex("key_record_id", info.key_record_id, sizeof info.key_record_id);
    puts("owner=kilix-secrets.test");
    puts("name=ledger");
    puts("revision=1");
    if (emit_case(dataset_key, &info, 0U) != 0
            || emit_case(dataset_key, &info, 100U) != 0
            || emit_case(dataset_key, &info, 65537U) != 0) {
        goto out;
    }
    result = 0;
out:
    sodium_memzero(dataset_key, sizeof dataset_key);
    sodium_memzero(stream_key, sizeof stream_key);
    sodium_memzero(&info, sizeof info);
    sodium_memzero(det_seed, sizeof det_seed);
    return result;
}
