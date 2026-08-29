#define _GNU_SOURCE

#include "internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum {
    BACKUP_HEADER_BYTES = 176,
    BACKUP_SLOT_AD_BYTES = 84,
    BACKUP_HEADER_MAX_BYTES = 1024
};

static const uint8_t BACKUP_MAGIC[8] = {'K','S','V','B','A','K','0','1'};
static const uint8_t BACKUP_SLOT_DOMAIN[8] = {'K','S','B','K','S','L','0','1'};
static const char BACKUP_CONTEXT[8] = {'K','S','B','A','C','K','0','1'};

ksec_result ksec_backup_validate_envelope_header(
        const uint8_t *header, size_t header_len, uint64_t artifact_len,
        uint32_t *vault_len, uint64_t *journal_len) {
    uint32_t parsed_vault_len;
    uint64_t parsed_journal_len;
    uint64_t archive_len;
    uint32_t opslimit;
    uint64_t memlimit;
    if (header == NULL || vault_len == NULL || journal_len == NULL
            || header_len != BACKUP_HEADER_BYTES) return KSEC_ERR_INVALID;
    if (memcmp(header, BACKUP_MAGIC, sizeof BACKUP_MAGIC) != 0
            || ksec_get_u16(header + 8U) != 1U
            || ksec_get_u16(header + 10U) != KSEC_PWHASH_ID_ARGON2ID13
            || ksec_get_u16(header + 12U) != KSEC_KDF_ID_BLAKE2B
            || ksec_get_u16(header + 14U)
                != KSEC_AEAD_ID_XCHACHA20POLY1305) return KSEC_ERR_INVALID;
    opslimit = ksec_get_u32(header + 16U);
    memlimit = ksec_get_u64(header + 20U);
    if (opslimit < KSEC_ARGON_OPS_MIN || opslimit > KSEC_ARGON_OPS_MAX
            || memlimit < KSEC_ARGON_MEM_MIN || memlimit > KSEC_ARGON_MEM_MAX
            || memlimit > SIZE_MAX) return KSEC_ERR_INVALID;
    parsed_vault_len = ksec_get_u32(header + 140U);
    parsed_journal_len = ksec_get_u64(header + 144U);
    if (parsed_vault_len == 0U
            || parsed_vault_len > BACKUP_HEADER_MAX_BYTES
            || parsed_journal_len > KSEC_MAX_JOURNAL_BYTES
            || parsed_journal_len > UINT64_MAX - parsed_vault_len) {
        return KSEC_ERR_LIMIT;
    }
    archive_len = (uint64_t)parsed_vault_len + parsed_journal_len;
    if (archive_len > SIZE_MAX
            || archive_len > UINT64_MAX - BACKUP_HEADER_BYTES - KSEC_TAG_BYTES
            || artifact_len != BACKUP_HEADER_BYTES + archive_len
                                    + KSEC_TAG_BYTES
            || artifact_len > KSEC_MAX_BACKUP_BYTES) return KSEC_ERR_INVALID;
    *vault_len = parsed_vault_len;
    *journal_len = parsed_journal_len;
    return KSEC_OK;
}

static int safe_source_fd(int fd, uint64_t maximum, size_t *length) {
    struct stat status;
    if (fd < 0 || length == NULL || fstat(fd, &status) != 0
            || !S_ISREG(status.st_mode) || status.st_uid != getuid()
            || status.st_nlink != 1 || (status.st_mode & 0777U) != 0600U
            || status.st_size < 0 || (uint64_t)status.st_size > maximum
            || (uint64_t)status.st_size > SIZE_MAX) return -1;
    *length = (size_t)status.st_size;
    return 0;
}

static ksec_result read_source_file(const char *path, uint64_t maximum,
                                    bool optional, uint8_t **bytes,
                                    size_t *length) {
    int fd;
    ksec_result result = KSEC_OK;
    if (path == NULL || bytes == NULL || length == NULL) return KSEC_ERR_INVALID;
    *bytes = NULL;
    *length = 0U;
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return optional && errno == ENOENT ? KSEC_OK : KSEC_ERR_IO;
    }
    if (safe_source_fd(fd, maximum, length) != 0 || (!optional && *length == 0U)) {
        result = KSEC_ERR_DENIED;
        goto out;
    }
    if (*length > 0U) {
        *bytes = malloc(*length);
        if (*bytes == NULL) { result = KSEC_ERR_MEMORY; goto out; }
        if (ksec_read_exact(fd, *bytes, *length) != 0) {
            result = KSEC_ERR_IO;
            goto out;
        }
    }
out:
    if (close(fd) != 0 && result == KSEC_OK) result = KSEC_ERR_IO;
    if (result != KSEC_OK && *bytes != NULL) {
        sodium_memzero(*bytes, *length);
        free(*bytes);
        *bytes = NULL;
        *length = 0U;
    }
    return result;
}

static void make_slot_ad(const uint8_t header[BACKUP_HEADER_BYTES],
                         uint8_t output[BACKUP_SLOT_AD_BYTES]) {
    size_t offset = 0U;
    memcpy(output + offset, BACKUP_SLOT_DOMAIN, 8U); offset += 8U;
    memcpy(output + offset, header + 8U, 36U); offset += 36U;
    memcpy(output + offset, header + 116U, 36U); offset += 36U;
    ksec_put_u32(output + offset, KSEC_MASTER_KEY_BYTES);
}

static ksec_result derive_passphrase_key(
        const uint8_t header[BACKUP_HEADER_BYTES], const uint8_t *passphrase,
        size_t passphrase_len, uint8_t key[32]) {
    uint32_t opslimit = ksec_get_u32(header + 16U);
    uint64_t memlimit = ksec_get_u64(header + 20U);
    if (passphrase == NULL || passphrase_len < 8U || passphrase_len > 1024U
            || opslimit < KSEC_ARGON_OPS_MIN || opslimit > KSEC_ARGON_OPS_MAX
            || memlimit < KSEC_ARGON_MEM_MIN || memlimit > KSEC_ARGON_MEM_MAX
            || memlimit > SIZE_MAX) return KSEC_ERR_INVALID;
    if (crypto_pwhash(key, 32U, (const char *)passphrase,
                      (unsigned long long)passphrase_len, header + 28U,
                      (unsigned long long)opslimit, (size_t)memlimit,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        return KSEC_ERR_MEMORY;
    }
    return KSEC_OK;
}

ksec_result ksec_backup_create(
        const ksec_store *store, const ksec_vault_header *header,
        const uint8_t master_key[KSEC_MASTER_KEY_BYTES],
        const uint8_t *passphrase, size_t passphrase_len, int output_fd) {
    uint8_t *vault = NULL;
    size_t vault_len = 0U;
    uint8_t *journal = NULL;
    size_t journal_len = 0U;
    uint8_t *archive = NULL;
    size_t archive_len = 0U;
    uint8_t *ciphertext = NULL;
    uint8_t encoded[BACKUP_HEADER_BYTES];
    uint8_t expected_vault[BACKUP_HEADER_MAX_BYTES];
    size_t expected_vault_len = 0U;
    uint8_t slot_ad[BACKUP_SLOT_AD_BYTES];
    uint8_t wrapping_key[32];
    uint8_t payload_key[32];
    unsigned long long wrapped_len = 0U;
    unsigned long long ciphertext_len = 0U;
    size_t index;
    uint32_t opslimit = 0U;
    uint64_t memlimit = 0U;
    ksec_result result;
    memset(encoded, 0, sizeof encoded);
    memset(expected_vault, 0, sizeof expected_vault);
    memset(wrapping_key, 0, sizeof wrapping_key);
    memset(payload_key, 0, sizeof payload_key);
    if (store == NULL || header == NULL || master_key == NULL
            || passphrase == NULL || output_fd < 0) return KSEC_ERR_INVALID;
    result = ksec_header_verify_master(header, master_key);
    if (result != KSEC_OK) return result;
    result = read_source_file(store->vault_path, BACKUP_HEADER_MAX_BYTES, false,
                              &vault, &vault_len);
    if (result != KSEC_OK) goto out;
    result = ksec_header_encode(header, expected_vault, sizeof expected_vault,
                                &expected_vault_len);
    if (result != KSEC_OK || vault_len != expected_vault_len
            || sodium_memcmp(vault, expected_vault, vault_len) != 0) {
        result = KSEC_ERR_CRYPTO;
        goto out;
    }
    result = read_source_file(store->journal_path, KSEC_MAX_JOURNAL_BYTES, true,
                              &journal, &journal_len);
    if (result != KSEC_OK) goto out;
    if (vault_len > UINT32_MAX || journal_len > UINT64_MAX - vault_len
            || (uint64_t)vault_len + (uint64_t)journal_len
                > KSEC_MAX_BACKUP_BYTES - BACKUP_HEADER_BYTES - KSEC_TAG_BYTES) {
        result = KSEC_ERR_LIMIT;
        goto out;
    }
    archive_len = vault_len + journal_len;
    archive = malloc(archive_len == 0U ? 1U : archive_len);
    ciphertext = malloc(archive_len + KSEC_TAG_BYTES);
    if (archive == NULL || ciphertext == NULL) {
        result = KSEC_ERR_MEMORY;
        goto out;
    }
    memcpy(archive, vault, vault_len);
    if (journal_len > 0U) memcpy(archive + vault_len, journal, journal_len);
    for (index = 0U; index < header->slot_count; index++) {
        if (header->slots[index].opslimit > opslimit) {
            opslimit = header->slots[index].opslimit;
        }
        if (header->slots[index].memlimit > memlimit) {
            memlimit = header->slots[index].memlimit;
        }
    }
    memcpy(encoded, BACKUP_MAGIC, sizeof BACKUP_MAGIC);
    ksec_put_u16(encoded + 8U, 1U);
    ksec_put_u16(encoded + 10U, KSEC_PWHASH_ID_ARGON2ID13);
    ksec_put_u16(encoded + 12U, KSEC_KDF_ID_BLAKE2B);
    ksec_put_u16(encoded + 14U, KSEC_AEAD_ID_XCHACHA20POLY1305);
    ksec_put_u32(encoded + 16U, opslimit);
    ksec_put_u64(encoded + 20U, memlimit);
    randombytes_buf(encoded + 28U, KSEC_SALT_BYTES);
    randombytes_buf(encoded + 44U, KSEC_NONCE_BYTES);
    memcpy(encoded + 116U, header->vault_uuid, KSEC_UUID_BYTES);
    ksec_put_u64(encoded + 132U, header->generation);
    ksec_put_u32(encoded + 140U, (uint32_t)vault_len);
    ksec_put_u64(encoded + 144U, (uint64_t)journal_len);
    randombytes_buf(encoded + 152U, KSEC_NONCE_BYTES);
    result = derive_passphrase_key(encoded, passphrase, passphrase_len,
                                   wrapping_key);
    if (result != KSEC_OK) goto out;
    make_slot_ad(encoded, slot_ad);
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            encoded + 68U, &wrapped_len, master_key, KSEC_MASTER_KEY_BYTES,
            slot_ad, sizeof slot_ad, NULL, encoded + 44U,
            wrapping_key) != 0 || wrapped_len != KSEC_SLOT_CIPHERTEXT_BYTES) {
        result = KSEC_ERR_CRYPTO;
        goto out;
    }
    if (crypto_kdf_derive_from_key(payload_key, sizeof payload_key, 1U,
                                   BACKUP_CONTEXT, master_key) != 0
            || crypto_aead_xchacha20poly1305_ietf_encrypt(
                ciphertext, &ciphertext_len, archive,
                (unsigned long long)archive_len, encoded, sizeof encoded,
                NULL, encoded + 152U, payload_key) != 0
            || ciphertext_len != archive_len + KSEC_TAG_BYTES) {
        result = KSEC_ERR_CRYPTO;
        goto out;
    }
    if (ksec_write_all(output_fd, encoded, sizeof encoded) != 0
            || ksec_write_all(output_fd, ciphertext,
                              (size_t)ciphertext_len) != 0) {
        result = KSEC_ERR_IO;
        goto out;
    }
    result = KSEC_OK;
out:
    if (vault != NULL) {
        sodium_memzero(vault, vault_len);
        free(vault);
    }
    if (journal != NULL) {
        sodium_memzero(journal, journal_len);
        free(journal);
    }
    if (archive != NULL) {
        sodium_memzero(archive, archive_len);
        free(archive);
    }
    if (ciphertext != NULL) {
        sodium_memzero(ciphertext, archive_len + KSEC_TAG_BYTES);
        free(ciphertext);
    }
    sodium_memzero(encoded, sizeof encoded);
    sodium_memzero(expected_vault, sizeof expected_vault);
    sodium_memzero(slot_ad, sizeof slot_ad);
    sodium_memzero(wrapping_key, sizeof wrapping_key);
    sodium_memzero(payload_key, sizeof payload_key);
    return result;
}

void ksec_backup_image_clear(ksec_backup_image *image) {
    if (image == NULL) return;
    if (image->vault != NULL) {
        sodium_memzero(image->vault, image->vault_len);
        free(image->vault);
    }
    if (image->journal != NULL) {
        sodium_memzero(image->journal, image->journal_len);
        free(image->journal);
    }
    ksec_secure_free(&image->master);
    sodium_memzero(image, sizeof *image);
}

ksec_result ksec_backup_open(int input_fd, const uint8_t *passphrase,
                             size_t passphrase_len, ksec_backup_image *image) {
    struct stat status;
    off_t start;
    uint8_t encoded[BACKUP_HEADER_BYTES];
    uint8_t slot_ad[BACKUP_SLOT_AD_BYTES];
    uint8_t wrapping_key[32];
    uint8_t payload_key[32];
    uint8_t *ciphertext = NULL;
    uint8_t *archive = NULL;
    uint32_t vault_len;
    uint64_t journal_len;
    uint64_t archive_len_u64;
    uint64_t artifact_len;
    size_t archive_len = 0U;
    unsigned long long master_len = 0U;
    unsigned long long plaintext_len = 0U;
    ksec_result result = KSEC_ERR_INVALID;
    if (input_fd < 0 || passphrase == NULL || image == NULL) {
        return KSEC_ERR_INVALID;
    }
    memset(image, 0, sizeof *image);
    memset(encoded, 0, sizeof encoded);
    memset(wrapping_key, 0, sizeof wrapping_key);
    memset(payload_key, 0, sizeof payload_key);
    start = lseek(input_fd, 0, SEEK_CUR);
    if (start < 0 || fstat(input_fd, &status) != 0 || !S_ISREG(status.st_mode)
            || status.st_size < start) {
        result = KSEC_ERR_IO;
        goto out;
    }
    artifact_len = (uint64_t)(status.st_size - start);
    if (artifact_len < BACKUP_HEADER_BYTES
            || ksec_read_exact(input_fd, encoded, sizeof encoded) != 0) {
        result = KSEC_ERR_INVALID;
        goto out;
    }
    result = ksec_backup_validate_envelope_header(
            encoded, sizeof encoded, artifact_len, &vault_len, &journal_len);
    if (result != KSEC_OK) goto out;
    archive_len_u64 = (uint64_t)vault_len + journal_len;
    archive_len = (size_t)archive_len_u64;
    ciphertext = malloc(archive_len + KSEC_TAG_BYTES);
    archive = malloc(archive_len == 0U ? 1U : archive_len);
    if (ciphertext == NULL || archive == NULL) {
        result = KSEC_ERR_MEMORY;
        goto out;
    }
    if (ksec_read_exact(input_fd, ciphertext,
                        archive_len + KSEC_TAG_BYTES) != 0) {
        result = KSEC_ERR_IO;
        goto out;
    }
    result = derive_passphrase_key(encoded, passphrase, passphrase_len,
                                   wrapping_key);
    if (result != KSEC_OK) goto out;
    result = ksec_secure_alloc(&image->master, KSEC_MASTER_KEY_BYTES);
    if (result != KSEC_OK) goto out;
    make_slot_ad(encoded, slot_ad);
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            image->master.data, &master_len, NULL, encoded + 68U,
            KSEC_SLOT_CIPHERTEXT_BYTES, slot_ad, sizeof slot_ad,
            encoded + 44U, wrapping_key) != 0
            || master_len != KSEC_MASTER_KEY_BYTES) {
        result = KSEC_ERR_CRYPTO;
        goto out;
    }
    if (crypto_kdf_derive_from_key(payload_key, sizeof payload_key, 1U,
                                   BACKUP_CONTEXT, image->master.data) != 0
            || crypto_aead_xchacha20poly1305_ietf_decrypt(
                archive, &plaintext_len, NULL, ciphertext,
                (unsigned long long)(archive_len + KSEC_TAG_BYTES), encoded,
                sizeof encoded, encoded + 152U, payload_key) != 0
            || plaintext_len != archive_len) {
        result = KSEC_ERR_CRYPTO;
        goto out;
    }
    image->vault = malloc(vault_len);
    if (image->vault == NULL) { result = KSEC_ERR_MEMORY; goto out; }
    memcpy(image->vault, archive, vault_len);
    image->vault_len = vault_len;
    if (journal_len > 0U) {
        image->journal = malloc((size_t)journal_len);
        if (image->journal == NULL) { result = KSEC_ERR_MEMORY; goto out; }
        memcpy(image->journal, archive + vault_len, (size_t)journal_len);
        image->journal_len = (size_t)journal_len;
    }
    result = ksec_header_decode(image->vault, image->vault_len,
                                &image->header);
    if (result != KSEC_OK
            || sodium_memcmp(image->header.vault_uuid, encoded + 116U,
                             KSEC_UUID_BYTES) != 0
            || image->header.generation != ksec_get_u64(encoded + 132U)) {
        result = KSEC_ERR_CRYPTO;
        goto out;
    }
    result = ksec_header_verify_master(&image->header, image->master.data);
out:
    if (result != KSEC_OK) ksec_backup_image_clear(image);
    if (ciphertext != NULL) {
        sodium_memzero(ciphertext, archive_len + KSEC_TAG_BYTES);
        free(ciphertext);
    }
    if (archive != NULL) {
        sodium_memzero(archive, archive_len);
        free(archive);
    }
    sodium_memzero(encoded, sizeof encoded);
    sodium_memzero(slot_ad, sizeof slot_ad);
    sodium_memzero(wrapping_key, sizeof wrapping_key);
    sodium_memzero(payload_key, sizeof payload_key);
    return result;
}
