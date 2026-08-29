#define _GNU_SOURCE

#include "internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

enum { MAX_VECTOR_ENTRIES = 64, MAX_VECTOR_KEY = 64, MAX_VECTOR_VALUE = 4096 };

typedef struct {
    char key[MAX_VECTOR_KEY];
    char value[MAX_VECTOR_VALUE];
} vector_entry;

typedef struct {
    vector_entry entries[MAX_VECTOR_ENTRIES];
    size_t count;
} vector_file;

static unsigned int checks_run;
static unsigned int checks_failed;

static void check_condition(int condition, const char *expression, int line) {
    checks_run++;
    if (!condition) {
        checks_failed++;
        fprintf(stderr, "FAIL vector line %d: %s\n", line, expression);
    }
}

#define CHECK(expression) check_condition((expression) ? 1 : 0, #expression, __LINE__)

static int load_vectors(vector_file *vectors) {
    FILE *stream;
    char line[MAX_VECTOR_KEY + MAX_VECTOR_VALUE + 4U];
    if (vectors == NULL) return -1;
    memset(vectors, 0, sizeof *vectors);
    stream = fopen("tests/vectors/full-v1.txt", "r");
    if (stream == NULL) return -1;
    while (fgets(line, sizeof line, stream) != NULL) {
        char *equals;
        size_t key_length;
        size_t value_length;
        size_t index;
        if (strchr(line, '\n') == NULL) {
            (void)fclose(stream);
            return -1;
        }
        line[strcspn(line, "\r\n")] = '\0';
        equals = strchr(line, '=');
        if (equals == NULL || equals == line || equals[1] == '\0'
                || strchr(equals + 1, '=') != NULL
                || vectors->count >= MAX_VECTOR_ENTRIES) {
            (void)fclose(stream);
            return -1;
        }
        *equals = '\0';
        key_length = strlen(line);
        value_length = strlen(equals + 1);
        if (key_length >= MAX_VECTOR_KEY || value_length >= MAX_VECTOR_VALUE) {
            (void)fclose(stream);
            return -1;
        }
        for (index = 0U; index < vectors->count; index++) {
            if (strcmp(vectors->entries[index].key, line) == 0) {
                (void)fclose(stream);
                return -1;
            }
        }
        memcpy(vectors->entries[vectors->count].key, line, key_length + 1U);
        memcpy(vectors->entries[vectors->count].value, equals + 1,
               value_length + 1U);
        vectors->count++;
    }
    if (ferror(stream) != 0 || fclose(stream) != 0) return -1;
    return 0;
}

static const char *vector_get(const vector_file *vectors, const char *key) {
    size_t index;
    if (vectors == NULL || key == NULL) return NULL;
    for (index = 0U; index < vectors->count; index++) {
        if (strcmp(vectors->entries[index].key, key) == 0) {
            return vectors->entries[index].value;
        }
    }
    return NULL;
}

static int vector_hex(const vector_file *vectors, const char *key,
                      uint8_t *output, size_t output_size, size_t *output_length) {
    const char *value = vector_get(vectors, key);
    size_t length;
    if (value == NULL || output == NULL || output_length == NULL) return -1;
    length = strlen(value);
    if ((length & 1U) != 0U || length / 2U > output_size) return -1;
    *output_length = length / 2U;
    return ksec_hex_decode(value, output, *output_length);
}

int main(void) {
    static const char header_context[8] = {'K','S','V','H','D','R','0','1'};
    static const char record_context[8] = {'K','S','V','R','E','C','0','1'};
    static const char backup_context[8] = {'K','S','B','A','C','K','0','1'};
    static const uint8_t backup_slot_domain[8] = {
        'K','S','B','K','S','L','0','1'
    };
    vector_file vectors;
    ksec_vault_header header;
    ksec_vault_header mutated_header;
    ksec_owned_record parsed_record;
    uint8_t header_bytes[1024];
    size_t header_length = 0U;
    uint8_t master[32];
    size_t master_length = 0U;
    uint8_t passphrase[128];
    size_t passphrase_length = 0U;
    uint8_t recovery[128];
    size_t recovery_length = 0U;
    uint8_t unlocked[32];
    uint8_t expected_key[32];
    size_t expected_key_length = 0U;
    uint8_t derived_key[32];
    uint8_t expected_ad[256];
    size_t expected_ad_length = 0U;
    uint8_t actual_ad[256];
    size_t actual_ad_length = 0U;
    uint8_t object_id[16];
    size_t object_id_length = 0U;
    uint8_t identity_public[KSEC_IDENTITY_KEY_BYTES];
    size_t identity_public_length = 0U;
    uint8_t expected_identity_anchor[KSEC_IDENTITY_ANCHOR_BYTES];
    size_t expected_identity_anchor_length = 0U;
    uint8_t actual_identity_anchor[KSEC_IDENTITY_ANCHOR_BYTES];
    uint8_t plaintext[1024];
    size_t plaintext_length = 0U;
    uint8_t nonce[24];
    size_t nonce_length = 0U;
    uint8_t ciphertext[1200];
    size_t ciphertext_length = 0U;
    uint8_t encrypted[1200];
    unsigned long long encrypted_length = 0U;
    uint8_t decrypted[1024];
    size_t decrypted_length = 0U;
    uint8_t mutation[1200];
    uint8_t altered_master[32];
    uint8_t altered_uuid[16];
    uint8_t altered_id[16];
    uint8_t altered_nonce[24];
    uint8_t backup_passphrase[128];
    size_t backup_passphrase_length = 0U;
    uint8_t backup_header[176];
    size_t backup_header_length = 0U;
    uint8_t backup_ciphertext[1024];
    size_t backup_ciphertext_length = 0U;
    uint8_t backup_bytes[1200];
    size_t backup_bytes_length = 0U;
    uint8_t backup_slot_ad[84];
    uint8_t backup_master[32];
    unsigned long long backup_master_length = 0U;
    uint8_t backup_plaintext[1024];
    unsigned long long backup_plaintext_length = 0U;
    ksec_backup_image backup_image;
    int backup_fd = -1;
    size_t index;

    CHECK(ksec_crypto_initialize() == KSEC_OK);
    CHECK(load_vectors(&vectors) == 0);
    CHECK(vectors.count == 50U);
    CHECK(strcmp(vector_get(&vectors, "vector_format"), "KSEC-FULL-V1") == 0);
    CHECK(strcmp(vector_get(&vectors, "provider"),
                 "libsodium-1.0.18-1+deb13u1") == 0);
    CHECK(strcmp(vector_get(&vectors, "argon2id_opslimit"), "3") == 0);
    CHECK(strcmp(vector_get(&vectors, "argon2id_memlimit"), "268435456") == 0);

    CHECK(vector_hex(&vectors, "header_bytes", header_bytes,
                     sizeof header_bytes, &header_length) == 0
          && header_length == 330U);
    CHECK(vector_hex(&vectors, "master_key", master, sizeof master,
                     &master_length) == 0 && master_length == sizeof master);
    CHECK(vector_hex(&vectors, "passphrase", passphrase, sizeof passphrase,
                     &passphrase_length) == 0);
    CHECK(vector_hex(&vectors, "recovery", recovery, sizeof recovery,
                     &recovery_length) == 0);
    CHECK(ksec_header_decode(header_bytes, header_length, &header) == KSEC_OK);
    CHECK(header.generation == 2U
          && header.flags == KSEC_HEADER_FLAG_RECOVERY_CONFIRMED);
    CHECK(ksec_header_unlock(&header, KSEC_SLOT_PASSPHRASE,
                             passphrase, passphrase_length, unlocked) == KSEC_OK
          && sodium_memcmp(unlocked, master, sizeof master) == 0);
    CHECK(ksec_header_unlock(&header, KSEC_SLOT_RECOVERY,
                             recovery, recovery_length, unlocked) == KSEC_OK
          && sodium_memcmp(unlocked, master, sizeof master) == 0);
    passphrase[0] ^= 1U;
    CHECK(ksec_header_unlock(&header, KSEC_SLOT_PASSPHRASE,
                             passphrase, passphrase_length, unlocked)
          == KSEC_ERR_CRYPTO);
    passphrase[0] ^= 1U;
    recovery[0] ^= 1U;
    CHECK(ksec_header_unlock(&header, KSEC_SLOT_RECOVERY,
                             recovery, recovery_length, unlocked)
          == KSEC_ERR_CRYPTO);
    recovery[0] ^= 1U;

    for (index = 0U; index < 2U; index++) {
        char key_name[32];
        int count = snprintf(key_name, sizeof key_name, "slot%zu_key", index);
        CHECK(count > 0 && (size_t)count < sizeof key_name
              && vector_hex(&vectors, key_name, expected_key,
                            sizeof expected_key, &expected_key_length) == 0
              && expected_key_length == sizeof expected_key);
        CHECK(crypto_pwhash(
                  derived_key, sizeof derived_key,
                  (const char *)(index == 0U ? passphrase : recovery),
                  (unsigned long long)(index == 0U
                      ? passphrase_length : recovery_length),
                  header.slots[index].salt,
                  (unsigned long long)header.slots[index].opslimit,
                  (size_t)header.slots[index].memlimit,
                  crypto_pwhash_ALG_ARGON2ID13) == 0
              && sodium_memcmp(derived_key, expected_key,
                               sizeof derived_key) == 0);
        count = snprintf(key_name, sizeof key_name, "slot%zu_ad", index);
        CHECK(count > 0 && (size_t)count < sizeof key_name
              && vector_hex(&vectors, key_name, expected_ad,
                            sizeof expected_ad, &expected_ad_length) == 0);
        CHECK(ksec_format_slot_ad(&header, &header.slots[index], actual_ad,
                                  sizeof actual_ad, &actual_ad_length) == KSEC_OK
              && actual_ad_length == expected_ad_length
              && sodium_memcmp(actual_ad, expected_ad,
                               actual_ad_length) == 0);
    }
    CHECK(vector_hex(&vectors, "header_key", expected_key,
                     sizeof expected_key, &expected_key_length) == 0
          && crypto_kdf_derive_from_key(derived_key, sizeof derived_key, 1U,
                                        header_context, master) == 0
          && sodium_memcmp(derived_key, expected_key, sizeof derived_key) == 0);

    mutated_header = header;
    mutated_header.slots[0].salt[0] ^= 1U;
    CHECK(ksec_header_unlock(&mutated_header, KSEC_SLOT_PASSPHRASE,
                             passphrase, passphrase_length, unlocked)
          == KSEC_ERR_CRYPTO);
    mutated_header = header;
    mutated_header.slots[0].nonce[0] ^= 1U;
    CHECK(ksec_header_unlock(&mutated_header, KSEC_SLOT_PASSPHRASE,
                             passphrase, passphrase_length, unlocked)
          == KSEC_ERR_CRYPTO);
    mutated_header = header;
    mutated_header.slots[0].wrapped[0] ^= 1U;
    CHECK(ksec_header_unlock(&mutated_header, KSEC_SLOT_PASSPHRASE,
                             passphrase, passphrase_length, unlocked)
          == KSEC_ERR_CRYPTO);
    mutated_header = header;
    mutated_header.auth_nonce[0] ^= 1U;
    CHECK(ksec_header_unlock(&mutated_header, KSEC_SLOT_PASSPHRASE,
                             passphrase, passphrase_length, unlocked)
          == KSEC_ERR_CRYPTO);
    mutated_header = header;
    mutated_header.auth_tag[0] ^= 1U;
    CHECK(ksec_header_unlock(&mutated_header, KSEC_SLOT_PASSPHRASE,
                             passphrase, passphrase_length, unlocked)
          == KSEC_ERR_CRYPTO);
    memcpy(mutation, header_bytes, header_length);
    mutation[9] = 2U;
    CHECK(ksec_header_decode(mutation, header_length, &mutated_header)
          == KSEC_ERR_INVALID);
    memcpy(mutation, header_bytes, header_length);
    mutation[47] = 2U;
    CHECK(ksec_header_decode(mutation, header_length, &mutated_header)
          == KSEC_ERR_INVALID);
    CHECK(ksec_header_decode(header_bytes, header_length - 1U, &mutated_header)
          == KSEC_ERR_INVALID);

    CHECK(vector_hex(&vectors, "object_id", object_id, sizeof object_id,
                     &object_id_length) == 0
          && object_id_length == sizeof object_id);
    CHECK(vector_hex(&vectors, "identity_public_key", identity_public,
                     sizeof identity_public, &identity_public_length) == 0
          && identity_public_length == sizeof identity_public
          && crypto_scalarmult_curve25519_base(derived_key, master) == 0
          && sodium_memcmp(derived_key, identity_public,
                           sizeof identity_public) == 0);
    CHECK(vector_hex(&vectors, "identity_anchor", expected_identity_anchor,
                     sizeof expected_identity_anchor,
                     &expected_identity_anchor_length) == 0
          && expected_identity_anchor_length
                == sizeof expected_identity_anchor
          && ksec_identity_anchor(header.vault_uuid, object_id, 7U,
                                  identity_public,
                                  actual_identity_anchor) == KSEC_OK
          && sodium_memcmp(actual_identity_anchor, expected_identity_anchor,
                           sizeof actual_identity_anchor) == 0);
    CHECK(ksec_identity_anchor(header.vault_uuid, object_id, 8U,
                               identity_public,
                               actual_identity_anchor) == KSEC_OK
          && sodium_memcmp(actual_identity_anchor, expected_identity_anchor,
                           sizeof actual_identity_anchor) != 0);
    CHECK(vector_hex(&vectors, "record_plaintext", plaintext,
                     sizeof plaintext, &plaintext_length) == 0);
    CHECK(vector_hex(&vectors, "record_ad", expected_ad, sizeof expected_ad,
                     &expected_ad_length) == 0);
    CHECK(ksec_format_record_ad(KSEC_OBJECT_SECRET, header.vault_uuid,
                                object_id, 7U, (uint32_t)plaintext_length,
                                "kilix-secrets.test", actual_ad,
                                sizeof actual_ad,
                                &actual_ad_length) == KSEC_OK
          && actual_ad_length == expected_ad_length
          && sodium_memcmp(actual_ad, expected_ad, actual_ad_length) == 0);
    CHECK(vector_hex(&vectors, "record_key", expected_key,
                     sizeof expected_key, &expected_key_length) == 0
          && crypto_kdf_derive_from_key(derived_key, sizeof derived_key, 1U,
                                        record_context, master) == 0
          && sodium_memcmp(derived_key, expected_key, sizeof derived_key) == 0);
    CHECK(vector_hex(&vectors, "record_nonce", nonce, sizeof nonce,
                     &nonce_length) == 0 && nonce_length == sizeof nonce);
    CHECK(vector_hex(&vectors, "record_ciphertext", ciphertext,
                     sizeof ciphertext, &ciphertext_length) == 0);
    CHECK(crypto_aead_xchacha20poly1305_ietf_encrypt(
              encrypted, &encrypted_length, plaintext,
              (unsigned long long)plaintext_length, actual_ad,
              (unsigned long long)actual_ad_length, NULL, nonce,
              derived_key) == 0
          && encrypted_length == ciphertext_length
          && sodium_memcmp(encrypted, ciphertext, ciphertext_length) == 0);
    CHECK(ksec_record_decrypt(master, KSEC_OBJECT_SECRET, header.vault_uuid,
                              object_id, 7U, "kilix-secrets.test", nonce,
                              ciphertext, ciphertext_length, decrypted,
                              sizeof decrypted, &decrypted_length) == KSEC_OK
          && decrypted_length == plaintext_length
          && sodium_memcmp(decrypted, plaintext, plaintext_length) == 0);
    memset(&parsed_record, 0, sizeof parsed_record);
    CHECK(ksec_record_parse(decrypted, decrypted_length, &parsed_record) == KSEC_OK
          && strcmp(parsed_record.type, "opaque") == 0
          && strcmp(parsed_record.label, "Synthetic full vector") == 0
          && parsed_record.field_count == 1U
          && parsed_record.fields[0].value.len == 7U);
    ksec_owned_record_clear(&parsed_record);

    memcpy(altered_master, master, sizeof altered_master);
    altered_master[0] ^= 1U;
    CHECK(ksec_record_decrypt(altered_master, KSEC_OBJECT_SECRET,
                              header.vault_uuid, object_id, 7U,
                              "kilix-secrets.test", nonce, ciphertext,
                              ciphertext_length, decrypted, sizeof decrypted,
                              &decrypted_length) == KSEC_ERR_CRYPTO);
    memcpy(altered_uuid, header.vault_uuid, sizeof altered_uuid);
    altered_uuid[0] ^= 1U;
    CHECK(ksec_record_decrypt(master, KSEC_OBJECT_SECRET, altered_uuid,
                              object_id, 7U, "kilix-secrets.test", nonce,
                              ciphertext, ciphertext_length, decrypted,
                              sizeof decrypted, &decrypted_length)
          == KSEC_ERR_CRYPTO);
    memcpy(altered_id, object_id, sizeof altered_id);
    altered_id[0] ^= 1U;
    CHECK(ksec_record_decrypt(master, KSEC_OBJECT_SECRET, header.vault_uuid,
                              altered_id, 7U, "kilix-secrets.test", nonce,
                              ciphertext, ciphertext_length, decrypted,
                              sizeof decrypted, &decrypted_length)
          == KSEC_ERR_CRYPTO);
    CHECK(ksec_record_decrypt(master, KSEC_OBJECT_SECRET, header.vault_uuid,
                              object_id, 8U, "kilix-secrets.test", nonce,
                              ciphertext, ciphertext_length, decrypted,
                              sizeof decrypted, &decrypted_length)
          == KSEC_ERR_CRYPTO);
    CHECK(ksec_record_decrypt(master, KSEC_OBJECT_SECRET, header.vault_uuid,
                              object_id, 7U, "other-app", nonce,
                              ciphertext, ciphertext_length, decrypted,
                              sizeof decrypted, &decrypted_length)
          == KSEC_ERR_CRYPTO);
    memcpy(altered_nonce, nonce, sizeof altered_nonce);
    altered_nonce[0] ^= 1U;
    CHECK(ksec_record_decrypt(master, KSEC_OBJECT_SECRET, header.vault_uuid,
                              object_id, 7U, "kilix-secrets.test",
                              altered_nonce, ciphertext, ciphertext_length,
                              decrypted, sizeof decrypted, &decrypted_length)
          == KSEC_ERR_CRYPTO);
    memcpy(mutation, ciphertext, ciphertext_length);
    mutation[0] ^= 1U;
    CHECK(ksec_record_decrypt(master, KSEC_OBJECT_SECRET, header.vault_uuid,
                              object_id, 7U, "kilix-secrets.test", nonce,
                              mutation, ciphertext_length, decrypted,
                              sizeof decrypted, &decrypted_length)
          == KSEC_ERR_CRYPTO);
    memcpy(mutation, ciphertext, ciphertext_length);
    mutation[ciphertext_length - 1U] ^= 1U;
    CHECK(ksec_record_decrypt(master, KSEC_OBJECT_SECRET, header.vault_uuid,
                              object_id, 7U, "kilix-secrets.test", nonce,
                              mutation, ciphertext_length, decrypted,
                              sizeof decrypted, &decrypted_length)
          == KSEC_ERR_CRYPTO);
    CHECK(ksec_record_decrypt(master, KSEC_OBJECT_SECRET, header.vault_uuid,
                              object_id, 7U, "kilix-secrets.test", nonce,
                              ciphertext, ciphertext_length - 1U, decrypted,
                              sizeof decrypted, &decrypted_length)
          == KSEC_ERR_CRYPTO);

    CHECK(vector_hex(&vectors, "backup_passphrase", backup_passphrase,
                     sizeof backup_passphrase,
                     &backup_passphrase_length) == 0);
    CHECK(vector_hex(&vectors, "backup_header", backup_header,
                     sizeof backup_header, &backup_header_length) == 0
          && backup_header_length == sizeof backup_header);
    CHECK(vector_hex(&vectors, "backup_ciphertext", backup_ciphertext,
                     sizeof backup_ciphertext,
                     &backup_ciphertext_length) == 0
          && backup_ciphertext_length == header_length + KSEC_TAG_BYTES);
    CHECK(vector_hex(&vectors, "backup_bytes", backup_bytes,
                     sizeof backup_bytes, &backup_bytes_length) == 0
          && backup_bytes_length == backup_header_length
                                   + backup_ciphertext_length
          && sodium_memcmp(backup_bytes, backup_header,
                           backup_header_length) == 0
          && sodium_memcmp(backup_bytes + backup_header_length,
                           backup_ciphertext,
                           backup_ciphertext_length) == 0);
    memcpy(backup_slot_ad, backup_slot_domain, sizeof backup_slot_domain);
    memcpy(backup_slot_ad + 8U, backup_header + 8U, 36U);
    memcpy(backup_slot_ad + 44U, backup_header + 116U, 36U);
    ksec_put_u32(backup_slot_ad + 80U, KSEC_MASTER_KEY_BYTES);
    CHECK(vector_hex(&vectors, "backup_slot_ad", expected_ad,
                     sizeof expected_ad, &expected_ad_length) == 0
          && expected_ad_length == sizeof backup_slot_ad
          && sodium_memcmp(expected_ad, backup_slot_ad,
                           sizeof backup_slot_ad) == 0);
    CHECK(vector_hex(&vectors, "backup_wrapping_key", expected_key,
                     sizeof expected_key, &expected_key_length) == 0
          && crypto_pwhash(
              derived_key, sizeof derived_key,
              (const char *)backup_passphrase,
              (unsigned long long)backup_passphrase_length,
              backup_header + 28U,
              (unsigned long long)ksec_get_u32(backup_header + 16U),
              (size_t)ksec_get_u64(backup_header + 20U),
              crypto_pwhash_ALG_ARGON2ID13) == 0
          && sodium_memcmp(derived_key, expected_key,
                           sizeof derived_key) == 0);
    CHECK(crypto_aead_xchacha20poly1305_ietf_decrypt(
              backup_master, &backup_master_length, NULL,
              backup_header + 68U, KSEC_SLOT_CIPHERTEXT_BYTES,
              backup_slot_ad, sizeof backup_slot_ad,
              backup_header + 44U, derived_key) == 0
          && backup_master_length == sizeof backup_master
          && sodium_memcmp(backup_master, master, sizeof master) == 0);
    CHECK(vector_hex(&vectors, "backup_payload_key", expected_key,
                     sizeof expected_key, &expected_key_length) == 0
          && crypto_kdf_derive_from_key(derived_key, sizeof derived_key, 1U,
                                        backup_context, master) == 0
          && sodium_memcmp(derived_key, expected_key,
                           sizeof derived_key) == 0);
    CHECK(crypto_aead_xchacha20poly1305_ietf_decrypt(
              backup_plaintext, &backup_plaintext_length, NULL,
              backup_ciphertext,
              (unsigned long long)backup_ciphertext_length,
              backup_header, sizeof backup_header, backup_header + 152U,
              derived_key) == 0
          && backup_plaintext_length == header_length
          && sodium_memcmp(backup_plaintext, header_bytes,
                           header_length) == 0);
    memset(&backup_image, 0, sizeof backup_image);
    backup_fd = memfd_create("ksec-vector-backup", MFD_CLOEXEC);
    CHECK(backup_fd >= 0
          && ksec_write_all(backup_fd, backup_bytes, backup_bytes_length) == 0
          && lseek(backup_fd, 0, SEEK_SET) == 0
          && ksec_backup_open(backup_fd, backup_passphrase,
                              backup_passphrase_length,
                              &backup_image) == KSEC_OK
          && backup_image.vault_len == header_length
          && backup_image.journal_len == 0U
          && sodium_memcmp(backup_image.vault, header_bytes,
                           header_length) == 0
          && sodium_memcmp(backup_image.master.data, master,
                           sizeof master) == 0);
    if (backup_fd >= 0) CHECK(close(backup_fd) == 0);
    backup_fd = -1;
    ksec_backup_image_clear(&backup_image);
    backup_bytes[backup_bytes_length - 1U] ^= 1U;
    backup_fd = memfd_create("ksec-vector-backup-corrupt", MFD_CLOEXEC);
    CHECK(backup_fd >= 0
          && ksec_write_all(backup_fd, backup_bytes, backup_bytes_length) == 0
          && lseek(backup_fd, 0, SEEK_SET) == 0
          && ksec_backup_open(backup_fd, backup_passphrase,
                              backup_passphrase_length,
                              &backup_image) == KSEC_ERR_CRYPTO);
    if (backup_fd >= 0) CHECK(close(backup_fd) == 0);
    backup_fd = -1;
    ksec_backup_image_clear(&backup_image);

    sodium_memzero(&vectors, sizeof vectors);
    sodium_memzero(&header, sizeof header);
    sodium_memzero(&mutated_header, sizeof mutated_header);
    sodium_memzero(master, sizeof master);
    sodium_memzero(passphrase, sizeof passphrase);
    sodium_memzero(recovery, sizeof recovery);
    sodium_memzero(unlocked, sizeof unlocked);
    sodium_memzero(expected_key, sizeof expected_key);
    sodium_memzero(derived_key, sizeof derived_key);
    sodium_memzero(expected_ad, sizeof expected_ad);
    sodium_memzero(actual_ad, sizeof actual_ad);
    sodium_memzero(identity_public, sizeof identity_public);
    sodium_memzero(expected_identity_anchor,
                   sizeof expected_identity_anchor);
    sodium_memzero(actual_identity_anchor, sizeof actual_identity_anchor);
    sodium_memzero(plaintext, sizeof plaintext);
    sodium_memzero(ciphertext, sizeof ciphertext);
    sodium_memzero(encrypted, sizeof encrypted);
    sodium_memzero(decrypted, sizeof decrypted);
    sodium_memzero(mutation, sizeof mutation);
    sodium_memzero(backup_passphrase, sizeof backup_passphrase);
    sodium_memzero(backup_header, sizeof backup_header);
    sodium_memzero(backup_ciphertext, sizeof backup_ciphertext);
    sodium_memzero(backup_bytes, sizeof backup_bytes);
    sodium_memzero(backup_slot_ad, sizeof backup_slot_ad);
    sodium_memzero(backup_master, sizeof backup_master);
    sodium_memzero(backup_plaintext, sizeof backup_plaintext);
    printf("full-vector checks: %u/%u passed\n",
           checks_run - checks_failed, checks_run);
    return checks_failed == 0U ? 0 : 1;
}
