#include "internal.h"

#include <stdio.h>
#include <string.h>

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

static int make_slot(ksec_vault_header *header, ksec_key_slot *slot,
                     uint16_t slot_type, uint8_t id_first,
                     uint8_t salt_first, uint8_t nonce_first,
                     const uint8_t *secret, size_t secret_length,
                     const uint8_t master_key[KSEC_MASTER_KEY_BYTES],
                     uint8_t wrapping_key[32], uint8_t *ad,
                     size_t *ad_length) {
    unsigned long long wrapped_length = 0U;
    memset(slot, 0, sizeof *slot);
    slot->slot_type = slot_type;
    slot->slot_version = 1U;
    slot->pwhash_id = KSEC_PWHASH_ID_ARGON2ID13;
    slot->aead_id = KSEC_AEAD_ID_XCHACHA20POLY1305;
    slot->opslimit = KSEC_ARGON_OPS_MIN;
    slot->memlimit = KSEC_ARGON_MEM_MIN;
    fill_sequence(slot->slot_id, sizeof slot->slot_id, id_first);
    fill_sequence(slot->salt, sizeof slot->salt, salt_first);
    fill_sequence(slot->nonce, sizeof slot->nonce, nonce_first);
    if (crypto_pwhash(wrapping_key, 32U, (const char *)secret,
                      (unsigned long long)secret_length, slot->salt,
                      (unsigned long long)slot->opslimit,
                      (size_t)slot->memlimit,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) return -1;
    if (ksec_format_slot_ad(header, slot, ad,
                            KSEC_SLOT_AD_FIXED_BYTES + KSEC_SALT_BYTES,
                            ad_length) != KSEC_OK) return -1;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            slot->wrapped, &wrapped_length, master_key, KSEC_MASTER_KEY_BYTES,
            ad, (unsigned long long)*ad_length, NULL, slot->nonce,
            wrapping_key) != 0
            || wrapped_length != KSEC_SLOT_CIPHERTEXT_BYTES) return -1;
    return 0;
}

int main(void) {
    static const uint8_t passphrase[] = "synthetic-vector-passphrase";
    static const uint8_t recovery[] =
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    static const uint8_t backup_passphrase[] =
        "synthetic-vector-backup-passphrase";
    static const uint8_t field_value[] = {
        0x00U, 0x01U, 0x02U, 0x7fU, 0x80U, 0xfeU, 0xffU
    };
    static const char header_context[8] = {'K','S','V','H','D','R','0','1'};
    static const char record_context[8] = {'K','S','V','R','E','C','0','1'};
    static const char backup_context[8] = {'K','S','B','A','C','K','0','1'};
    static const uint8_t backup_slot_domain[8] = {
        'K','S','B','K','S','L','0','1'
    };
    ksec_vault_header header;
    ksec_field field;
    ksec_record record;
    uint8_t master_key[32];
    uint8_t record_key[32];
    uint8_t header_key[32];
    uint8_t slot0_key[32];
    uint8_t slot1_key[32];
    uint8_t slot0_ad[KSEC_SLOT_AD_FIXED_BYTES + KSEC_SALT_BYTES];
    uint8_t slot1_ad[KSEC_SLOT_AD_FIXED_BYTES + KSEC_SALT_BYTES];
    size_t slot0_ad_length = 0U;
    size_t slot1_ad_length = 0U;
    uint8_t object_id[16];
    uint8_t identity_public[KSEC_IDENTITY_KEY_BYTES];
    uint8_t identity_anchor[KSEC_IDENTITY_ANCHOR_BYTES];
    uint8_t record_ad[KSEC_RECORD_AD_FIXED_BYTES + KSEC_MAX_APP_ID];
    size_t record_ad_length = 0U;
    uint8_t record_nonce[24];
    uint8_t plaintext[1024];
    size_t plaintext_length = 0U;
    uint8_t ciphertext[1024 + KSEC_TAG_BYTES];
    unsigned long long ciphertext_length = 0U;
    uint8_t encoded_header[1024];
    size_t encoded_header_length = 0U;
    size_t header_base_length;
    unsigned long long tag_length = 0U;
    uint8_t backup_header[176];
    uint8_t backup_slot_ad[84];
    uint8_t backup_wrapping_key[32];
    uint8_t backup_payload_key[32];
    uint8_t backup_ciphertext[1024 + KSEC_TAG_BYTES];
    uint8_t backup_bytes[176 + 1024 + KSEC_TAG_BYTES];
    unsigned long long backup_wrapped_length = 0U;
    unsigned long long backup_ciphertext_length = 0U;
    size_t backup_bytes_length = 0U;
    int result = 1;

    if (ksec_crypto_initialize() != KSEC_OK) return 1;
    memset(&header, 0, sizeof header);
    memset(&record, 0, sizeof record);
    header.format_version = KSEC_FORMAT_VERSION;
    header.generation = 2U;
    header.slot_count = 2U;
    header.flags = KSEC_HEADER_FLAG_RECOVERY_CONFIRMED;
    fill_sequence(master_key, sizeof master_key, 0x00U);
    fill_sequence(header.vault_uuid, sizeof header.vault_uuid, 0x10U);
    fill_sequence(object_id, sizeof object_id, 0x20U);
    if (crypto_scalarmult_curve25519_base(identity_public, master_key) != 0
            || ksec_identity_anchor(header.vault_uuid, object_id, 7U,
                                    identity_public,
                                    identity_anchor) != KSEC_OK) goto out;

    if (make_slot(&header, &header.slots[0], KSEC_SLOT_PASSPHRASE,
                  0x40U, 0x60U, 0x80U, passphrase,
                  sizeof passphrase - 1U, master_key, slot0_key,
                  slot0_ad, &slot0_ad_length) != 0) goto out;
    if (make_slot(&header, &header.slots[1], KSEC_SLOT_RECOVERY,
                  0x50U, 0x70U, 0xa0U, recovery,
                  sizeof recovery - 1U, master_key, slot1_key,
                  slot1_ad, &slot1_ad_length) != 0) goto out;

    fill_sequence(header.auth_nonce, sizeof header.auth_nonce, 0xc0U);
    if (crypto_kdf_derive_from_key(header_key, sizeof header_key, 1U,
                                   header_context, master_key) != 0
            || ksec_header_encode(&header, encoded_header,
                                  sizeof encoded_header,
                                  &encoded_header_length) != KSEC_OK) goto out;
    header_base_length = encoded_header_length - KSEC_NONCE_BYTES
        - KSEC_HEADER_TAG_BYTES;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            header.auth_tag, &tag_length, NULL, 0U, encoded_header,
            (unsigned long long)header_base_length, NULL, header.auth_nonce,
            header_key) != 0 || tag_length != KSEC_HEADER_TAG_BYTES
            || ksec_header_encode(&header, encoded_header,
                                  sizeof encoded_header,
                                  &encoded_header_length) != KSEC_OK) goto out;

    field.name = "binary";
    field.value = field_value;
    field.value_len = sizeof field_value;
    record.owner = "kilix-secrets.test";
    record.type = "opaque";
    record.label = "Synthetic full vector";
    record.expires_at = UINT64_C(2000000000);
    record.fields = &field;
    record.field_count = 1U;
    if (ksec_record_serialize(&record, plaintext, sizeof plaintext,
                              &plaintext_length) != KSEC_OK
            || ksec_format_record_ad(KSEC_OBJECT_SECRET, header.vault_uuid,
                                     object_id, 7U,
                                     (uint32_t)plaintext_length,
                                     record.owner, record_ad, sizeof record_ad,
                                     &record_ad_length) != KSEC_OK
            || crypto_kdf_derive_from_key(record_key, sizeof record_key, 1U,
                                          record_context, master_key) != 0) {
        goto out;
    }
    fill_sequence(record_nonce, sizeof record_nonce, 0xe0U);
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            ciphertext, &ciphertext_length, plaintext,
            (unsigned long long)plaintext_length, record_ad,
            (unsigned long long)record_ad_length, NULL, record_nonce,
            record_key) != 0) goto out;

    memset(backup_header, 0, sizeof backup_header);
    memcpy(backup_header, "KSVBAK01", 8U);
    ksec_put_u16(backup_header + 8U, 1U);
    ksec_put_u16(backup_header + 10U, KSEC_PWHASH_ID_ARGON2ID13);
    ksec_put_u16(backup_header + 12U, KSEC_KDF_ID_BLAKE2B);
    ksec_put_u16(backup_header + 14U, KSEC_AEAD_ID_XCHACHA20POLY1305);
    ksec_put_u32(backup_header + 16U, KSEC_ARGON_OPS_MIN);
    ksec_put_u64(backup_header + 20U, KSEC_ARGON_MEM_MIN);
    fill_sequence(backup_header + 28U, KSEC_SALT_BYTES, 0x30U);
    fill_sequence(backup_header + 44U, KSEC_NONCE_BYTES, 0x48U);
    memcpy(backup_header + 116U, header.vault_uuid, KSEC_UUID_BYTES);
    ksec_put_u64(backup_header + 132U, header.generation);
    ksec_put_u32(backup_header + 140U, (uint32_t)encoded_header_length);
    ksec_put_u64(backup_header + 144U, 0U);
    fill_sequence(backup_header + 152U, KSEC_NONCE_BYTES, 0xd0U);
    memcpy(backup_slot_ad, backup_slot_domain, sizeof backup_slot_domain);
    memcpy(backup_slot_ad + 8U, backup_header + 8U, 36U);
    memcpy(backup_slot_ad + 44U, backup_header + 116U, 36U);
    ksec_put_u32(backup_slot_ad + 80U, KSEC_MASTER_KEY_BYTES);
    if (crypto_pwhash(
            backup_wrapping_key, sizeof backup_wrapping_key,
            (const char *)backup_passphrase,
            (unsigned long long)(sizeof backup_passphrase - 1U),
            backup_header + 28U, KSEC_ARGON_OPS_MIN,
            (size_t)KSEC_ARGON_MEM_MIN,
            crypto_pwhash_ALG_ARGON2ID13) != 0
            || crypto_aead_xchacha20poly1305_ietf_encrypt(
                backup_header + 68U, &backup_wrapped_length, master_key,
                sizeof master_key, backup_slot_ad, sizeof backup_slot_ad,
                NULL, backup_header + 44U, backup_wrapping_key) != 0
            || backup_wrapped_length != KSEC_SLOT_CIPHERTEXT_BYTES
            || crypto_kdf_derive_from_key(
                backup_payload_key, sizeof backup_payload_key, 1U,
                backup_context, master_key) != 0
            || crypto_aead_xchacha20poly1305_ietf_encrypt(
                backup_ciphertext, &backup_ciphertext_length, encoded_header,
                (unsigned long long)encoded_header_length, backup_header,
                sizeof backup_header, NULL, backup_header + 152U,
                backup_payload_key) != 0) goto out;
    backup_bytes_length = sizeof backup_header
        + (size_t)backup_ciphertext_length;
    memcpy(backup_bytes, backup_header, sizeof backup_header);
    memcpy(backup_bytes + sizeof backup_header, backup_ciphertext,
           (size_t)backup_ciphertext_length);

    puts("vector_format=KSEC-FULL-V1");
    puts("provider=libsodium-1.0.18-1+deb13u1");
    puts("format_version=1");
    puts("kdf_id=1");
    puts("aead_id=1");
    puts("argon2id_opslimit=3");
    puts("argon2id_memlimit=268435456");
    print_hex("master_key", master_key, sizeof master_key);
    print_hex("vault_uuid", header.vault_uuid, sizeof header.vault_uuid);
    puts("header_generation=2");
    puts("header_flags=1");
    print_hex("passphrase", passphrase, sizeof passphrase - 1U);
    print_hex("slot0_id", header.slots[0].slot_id,
              sizeof header.slots[0].slot_id);
    print_hex("slot0_salt", header.slots[0].salt,
              sizeof header.slots[0].salt);
    print_hex("slot0_ad", slot0_ad, slot0_ad_length);
    print_hex("slot0_key", slot0_key, sizeof slot0_key);
    print_hex("slot0_nonce", header.slots[0].nonce,
              sizeof header.slots[0].nonce);
    print_hex("slot0_wrapped", header.slots[0].wrapped,
              sizeof header.slots[0].wrapped);
    print_hex("recovery", recovery, sizeof recovery - 1U);
    print_hex("slot1_id", header.slots[1].slot_id,
              sizeof header.slots[1].slot_id);
    print_hex("slot1_salt", header.slots[1].salt,
              sizeof header.slots[1].salt);
    print_hex("slot1_ad", slot1_ad, slot1_ad_length);
    print_hex("slot1_key", slot1_key, sizeof slot1_key);
    print_hex("slot1_nonce", header.slots[1].nonce,
              sizeof header.slots[1].nonce);
    print_hex("slot1_wrapped", header.slots[1].wrapped,
              sizeof header.slots[1].wrapped);
    print_hex("header_key", header_key, sizeof header_key);
    print_hex("header_nonce", header.auth_nonce, sizeof header.auth_nonce);
    print_hex("header_tag", header.auth_tag, sizeof header.auth_tag);
    print_hex("header_bytes", encoded_header, encoded_header_length);
    print_hex("object_id", object_id, sizeof object_id);
    puts("record_revision=7");
    print_hex("identity_public_key", identity_public,
              sizeof identity_public);
    print_hex("identity_anchor", identity_anchor, sizeof identity_anchor);
    puts("record_owner=kilix-secrets.test");
    print_hex("record_plaintext", plaintext, plaintext_length);
    print_hex("record_ad", record_ad, record_ad_length);
    print_hex("record_key", record_key, sizeof record_key);
    print_hex("record_nonce", record_nonce, sizeof record_nonce);
    print_hex("record_ciphertext", ciphertext, (size_t)ciphertext_length);
    print_hex("backup_passphrase", backup_passphrase,
              sizeof backup_passphrase - 1U);
    print_hex("backup_salt", backup_header + 28U, KSEC_SALT_BYTES);
    print_hex("backup_wrap_nonce", backup_header + 44U, KSEC_NONCE_BYTES);
    print_hex("backup_slot_ad", backup_slot_ad, sizeof backup_slot_ad);
    print_hex("backup_wrapping_key", backup_wrapping_key,
              sizeof backup_wrapping_key);
    print_hex("backup_wrapped_master", backup_header + 68U,
              KSEC_SLOT_CIPHERTEXT_BYTES);
    print_hex("backup_payload_key", backup_payload_key,
              sizeof backup_payload_key);
    print_hex("backup_payload_nonce", backup_header + 152U,
              KSEC_NONCE_BYTES);
    print_hex("backup_header", backup_header, sizeof backup_header);
    print_hex("backup_ciphertext", backup_ciphertext,
              (size_t)backup_ciphertext_length);
    print_hex("backup_bytes", backup_bytes, backup_bytes_length);
    result = 0;
out:
    sodium_memzero(&header, sizeof header);
    sodium_memzero(master_key, sizeof master_key);
    sodium_memzero(record_key, sizeof record_key);
    sodium_memzero(header_key, sizeof header_key);
    sodium_memzero(slot0_key, sizeof slot0_key);
    sodium_memzero(slot1_key, sizeof slot1_key);
    sodium_memzero(slot0_ad, sizeof slot0_ad);
    sodium_memzero(slot1_ad, sizeof slot1_ad);
    sodium_memzero(identity_public, sizeof identity_public);
    sodium_memzero(identity_anchor, sizeof identity_anchor);
    sodium_memzero(record_ad, sizeof record_ad);
    sodium_memzero(plaintext, sizeof plaintext);
    sodium_memzero(ciphertext, sizeof ciphertext);
    sodium_memzero(encoded_header, sizeof encoded_header);
    sodium_memzero(backup_header, sizeof backup_header);
    sodium_memzero(backup_slot_ad, sizeof backup_slot_ad);
    sodium_memzero(backup_wrapping_key, sizeof backup_wrapping_key);
    sodium_memzero(backup_payload_key, sizeof backup_payload_key);
    sodium_memzero(backup_ciphertext, sizeof backup_ciphertext);
    sodium_memzero(backup_bytes, sizeof backup_bytes);
    return result;
}
