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
    static const uint8_t field_value[] = {
        0x00U, 0x01U, 0x02U, 0x7fU, 0x80U, 0xfeU, 0xffU
    };
    static const char header_context[8] = {'K','S','V','H','D','R','0','1'};
    static const char record_context[8] = {'K','S','V','R','E','C','0','1'};
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
    int result = 1;

    if (ksec_crypto_initialize() != KSEC_OK) return 1;
    memset(&header, 0, sizeof header);
    header.format_version = KSEC_FORMAT_VERSION;
    header.generation = 2U;
    header.slot_count = 2U;
    header.flags = KSEC_HEADER_FLAG_RECOVERY_CONFIRMED;
    fill_sequence(master_key, sizeof master_key, 0x00U);
    fill_sequence(header.vault_uuid, sizeof header.vault_uuid, 0x10U);
    fill_sequence(object_id, sizeof object_id, 0x20U);

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
    puts("record_owner=kilix-secrets.test");
    print_hex("record_plaintext", plaintext, plaintext_length);
    print_hex("record_ad", record_ad, record_ad_length);
    print_hex("record_key", record_key, sizeof record_key);
    print_hex("record_nonce", record_nonce, sizeof record_nonce);
    print_hex("record_ciphertext", ciphertext, (size_t)ciphertext_length);
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
    sodium_memzero(record_ad, sizeof record_ad);
    sodium_memzero(plaintext, sizeof plaintext);
    sodium_memzero(ciphertext, sizeof ciphertext);
    sodium_memzero(encoded_header, sizeof encoded_header);
    return result;
}
