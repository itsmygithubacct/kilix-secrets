#include "internal.h"

#include <string.h>

static const uint8_t RECORD_DOMAIN[8] = {'K','S','V','A','D','0','0','1'};
static const uint8_t SLOT_DOMAIN[8] = {'K','S','S','A','D','0','0','1'};

ksec_result ksec_format_record_ad(uint16_t object_type,
                                  const uint8_t vault_uuid[KSEC_UUID_BYTES],
                                  const uint8_t object_id[KSEC_RECORD_ID_BYTES],
                                  uint64_t revision, uint32_t plaintext_length,
                                  const char *owner, uint8_t *output,
                                  size_t output_size, size_t *output_length) {
    size_t owner_length;
    size_t needed;
    size_t offset = 0;
    if (vault_uuid == NULL || object_id == NULL || owner == NULL || output == NULL
            || output_length == NULL || ksec_validate_app_id(owner) != 0
            || revision == 0 || plaintext_length == 0
            || (object_type != KSEC_OBJECT_SECRET
                && object_type != KSEC_OBJECT_DEVICE_IDENTITY
                && object_type != KSEC_OBJECT_BACKUP_METADATA)) {
        return KSEC_ERR_INVALID;
    }
    owner_length = strlen(owner);
    needed = KSEC_RECORD_AD_FIXED_BYTES + owner_length;
    if (needed > output_size || owner_length > UINT16_MAX) return KSEC_ERR_LIMIT;
    memcpy(output + offset, RECORD_DOMAIN, sizeof RECORD_DOMAIN); offset += 8U;
    ksec_put_u16(output + offset, KSEC_FORMAT_VERSION); offset += 2U;
    ksec_put_u16(output + offset, object_type); offset += 2U;
    ksec_put_u16(output + offset, KSEC_KDF_ID_BLAKE2B); offset += 2U;
    ksec_put_u16(output + offset, KSEC_AEAD_ID_XCHACHA20POLY1305); offset += 2U;
    memcpy(output + offset, vault_uuid, KSEC_UUID_BYTES); offset += KSEC_UUID_BYTES;
    memcpy(output + offset, object_id, KSEC_RECORD_ID_BYTES); offset += KSEC_RECORD_ID_BYTES;
    ksec_put_u64(output + offset, revision); offset += 8U;
    ksec_put_u32(output + offset, plaintext_length); offset += 4U;
    ksec_put_u16(output + offset, (uint16_t)owner_length); offset += 2U;
    memcpy(output + offset, owner, owner_length); offset += owner_length;
    *output_length = offset;
    return KSEC_OK;
}

ksec_result ksec_parse_record_ad(const uint8_t *input, size_t input_length,
                                 uint16_t *object_type,
                                 uint8_t vault_uuid[KSEC_UUID_BYTES],
                                 uint8_t object_id[KSEC_RECORD_ID_BYTES],
                                 uint64_t *revision, uint32_t *plaintext_length,
                                 char owner[KSEC_MAX_APP_ID + 1U]) {
    size_t offset = 0;
    uint16_t owner_length;
    if (input == NULL || object_type == NULL || vault_uuid == NULL || object_id == NULL
            || revision == NULL || plaintext_length == NULL || owner == NULL
            || input_length < KSEC_RECORD_AD_FIXED_BYTES) return KSEC_ERR_INVALID;
    if (memcmp(input, RECORD_DOMAIN, 8U) != 0) return KSEC_ERR_INVALID;
    offset += 8U;
    if (ksec_get_u16(input + offset) != KSEC_FORMAT_VERSION) return KSEC_ERR_INVALID;
    offset += 2U;
    *object_type = ksec_get_u16(input + offset); offset += 2U;
    if (*object_type < KSEC_OBJECT_SECRET || *object_type > KSEC_OBJECT_BACKUP_METADATA) return KSEC_ERR_INVALID;
    if (ksec_get_u16(input + offset) != KSEC_KDF_ID_BLAKE2B) return KSEC_ERR_INVALID;
    offset += 2U;
    if (ksec_get_u16(input + offset) != KSEC_AEAD_ID_XCHACHA20POLY1305) return KSEC_ERR_INVALID;
    offset += 2U;
    memcpy(vault_uuid, input + offset, KSEC_UUID_BYTES); offset += KSEC_UUID_BYTES;
    memcpy(object_id, input + offset, KSEC_RECORD_ID_BYTES); offset += KSEC_RECORD_ID_BYTES;
    *revision = ksec_get_u64(input + offset); offset += 8U;
    *plaintext_length = ksec_get_u32(input + offset); offset += 4U;
    owner_length = ksec_get_u16(input + offset); offset += 2U;
    if (owner_length == 0 || owner_length > KSEC_MAX_APP_ID
            || input_length != offset + owner_length || *revision == 0
            || *plaintext_length == 0) return KSEC_ERR_INVALID;
    if (ksec_validate_app_id_bytes(input + offset, owner_length) != 0) {
        return KSEC_ERR_INVALID;
    }
    memcpy(owner, input + offset, owner_length);
    owner[owner_length] = '\0';
    return KSEC_OK;
}

ksec_result ksec_format_slot_ad(const ksec_vault_header *header,
                                const ksec_key_slot *slot, uint8_t *output,
                                size_t output_size, size_t *output_length) {
    size_t offset = 0;
    size_t needed = KSEC_SLOT_AD_FIXED_BYTES + KSEC_SALT_BYTES;
    if (header == NULL || slot == NULL || output == NULL || output_length == NULL
            || output_size < needed || header->format_version != KSEC_FORMAT_VERSION
            || (slot->slot_type != KSEC_SLOT_PASSPHRASE
                && slot->slot_type != KSEC_SLOT_RECOVERY)
            || slot->slot_version != 1U
            || slot->pwhash_id != KSEC_PWHASH_ID_ARGON2ID13
            || slot->aead_id != KSEC_AEAD_ID_XCHACHA20POLY1305
            || slot->opslimit < KSEC_ARGON_OPS_MIN || slot->opslimit > KSEC_ARGON_OPS_MAX
            || slot->memlimit < KSEC_ARGON_MEM_MIN || slot->memlimit > KSEC_ARGON_MEM_MAX) {
        return KSEC_ERR_INVALID;
    }
    memcpy(output + offset, SLOT_DOMAIN, sizeof SLOT_DOMAIN); offset += 8U;
    ksec_put_u16(output + offset, header->format_version); offset += 2U;
    ksec_put_u16(output + offset, slot->slot_type); offset += 2U;
    ksec_put_u16(output + offset, slot->slot_version); offset += 2U;
    ksec_put_u16(output + offset, slot->pwhash_id); offset += 2U;
    ksec_put_u16(output + offset, slot->aead_id); offset += 2U;
    memcpy(output + offset, header->vault_uuid, KSEC_UUID_BYTES); offset += KSEC_UUID_BYTES;
    memcpy(output + offset, slot->slot_id, KSEC_SLOT_ID_BYTES); offset += KSEC_SLOT_ID_BYTES;
    ksec_put_u32(output + offset, slot->opslimit); offset += 4U;
    ksec_put_u64(output + offset, slot->memlimit); offset += 8U;
    ksec_put_u16(output + offset, KSEC_SALT_BYTES); offset += 2U;
    memcpy(output + offset, slot->salt, KSEC_SALT_BYTES); offset += KSEC_SALT_BYTES;
    ksec_put_u32(output + offset, KSEC_MASTER_KEY_BYTES); offset += 4U;
    *output_length = offset;
    return KSEC_OK;
}
