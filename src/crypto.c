#include "internal.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

enum {
    KSEC_HEADER_PREFIX_BYTES = 42,
    KSEC_SLOT_BYTES = 124,
    KSEC_HEADER_BASE_BYTES = KSEC_HEADER_PREFIX_BYTES + 2 * KSEC_SLOT_BYTES,
    KSEC_HEADER_BYTES = KSEC_HEADER_BASE_BYTES + KSEC_NONCE_BYTES + KSEC_HEADER_TAG_BYTES,
    KSEC_RECORD_PLAIN_FIXED_BYTES = 26
};

static const uint8_t HEADER_MAGIC[8] = {'K','S','V','L','T','0','0','1'};
static const uint8_t RECORD_PLAIN_MAGIC[8] = {'K','S','R','P','L','0','0','1'};
static const char HEADER_CONTEXT[crypto_kdf_CONTEXTBYTES] = {'K','S','V','H','D','R','0','1'};
static const char RECORD_CONTEXT[crypto_kdf_CONTEXTBYTES] = {'K','S','V','R','E','C','0','1'};

static ksec_result encode_header_base(const ksec_vault_header *header,
                                      uint8_t output[KSEC_HEADER_BASE_BYTES]) {
    size_t offset = 0;
    size_t index;
    if (header == NULL || header->format_version != KSEC_FORMAT_VERSION
            || header->generation == 0 || header->slot_count != 2U
            || (header->flags & (uint16_t)~KSEC_HEADER_FLAG_RECOVERY_CONFIRMED) != 0U
            || header->slots[0].slot_type == header->slots[1].slot_type
            || sodium_memcmp(header->slots[0].slot_id, header->slots[1].slot_id,
                             KSEC_SLOT_ID_BYTES) == 0) {
        return KSEC_ERR_INVALID;
    }
    memcpy(output + offset, HEADER_MAGIC, sizeof HEADER_MAGIC); offset += 8U;
    ksec_put_u16(output + offset, header->format_version); offset += 2U;
    ksec_put_u32(output + offset, KSEC_HEADER_BYTES); offset += 4U;
    memcpy(output + offset, header->vault_uuid, KSEC_UUID_BYTES); offset += KSEC_UUID_BYTES;
    ksec_put_u64(output + offset, header->generation); offset += 8U;
    ksec_put_u16(output + offset, header->slot_count); offset += 2U;
    ksec_put_u16(output + offset, header->flags); offset += 2U;
    for (index = 0; index < 2U; index++) {
        const ksec_key_slot *slot = &header->slots[index];
        if ((slot->slot_type != KSEC_SLOT_PASSPHRASE
                && slot->slot_type != KSEC_SLOT_RECOVERY)
                || slot->slot_version != 1U
                || slot->pwhash_id != KSEC_PWHASH_ID_ARGON2ID13
                || slot->aead_id != KSEC_AEAD_ID_XCHACHA20POLY1305
                || slot->opslimit < KSEC_ARGON_OPS_MIN
                || slot->opslimit > KSEC_ARGON_OPS_MAX
                || slot->memlimit < KSEC_ARGON_MEM_MIN
                || slot->memlimit > KSEC_ARGON_MEM_MAX) {
            return KSEC_ERR_INVALID;
        }
        ksec_put_u16(output + offset, slot->slot_type); offset += 2U;
        ksec_put_u16(output + offset, slot->slot_version); offset += 2U;
        ksec_put_u16(output + offset, slot->pwhash_id); offset += 2U;
        ksec_put_u16(output + offset, slot->aead_id); offset += 2U;
        memcpy(output + offset, slot->slot_id, KSEC_SLOT_ID_BYTES); offset += KSEC_SLOT_ID_BYTES;
        ksec_put_u32(output + offset, slot->opslimit); offset += 4U;
        ksec_put_u64(output + offset, slot->memlimit); offset += 8U;
        memcpy(output + offset, slot->salt, KSEC_SALT_BYTES); offset += KSEC_SALT_BYTES;
        memcpy(output + offset, slot->nonce, KSEC_NONCE_BYTES); offset += KSEC_NONCE_BYTES;
        memcpy(output + offset, slot->wrapped, KSEC_SLOT_CIPHERTEXT_BYTES);
        offset += KSEC_SLOT_CIPHERTEXT_BYTES;
    }
    return offset == KSEC_HEADER_BASE_BYTES ? KSEC_OK : KSEC_ERR_INVALID;
}

static ksec_result derive_terminal_key(const uint8_t master_key[KSEC_MASTER_KEY_BYTES],
                                       const char context[crypto_kdf_CONTEXTBYTES],
                                       uint8_t output[crypto_aead_xchacha20poly1305_ietf_KEYBYTES]) {
    if (crypto_kdf_derive_from_key(
            output, crypto_aead_xchacha20poly1305_ietf_KEYBYTES, 1U, context,
                                   master_key) != 0) {
        return KSEC_ERR_CRYPTO;
    }
    return KSEC_OK;
}

static ksec_result derive_slot_key(const ksec_key_slot *slot,
                                   const uint8_t *secret, size_t secret_len,
                                   uint8_t output[crypto_aead_xchacha20poly1305_ietf_KEYBYTES]) {
    if (slot == NULL || secret == NULL || secret_len == 0 || secret_len > 1024U
            || slot->opslimit < KSEC_ARGON_OPS_MIN
            || slot->opslimit > KSEC_ARGON_OPS_MAX
            || slot->memlimit < KSEC_ARGON_MEM_MIN
            || slot->memlimit > KSEC_ARGON_MEM_MAX
            || slot->memlimit > SIZE_MAX) {
        return KSEC_ERR_INVALID;
    }
    if (crypto_pwhash(output, crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
                      (const char *)secret, (unsigned long long)secret_len,
                      slot->salt, (unsigned long long)slot->opslimit,
                      (size_t)slot->memlimit,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        return KSEC_ERR_MEMORY;
    }
    return KSEC_OK;
}

static ksec_result wrap_slot(const ksec_vault_header *header, ksec_key_slot *slot,
                             const uint8_t *secret, size_t secret_len,
                             const uint8_t master_key[KSEC_MASTER_KEY_BYTES]) {
    uint8_t wrapping_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    uint8_t ad[KSEC_SLOT_AD_FIXED_BYTES + KSEC_SALT_BYTES];
    size_t ad_len = 0;
    unsigned long long wrapped_len = 0;
    ksec_result result = derive_slot_key(slot, secret, secret_len, wrapping_key);
    if (result != KSEC_OK) return result;
    result = ksec_format_slot_ad(header, slot, ad, sizeof ad, &ad_len);
    if (result != KSEC_OK) goto out;
    randombytes_buf(slot->nonce, KSEC_NONCE_BYTES);
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            slot->wrapped, &wrapped_len, master_key, KSEC_MASTER_KEY_BYTES,
            ad, (unsigned long long)ad_len, NULL, slot->nonce, wrapping_key) != 0
            || wrapped_len != KSEC_SLOT_CIPHERTEXT_BYTES) {
        result = KSEC_ERR_CRYPTO;
    }
out:
    sodium_memzero(wrapping_key, sizeof wrapping_key);
    sodium_memzero(ad, sizeof ad);
    return result;
}

static ksec_result authenticate_header(ksec_vault_header *header,
                                       const uint8_t master_key[KSEC_MASTER_KEY_BYTES]) {
    uint8_t base[KSEC_HEADER_BASE_BYTES];
    uint8_t header_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    unsigned long long tag_len = 0;
    ksec_result result = encode_header_base(header, base);
    if (result != KSEC_OK) return result;
    result = derive_terminal_key(master_key, HEADER_CONTEXT, header_key);
    if (result != KSEC_OK) goto out;
    randombytes_buf(header->auth_nonce, KSEC_NONCE_BYTES);
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            header->auth_tag, &tag_len, NULL, 0U, base, sizeof base, NULL,
            header->auth_nonce, header_key) != 0
            || tag_len != KSEC_HEADER_TAG_BYTES) {
        result = KSEC_ERR_CRYPTO;
    }
out:
    sodium_memzero(header_key, sizeof header_key);
    sodium_memzero(base, sizeof base);
    return result;
}

static ksec_result verify_header(const ksec_vault_header *header,
                                 const uint8_t master_key[KSEC_MASTER_KEY_BYTES]) {
    uint8_t base[KSEC_HEADER_BASE_BYTES];
    uint8_t header_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    uint8_t empty[1] = {0};
    unsigned long long decoded_len = 0;
    ksec_result result = encode_header_base(header, base);
    if (result != KSEC_OK) return result;
    result = derive_terminal_key(master_key, HEADER_CONTEXT, header_key);
    if (result != KSEC_OK) goto out;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            empty, &decoded_len, NULL, header->auth_tag, KSEC_HEADER_TAG_BYTES,
            base, sizeof base, header->auth_nonce, header_key) != 0
            || decoded_len != 0U) {
        result = KSEC_ERR_CRYPTO;
    }
out:
    sodium_memzero(header_key, sizeof header_key);
    sodium_memzero(base, sizeof base);
    sodium_memzero(empty, sizeof empty);
    return result;
}

ksec_result ksec_crypto_initialize(void) {
    return sodium_init() < 0 ? KSEC_ERR_CRYPTO : KSEC_OK;
}

ksec_result ksec_header_create(ksec_vault_header *header,
                               const uint8_t *passphrase, size_t passphrase_len,
                               const uint8_t *recovery, size_t recovery_len,
                               uint32_t opslimit, uint64_t memlimit,
                               uint8_t master_key[KSEC_MASTER_KEY_BYTES]) {
    size_t index;
    ksec_result result;
    if (header == NULL || passphrase == NULL || recovery == NULL || master_key == NULL
            || passphrase_len < 8U || passphrase_len > 1024U
            || recovery_len < 32U || recovery_len > 1024U
            || opslimit < KSEC_ARGON_OPS_MIN || opslimit > KSEC_ARGON_OPS_MAX
            || memlimit < KSEC_ARGON_MEM_MIN || memlimit > KSEC_ARGON_MEM_MAX) {
        return KSEC_ERR_INVALID;
    }
    memset(header, 0, sizeof *header);
    header->format_version = KSEC_FORMAT_VERSION;
    header->generation = 1U;
    header->slot_count = 2U;
    randombytes_buf(header->vault_uuid, KSEC_UUID_BYTES);
    randombytes_buf(master_key, KSEC_MASTER_KEY_BYTES);
    for (index = 0; index < 2U; index++) {
        ksec_key_slot *slot = &header->slots[index];
        slot->slot_type = index == 0U ? KSEC_SLOT_PASSPHRASE : KSEC_SLOT_RECOVERY;
        slot->slot_version = 1U;
        slot->pwhash_id = KSEC_PWHASH_ID_ARGON2ID13;
        slot->aead_id = KSEC_AEAD_ID_XCHACHA20POLY1305;
        slot->opslimit = opslimit;
        slot->memlimit = memlimit;
        randombytes_buf(slot->slot_id, KSEC_SLOT_ID_BYTES);
        randombytes_buf(slot->salt, KSEC_SALT_BYTES);
    }
    result = wrap_slot(header, &header->slots[0], passphrase, passphrase_len, master_key);
    if (result != KSEC_OK) goto fail;
    result = wrap_slot(header, &header->slots[1], recovery, recovery_len, master_key);
    if (result != KSEC_OK) goto fail;
    result = authenticate_header(header, master_key);
    if (result != KSEC_OK) goto fail;
    return KSEC_OK;
fail:
    sodium_memzero(master_key, KSEC_MASTER_KEY_BYTES);
    sodium_memzero(header, sizeof *header);
    return result;
}

ksec_result ksec_header_unlock(const ksec_vault_header *header,
                               ksec_slot_type slot_type,
                               const uint8_t *secret, size_t secret_len,
                               uint8_t master_key[KSEC_MASTER_KEY_BYTES]) {
    const ksec_key_slot *slot = NULL;
    uint8_t wrapping_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    uint8_t ad[KSEC_SLOT_AD_FIXED_BYTES + KSEC_SALT_BYTES];
    size_t ad_len = 0;
    unsigned long long master_len = 0;
    size_t index;
    ksec_result result;
    if (header == NULL || secret == NULL || master_key == NULL
            || header->format_version != KSEC_FORMAT_VERSION
            || header->generation == 0U || header->slot_count != 2U
            || header->slots[0].slot_type == header->slots[1].slot_type
            || sodium_memcmp(header->slots[0].slot_id, header->slots[1].slot_id,
                             KSEC_SLOT_ID_BYTES) == 0
            || (slot_type != KSEC_SLOT_PASSPHRASE && slot_type != KSEC_SLOT_RECOVERY)) {
        if (master_key != NULL) sodium_memzero(master_key, KSEC_MASTER_KEY_BYTES);
        return KSEC_ERR_INVALID;
    }
    for (index = 0; index < header->slot_count; index++) {
        if (header->slots[index].slot_type == (uint16_t)slot_type) {
            if (slot != NULL) return KSEC_ERR_INVALID;
            slot = &header->slots[index];
        }
    }
    if (slot == NULL) {
        sodium_memzero(master_key, KSEC_MASTER_KEY_BYTES);
        return KSEC_ERR_NOT_FOUND;
    }
    result = derive_slot_key(slot, secret, secret_len, wrapping_key);
    if (result != KSEC_OK) {
        sodium_memzero(master_key, KSEC_MASTER_KEY_BYTES);
        return result;
    }
    result = ksec_format_slot_ad(header, slot, ad, sizeof ad, &ad_len);
    if (result != KSEC_OK) goto out;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            master_key, &master_len, NULL, slot->wrapped, KSEC_SLOT_CIPHERTEXT_BYTES,
            ad, (unsigned long long)ad_len, slot->nonce, wrapping_key) != 0
            || master_len != KSEC_MASTER_KEY_BYTES) {
        result = KSEC_ERR_CRYPTO;
        goto out;
    }
    result = verify_header(header, master_key);
    if (result != KSEC_OK) sodium_memzero(master_key, KSEC_MASTER_KEY_BYTES);
out:
    if (result != KSEC_OK) sodium_memzero(master_key, KSEC_MASTER_KEY_BYTES);
    sodium_memzero(wrapping_key, sizeof wrapping_key);
    sodium_memzero(ad, sizeof ad);
    return result;
}

ksec_result ksec_header_confirm_recovery(
        ksec_vault_header *header,
        const uint8_t master_key[KSEC_MASTER_KEY_BYTES]) {
    uint8_t old_nonce[KSEC_NONCE_BYTES];
    uint8_t old_tag[KSEC_HEADER_TAG_BYTES];
    uint64_t old_generation;
    ksec_result result;
    if (header == NULL || master_key == NULL
            || (header->flags & (uint16_t)~KSEC_HEADER_FLAG_RECOVERY_CONFIRMED) != 0U) {
        return KSEC_ERR_INVALID;
    }
    if ((header->flags & KSEC_HEADER_FLAG_RECOVERY_CONFIRMED) != 0U) {
        return KSEC_ERR_EXISTS;
    }
    if (header->generation == UINT64_MAX) return KSEC_ERR_LIMIT;
    result = verify_header(header, master_key);
    if (result != KSEC_OK) return result;
    old_generation = header->generation;
    memcpy(old_nonce, header->auth_nonce, sizeof old_nonce);
    memcpy(old_tag, header->auth_tag, sizeof old_tag);
    header->generation++;
    header->flags |= KSEC_HEADER_FLAG_RECOVERY_CONFIRMED;
    result = authenticate_header(header, master_key);
    if (result != KSEC_OK) {
        header->generation = old_generation;
        header->flags &= (uint16_t)~KSEC_HEADER_FLAG_RECOVERY_CONFIRMED;
        memcpy(header->auth_nonce, old_nonce, sizeof old_nonce);
        memcpy(header->auth_tag, old_tag, sizeof old_tag);
    }
    sodium_memzero(old_nonce, sizeof old_nonce);
    sodium_memzero(old_tag, sizeof old_tag);
    return result;
}

ksec_result ksec_header_rewrap_slot(
        ksec_vault_header *header, ksec_slot_type slot_type,
        const uint8_t *new_secret, size_t new_secret_len,
        uint32_t opslimit, uint64_t memlimit,
        const uint8_t master_key[KSEC_MASTER_KEY_BYTES]) {
    ksec_vault_header previous;
    ksec_key_slot *slot = NULL;
    size_t index;
    ksec_result result;
    if (header == NULL || new_secret == NULL || master_key == NULL
            || (slot_type != KSEC_SLOT_PASSPHRASE
                && slot_type != KSEC_SLOT_RECOVERY)
            || (slot_type == KSEC_SLOT_PASSPHRASE && new_secret_len < 8U)
            || (slot_type == KSEC_SLOT_RECOVERY && new_secret_len < 32U)
            || new_secret_len > 1024U
            || opslimit < KSEC_ARGON_OPS_MIN || opslimit > KSEC_ARGON_OPS_MAX
            || memlimit < KSEC_ARGON_MEM_MIN || memlimit > KSEC_ARGON_MEM_MAX
            || header->generation == UINT64_MAX) return KSEC_ERR_INVALID;
    result = verify_header(header, master_key);
    if (result != KSEC_OK) return result;
    for (index = 0; index < header->slot_count; index++) {
        if (header->slots[index].slot_type == (uint16_t)slot_type) {
            if (slot != NULL) return KSEC_ERR_INVALID;
            slot = &header->slots[index];
        }
    }
    if (slot == NULL) return KSEC_ERR_NOT_FOUND;
    previous = *header;
    header->generation++;
    slot->opslimit = opslimit;
    slot->memlimit = memlimit;
    randombytes_buf(slot->slot_id, KSEC_SLOT_ID_BYTES);
    randombytes_buf(slot->salt, KSEC_SALT_BYTES);
    result = wrap_slot(header, slot, new_secret, new_secret_len, master_key);
    if (result == KSEC_OK) result = authenticate_header(header, master_key);
    if (result != KSEC_OK) *header = previous;
    sodium_memzero(&previous, sizeof previous);
    return result;
}

ksec_result ksec_header_rotate_master(
        ksec_vault_header *header,
        const uint8_t old_master_key[KSEC_MASTER_KEY_BYTES],
        const uint8_t new_master_key[KSEC_MASTER_KEY_BYTES],
        const uint8_t *passphrase, size_t passphrase_len,
        const uint8_t *recovery, size_t recovery_len,
        uint32_t opslimit, uint64_t memlimit) {
    ksec_vault_header previous;
    size_t index;
    ksec_result result;
    if (header == NULL || old_master_key == NULL || new_master_key == NULL
            || passphrase == NULL || recovery == NULL
            || passphrase_len < 8U || passphrase_len > 1024U
            || recovery_len < 32U || recovery_len > 1024U
            || opslimit < KSEC_ARGON_OPS_MIN || opslimit > KSEC_ARGON_OPS_MAX
            || memlimit < KSEC_ARGON_MEM_MIN || memlimit > KSEC_ARGON_MEM_MAX
            || header->generation == UINT64_MAX
            || (header->flags & KSEC_HEADER_FLAG_RECOVERY_CONFIRMED) == 0U
            || sodium_memcmp(old_master_key, new_master_key,
                             KSEC_MASTER_KEY_BYTES) == 0) return KSEC_ERR_INVALID;
    result = verify_header(header, old_master_key);
    if (result != KSEC_OK) return result;
    previous = *header;
    header->generation++;
    for (index = 0; index < header->slot_count; index++) {
        ksec_key_slot *slot = &header->slots[index];
        const uint8_t *secret;
        size_t secret_len;
        if (slot->slot_type == KSEC_SLOT_PASSPHRASE) {
            secret = passphrase;
            secret_len = passphrase_len;
        } else if (slot->slot_type == KSEC_SLOT_RECOVERY) {
            secret = recovery;
            secret_len = recovery_len;
        } else {
            result = KSEC_ERR_INVALID;
            goto fail;
        }
        slot->opslimit = opslimit;
        slot->memlimit = memlimit;
        randombytes_buf(slot->slot_id, KSEC_SLOT_ID_BYTES);
        randombytes_buf(slot->salt, KSEC_SALT_BYTES);
        result = wrap_slot(header, slot, secret, secret_len, new_master_key);
        if (result != KSEC_OK) goto fail;
    }
    result = authenticate_header(header, new_master_key);
    if (result == KSEC_OK) {
        sodium_memzero(&previous, sizeof previous);
        return KSEC_OK;
    }
fail:
    *header = previous;
    sodium_memzero(&previous, sizeof previous);
    return result;
}

ksec_result ksec_header_encode(const ksec_vault_header *header, uint8_t *output,
                               size_t output_size, size_t *output_length) {
    ksec_result result;
    if (output == NULL || output_length == NULL || output_size < KSEC_HEADER_BYTES) {
        return KSEC_ERR_LIMIT;
    }
    result = encode_header_base(header, output);
    if (result != KSEC_OK) return result;
    memcpy(output + KSEC_HEADER_BASE_BYTES, header->auth_nonce, KSEC_NONCE_BYTES);
    memcpy(output + KSEC_HEADER_BASE_BYTES + KSEC_NONCE_BYTES,
           header->auth_tag, KSEC_HEADER_TAG_BYTES);
    *output_length = KSEC_HEADER_BYTES;
    return KSEC_OK;
}

ksec_result ksec_header_decode(const uint8_t *input, size_t input_length,
                               ksec_vault_header *header) {
    size_t offset = 0;
    size_t index;
    if (input == NULL || header == NULL || input_length != KSEC_HEADER_BYTES
            || memcmp(input, HEADER_MAGIC, sizeof HEADER_MAGIC) != 0) {
        return KSEC_ERR_INVALID;
    }
    memset(header, 0, sizeof *header);
    offset += 8U;
    header->format_version = ksec_get_u16(input + offset); offset += 2U;
    if (header->format_version != KSEC_FORMAT_VERSION
            || ksec_get_u32(input + offset) != KSEC_HEADER_BYTES) return KSEC_ERR_INVALID;
    offset += 4U;
    memcpy(header->vault_uuid, input + offset, KSEC_UUID_BYTES); offset += KSEC_UUID_BYTES;
    header->generation = ksec_get_u64(input + offset); offset += 8U;
    header->slot_count = ksec_get_u16(input + offset); offset += 2U;
    header->flags = ksec_get_u16(input + offset); offset += 2U;
    if (header->generation == 0 || header->slot_count != 2U
            || (header->flags & (uint16_t)~KSEC_HEADER_FLAG_RECOVERY_CONFIRMED) != 0U) {
        return KSEC_ERR_INVALID;
    }
    for (index = 0; index < 2U; index++) {
        ksec_key_slot *slot = &header->slots[index];
        slot->slot_type = ksec_get_u16(input + offset); offset += 2U;
        slot->slot_version = ksec_get_u16(input + offset); offset += 2U;
        slot->pwhash_id = ksec_get_u16(input + offset); offset += 2U;
        slot->aead_id = ksec_get_u16(input + offset); offset += 2U;
        memcpy(slot->slot_id, input + offset, KSEC_SLOT_ID_BYTES); offset += KSEC_SLOT_ID_BYTES;
        slot->opslimit = ksec_get_u32(input + offset); offset += 4U;
        slot->memlimit = ksec_get_u64(input + offset); offset += 8U;
        memcpy(slot->salt, input + offset, KSEC_SALT_BYTES); offset += KSEC_SALT_BYTES;
        memcpy(slot->nonce, input + offset, KSEC_NONCE_BYTES); offset += KSEC_NONCE_BYTES;
        memcpy(slot->wrapped, input + offset, KSEC_SLOT_CIPHERTEXT_BYTES);
        offset += KSEC_SLOT_CIPHERTEXT_BYTES;
        if ((slot->slot_type != KSEC_SLOT_PASSPHRASE
                    && slot->slot_type != KSEC_SLOT_RECOVERY)
                || slot->slot_version != 1U
                || slot->pwhash_id != KSEC_PWHASH_ID_ARGON2ID13
                || slot->aead_id != KSEC_AEAD_ID_XCHACHA20POLY1305
                || slot->opslimit < KSEC_ARGON_OPS_MIN
                || slot->opslimit > KSEC_ARGON_OPS_MAX
                || slot->memlimit < KSEC_ARGON_MEM_MIN
                || slot->memlimit > KSEC_ARGON_MEM_MAX) return KSEC_ERR_INVALID;
    }
    if (header->slots[0].slot_type == header->slots[1].slot_type
            || sodium_memcmp(header->slots[0].slot_id, header->slots[1].slot_id,
                             KSEC_SLOT_ID_BYTES) == 0) return KSEC_ERR_INVALID;
    memcpy(header->auth_nonce, input + offset, KSEC_NONCE_BYTES); offset += KSEC_NONCE_BYTES;
    memcpy(header->auth_tag, input + offset, KSEC_HEADER_TAG_BYTES); offset += KSEC_HEADER_TAG_BYTES;
    return offset == input_length ? KSEC_OK : KSEC_ERR_INVALID;
}

ksec_result ksec_record_encrypt(const uint8_t master_key[KSEC_MASTER_KEY_BYTES],
                                uint16_t object_type,
                                const uint8_t vault_uuid[KSEC_UUID_BYTES],
                                const uint8_t object_id[KSEC_RECORD_ID_BYTES],
                                uint64_t revision, const char *owner,
                                const uint8_t *plaintext, size_t plaintext_len,
                                uint8_t nonce[KSEC_NONCE_BYTES],
                                uint8_t *ciphertext, size_t ciphertext_size,
                                size_t *ciphertext_len) {
    uint8_t key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    uint8_t ad[KSEC_RECORD_AD_FIXED_BYTES + KSEC_MAX_APP_ID];
    size_t ad_len = 0;
    unsigned long long encoded_len = 0;
    ksec_result result;
    if (master_key == NULL || plaintext == NULL || nonce == NULL || ciphertext == NULL
            || ciphertext_len == NULL || plaintext_len == 0
            || plaintext_len > KSEC_MAX_RECORD_PLAINTEXT
            || ciphertext_size < plaintext_len + KSEC_TAG_BYTES
            || plaintext_len > UINT32_MAX) return KSEC_ERR_INVALID;
    result = ksec_format_record_ad(object_type, vault_uuid, object_id, revision,
                                   (uint32_t)plaintext_len, owner, ad, sizeof ad, &ad_len);
    if (result != KSEC_OK) return result;
    result = derive_terminal_key(master_key, RECORD_CONTEXT, key);
    if (result != KSEC_OK) goto out;
    randombytes_buf(nonce, KSEC_NONCE_BYTES);
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            ciphertext, &encoded_len, plaintext, (unsigned long long)plaintext_len,
            ad, (unsigned long long)ad_len, NULL, nonce, key) != 0
            || encoded_len != plaintext_len + KSEC_TAG_BYTES) {
        result = KSEC_ERR_CRYPTO;
    } else {
        *ciphertext_len = (size_t)encoded_len;
    }
out:
    sodium_memzero(key, sizeof key);
    sodium_memzero(ad, sizeof ad);
    return result;
}

ksec_result ksec_record_decrypt(const uint8_t master_key[KSEC_MASTER_KEY_BYTES],
                                uint16_t object_type,
                                const uint8_t vault_uuid[KSEC_UUID_BYTES],
                                const uint8_t object_id[KSEC_RECORD_ID_BYTES],
                                uint64_t revision, const char *owner,
                                const uint8_t nonce[KSEC_NONCE_BYTES],
                                const uint8_t *ciphertext, size_t ciphertext_len,
                                uint8_t *plaintext, size_t plaintext_size,
                                size_t *plaintext_len) {
    uint8_t key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    uint8_t ad[KSEC_RECORD_AD_FIXED_BYTES + KSEC_MAX_APP_ID];
    size_t ad_len = 0;
    size_t expected_plain;
    unsigned long long decoded_len = 0;
    ksec_result result;
    if (master_key == NULL || vault_uuid == NULL || object_id == NULL || owner == NULL
            || nonce == NULL || ciphertext == NULL || plaintext == NULL
            || plaintext_len == NULL || ciphertext_len <= KSEC_TAG_BYTES) return KSEC_ERR_INVALID;
    expected_plain = ciphertext_len - KSEC_TAG_BYTES;
    if (expected_plain > plaintext_size || expected_plain > UINT32_MAX) return KSEC_ERR_LIMIT;
    result = ksec_format_record_ad(object_type, vault_uuid, object_id, revision,
                                   (uint32_t)expected_plain, owner, ad, sizeof ad, &ad_len);
    if (result != KSEC_OK) return result;
    result = derive_terminal_key(master_key, RECORD_CONTEXT, key);
    if (result != KSEC_OK) goto out;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext, &decoded_len, NULL, ciphertext,
            (unsigned long long)ciphertext_len, ad, (unsigned long long)ad_len,
            nonce, key) != 0 || decoded_len != expected_plain) {
        sodium_memzero(plaintext, plaintext_size);
        result = KSEC_ERR_CRYPTO;
    } else {
        *plaintext_len = (size_t)decoded_len;
    }
out:
    sodium_memzero(key, sizeof key);
    sodium_memzero(ad, sizeof ad);
    return result;
}

void ksec_owned_record_clear(ksec_owned_record *record) {
    size_t index;
    if (record == NULL) return;
    for (index = 0; index < record->field_count && index < KSEC_MAX_FIELDS; index++) {
        ksec_secure_free(&record->fields[index].value);
    }
    sodium_memzero(record, sizeof *record);
}

ksec_result ksec_record_serialize(const ksec_record *record, uint8_t *output,
                                  size_t output_size, size_t *output_length) {
    size_t type_len;
    size_t label_len;
    size_t needed = KSEC_RECORD_PLAIN_FIXED_BYTES;
    size_t offset = 0;
    size_t index;
    if (record == NULL || output == NULL || output_length == NULL
            || ksec_validate_app_id(record->owner) != 0
            || ksec_validate_name(record->type, KSEC_MAX_TYPE) != 0
            || ksec_validate_name(record->label, KSEC_MAX_LABEL) != 0
            || record->fields == NULL || record->field_count == 0
            || record->field_count > KSEC_MAX_FIELDS) return KSEC_ERR_INVALID;
    type_len = strlen(record->type);
    label_len = strlen(record->label);
    needed += type_len + label_len;
    for (index = 0; index < record->field_count; index++) {
        const ksec_field *field = &record->fields[index];
        size_t name_len;
        size_t prior;
        if (ksec_validate_name(field->name, KSEC_MAX_FIELD_NAME) != 0
                || field->value == NULL || field->value_len == 0
                || field->value_len > KSEC_MAX_SECRET_BYTES) return KSEC_ERR_INVALID;
        for (prior = 0; prior < index; prior++) {
            if (strcmp(record->fields[prior].name, field->name) == 0) {
                return KSEC_ERR_INVALID;
            }
        }
        name_len = strlen(field->name);
        if (needed > SIZE_MAX - 6U - name_len - field->value_len) return KSEC_ERR_LIMIT;
        needed += 6U + name_len + field->value_len;
    }
    if (needed > output_size || needed > KSEC_MAX_RECORD_PLAINTEXT) return KSEC_ERR_LIMIT;
    memcpy(output + offset, RECORD_PLAIN_MAGIC, sizeof RECORD_PLAIN_MAGIC); offset += 8U;
    ksec_put_u16(output + offset, KSEC_FORMAT_VERSION); offset += 2U;
    ksec_put_u16(output + offset, 0U); offset += 2U;
    ksec_put_u64(output + offset, record->expires_at); offset += 8U;
    ksec_put_u16(output + offset, (uint16_t)type_len); offset += 2U;
    ksec_put_u16(output + offset, (uint16_t)label_len); offset += 2U;
    ksec_put_u16(output + offset, (uint16_t)record->field_count); offset += 2U;
    memcpy(output + offset, record->type, type_len); offset += type_len;
    memcpy(output + offset, record->label, label_len); offset += label_len;
    for (index = 0; index < record->field_count; index++) {
        size_t name_len = strlen(record->fields[index].name);
        ksec_put_u16(output + offset, (uint16_t)name_len); offset += 2U;
        ksec_put_u32(output + offset, (uint32_t)record->fields[index].value_len); offset += 4U;
        memcpy(output + offset, record->fields[index].name, name_len); offset += name_len;
        memcpy(output + offset, record->fields[index].value,
               record->fields[index].value_len); offset += record->fields[index].value_len;
    }
    *output_length = offset;
    return KSEC_OK;
}

ksec_result ksec_record_parse(const uint8_t *input, size_t input_length,
                              ksec_owned_record *record) {
    size_t offset = 0;
    uint16_t type_len;
    uint16_t label_len;
    uint16_t field_count;
    size_t index;
    ksec_result result = KSEC_ERR_INVALID;
    if (input == NULL || record == NULL || input_length < KSEC_RECORD_PLAIN_FIXED_BYTES
            || input_length > KSEC_MAX_RECORD_PLAINTEXT
            || memcmp(input, RECORD_PLAIN_MAGIC, sizeof RECORD_PLAIN_MAGIC) != 0) {
        return KSEC_ERR_INVALID;
    }
    memset(record, 0, sizeof *record);
    offset += 8U;
    if (ksec_get_u16(input + offset) != KSEC_FORMAT_VERSION) goto fail;
    offset += 2U;
    if (ksec_get_u16(input + offset) != 0U) goto fail;
    offset += 2U;
    record->expires_at = ksec_get_u64(input + offset); offset += 8U;
    type_len = ksec_get_u16(input + offset); offset += 2U;
    label_len = ksec_get_u16(input + offset); offset += 2U;
    field_count = ksec_get_u16(input + offset); offset += 2U;
    if (type_len == 0 || type_len > KSEC_MAX_TYPE || label_len == 0
            || label_len > KSEC_MAX_LABEL || field_count == 0
            || field_count > KSEC_MAX_FIELDS
            || input_length - offset < (size_t)type_len + (size_t)label_len) goto fail;
    if (ksec_validate_text_bytes(input + offset, type_len, KSEC_MAX_TYPE) != 0
            || ksec_validate_text_bytes(input + offset + type_len, label_len,
                                        KSEC_MAX_LABEL) != 0) goto fail;
    memcpy(record->type, input + offset, type_len); record->type[type_len] = '\0'; offset += type_len;
    memcpy(record->label, input + offset, label_len); record->label[label_len] = '\0'; offset += label_len;
    for (index = 0; index < field_count; index++) {
        uint16_t name_len;
        uint32_t value_len;
        if (input_length - offset < 6U) goto fail;
        name_len = ksec_get_u16(input + offset); offset += 2U;
        value_len = ksec_get_u32(input + offset); offset += 4U;
        if (name_len == 0 || name_len > KSEC_MAX_FIELD_NAME || value_len == 0
                || value_len > KSEC_MAX_SECRET_BYTES
                || input_length - offset < (size_t)name_len + value_len) goto fail;
        if (ksec_validate_text_bytes(input + offset, name_len,
                                     KSEC_MAX_FIELD_NAME) != 0) goto fail;
        memcpy(record->fields[index].name, input + offset, name_len);
        record->fields[index].name[name_len] = '\0'; offset += name_len;
        {
            size_t prior;
            for (prior = 0; prior < index; prior++) {
                if (strcmp(record->fields[prior].name,
                           record->fields[index].name) == 0) goto fail;
            }
        }
        result = ksec_secure_alloc(&record->fields[index].value, value_len);
        if (result != KSEC_OK) goto fail;
        memcpy(record->fields[index].value.data, input + offset, value_len); offset += value_len;
        record->field_count++;
    }
    if (offset != input_length) goto fail;
    return KSEC_OK;
fail:
    ksec_owned_record_clear(record);
    return result == KSEC_ERR_MEMORY ? result : KSEC_ERR_INVALID;
}
