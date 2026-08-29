#ifndef KSEC_INTERNAL_H
#define KSEC_INTERNAL_H

#define _GNU_SOURCE

#include "kilix_secrets.h"

#include <sodium.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define KSEC_FORMAT_VERSION 1U
#define KSEC_PWHASH_ID_ARGON2ID13 1U
#define KSEC_KDF_ID_BLAKE2B 1U
#define KSEC_AEAD_ID_XCHACHA20POLY1305 1U
#define KSEC_OBJECT_SECRET 1U
#define KSEC_OBJECT_DEVICE_IDENTITY 2U
#define KSEC_OBJECT_BACKUP_METADATA 3U
#define KSEC_HEADER_FLAG_RECOVERY_CONFIRMED 1U

#define KSEC_UUID_BYTES 16U
#define KSEC_SLOT_ID_BYTES 16U
#define KSEC_MASTER_KEY_BYTES crypto_kdf_KEYBYTES
#define KSEC_NONCE_BYTES crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
#define KSEC_TAG_BYTES crypto_aead_xchacha20poly1305_ietf_ABYTES
#define KSEC_SALT_BYTES crypto_pwhash_SALTBYTES
#define KSEC_SLOT_CIPHERTEXT_BYTES (KSEC_MASTER_KEY_BYTES + KSEC_TAG_BYTES)
#define KSEC_HEADER_TAG_BYTES crypto_aead_xchacha20poly1305_ietf_ABYTES

#define KSEC_ARGON_OPS_MIN 3U
#define KSEC_ARGON_OPS_MAX 6U
#define KSEC_ARGON_MEM_MIN (UINT64_C(256) * UINT64_C(1024) * UINT64_C(1024))
#define KSEC_ARGON_MEM_MAX (UINT64_C(512) * UINT64_C(1024) * UINT64_C(1024))

#define KSEC_PROTOCOL_VERSION 1U
#define KSEC_PROTOCOL_MAGIC UINT32_C(0x4b534543)
#define KSEC_PROTOCOL_HEADER_BYTES 24U
#define KSEC_PROTOCOL_MAX_PAYLOAD 65536U
#define KSEC_PROTOCOL_MAX_PACKET (KSEC_PROTOCOL_HEADER_BYTES + KSEC_PROTOCOL_MAX_PAYLOAD)

#define KSEC_MAX_TYPE 32U
#define KSEC_MAX_LABEL 128U
#define KSEC_MAX_RECORDS 1024U
#define KSEC_MAX_OWNER_BYTES KSEC_MAX_APP_ID
#define KSEC_MAX_RECORD_PLAINTEXT (KSEC_MAX_SECRET_BYTES + 4096U)
#define KSEC_MAX_JOURNAL_BYTES (UINT64_C(128) * UINT64_C(1024) * UINT64_C(1024))
#define KSEC_MAX_BACKUP_BYTES (KSEC_MAX_JOURNAL_BYTES + UINT64_C(4096))
#define KSEC_MAX_AUDIT_BYTES (UINT64_C(4) * UINT64_C(1024) * UINT64_C(1024))
#define KSEC_MAX_CAPABILITIES 256U
#define KSEC_MAX_CONNECTIONS 64U

#define KSEC_IDENTITY_FRAME_MAGIC UINT32_C(0x4b534944)
#define KSEC_IDENTITY_FRAME_VERSION 1U
#define KSEC_IDENTITY_FRAME_BYTES 144U
#define KSEC_IDENTITY_INFO_FRAME_MAGIC UINT32_C(0x4b534950)
#define KSEC_IDENTITY_INFO_FRAME_BYTES 112U

#define KSEC_GRANTABLE_VERBS \
    ((uint32_t)(KSEC_VERB_READ | KSEC_VERB_REPLACE | KSEC_VERB_DELETE \
                | KSEC_VERB_LIST_OWN | KSEC_VERB_USE))

#define KSEC_RECORD_AD_FIXED_BYTES 62U
#define KSEC_SLOT_AD_FIXED_BYTES 68U

typedef struct {
    uint8_t *data;
    size_t len;
} ksec_secure_buffer;

typedef struct {
    uint16_t slot_type;
    uint16_t slot_version;
    uint16_t pwhash_id;
    uint16_t aead_id;
    uint8_t slot_id[KSEC_SLOT_ID_BYTES];
    uint32_t opslimit;
    uint64_t memlimit;
    uint8_t salt[KSEC_SALT_BYTES];
    uint8_t nonce[KSEC_NONCE_BYTES];
    uint8_t wrapped[KSEC_SLOT_CIPHERTEXT_BYTES];
} ksec_key_slot;

typedef struct {
    uint16_t format_version;
    uint8_t vault_uuid[KSEC_UUID_BYTES];
    uint64_t generation;
    uint16_t slot_count;
    uint16_t flags;
    ksec_key_slot slots[2];
    uint8_t auth_nonce[KSEC_NONCE_BYTES];
    uint8_t auth_tag[KSEC_HEADER_TAG_BYTES];
} ksec_vault_header;

typedef struct {
    char name[KSEC_MAX_FIELD_NAME + 1U];
    ksec_secure_buffer value;
} ksec_owned_field;

typedef struct {
    char application_id[KSEC_MAX_APP_ID + 1U];
    uint32_t verbs;
} ksec_owned_grant;

typedef struct {
    uint8_t id[KSEC_RECORD_ID_BYTES];
    char owner[KSEC_MAX_APP_ID + 1U];
    char type[KSEC_MAX_TYPE + 1U];
    char label[KSEC_MAX_LABEL + 1U];
    uint16_t object_type;
    uint64_t revision;
    uint64_t expires_at;
    size_t field_count;
    ksec_owned_field fields[KSEC_MAX_FIELDS];
    size_t grant_count;
    ksec_owned_grant grants[KSEC_MAX_GRANTS];
    bool deleted;
} ksec_owned_record;

typedef struct {
    char root_dir[4096];
    char data_dir[4096];
    char vault_path[4096];
    char journal_path[4096];
    char lock_path[4096];
    int lock_fd;
    uint64_t last_revision;
    bool torn_tail;
    ksec_owned_record *records;
    size_t record_count;
} ksec_store;

typedef struct {
    bool active;
    bool activated;
    uint8_t token[KSEC_CAPABILITY_BYTES];
    char app_id[KSEC_MAX_APP_ID + 1U];
    uint32_t verbs;
    bool record_scoped;
    uint8_t record_id[KSEC_RECORD_ID_BYTES];
    pid_t target_pid;
    uint64_t target_start_time;
    pid_t supervisor_pid;
    uint64_t supervisor_start_time;
    uint64_t expires_at;
    int connection_fd;
} ksec_capability;

typedef struct {
    ksec_capability entries[KSEC_MAX_CAPABILITIES];
} ksec_policy;

typedef struct {
    uint8_t *vault;
    size_t vault_len;
    uint8_t *journal;
    size_t journal_len;
    ksec_vault_header header;
    ksec_secure_buffer master;
} ksec_backup_image;

typedef enum {
    KSEC_OP_ACTIVATE = 1,
    KSEC_OP_MINT = 2,
    KSEC_OP_INIT = 3,
    KSEC_OP_UNLOCK = 4,
    KSEC_OP_LOCK = 5,
    KSEC_OP_PUT = 6,
    KSEC_OP_REPLACE = 7,
    KSEC_OP_GET = 8,
    KSEC_OP_DELETE = 9,
    KSEC_OP_LIST = 10,
    KSEC_OP_DOCTOR = 11,
    KSEC_OP_COMPACT = 12,
    KSEC_OP_CHANGE_PASSPHRASE = 13,
    KSEC_OP_ROTATE_MASTER = 14,
    KSEC_OP_EXPORT_BACKUP = 15,
    KSEC_OP_IMPORT_BACKUP = 16,
    KSEC_OP_SHOW = 17,
    KSEC_OP_GRANT = 18,
    KSEC_OP_REVOKE = 19,
    KSEC_OP_RESET_VAULT = 20,
    KSEC_OP_IDENTITY_OPEN = 21,
    KSEC_OP_IDENTITY_INFO = 22,
    KSEC_OP_MAX = KSEC_OP_IDENTITY_INFO
} ksec_operation;

typedef struct {
    uint16_t version;
    uint16_t operation;
    uint32_t flags;
    uint64_t request_id;
    uint32_t payload_len;
} ksec_packet_header;

void ksec_put_u16(uint8_t out[2], uint16_t value);
void ksec_put_u32(uint8_t out[4], uint32_t value);
void ksec_put_u64(uint8_t out[8], uint64_t value);
uint16_t ksec_get_u16(const uint8_t in[2]);
uint32_t ksec_get_u32(const uint8_t in[4]);
uint64_t ksec_get_u64(const uint8_t in[8]);
int ksec_write_all(int fd, const void *data, size_t length);
int ksec_read_exact(int fd, void *data, size_t length);
int ksec_copy_fd(int input_fd, int output_fd, size_t limit, size_t *copied);
int ksec_set_cloexec(int fd, bool enabled);
int ksec_sync_directory(const char *path);
int ksec_parent_directory(const char *path, char *output, size_t output_size);
int ksec_validate_secure_directory(const char *path, bool require_user_leaf);
int ksec_validate_app_id(const char *value);
int ksec_validate_app_id_bytes(const uint8_t *value, size_t length);
int ksec_validate_name(const char *value, size_t max_length);
int ksec_validate_text_bytes(const uint8_t *value, size_t length,
                             size_t max_length);
uint64_t ksec_now_seconds(void);
int ksec_process_start_time(pid_t pid, uint64_t *out);
int ksec_safe_equal(const uint8_t *left, const uint8_t *right, size_t length);
void ksec_hex_encode(const uint8_t *input, size_t length, char *output);
int ksec_hex_decode(const char *input, uint8_t *output, size_t output_length);

ksec_result ksec_secure_alloc(ksec_secure_buffer *buffer, size_t length);
void ksec_secure_free(ksec_secure_buffer *buffer);
ksec_result ksec_identity_anchor(
        const uint8_t vault_uuid[KSEC_UUID_BYTES],
        const uint8_t record_id[KSEC_RECORD_ID_BYTES], uint64_t record_revision,
        const uint8_t public_key[KSEC_IDENTITY_KEY_BYTES],
        uint8_t anchor[KSEC_IDENTITY_ANCHOR_BYTES]);
typedef enum {
    KSEC_TEST_STORE_HEADER_OPEN = 1,
    KSEC_TEST_STORE_HEADER_WRITE = 2,
    KSEC_TEST_STORE_HEADER_FSYNC = 3,
    KSEC_TEST_STORE_HEADER_CLOSE = 4,
    KSEC_TEST_STORE_HEADER_RENAME = 5,
    KSEC_TEST_STORE_HEADER_DIRSYNC = 6,
    KSEC_TEST_STORE_APPEND_OPEN = 7,
    KSEC_TEST_STORE_APPEND_WRITE = 8,
    KSEC_TEST_STORE_APPEND_FSYNC = 9,
    KSEC_TEST_STORE_APPEND_CLOSE = 10,
    KSEC_TEST_STORE_APPEND_DIRSYNC = 11,
    KSEC_TEST_STORE_COMPACT_OPEN = 12,
    KSEC_TEST_STORE_COMPACT_WRITE = 13,
    KSEC_TEST_STORE_COMPACT_FSYNC = 14,
    KSEC_TEST_STORE_COMPACT_CLOSE = 15,
    KSEC_TEST_STORE_COMPACT_RENAME = 16,
    KSEC_TEST_STORE_COMPACT_DIRSYNC = 17,
    KSEC_TEST_STORE_ROTATE_DIRECTORY = 18,
    KSEC_TEST_STORE_ROTATE_HEADER = 19,
    KSEC_TEST_STORE_ROTATE_JOURNAL = 20,
    KSEC_TEST_STORE_ROTATE_VERIFY = 21,
    KSEC_TEST_STORE_ROTATE_PRESYNC = 22,
    KSEC_TEST_STORE_ROTATE_EXCHANGE = 23,
    KSEC_TEST_STORE_ROTATE_POSTSYNC = 24,
    KSEC_TEST_STORE_ROTATE_RETAIN = 25,
    KSEC_TEST_STORE_ROTATE_RETAIN_SYNC = 26,
    KSEC_TEST_STORE_IMPORT_DIRECTORY = 27,
    KSEC_TEST_STORE_IMPORT_VAULT = 28,
    KSEC_TEST_STORE_IMPORT_JOURNAL = 29,
    KSEC_TEST_STORE_IMPORT_VERIFY = 30,
    KSEC_TEST_STORE_IMPORT_PRESYNC = 31,
    KSEC_TEST_STORE_IMPORT_EXCHANGE = 32,
    KSEC_TEST_STORE_IMPORT_POSTSYNC = 33,
    KSEC_TEST_STORE_IMPORT_RETAIN = 34,
    KSEC_TEST_STORE_IMPORT_RETAIN_SYNC = 35,
    KSEC_TEST_STORE_RESET_DIRECTORY = 36,
    KSEC_TEST_STORE_RESET_VAULT = 37,
    KSEC_TEST_STORE_RESET_JOURNAL = 38,
    KSEC_TEST_STORE_RESET_VERIFY = 39,
    KSEC_TEST_STORE_RESET_PRESYNC = 40,
    KSEC_TEST_STORE_RESET_EXCHANGE = 41,
    KSEC_TEST_STORE_RESET_POSTSYNC = 42,
    KSEC_TEST_STORE_RESET_RETAIN = 43,
    KSEC_TEST_STORE_RESET_RETAIN_SYNC = 44
} ksec_test_store_point;

#ifdef KSEC_TESTING
void ksec_test_force_mlock_failure(bool enabled);
void ksec_test_store_fault_reset(void);
void ksec_test_store_crash_after(ksec_test_store_point point,
                                 unsigned int occurrence, int exit_status);
void ksec_test_store_fail_at(ksec_test_store_point point,
                             unsigned int occurrence, int error_number,
                             size_t partial_write_bytes);
#endif

ksec_result ksec_format_record_ad(uint16_t object_type,
                                  const uint8_t vault_uuid[KSEC_UUID_BYTES],
                                  const uint8_t object_id[KSEC_RECORD_ID_BYTES],
                                  uint64_t revision, uint32_t plaintext_length,
                                  const char *owner, uint8_t *output,
                                  size_t output_size, size_t *output_length);
ksec_result ksec_parse_record_ad(const uint8_t *input, size_t input_length,
                                 uint16_t *object_type,
                                 uint8_t vault_uuid[KSEC_UUID_BYTES],
                                 uint8_t object_id[KSEC_RECORD_ID_BYTES],
                                 uint64_t *revision, uint32_t *plaintext_length,
                                 char owner[KSEC_MAX_APP_ID + 1U]);
ksec_result ksec_format_slot_ad(const ksec_vault_header *header,
                                const ksec_key_slot *slot, uint8_t *output,
                                size_t output_size, size_t *output_length);

ksec_result ksec_crypto_initialize(void);
ksec_result ksec_header_create(ksec_vault_header *header,
                               const uint8_t *passphrase, size_t passphrase_len,
                               const uint8_t *recovery, size_t recovery_len,
                               uint32_t opslimit, uint64_t memlimit,
                               uint8_t master_key[KSEC_MASTER_KEY_BYTES]);
ksec_result ksec_header_unlock(const ksec_vault_header *header,
                               ksec_slot_type slot_type,
                               const uint8_t *secret, size_t secret_len,
                               uint8_t master_key[KSEC_MASTER_KEY_BYTES]);
ksec_result ksec_header_confirm_recovery(
        ksec_vault_header *header,
        const uint8_t master_key[KSEC_MASTER_KEY_BYTES]);
ksec_result ksec_header_rewrap_slot(
        ksec_vault_header *header, ksec_slot_type slot_type,
        const uint8_t *new_secret, size_t new_secret_len,
        uint32_t opslimit, uint64_t memlimit,
        const uint8_t master_key[KSEC_MASTER_KEY_BYTES]);
ksec_result ksec_header_rotate_master(
        ksec_vault_header *header,
        const uint8_t old_master_key[KSEC_MASTER_KEY_BYTES],
        const uint8_t new_master_key[KSEC_MASTER_KEY_BYTES],
        const uint8_t *passphrase, size_t passphrase_len,
        const uint8_t *recovery, size_t recovery_len,
        uint32_t opslimit, uint64_t memlimit);
ksec_result ksec_header_verify_master(
        const ksec_vault_header *header,
        const uint8_t master_key[KSEC_MASTER_KEY_BYTES]);
ksec_result ksec_header_encode(const ksec_vault_header *header, uint8_t *output,
                               size_t output_size, size_t *output_length);
ksec_result ksec_header_decode(const uint8_t *input, size_t input_length,
                               ksec_vault_header *header);
ksec_result ksec_record_encrypt(const uint8_t master_key[KSEC_MASTER_KEY_BYTES],
                                uint16_t object_type,
                                const uint8_t vault_uuid[KSEC_UUID_BYTES],
                                const uint8_t object_id[KSEC_RECORD_ID_BYTES],
                                uint64_t revision, const char *owner,
                                const uint8_t *plaintext, size_t plaintext_len,
                                uint8_t nonce[KSEC_NONCE_BYTES],
                                uint8_t *ciphertext, size_t ciphertext_size,
                                size_t *ciphertext_len);
ksec_result ksec_record_decrypt(const uint8_t master_key[KSEC_MASTER_KEY_BYTES],
                                uint16_t object_type,
                                const uint8_t vault_uuid[KSEC_UUID_BYTES],
                                const uint8_t object_id[KSEC_RECORD_ID_BYTES],
                                uint64_t revision, const char *owner,
                                const uint8_t nonce[KSEC_NONCE_BYTES],
                                const uint8_t *ciphertext, size_t ciphertext_len,
                                uint8_t *plaintext, size_t plaintext_size,
                                size_t *plaintext_len);

void ksec_owned_record_clear(ksec_owned_record *record);
ksec_result ksec_record_serialize(const ksec_record *record, uint8_t *output,
                                  size_t output_size, size_t *output_length);
ksec_result ksec_record_parse(const uint8_t *input, size_t input_length,
                              ksec_owned_record *record);

ksec_result ksec_store_open(ksec_store *store, const char *data_dir, bool create);
void ksec_store_close(ksec_store *store);
void ksec_store_clear_records(ksec_store *store);
ksec_result ksec_store_write_header(ksec_store *store,
                                    const ksec_vault_header *header);
ksec_result ksec_store_read_header(ksec_store *store, ksec_vault_header *header);
ksec_result ksec_store_load(ksec_store *store,
                            const ksec_vault_header *header,
                            const uint8_t master_key[KSEC_MASTER_KEY_BYTES]);
ksec_result ksec_store_append(ksec_store *store,
                              const ksec_vault_header *header,
                              const uint8_t master_key[KSEC_MASTER_KEY_BYTES],
                              ksec_owned_record *record, bool deletion);
ksec_owned_record *ksec_store_find(ksec_store *store,
                                   const uint8_t id[KSEC_RECORD_ID_BYTES]);
ksec_result ksec_store_compact(ksec_store *store,
                               const ksec_vault_header *header,
                               const uint8_t master_key[KSEC_MASTER_KEY_BYTES]);
ksec_result ksec_store_rotate_generation(
        ksec_store *store, const ksec_vault_header *new_header,
        const uint8_t new_master_key[KSEC_MASTER_KEY_BYTES]);
ksec_result ksec_store_import_generation(ksec_store *store,
                                         const ksec_backup_image *image);
ksec_result ksec_store_reset_generation(
        ksec_store *store, const ksec_vault_header *new_header,
        const uint8_t new_master_key[KSEC_MASTER_KEY_BYTES]);

void ksec_policy_init(ksec_policy *policy);
void ksec_policy_clear(ksec_policy *policy);
ksec_result ksec_policy_mint(ksec_policy *policy, pid_t supervisor_pid,
                             pid_t target_pid, const char *app_id,
                             uint32_t verbs, const uint8_t *record_id,
                             uint32_t lifetime_seconds, int *out_fd);
ksec_result ksec_policy_activate(ksec_policy *policy, int connection_fd,
                                 pid_t peer_pid, const uint8_t *token,
                                 size_t token_len, ksec_capability **out);
void ksec_policy_disconnect(ksec_policy *policy, int connection_fd);
ksec_result ksec_policy_authorize(ksec_capability *capability, uint32_t verb,
                                  const char *owner, const uint8_t *record_id);

ksec_result ksec_audit_open(const char *data_dir, int *out_fd);
ksec_result ksec_audit_event(int fd, const char *event, const char *outcome,
                             uid_t uid, pid_t pid, const char *app_id,
                             const uint8_t *record_id);

ksec_result ksec_backup_create(
        const ksec_store *store, const ksec_vault_header *header,
        const uint8_t master_key[KSEC_MASTER_KEY_BYTES],
        const uint8_t *passphrase, size_t passphrase_len, int output_fd);
ksec_result ksec_backup_open(int input_fd, const uint8_t *passphrase,
                             size_t passphrase_len, ksec_backup_image *image);
ksec_result ksec_backup_validate_envelope_header(
        const uint8_t *header, size_t header_len, uint64_t artifact_len,
        uint32_t *vault_len, uint64_t *journal_len);
void ksec_backup_image_clear(ksec_backup_image *image);

ksec_result ksec_packet_encode(const ksec_packet_header *header,
                               const uint8_t *payload, uint8_t *output,
                               size_t output_size, size_t *output_length);
ksec_result ksec_packet_decode(const uint8_t *input, size_t input_length,
                               ksec_packet_header *header,
                               const uint8_t **payload);
ksec_result ksec_send_packet(int fd, const ksec_packet_header *header,
                             const uint8_t *payload, int passed_fd);
ksec_result ksec_recv_packet(int fd, ksec_packet_header *header, uint8_t *payload,
                             size_t payload_size, int *received_fd);

#endif
