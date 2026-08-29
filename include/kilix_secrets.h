#ifndef KILIX_SECRETS_H
#define KILIX_SECRETS_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KSEC_RECORD_ID_BYTES 16U
#define KSEC_CAPABILITY_BYTES 32U
#define KSEC_MAX_APP_ID 64U
#define KSEC_MAX_FIELD_NAME 32U
#define KSEC_MAX_FIELDS 8U
#define KSEC_MAX_GRANTS 16U
#define KSEC_MAX_SECRET_BYTES 65536U
#define KSEC_IDENTITY_KEY_BYTES 32U
#define KSEC_IDENTITY_ANCHOR_BYTES 32U
#define KSEC_IDENTITY_INFO_VERSION 1U
#define KSEC_MAX_IDENTITY_LEASES 128U
#define KSEC_IDENTITY_OWNER "kilix-pairingd"
#define KSEC_IDENTITY_TYPE "device-identity"
#define KSEC_IDENTITY_PRIVATE_FIELD "private-key"
#define KSEC_RESET_CONFIRMATION "RESET-VAULT-AND-LOSE-IDENTITY"

typedef struct ksec_client ksec_client;

typedef enum {
    KSEC_OK = 0,
    KSEC_ERR_LOCKED = 1,
    KSEC_ERR_DENIED = 2,
    KSEC_ERR_NOT_FOUND = 3,
    KSEC_ERR_EXPIRED = 4,
    KSEC_ERR_INVALID = 5,
    KSEC_ERR_LIMIT = 6,
    KSEC_ERR_IO = 7,
    KSEC_ERR_CRYPTO = 8,
    KSEC_ERR_PROTOCOL = 9,
    KSEC_ERR_BUSY = 10,
    KSEC_ERR_EXISTS = 11,
    KSEC_ERR_AUDIT = 12,
    KSEC_ERR_MEMORY = 13,
    KSEC_ERR_CONFLICT = 14
} ksec_result;

typedef enum {
    KSEC_VERB_CREATE = 1U << 0,
    KSEC_VERB_READ = 1U << 1,
    KSEC_VERB_REPLACE = 1U << 2,
    KSEC_VERB_DELETE = 1U << 3,
    KSEC_VERB_LIST_OWN = 1U << 4,
    KSEC_VERB_USE = 1U << 5,
    KSEC_VERB_DOCTOR = 1U << 6,
    KSEC_VERB_ALL = (1U << 7) - 1U
} ksec_verb;

typedef enum {
    KSEC_SLOT_PASSPHRASE = 1,
    KSEC_SLOT_RECOVERY = 2
} ksec_slot_type;

typedef struct {
    const char *name;
    const uint8_t *value;
    size_t value_len;
} ksec_field;

typedef struct {
    const char *application_id;
    uint32_t verbs;
} ksec_grant;

typedef struct {
    const char *owner;
    const char *type;
    const char *label;
    uint64_t expires_at;
    const ksec_field *fields;
    size_t field_count;
    const ksec_grant *grants;
    size_t grant_count;
} ksec_record;

typedef struct {
    uint32_t version;
    uint32_t reserved;
    uint8_t vault_uuid[16];
    uint8_t record_id[KSEC_RECORD_ID_BYTES];
    uint64_t record_revision;
    uint8_t public_key[KSEC_IDENTITY_KEY_BYTES];
    uint8_t anchor[KSEC_IDENTITY_ANCHOR_BYTES];
} ksec_identity_info;

const char *ksec_result_string(ksec_result result);

ksec_result ksec_connect(ksec_client **out);
ksec_result ksec_connect_at(ksec_client **out, const char *socket_path,
                            int capability_fd);
void ksec_client_free(ksec_client *client);

ksec_result ksec_supervisor_mint(const char *socket_path, pid_t child_pid,
                                 const char *application_id,
                                 uint32_t verb_mask, uint32_t lifetime_seconds,
                                 int *out_capability_fd);
ksec_result ksec_supervisor_mint_scoped(
        const char *socket_path, pid_t child_pid, const char *application_id,
        uint32_t verb_mask,
        const uint8_t record_id[KSEC_RECORD_ID_BYTES],
        uint32_t lifetime_seconds, int *out_capability_fd);

ksec_result ksec_vault_init(ksec_client *client, int passphrase_fd,
                            int recovery_output_fd);
ksec_result ksec_unlock(ksec_client *client, ksec_slot_type slot_type,
                        int secret_input_fd);
ksec_result ksec_lock(ksec_client *client);
ksec_result ksec_change_passphrase(ksec_client *client,
                                   int new_passphrase_fd);
ksec_result ksec_rotate_master(ksec_client *client, int passphrase_fd,
                               int recovery_fd);
ksec_result ksec_export_backup(ksec_client *client, int passphrase_fd,
                               int output_fd);
ksec_result ksec_import_backup(ksec_client *client, int passphrase_fd,
                               int input_fd);
ksec_result ksec_reset_vault(ksec_client *client, const char *confirmation,
                             int new_passphrase_fd, int recovery_output_fd);

ksec_result ksec_put(ksec_client *client, const ksec_record *record,
                     uint8_t record_id[KSEC_RECORD_ID_BYTES]);
ksec_result ksec_replace(ksec_client *client,
                         const uint8_t record_id[KSEC_RECORD_ID_BYTES],
                         const ksec_record *record);
ksec_result ksec_get_to_fd(ksec_client *client,
                           const uint8_t record_id[KSEC_RECORD_ID_BYTES],
                           const char *field, int output_fd);
ksec_result ksec_get_buf(ksec_client *client,
                         const uint8_t record_id[KSEC_RECORD_ID_BYTES],
                         const char *field, uint8_t *buf, size_t buf_len,
                         size_t *out_len);
/*
 * Atomically delivers the F113 X25519 private key into the caller-owned
 * 32-byte buffer, returns its derived public identity and stable anchor, and
 * returns a CLOEXEC, nonblocking lease descriptor. The caller must lock and
 * clear private_key, keep client connected, poll lease_fd, and invalidate all
 * dependent work on POLLHUP/POLLERR/EOF. expected_anchor may be NULL only when
 * intentionally accepting the currently stored generation. Outputs are
 * cleared on failure. The multiplexer must never receive private_key or
 * lease_fd.
 */
ksec_result ksec_identity_open(
        ksec_client *client,
        const uint8_t record_id[KSEC_RECORD_ID_BYTES],
        const uint8_t expected_anchor[KSEC_IDENTITY_ANCHOR_BYTES],
        uint8_t private_key[KSEC_IDENTITY_KEY_BYTES],
        ksec_identity_info *info, int *lease_fd);
/* Returns only derived public identity metadata; no private bytes or lease. */
ksec_result ksec_identity_info_get(
        ksec_client *client,
        const uint8_t record_id[KSEC_RECORD_ID_BYTES],
        const uint8_t expected_anchor[KSEC_IDENTITY_ANCHOR_BYTES],
        ksec_identity_info *info);
ksec_result ksec_delete(ksec_client *client,
                        const uint8_t record_id[KSEC_RECORD_ID_BYTES]);
ksec_result ksec_list_to_fd(ksec_client *client, int output_fd);
ksec_result ksec_show_to_fd(ksec_client *client,
                            const uint8_t record_id[KSEC_RECORD_ID_BYTES],
                            int output_fd);
ksec_result ksec_grant_record(
        ksec_client *client,
        const uint8_t record_id[KSEC_RECORD_ID_BYTES],
        const char *application_id, uint32_t verbs);
ksec_result ksec_revoke_record(
        ksec_client *client,
        const uint8_t record_id[KSEC_RECORD_ID_BYTES],
        const char *application_id);
ksec_result ksec_doctor_to_fd(ksec_client *client, int output_fd);
ksec_result ksec_compact(ksec_client *client);

#ifdef __cplusplus
}
#endif

#endif
