#define _GNU_SOURCE

#include "internal.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static unsigned int checks_run;
static unsigned int checks_failed;
static ksec_vault_header fixture_header;
static uint8_t fixture_master[KSEC_MASTER_KEY_BYTES];

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

static int all_zero(const uint8_t *bytes, size_t length) {
    size_t index;
    uint8_t combined = 0U;
    for (index = 0; index < length; index++) combined |= bytes[index];
    return combined == 0U;
}

static void fill_sequence(uint8_t *bytes, size_t length, uint8_t first) {
    size_t index;
    for (index = 0; index < length; index++) {
        bytes[index] = (uint8_t)(first + (uint8_t)index);
    }
}

static int count_open_fds(void) {
    DIR *directory = opendir("/proc/self/fd");
    struct dirent *entry;
    int count = 0;
    if (directory == NULL) return -1;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            count++;
        }
    }
    if (closedir(directory) != 0) return -1;
    return count;
}

static void test_utilities(void) {
    uint8_t bytes[8];
    uint8_t decoded[4];
    char hex[9];
    uint64_t start_time = 0;
    const uint8_t valid_utf8[] = {'c', 'a', 'f', 0xc3U, 0xa9U};
    const uint8_t overlong[] = {0xc0U, 0xafU};
    const uint8_t surrogate[] = {0xedU, 0xa0U, 0x80U};
    const uint8_t embedded_nul[] = {'a', 0U, 'b'};

    ksec_put_u16(bytes, UINT16_C(0x1234));
    CHECK(bytes[0] == 0x12U && bytes[1] == 0x34U);
    CHECK(ksec_get_u16(bytes) == UINT16_C(0x1234));
    ksec_put_u32(bytes, UINT32_C(0x12345678));
    CHECK(ksec_get_u32(bytes) == UINT32_C(0x12345678));
    ksec_put_u64(bytes, UINT64_C(0x0123456789abcdef));
    CHECK(ksec_get_u64(bytes) == UINT64_C(0x0123456789abcdef));

    ksec_hex_encode(bytes, 4U, hex);
    CHECK(strcmp(hex, "01234567") == 0);
    CHECK(ksec_hex_decode(hex, decoded, sizeof decoded) == 0);
    CHECK(memcmp(bytes, decoded, sizeof decoded) == 0);
    CHECK(ksec_hex_decode("0123456g", decoded, sizeof decoded) != 0);
    CHECK(ksec_hex_decode("0123", decoded, sizeof decoded) != 0);

    CHECK(ksec_validate_app_id("kilix-secrets.test") == 0);
    CHECK(ksec_validate_app_id("Kilix") != 0);
    CHECK(ksec_validate_app_id_bytes(embedded_nul, sizeof embedded_nul) != 0);
    CHECK(ksec_validate_text_bytes(valid_utf8, sizeof valid_utf8, 8U) == 0);
    CHECK(ksec_validate_text_bytes(overlong, sizeof overlong, 8U) != 0);
    CHECK(ksec_validate_text_bytes(surrogate, sizeof surrogate, 8U) != 0);
    CHECK(ksec_validate_text_bytes(embedded_nul, sizeof embedded_nul, 8U) != 0);
    CHECK(ksec_process_start_time(getpid(), &start_time) == 0 && start_time != 0U);
    CHECK(strcmp(ksec_result_string(KSEC_ERR_CRYPTO), "authentication failure") == 0);
    CHECK(strcmp(ksec_result_string((ksec_result)99), "unknown result") == 0);
}

static void check_record_ad_vector(uint16_t object_type, uint64_t revision,
                                   uint32_t plaintext_length, const char *owner,
                                   const char *expected_hex) {
    uint8_t uuid[KSEC_UUID_BYTES];
    uint8_t object_id[KSEC_RECORD_ID_BYTES];
    uint8_t encoded[KSEC_RECORD_AD_FIXED_BYTES + KSEC_MAX_APP_ID];
    uint8_t expected[KSEC_RECORD_AD_FIXED_BYTES + KSEC_MAX_APP_ID];
    uint8_t parsed_uuid[KSEC_UUID_BYTES];
    uint8_t parsed_id[KSEC_RECORD_ID_BYTES];
    uint16_t parsed_type = 0;
    uint64_t parsed_revision = 0;
    uint32_t parsed_length = 0;
    char parsed_owner[KSEC_MAX_APP_ID + 1U];
    size_t encoded_len = 0;
    size_t expected_len = strlen(expected_hex) / 2U;
    fill_sequence(uuid, sizeof uuid, 0x00U);
    fill_sequence(object_id, sizeof object_id, 0x01U);
    object_id[0] = 0x01U;
    object_id[1] = 0x23U;
    object_id[2] = 0x45U;
    object_id[3] = 0x67U;
    object_id[4] = 0x89U;
    object_id[5] = 0xabU;
    object_id[6] = 0xcdU;
    object_id[7] = 0xefU;
    memcpy(object_id + 8U, object_id, 8U);
    uuid[0] = 0x00U;
    uuid[1] = 0x11U;
    uuid[2] = 0x22U;
    uuid[3] = 0x33U;
    uuid[4] = 0x44U;
    uuid[5] = 0x55U;
    uuid[6] = 0x66U;
    uuid[7] = 0x77U;
    uuid[8] = 0x88U;
    uuid[9] = 0x99U;
    uuid[10] = 0xaaU;
    uuid[11] = 0xbbU;
    uuid[12] = 0xccU;
    uuid[13] = 0xddU;
    uuid[14] = 0xeeU;
    uuid[15] = 0xffU;
    CHECK(expected_len <= sizeof expected);
    CHECK(ksec_hex_decode(expected_hex, expected, expected_len) == 0);
    CHECK(ksec_format_record_ad(object_type, uuid, object_id, revision,
                                plaintext_length, owner, encoded, sizeof encoded,
                                &encoded_len) == KSEC_OK);
    CHECK(encoded_len == expected_len);
    CHECK(memcmp(encoded, expected, expected_len) == 0);
    CHECK(ksec_parse_record_ad(encoded, encoded_len, &parsed_type, parsed_uuid,
                               parsed_id, &parsed_revision, &parsed_length,
                               parsed_owner) == KSEC_OK);
    CHECK(parsed_type == object_type && parsed_revision == revision
          && parsed_length == plaintext_length);
    CHECK(memcmp(parsed_uuid, uuid, sizeof uuid) == 0);
    CHECK(memcmp(parsed_id, object_id, sizeof object_id) == 0);
    CHECK(strcmp(parsed_owner, owner) == 0);
    CHECK(ksec_parse_record_ad(encoded, encoded_len - 1U, &parsed_type,
                               parsed_uuid, parsed_id, &parsed_revision,
                               &parsed_length, parsed_owner) == KSEC_ERR_INVALID);
    encoded[encoded_len] = 0U;
    CHECK(ksec_parse_record_ad(encoded, encoded_len + 1U, &parsed_type,
                               parsed_uuid, parsed_id, &parsed_revision,
                               &parsed_length, parsed_owner) == KSEC_ERR_INVALID);
}

static void check_slot_ad_vector(uint16_t slot_type, uint32_t opslimit,
                                 uint64_t memlimit, const char *expected_hex) {
    ksec_vault_header header;
    ksec_key_slot slot;
    uint8_t encoded[KSEC_SLOT_AD_FIXED_BYTES + KSEC_SALT_BYTES];
    uint8_t expected[KSEC_SLOT_AD_FIXED_BYTES + KSEC_SALT_BYTES];
    size_t encoded_len = 0;
    size_t expected_len = strlen(expected_hex) / 2U;
    memset(&header, 0, sizeof header);
    memset(&slot, 0, sizeof slot);
    header.format_version = KSEC_FORMAT_VERSION;
    CHECK(ksec_hex_decode("00112233445566778899aabbccddeeff",
                          header.vault_uuid, sizeof header.vault_uuid) == 0);
    slot.slot_type = slot_type;
    slot.slot_version = 1U;
    slot.pwhash_id = KSEC_PWHASH_ID_ARGON2ID13;
    slot.aead_id = KSEC_AEAD_ID_XCHACHA20POLY1305;
    slot.opslimit = opslimit;
    slot.memlimit = memlimit;
    CHECK(ksec_hex_decode("fedcba9876543210fedcba9876543210",
                          slot.slot_id, sizeof slot.slot_id) == 0);
    fill_sequence(slot.salt, sizeof slot.salt, 0xa0U);
    CHECK(ksec_hex_decode(expected_hex, expected, expected_len) == 0);
    CHECK(ksec_format_slot_ad(&header, &slot, encoded, sizeof encoded,
                              &encoded_len) == KSEC_OK);
    CHECK(encoded_len == expected_len);
    CHECK(memcmp(encoded, expected, expected_len) == 0);
}

static void test_ad_vectors(void) {
    static const char r1[] = "4b53564144303031000100010001000100112233445566778899aabbccddeeff0123456789abcdef0123456789abcdef00000000000000010000002000126b696c69782d736563726574732e74657374";
    static const char r2[] = "4b53564144303031000100010001000100112233445566778899aabbccddeeff0123456789abcdef0123456789abcdef00000000000000020000002000126b696c69782d736563726574732e74657374";
    static const char r3[] = "4b53564144303031000100020001000100112233445566778899aabbccddeeff0123456789abcdef0123456789abcdef000000000000000100000020000e6b696c69782d70616972696e6764";
    static const char r4[] = "4b53564144303031000100030001000100112233445566778899aabbccddeeff0123456789abcdef0123456789abcdef00000000000000070000008000126b696c69782d736563726574732e74657374";
    static const char s1[] = "4b535341443030310001000100010001000100112233445566778899aabbccddeefffedcba9876543210fedcba98765432100000000400000000200000000010a0a1a2a3a4a5a6a7a8a9aaabacadaeaf00000020";
    static const char s2[] = "4b535341443030310001000100010001000100112233445566778899aabbccddeefffedcba9876543210fedcba98765432100000000300000000100000000010a0a1a2a3a4a5a6a7a8a9aaabacadaeaf00000020";
    static const char s3[] = "4b535341443030310001000200010001000100112233445566778899aabbccddeefffedcba9876543210fedcba98765432100000000400000000200000000010a0a1a2a3a4a5a6a7a8a9aaabacadaeaf00000020";
    check_record_ad_vector(KSEC_OBJECT_SECRET, 1U, 32U,
                           "kilix-secrets.test", r1);
    check_record_ad_vector(KSEC_OBJECT_SECRET, 2U, 32U,
                           "kilix-secrets.test", r2);
    check_record_ad_vector(KSEC_OBJECT_DEVICE_IDENTITY, 1U, 32U,
                           "kilix-pairingd", r3);
    check_record_ad_vector(KSEC_OBJECT_BACKUP_METADATA, 7U, 128U,
                           "kilix-secrets.test", r4);
    check_slot_ad_vector(KSEC_SLOT_PASSPHRASE, 4U,
                         UINT64_C(512) * 1024U * 1024U, s1);
    check_slot_ad_vector(KSEC_SLOT_PASSPHRASE, 3U,
                         UINT64_C(256) * 1024U * 1024U, s2);
    check_slot_ad_vector(KSEC_SLOT_RECOVERY, 4U,
                         UINT64_C(512) * 1024U * 1024U, s3);
}

static void test_record_codec(void) {
    const uint8_t first_value[] = {0U, 1U, 2U, 3U};
    const uint8_t second_value[] = {'v', 'a', 'l', 'u', 'e'};
    ksec_field fields[2] = {
        {"binary", first_value, sizeof first_value},
        {"password", second_value, sizeof second_value}
    };
    ksec_record input = {
        "kilix-secrets.test", "opaque", "Synthetic café", 1234U,
        fields, 2U
    };
    uint8_t encoded[1024];
    size_t encoded_len = 0;
    ksec_owned_record parsed;
    ksec_field duplicates[2] = {
        {"same", first_value, sizeof first_value},
        {"same", second_value, sizeof second_value}
    };
    memset(&parsed, 0, sizeof parsed);
    CHECK(ksec_record_serialize(&input, encoded, sizeof encoded,
                                &encoded_len) == KSEC_OK);
    CHECK(ksec_record_parse(encoded, encoded_len, &parsed) == KSEC_OK);
    CHECK(strcmp(parsed.type, input.type) == 0);
    CHECK(strcmp(parsed.label, input.label) == 0);
    CHECK(parsed.expires_at == input.expires_at && parsed.field_count == 2U);
    CHECK(memcmp(parsed.fields[0].value.data, first_value,
                 sizeof first_value) == 0);
    CHECK(memcmp(parsed.fields[1].value.data, second_value,
                 sizeof second_value) == 0);
    ksec_owned_record_clear(&parsed);

    input.fields = duplicates;
    CHECK(ksec_record_serialize(&input, encoded, sizeof encoded,
                                &encoded_len) == KSEC_ERR_INVALID);
    input.fields = fields;
    CHECK(ksec_record_serialize(&input, encoded, sizeof encoded,
                                &encoded_len) == KSEC_OK);
    encoded[10] = 0U;
    encoded[11] = 1U;
    CHECK(ksec_record_parse(encoded, encoded_len, &parsed) == KSEC_ERR_INVALID);
    CHECK(parsed.field_count == 0U);
    CHECK(ksec_record_serialize(&input, encoded, sizeof encoded,
                                &encoded_len) == KSEC_OK);
    encoded[26] = 0U;
    CHECK(ksec_record_parse(encoded, encoded_len, &parsed) == KSEC_ERR_INVALID);
    CHECK(ksec_record_serialize(&input, encoded, sizeof encoded,
                                &encoded_len) == KSEC_OK);
    encoded[26] = 0xc0U;
    CHECK(ksec_record_parse(encoded, encoded_len, &parsed) == KSEC_ERR_INVALID);
    CHECK(ksec_record_serialize(&input, encoded, sizeof encoded,
                                &encoded_len) == KSEC_OK);
    encoded[encoded_len] = 0U;
    CHECK(ksec_record_parse(encoded, encoded_len + 1U, &parsed) == KSEC_ERR_INVALID);
    CHECK(ksec_record_parse(encoded, 25U, &parsed) == KSEC_ERR_INVALID);
}

static void send_two_fds(int socket_fd, const uint8_t *packet,
                         size_t packet_len, int first_fd, int second_fd) {
    uint8_t control[CMSG_SPACE(sizeof(int) * 2U)];
    int fds[2] = {first_fd, second_fd};
    struct iovec iov;
    struct msghdr message;
    struct cmsghdr *cmsg;
    memset(&message, 0, sizeof message);
    memset(control, 0, sizeof control);
    iov.iov_base = (void *)packet;
    iov.iov_len = packet_len;
    message.msg_iov = &iov;
    message.msg_iovlen = 1U;
    message.msg_control = control;
    message.msg_controllen = sizeof control;
    cmsg = CMSG_FIRSTHDR(&message);
    if (cmsg == NULL) return;
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof fds);
    memcpy(CMSG_DATA(cmsg), fds, sizeof fds);
    (void)sendmsg(socket_fd, &message, MSG_NOSIGNAL);
}

static void test_protocol(void) {
    ksec_packet_header header = {KSEC_PROTOCOL_VERSION, KSEC_OP_GET, 0U,
                                 UINT64_C(0x0102030405060708), 3U};
    ksec_packet_header parsed;
    const uint8_t payload[] = {0xaaU, 0xbbU, 0xccU};
    const uint8_t *parsed_payload = NULL;
    uint8_t packet[KSEC_PROTOCOL_MAX_PACKET];
    uint8_t received[16];
    size_t packet_len = 0;
    int sockets[2];
    int pipes[2];
    int received_fd = -1;
    int before;
    int after;
    char marker = 0;

    CHECK(ksec_packet_encode(&header, payload, packet, sizeof packet,
                             &packet_len) == KSEC_OK);
    CHECK(packet_len == KSEC_PROTOCOL_HEADER_BYTES + sizeof payload);
    CHECK(ksec_packet_decode(packet, packet_len, &parsed,
                             &parsed_payload) == KSEC_OK);
    CHECK(parsed.operation == header.operation && parsed.request_id == header.request_id);
    CHECK(memcmp(parsed_payload, payload, sizeof payload) == 0);
    CHECK(ksec_packet_decode(packet, packet_len - 1U, &parsed,
                             &parsed_payload) == KSEC_ERR_PROTOCOL);
    packet[packet_len] = 0U;
    CHECK(ksec_packet_decode(packet, packet_len + 1U, &parsed,
                             &parsed_payload) == KSEC_ERR_PROTOCOL);
    packet[8] = 1U;
    CHECK(ksec_packet_decode(packet, packet_len, &parsed,
                             &parsed_payload) == KSEC_ERR_PROTOCOL);
    packet[8] = 0U;
    packet[6] = 0U;
    packet[7] = 99U;
    CHECK(ksec_packet_decode(packet, packet_len, &parsed,
                             &parsed_payload) == KSEC_ERR_PROTOCOL);

    header.operation = KSEC_OP_GET;
    CHECK(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets) == 0);
    CHECK(pipe2(pipes, O_CLOEXEC) == 0);
    CHECK(ksec_write_all(pipes[1], "x", 1U) == 0);
    CHECK(ksec_send_packet(sockets[0], &header, payload, pipes[0]) == KSEC_OK);
    CHECK(ksec_recv_packet(sockets[1], &parsed, received, sizeof received,
                           &received_fd) == KSEC_OK);
    CHECK(received_fd >= 0);
    CHECK(fcntl(received_fd, F_GETFD) >= 0
          && (fcntl(received_fd, F_GETFD) & FD_CLOEXEC) != 0);
    CHECK(read(received_fd, &marker, 1U) == 1 && marker == 'x');
    if (received_fd >= 0) (void)close(received_fd);

    CHECK(ksec_packet_encode(&header, payload, packet, sizeof packet,
                             &packet_len) == KSEC_OK);
    before = count_open_fds();
    send_two_fds(sockets[0], packet, packet_len, pipes[0], pipes[1]);
    received_fd = -1;
    CHECK(ksec_recv_packet(sockets[1], &parsed, received, sizeof received,
                           &received_fd) == KSEC_ERR_PROTOCOL);
    after = count_open_fds();
    CHECK(before >= 0 && before == after);
    (void)close(pipes[0]);
    (void)close(pipes[1]);
    (void)close(sockets[0]);
    (void)close(sockets[1]);
}

static void test_crypto(void) {
    static const uint8_t passphrase[] = "synthetic-passphrase";
    static const uint8_t wrong_passphrase[] = "synthetic-wrong-passphrase";
    static const uint8_t new_passphrase[] = "synthetic-new-passphrase";
    static const uint8_t recovery[] =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    ksec_vault_header header;
    ksec_vault_header decoded;
    ksec_vault_header tampered;
    ksec_vault_header rewrapped;
    ksec_vault_header rotated;
    ksec_vault_header previous;
    uint8_t master[KSEC_MASTER_KEY_BYTES];
    uint8_t new_master[KSEC_MASTER_KEY_BYTES];
    uint8_t unlocked[KSEC_MASTER_KEY_BYTES];
    uint8_t encoded[1024];
    size_t encoded_len = 0;
    uint8_t uuid[KSEC_UUID_BYTES];
    uint8_t object_id[KSEC_RECORD_ID_BYTES];
    uint8_t nonce[KSEC_NONCE_BYTES];
    uint8_t second_nonce[KSEC_NONCE_BYTES];
    const uint8_t plaintext[] = "fixture-data";
    uint8_t ciphertext[sizeof plaintext + KSEC_TAG_BYTES];
    uint8_t second_ciphertext[sizeof plaintext + KSEC_TAG_BYTES];
    uint8_t decrypted[sizeof plaintext];
    size_t ciphertext_len = 0;
    size_t second_len = 0;
    size_t decrypted_len = 0;

    memset(master, 0, sizeof master);
    CHECK(ksec_header_create(&header, passphrase, sizeof passphrase - 1U,
                             recovery, sizeof recovery - 1U, 3U,
                             KSEC_ARGON_MEM_MIN, master) == KSEC_OK);
    CHECK(!all_zero(master, sizeof master));
    CHECK(header.flags == 0U && header.generation == 1U);
    CHECK(ksec_header_encode(&header, encoded, sizeof encoded,
                             &encoded_len) == KSEC_OK);
    CHECK(encoded_len == 330U);
    CHECK(ksec_header_decode(encoded, encoded_len, &decoded) == KSEC_OK);
    memset(unlocked, 0xa5, sizeof unlocked);
    CHECK(ksec_header_unlock(&decoded, KSEC_SLOT_PASSPHRASE,
                             wrong_passphrase, sizeof wrong_passphrase - 1U,
                             unlocked) == KSEC_ERR_CRYPTO);
    CHECK(all_zero(unlocked, sizeof unlocked));
    CHECK(ksec_header_unlock(&decoded, KSEC_SLOT_PASSPHRASE,
                             passphrase, sizeof passphrase - 1U,
                             unlocked) == KSEC_OK);
    CHECK(memcmp(unlocked, master, sizeof master) == 0);
    sodium_memzero(unlocked, sizeof unlocked);

    tampered = decoded;
    tampered.auth_tag[0] ^= 1U;
    CHECK(ksec_header_unlock(&tampered, KSEC_SLOT_PASSPHRASE,
                             passphrase, sizeof passphrase - 1U,
                             unlocked) == KSEC_ERR_CRYPTO);
    CHECK(all_zero(unlocked, sizeof unlocked));
    CHECK(ksec_header_unlock(&decoded, KSEC_SLOT_RECOVERY,
                             recovery, sizeof recovery - 1U,
                             unlocked) == KSEC_OK);
    CHECK(memcmp(unlocked, master, sizeof master) == 0);
    CHECK(ksec_header_confirm_recovery(&decoded, unlocked) == KSEC_OK);
    CHECK((decoded.flags & KSEC_HEADER_FLAG_RECOVERY_CONFIRMED) != 0U
          && decoded.generation == 2U);
    CHECK(ksec_header_confirm_recovery(&decoded, unlocked) == KSEC_ERR_EXISTS);
    rewrapped = decoded;
    CHECK(ksec_header_rewrap_slot(&rewrapped, KSEC_SLOT_PASSPHRASE,
                                  new_passphrase,
                                  sizeof new_passphrase - 1U,
                                  KSEC_ARGON_OPS_MIN, KSEC_ARGON_MEM_MIN,
                                  master) == KSEC_OK);
    CHECK(rewrapped.generation == decoded.generation + 1U);
    CHECK(ksec_header_unlock(&rewrapped, KSEC_SLOT_PASSPHRASE,
                             passphrase, sizeof passphrase - 1U,
                             unlocked) == KSEC_ERR_CRYPTO);
    CHECK(ksec_header_unlock(&rewrapped, KSEC_SLOT_PASSPHRASE,
                             new_passphrase, sizeof new_passphrase - 1U,
                             unlocked) == KSEC_OK
          && memcmp(unlocked, master, sizeof master) == 0);
    CHECK(ksec_header_unlock(&rewrapped, KSEC_SLOT_RECOVERY,
                             recovery, sizeof recovery - 1U,
                             unlocked) == KSEC_OK
          && memcmp(unlocked, master, sizeof master) == 0);
    previous = rewrapped;
    CHECK(ksec_header_rewrap_slot(&rewrapped, KSEC_SLOT_PASSPHRASE,
                                  new_passphrase,
                                  sizeof new_passphrase - 1U,
                                  KSEC_ARGON_OPS_MIN - 1U,
                                  KSEC_ARGON_MEM_MIN, master)
          == KSEC_ERR_INVALID);
    CHECK(memcmp(&rewrapped, &previous, sizeof rewrapped) == 0);
    fill_sequence(new_master, sizeof new_master, 0x90U);
    rotated = rewrapped;
    CHECK(ksec_header_rotate_master(&rotated, master, new_master,
                                    new_passphrase,
                                    sizeof new_passphrase - 1U,
                                    recovery, sizeof recovery - 1U,
                                    KSEC_ARGON_OPS_MIN,
                                    KSEC_ARGON_MEM_MIN) == KSEC_OK);
    CHECK(rotated.generation == rewrapped.generation + 1U);
    CHECK(ksec_header_unlock(&rotated, KSEC_SLOT_PASSPHRASE,
                             new_passphrase, sizeof new_passphrase - 1U,
                             unlocked) == KSEC_OK
          && memcmp(unlocked, new_master, sizeof new_master) == 0);
    CHECK(ksec_header_unlock(&rotated, KSEC_SLOT_RECOVERY,
                             recovery, sizeof recovery - 1U,
                             unlocked) == KSEC_OK
          && memcmp(unlocked, new_master, sizeof new_master) == 0);
    previous = rotated;
    CHECK(ksec_header_rotate_master(&rotated, new_master, new_master,
                                    new_passphrase,
                                    sizeof new_passphrase - 1U,
                                    recovery, sizeof recovery - 1U,
                                    KSEC_ARGON_OPS_MIN,
                                    KSEC_ARGON_MEM_MIN) == KSEC_ERR_INVALID);
    CHECK(memcmp(&rotated, &previous, sizeof rotated) == 0);
    sodium_memzero(new_master, sizeof new_master);
    sodium_memzero(&rewrapped, sizeof rewrapped);
    sodium_memzero(&rotated, sizeof rotated);
    sodium_memzero(&previous, sizeof previous);
    sodium_memzero(unlocked, sizeof unlocked);
    CHECK(ksec_header_encode(&decoded, encoded, sizeof encoded,
                             &encoded_len) == KSEC_OK);
    CHECK(ksec_header_decode(encoded, encoded_len, &fixture_header) == KSEC_OK);
    memcpy(fixture_master, master, sizeof fixture_master);
    encoded[40] = 0x80U;
    CHECK(ksec_header_decode(encoded, encoded_len, &tampered) == KSEC_ERR_INVALID);
    CHECK(ksec_header_encode(&decoded, encoded, sizeof encoded,
                             &encoded_len) == KSEC_OK);
    memcpy(encoded + 42U + 8U, decoded.slots[1].slot_id, KSEC_SLOT_ID_BYTES);
    CHECK(ksec_header_decode(encoded, encoded_len, &tampered) == KSEC_ERR_INVALID);
    CHECK(ksec_header_encode(&decoded, encoded, sizeof encoded,
                             &encoded_len) == KSEC_OK);
    ksec_put_u32(encoded + 66U, KSEC_ARGON_OPS_MAX + 1U);
    CHECK(ksec_header_decode(encoded, encoded_len, &tampered) == KSEC_ERR_INVALID);

    memcpy(uuid, decoded.vault_uuid, sizeof uuid);
    fill_sequence(object_id, sizeof object_id, 0x40U);
    CHECK(ksec_record_encrypt(master, KSEC_OBJECT_SECRET, uuid, object_id, 1U,
                              "kilix-secrets.test", plaintext, sizeof plaintext,
                              nonce, ciphertext, sizeof ciphertext,
                              &ciphertext_len) == KSEC_OK);
    CHECK(ciphertext_len == sizeof plaintext + KSEC_TAG_BYTES);
    CHECK(ksec_record_decrypt(master, KSEC_OBJECT_SECRET, uuid, object_id, 1U,
                              "kilix-secrets.test", nonce, ciphertext,
                              ciphertext_len, decrypted, sizeof decrypted,
                              &decrypted_len) == KSEC_OK);
    CHECK(decrypted_len == sizeof plaintext
          && memcmp(decrypted, plaintext, sizeof plaintext) == 0);
    CHECK(ksec_record_encrypt(master, KSEC_OBJECT_SECRET, uuid, object_id, 1U,
                              "kilix-secrets.test", plaintext, sizeof plaintext,
                              second_nonce, second_ciphertext, sizeof second_ciphertext,
                              &second_len) == KSEC_OK);
    CHECK(memcmp(nonce, second_nonce, sizeof nonce) != 0);
    CHECK(memcmp(ciphertext, second_ciphertext, ciphertext_len) != 0);

    unlocked[0] ^= 1U;
    CHECK(ksec_record_decrypt(unlocked, KSEC_OBJECT_SECRET, uuid, object_id, 1U,
                              "kilix-secrets.test", nonce, ciphertext,
                              ciphertext_len, decrypted, sizeof decrypted,
                              &decrypted_len) == KSEC_ERR_CRYPTO);
    unlocked[0] ^= 1U;
    uuid[0] ^= 1U;
    CHECK(ksec_record_decrypt(master, KSEC_OBJECT_SECRET, uuid, object_id, 1U,
                              "kilix-secrets.test", nonce, ciphertext,
                              ciphertext_len, decrypted, sizeof decrypted,
                              &decrypted_len) == KSEC_ERR_CRYPTO);
    uuid[0] ^= 1U;
    object_id[0] ^= 1U;
    CHECK(ksec_record_decrypt(master, KSEC_OBJECT_SECRET, uuid, object_id, 1U,
                              "kilix-secrets.test", nonce, ciphertext,
                              ciphertext_len, decrypted, sizeof decrypted,
                              &decrypted_len) == KSEC_ERR_CRYPTO);
    object_id[0] ^= 1U;
    CHECK(ksec_record_decrypt(master, KSEC_OBJECT_SECRET, uuid, object_id, 2U,
                              "kilix-secrets.test", nonce, ciphertext,
                              ciphertext_len, decrypted, sizeof decrypted,
                              &decrypted_len) == KSEC_ERR_CRYPTO);
    CHECK(ksec_record_decrypt(master, KSEC_OBJECT_SECRET, uuid, object_id, 1U,
                              "other-app", nonce, ciphertext, ciphertext_len,
                              decrypted, sizeof decrypted,
                              &decrypted_len) == KSEC_ERR_CRYPTO);
    nonce[0] ^= 1U;
    CHECK(ksec_record_decrypt(master, KSEC_OBJECT_SECRET, uuid, object_id, 1U,
                              "kilix-secrets.test", nonce, ciphertext,
                              ciphertext_len, decrypted, sizeof decrypted,
                              &decrypted_len) == KSEC_ERR_CRYPTO);
    nonce[0] ^= 1U;
    ciphertext[0] ^= 1U;
    CHECK(ksec_record_decrypt(master, KSEC_OBJECT_SECRET, uuid, object_id, 1U,
                              "kilix-secrets.test", nonce, ciphertext,
                              ciphertext_len, decrypted, sizeof decrypted,
                              &decrypted_len) == KSEC_ERR_CRYPTO);
    ciphertext[0] ^= 1U;
    CHECK(ksec_record_decrypt(master, KSEC_OBJECT_SECRET, uuid, object_id, 1U,
                              "kilix-secrets.test", nonce, ciphertext,
                              ciphertext_len - 1U, decrypted, sizeof decrypted,
                              &decrypted_len) == KSEC_ERR_CRYPTO);
    sodium_memzero(master, sizeof master);
    sodium_memzero(unlocked, sizeof unlocked);
    sodium_memzero(decrypted, sizeof decrypted);
}

static int make_temp_dir(char path[4096]) {
    const char *root = getenv("TMPDIR");
    struct stat status;
    int count;
    if (root == NULL || root[0] != '/' || lstat(root, &status) != 0
            || !S_ISDIR(status.st_mode) || S_ISLNK(status.st_mode)) return -1;
    count = snprintf(path, 4096U, "%s/ksec-unit.XXXXXX", root);
    if (count < 0 || count >= 4096) return -1;
    return mkdtemp(path) == NULL ? -1 : 0;
}

static void cleanup_store_dir(const char *path) {
    static const char *const leaves[] = {
        "vault.ksv", "journal.ksj", "writer.lock", "audit.log", "audit.log.1",
        ".vault.ksv.tmp", ".journal.ksj.tmp", "vault-link"
    };
    size_t index;
    char child[4096];
    for (index = 0; index < sizeof leaves / sizeof leaves[0]; index++) {
        int count = snprintf(child, sizeof child, "%s/%s", path, leaves[index]);
        if (count >= 0 && (size_t)count < sizeof child) (void)unlink(child);
    }
    (void)rmdir(path);
}

static ksec_result make_owned_record(ksec_owned_record *owned,
                                     const uint8_t id[KSEC_RECORD_ID_BYTES],
                                     const uint8_t *value, size_t value_len,
                                     const char *label) {
    ksec_field field = {"value", value, value_len};
    ksec_record record = {"kilix-secrets.test", "opaque", label, 0U, &field, 1U};
    uint8_t encoded[1024];
    size_t encoded_len = 0;
    ksec_result result = ksec_record_serialize(&record, encoded, sizeof encoded,
                                               &encoded_len);
    if (result != KSEC_OK) return result;
    result = ksec_record_parse(encoded, encoded_len, owned);
    sodium_memzero(encoded, sizeof encoded);
    if (result != KSEC_OK) return result;
    memcpy(owned->id, id, KSEC_RECORD_ID_BYTES);
    memcpy(owned->owner, record.owner, strlen(record.owner) + 1U);
    owned->object_type = KSEC_OBJECT_SECRET;
    return KSEC_OK;
}

static void test_store(void) {
    char directory[4096];
    char vault_path[4096];
    char journal_path[4096];
    char link_path[4096];
    ksec_store store;
    ksec_store second;
    ksec_owned_record record;
    ksec_owned_record replacement;
    ksec_owned_record tombstone;
    ksec_vault_header read_header;
    uint8_t id[KSEC_RECORD_ID_BYTES];
    const uint8_t first[] = "first-fixture";
    const uint8_t next[] = "next-fixture";
    int fd;

    memset(&store, 0, sizeof store);
    memset(&second, 0, sizeof second);
    memset(&record, 0, sizeof record);
    memset(&replacement, 0, sizeof replacement);
    memset(&tombstone, 0, sizeof tombstone);
    fill_sequence(id, sizeof id, 0x70U);
    CHECK(make_temp_dir(directory) == 0);
    CHECK(ksec_store_open(&store, directory, false) == KSEC_OK);
    CHECK(ksec_store_open(&second, directory, false) == KSEC_ERR_BUSY);
    CHECK(ksec_store_write_header(&store, &fixture_header) == KSEC_OK);
    CHECK(ksec_store_read_header(&store, &read_header) == KSEC_OK);
    CHECK(read_header.flags == fixture_header.flags);
    CHECK(make_owned_record(&record, id, first, sizeof first, "first") == KSEC_OK);
    CHECK(ksec_store_append(&store, &fixture_header, fixture_master, &record,
                            false) == KSEC_OK);
    CHECK(store.last_revision == 1U && store.record_count == 1U);
    CHECK(ksec_store_find(&store, id) != NULL);
    CHECK(make_owned_record(&replacement, id, next, sizeof next, "next") == KSEC_OK);
    CHECK(ksec_store_append(&store, &fixture_header, fixture_master, &replacement,
                            false) == KSEC_OK);
    CHECK(store.last_revision == 2U && store.record_count == 1U);
    memcpy(tombstone.id, id, sizeof id);
    memcpy(tombstone.owner, "kilix-secrets.test", sizeof "kilix-secrets.test");
    tombstone.object_type = KSEC_OBJECT_SECRET;
    CHECK(ksec_store_append(&store, &fixture_header, fixture_master, &tombstone,
                            true) == KSEC_OK);
    CHECK(store.last_revision == 3U && store.record_count == 0U);
    CHECK(ksec_store_compact(&store, &fixture_header, fixture_master) == KSEC_OK);
    ksec_store_close(&store);
    CHECK(ksec_store_open(&store, directory, false) == KSEC_OK);
    CHECK(ksec_store_load(&store, &fixture_header, fixture_master) == KSEC_OK);
    CHECK(store.last_revision == 3U && store.record_count == 0U && !store.torn_tail);
    CHECK(make_owned_record(&record, id, first, sizeof first, "after-compact") == KSEC_OK);
    CHECK(ksec_store_append(&store, &fixture_header, fixture_master, &record,
                            false) == KSEC_OK);
    CHECK(store.last_revision == 4U && ksec_store_find(&store, id) != NULL
          && ksec_store_find(&store, id)->revision == 4U);
    ksec_store_close(&store);

    CHECK(snprintf(journal_path, sizeof journal_path, "%s/journal.ksj", directory) > 0);
    fd = open(journal_path, O_WRONLY | O_APPEND | O_CLOEXEC);
    CHECK(fd >= 0);
    if (fd >= 0) {
        CHECK(ksec_write_all(fd, "torn", 4U) == 0);
        CHECK(close(fd) == 0);
    }
    CHECK(ksec_store_open(&store, directory, false) == KSEC_OK);
    CHECK(ksec_store_load(&store, &fixture_header, fixture_master) == KSEC_OK);
    CHECK(store.torn_tail && store.last_revision == 4U);
    CHECK(make_owned_record(&record, id, first, sizeof first, "refused") == KSEC_OK);
    CHECK(ksec_store_append(&store, &fixture_header, fixture_master, &record,
                            false) == KSEC_ERR_INVALID);
    ksec_owned_record_clear(&record);
    ksec_store_close(&store);

    CHECK(snprintf(vault_path, sizeof vault_path, "%s/vault.ksv", directory) > 0);
    CHECK(snprintf(link_path, sizeof link_path, "%s/vault-link", directory) > 0);
    CHECK(link(vault_path, link_path) == 0);
    CHECK(ksec_store_open(&store, directory, false) == KSEC_OK);
    CHECK(ksec_store_read_header(&store, &read_header) == KSEC_ERR_DENIED);
    ksec_store_close(&store);
    CHECK(unlink(link_path) == 0);
    cleanup_store_dir(directory);

    CHECK(make_temp_dir(directory) == 0);
    CHECK(chmod(directory, 0755) == 0);
    CHECK(ksec_store_open(&store, directory, false) == KSEC_ERR_DENIED);
    CHECK(chmod(directory, 0700) == 0);
    cleanup_store_dir(directory);
}

static void test_audit(void) {
    char directory[4096];
    char audit_path[4096];
    char rotated_path[4096];
    char contents[1024];
    struct stat status;
    int fd = -1;
    ssize_t count;
    uint8_t id[KSEC_RECORD_ID_BYTES];
    fill_sequence(id, sizeof id, 0x20U);
    CHECK(make_temp_dir(directory) == 0);
    CHECK(ksec_audit_open(directory, &fd) == KSEC_OK);
    CHECK(ksec_audit_event(fd, "create", "begin", getuid(), getpid(),
                           "kilix-secrets.test", id) == KSEC_OK);
    CHECK(fstat(fd, &status) == 0 && S_ISREG(status.st_mode)
          && (status.st_mode & 0777U) == 0600U);
    CHECK(close(fd) == 0);
    CHECK(snprintf(audit_path, sizeof audit_path, "%s/audit.log", directory) > 0);
    fd = open(audit_path, O_RDONLY | O_CLOEXEC);
    CHECK(fd >= 0);
    count = fd >= 0 ? read(fd, contents, sizeof contents - 1U) : -1;
    CHECK(count > 0);
    if (count > 0) {
        contents[(size_t)count] = '\0';
        CHECK(strstr(contents, "event=create") != NULL);
        CHECK(strstr(contents, "fixture") == NULL);
    }
    if (fd >= 0) CHECK(close(fd) == 0);
    fd = open(audit_path, O_WRONLY | O_CLOEXEC);
    CHECK(fd >= 0);
    if (fd >= 0) {
        CHECK(ftruncate(fd, (off_t)KSEC_MAX_AUDIT_BYTES) == 0);
        CHECK(ksec_audit_event(fd, "create", "begin", getuid(), getpid(),
                               "kilix-secrets.test", id) == KSEC_ERR_AUDIT);
        CHECK(close(fd) == 0);
    }
    CHECK(ksec_audit_open(directory, &fd) == KSEC_OK);
    if (fd >= 0) CHECK(close(fd) == 0);
    CHECK(snprintf(rotated_path, sizeof rotated_path, "%s/audit.log.1", directory) > 0);
    CHECK(lstat(rotated_path, &status) == 0
          && (uint64_t)status.st_size == KSEC_MAX_AUDIT_BYTES);
    cleanup_store_dir(directory);
}

static pid_t spawn_waiting_child(int pipe_fd[2]) {
    pid_t child;
    if (pipe2(pipe_fd, O_CLOEXEC) != 0) return -1;
    child = fork();
    if (child == 0) {
        char byte;
        (void)close(pipe_fd[1]);
        while (read(pipe_fd[0], &byte, 1U) < 0 && errno == EINTR) {}
        (void)close(pipe_fd[0]);
        _exit(0);
    }
    if (child < 0) {
        (void)close(pipe_fd[0]);
        (void)close(pipe_fd[1]);
        return -1;
    }
    (void)close(pipe_fd[0]);
    pipe_fd[0] = -1;
    return child;
}

static void stop_waiting_child(pid_t child, int write_fd) {
    int status = 0;
    if (write_fd >= 0) (void)close(write_fd);
    if (child > 0) CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status));
}

static void test_policy(void) {
    ksec_policy policy;
    ksec_capability *capability = NULL;
    uint8_t token[KSEC_CAPABILITY_BYTES];
    uint8_t record_id[KSEC_RECORD_ID_BYTES];
    uint8_t other_id[KSEC_RECORD_ID_BYTES];
    int capability_fd = -1;
    int wait_pipe[2] = {-1, -1};
    pid_t child;
    fill_sequence(record_id, sizeof record_id, 0x11U);
    fill_sequence(other_id, sizeof other_id, 0x22U);
    ksec_policy_init(&policy);
    child = spawn_waiting_child(wait_pipe);
    CHECK(child > 0);
    CHECK(ksec_policy_mint(&policy, getpid(), child, "kilix-secrets.test",
                           KSEC_VERB_USE, record_id, 60U,
                           &capability_fd) == KSEC_OK);
    CHECK(ksec_read_exact(capability_fd, token, sizeof token) == 0);
    CHECK(close(capability_fd) == 0);
    capability_fd = -1;
    CHECK(ksec_policy_activate(&policy, 123, getpid(), token, sizeof token,
                               &capability) == KSEC_ERR_DENIED);
    CHECK(ksec_policy_activate(&policy, 123, child, token, sizeof token,
                               &capability) == KSEC_OK);
    CHECK(capability != NULL);
    CHECK(ksec_policy_activate(&policy, 124, child, token, sizeof token,
                               &capability) == KSEC_ERR_DENIED);
    CHECK(ksec_policy_authorize(capability, KSEC_VERB_USE,
                                "kilix-secrets.test", record_id) == KSEC_OK);
    CHECK(ksec_policy_authorize(capability, KSEC_VERB_READ,
                                "kilix-secrets.test", record_id) == KSEC_ERR_DENIED);
    CHECK(ksec_policy_authorize(capability, KSEC_VERB_USE,
                                "other-app", record_id) == KSEC_ERR_DENIED);
    CHECK(ksec_policy_authorize(capability, KSEC_VERB_USE,
                                "kilix-secrets.test", other_id) == KSEC_ERR_DENIED);
    CHECK(ksec_policy_authorize(capability, KSEC_VERB_USE,
                                "kilix-secrets.test", NULL) == KSEC_ERR_DENIED);
    capability->expires_at = ksec_now_seconds();
    CHECK(ksec_policy_authorize(capability, KSEC_VERB_USE,
                                "kilix-secrets.test", record_id) == KSEC_ERR_DENIED);
    ksec_policy_disconnect(&policy, 123);
    CHECK(!policy.entries[0].active);
    stop_waiting_child(child, wait_pipe[1]);
    ksec_policy_clear(&policy);
    sodium_memzero(token, sizeof token);
}

static void test_secure_memory_failure(void) {
    ksec_secure_buffer buffer = {0};
    ksec_test_force_mlock_failure(true);
    CHECK(ksec_secure_alloc(&buffer, 4096U) == KSEC_ERR_MEMORY);
    CHECK(buffer.data == NULL && buffer.len == 0U);
    ksec_test_force_mlock_failure(false);
    CHECK(ksec_secure_alloc(&buffer, 4096U) == KSEC_OK);
    ksec_secure_free(&buffer);
}

int main(void) {
    if (ksec_crypto_initialize() != KSEC_OK) {
        fprintf(stderr, "libsodium initialization failed\n");
        return 1;
    }
    test_utilities();
    test_ad_vectors();
    test_record_codec();
    test_protocol();
    test_crypto();
    test_store();
    test_audit();
    test_policy();
    test_secure_memory_failure();
    sodium_memzero(fixture_master, sizeof fixture_master);
    sodium_memzero(&fixture_header, sizeof fixture_header);
    printf("unit checks: %u/%u passed\n", checks_run - checks_failed, checks_run);
    return checks_failed == 0U ? 0 : 1;
}
