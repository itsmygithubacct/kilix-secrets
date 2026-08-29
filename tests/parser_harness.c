#define _GNU_SOURCE

#include "internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define HARNESS_MAX_INPUT (1024U * 1024U)
#define HARNESS_MAX_STREAM_ITEM 4096U

static int read_stdin(uint8_t **out, size_t *out_len) {
    uint8_t *buffer = malloc(HARNESS_MAX_INPUT);
    size_t total = 0;
    if (buffer == NULL || out == NULL || out_len == NULL) {
        free(buffer);
        return -1;
    }
    while (total < HARNESS_MAX_INPUT) {
        ssize_t count = read(STDIN_FILENO, buffer + total, HARNESS_MAX_INPUT - total);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) { free(buffer); return -1; }
        if (count == 0) break;
        total += (size_t)count;
    }
    if (total == HARNESS_MAX_INPUT) {
        uint8_t extra;
        ssize_t count;
        do {
            count = read(STDIN_FILENO, &extra, 1U);
        } while (count < 0 && errno == EINTR);
        if (count != 0) { free(buffer); return -1; }
    }
    *out = buffer;
    *out_len = total;
    return 0;
}

static ksec_result parse_protocol(const uint8_t *data, size_t length) {
    ksec_packet_header header;
    const uint8_t *payload = NULL;
    return ksec_packet_decode(data, length, &header, &payload);
}

static ksec_result parse_header(const uint8_t *data, size_t length) {
    ksec_vault_header header;
    ksec_result result = ksec_header_decode(data, length, &header);
    sodium_memzero(&header, sizeof header);
    return result;
}

static ksec_result parse_record(const uint8_t *data, size_t length) {
    ksec_owned_record record;
    ksec_result result;
    memset(&record, 0, sizeof record);
    result = ksec_record_parse(data, length, &record);
    ksec_owned_record_clear(&record);
    return result;
}

static ksec_result parse_ad(const uint8_t *data, size_t length) {
    uint16_t object_type = 0;
    uint8_t vault_uuid[KSEC_UUID_BYTES];
    uint8_t object_id[KSEC_RECORD_ID_BYTES];
    uint64_t revision = 0;
    uint32_t plaintext_length = 0;
    char owner[KSEC_MAX_APP_ID + 1U];
    ksec_result result = ksec_parse_record_ad(data, length, &object_type,
                                              vault_uuid, object_id, &revision,
                                              &plaintext_length, owner);
    sodium_memzero(vault_uuid, sizeof vault_uuid);
    sodium_memzero(object_id, sizeof object_id);
    sodium_memzero(owner, sizeof owner);
    return result;
}

static ksec_result parse_backup(const uint8_t *data, size_t length) {
    uint32_t vault_len = 0U;
    uint64_t journal_len = 0U;
    if (length < 176U) return KSEC_ERR_INVALID;
    return ksec_backup_validate_envelope_header(data, 176U, (uint64_t)length,
                                                &vault_len, &journal_len);
}

static void exercise_all(const uint8_t *data, size_t length) {
    (void)parse_protocol(data, length);
    (void)parse_header(data, length);
    (void)parse_record(data, length);
    (void)parse_ad(data, length);
    (void)parse_backup(data, length);
}

static int read_exact_or_eof(uint8_t *buffer, size_t length, int eof_ok) {
    size_t offset = 0U;
    while (offset < length) {
        ssize_t count = read(STDIN_FILENO, buffer + offset, length - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) return -1;
        if (count == 0) return offset == 0U && eof_ok != 0 ? 1 : -1;
        offset += (size_t)count;
    }
    return 0;
}

static int process_stream(void) {
    uint8_t length_bytes[4];
    uint8_t *item = malloc(HARNESS_MAX_STREAM_ITEM);
    size_t processed = 0U;
    int exit_code = 0;
    if (item == NULL) return 2;
    for (;;) {
        uint32_t item_length;
        int read_result = read_exact_or_eof(length_bytes, sizeof length_bytes, 1);
        if (read_result == 1) break;
        if (read_result != 0) { exit_code = 2; break; }
        item_length = ksec_get_u32(length_bytes);
        if (item_length > HARNESS_MAX_STREAM_ITEM
                || read_exact_or_eof(item, (size_t)item_length, 0) != 0) {
            exit_code = 2;
            break;
        }
        exercise_all(item, (size_t)item_length);
        sodium_memzero(item, (size_t)item_length);
        processed++;
    }
    sodium_memzero(item, HARNESS_MAX_STREAM_ITEM);
    free(item);
    sodium_memzero(length_bytes, sizeof length_bytes);
    if (exit_code == 0) {
        printf("mutation inputs: %zu/%zu processed\n", processed, processed);
    }
    return exit_code;
}

int main(int argc, char **argv) {
    uint8_t *data = NULL;
    size_t length = 0;
    ksec_result result;
    if (argc != 2 || ksec_crypto_initialize() != KSEC_OK) return 2;
    if (strcmp(argv[1], "stream") == 0) return process_stream();
    if (read_stdin(&data, &length) != 0) return 2;
    if (strcmp(argv[1], "protocol-reject") == 0) result = parse_protocol(data, length);
    else if (strcmp(argv[1], "header-reject") == 0) result = parse_header(data, length);
    else if (strcmp(argv[1], "record-reject") == 0) result = parse_record(data, length);
    else if (strcmp(argv[1], "ad-reject") == 0) result = parse_ad(data, length);
    else if (strcmp(argv[1], "backup-reject") == 0) {
        result = parse_backup(data, length);
    }
    else {
        sodium_memzero(data, length);
        free(data);
        return 2;
    }
    sodium_memzero(data, length);
    free(data);
    return result == KSEC_OK ? 1 : 0;
}
