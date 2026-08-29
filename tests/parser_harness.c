#define _GNU_SOURCE

#include "internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define HARNESS_MAX_INPUT (1024U * 1024U)

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

static void exercise_all(const uint8_t *data, size_t length) {
    (void)parse_protocol(data, length);
    (void)parse_header(data, length);
    (void)parse_record(data, length);
    (void)parse_ad(data, length);
}

static int process_stream(const uint8_t *data, size_t length) {
    size_t offset = 0;
    unsigned int processed = 0;
    while (offset < length) {
        uint32_t item_length;
        if (length - offset < 4U) return 2;
        item_length = ksec_get_u32(data + offset);
        offset += 4U;
        if ((size_t)item_length > length - offset) return 2;
        exercise_all(data + offset, item_length);
        offset += item_length;
        processed++;
    }
    printf("mutation inputs: %u/%u processed\n", processed, processed);
    return 0;
}

int main(int argc, char **argv) {
    uint8_t *data = NULL;
    size_t length = 0;
    ksec_result result;
    int exit_code;
    if (argc != 2 || ksec_crypto_initialize() != KSEC_OK
            || read_stdin(&data, &length) != 0) return 2;
    if (strcmp(argv[1], "protocol-reject") == 0) result = parse_protocol(data, length);
    else if (strcmp(argv[1], "header-reject") == 0) result = parse_header(data, length);
    else if (strcmp(argv[1], "record-reject") == 0) result = parse_record(data, length);
    else if (strcmp(argv[1], "ad-reject") == 0) result = parse_ad(data, length);
    else if (strcmp(argv[1], "stream") == 0) {
        exit_code = process_stream(data, length);
        sodium_memzero(data, length);
        free(data);
        return exit_code;
    } else {
        sodium_memzero(data, length);
        free(data);
        return 2;
    }
    sodium_memzero(data, length);
    free(data);
    return result == KSEC_OK ? 1 : 0;
}
