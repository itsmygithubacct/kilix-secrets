/*
 * Sealed dataset file v1, dataset-key record schema and request-payload
 * parsers (docs/SEALED-DATASETS.md sections 2, 3 and 4).
 *
 * SKELETON: every function below is a stub owned by lane L1 and returns
 * KSEC_ERR_PROTOCOL until implemented.
 */
#include "internal.h"

ksec_result ksec_dataset_encode_prefix(const ksec_dataset_header_info *info,
                                       uint8_t *output, size_t output_size,
                                       size_t *output_length) {
    (void)info; (void)output; (void)output_size; (void)output_length;
    return KSEC_ERR_PROTOCOL; /* PLACEHOLDER (lane L1) */
}

ksec_result ksec_dataset_parse_prefix(const uint8_t *input, size_t input_length,
                                      ksec_dataset_header_info *info,
                                      size_t *prefix_length) {
    (void)input; (void)input_length; (void)info; (void)prefix_length;
    return KSEC_ERR_PROTOCOL; /* PLACEHOLDER (lane L1) */
}

ksec_result ksec_dataset_sealed_length(uint64_t plaintext_length,
                                       size_t prefix_length,
                                       uint64_t *sealed_length) {
    (void)plaintext_length; (void)prefix_length; (void)sealed_length;
    return KSEC_ERR_PROTOCOL; /* PLACEHOLDER (lane L1) */
}

ksec_result ksec_dataset_seal(const uint8_t key[KSEC_DATASET_KEY_BYTES],
                              const ksec_dataset_header_info *info,
                              int plaintext_fd, int output_fd) {
    (void)key; (void)info; (void)plaintext_fd; (void)output_fd;
    return KSEC_ERR_PROTOCOL; /* PLACEHOLDER (lane L1) */
}

ksec_result ksec_dataset_unseal(const uint8_t key[KSEC_DATASET_KEY_BYTES],
                                const ksec_dataset_header_info *expected,
                                int sealed_fd, int output_fd,
                                ksec_dataset_header_info *actual) {
    (void)key; (void)expected; (void)sealed_fd; (void)output_fd; (void)actual;
    return KSEC_ERR_PROTOCOL; /* PLACEHOLDER (lane L1) */
}

ksec_result ksec_dataset_parse_create_request(const uint8_t *payload,
                                              size_t payload_length,
                                              char label[KSEC_MAX_LABEL + 1U]) {
    (void)payload; (void)payload_length; (void)label;
    return KSEC_ERR_PROTOCOL; /* PLACEHOLDER (lane L1) */
}

ksec_result ksec_dataset_parse_seal_request(
        const uint8_t *payload, size_t payload_length,
        uint8_t record_id[KSEC_RECORD_ID_BYTES], uint64_t *revision,
        char name[KSEC_MAX_DATASET_NAME + 1U]) {
    (void)payload; (void)payload_length; (void)record_id; (void)revision;
    (void)name;
    return KSEC_ERR_PROTOCOL; /* PLACEHOLDER (lane L1) */
}

ksec_result ksec_dataset_parse_unseal_request(
        const uint8_t *payload, size_t payload_length,
        uint8_t record_id[KSEC_RECORD_ID_BYTES],
        char name[KSEC_MAX_DATASET_NAME + 1U]) {
    (void)payload; (void)payload_length; (void)record_id; (void)name;
    return KSEC_ERR_PROTOCOL; /* PLACEHOLDER (lane L1) */
}

ksec_result ksec_validate_dataset_key_record(const ksec_owned_record *record) {
    (void)record;
    return KSEC_ERR_PROTOCOL; /* PLACEHOLDER (lane L1) */
}
