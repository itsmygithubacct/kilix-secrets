#include "internal.h"

#include <string.h>

#ifdef KSEC_TESTING
static bool force_mlock_failure;

void ksec_test_force_mlock_failure(bool enabled) {
    force_mlock_failure = enabled;
}
#endif

ksec_result ksec_secure_alloc(ksec_secure_buffer *buffer, size_t length) {
    if (buffer == NULL || length == 0 || length > KSEC_MAX_RECORD_PLAINTEXT) {
        return KSEC_ERR_INVALID;
    }
    buffer->data = sodium_malloc(length);
    if (buffer->data == NULL) return KSEC_ERR_MEMORY;
    buffer->len = length;
    memset(buffer->data, 0, length);
#ifdef KSEC_TESTING
    if (force_mlock_failure) {
        sodium_free(buffer->data);
        buffer->data = NULL;
        buffer->len = 0;
        return KSEC_ERR_MEMORY;
    }
#endif
    if (sodium_mlock(buffer->data, length) != 0) {
        sodium_memzero(buffer->data, length);
        sodium_free(buffer->data);
        buffer->data = NULL;
        buffer->len = 0;
        return KSEC_ERR_MEMORY;
    }
    return KSEC_OK;
}

void ksec_secure_free(ksec_secure_buffer *buffer) {
    if (buffer == NULL || buffer->data == NULL) return;
    sodium_memzero(buffer->data, buffer->len);
    (void)sodium_munlock(buffer->data, buffer->len);
    sodium_free(buffer->data);
    buffer->data = NULL;
    buffer->len = 0;
}
