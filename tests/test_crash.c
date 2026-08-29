#define _GNU_SOURCE

#include "internal.h"

#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct {
    size_t passed;
    size_t total;
} check_state;

#define CHECK(state, condition, description) do { \
    (state)->total++; \
    if (condition) { \
        (state)->passed++; \
    } else { \
        fprintf(stderr, "not ok %zu - %s (line %d)\n", \
                (state)->total, description, __LINE__); \
    } \
} while (0)

static int remove_entry(const char *path, const struct stat *status,
                        int type, struct FTW *walk) {
    (void)status;
    (void)type;
    (void)walk;
    return remove(path);
}

static int remove_tree(const char *path) {
    return nftw(path, remove_entry, 32, FTW_DEPTH | FTW_PHYS);
}

static int make_path(char *output, size_t output_size, const char *directory,
                     const char *leaf) {
    int count = snprintf(output, output_size, "%s/%s", directory, leaf);
    return count < 0 || (size_t)count >= output_size ? -1 : 0;
}

static int copy_file(const char *source, const char *destination) {
    uint8_t buffer[8192];
    int input = -1;
    int output = -1;
    int result = -1;
    input = open(source, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (input < 0) goto out;
    output = open(destination, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC
                                   | O_NOFOLLOW, 0600);
    if (output < 0) goto out;
    for (;;) {
        ssize_t count = read(input, buffer, sizeof buffer);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) goto out;
        if (count == 0) break;
        if (ksec_write_all(output, buffer, (size_t)count) != 0) goto out;
    }
    if (fsync(output) != 0) goto out;
    result = 0;
out:
    sodium_memzero(buffer, sizeof buffer);
    if (input >= 0 && close(input) != 0) result = -1;
    if (output >= 0 && close(output) != 0) result = -1;
    return result;
}

static int copy_store(const char *source, const char *destination,
                      bool include_journal) {
    char source_path[4096];
    char destination_path[4096];
    if (mkdir(destination, 0700) != 0
            || make_path(source_path, sizeof source_path, source, "vault.ksv") != 0
            || make_path(destination_path, sizeof destination_path, destination,
                         "vault.ksv") != 0
            || copy_file(source_path, destination_path) != 0) return -1;
    if (!include_journal) return 0;
    if (make_path(source_path, sizeof source_path, source, "journal.ksj") != 0
            || make_path(destination_path, sizeof destination_path, destination,
                         "journal.ksj") != 0
            || copy_file(source_path, destination_path) != 0) return -1;
    return 0;
}

static ksec_result make_record(ksec_owned_record *record, const uint8_t id[16],
                               const char *value) {
    size_t length = strlen(value);
    ksec_result result;
    memset(record, 0, sizeof *record);
    memcpy(record->id, id, KSEC_RECORD_ID_BYTES);
    memcpy(record->owner, "kilix-secrets.test", sizeof "kilix-secrets.test");
    memcpy(record->type, "opaque", sizeof "opaque");
    memcpy(record->label, "crash-fixture", sizeof "crash-fixture");
    record->object_type = KSEC_OBJECT_SECRET;
    record->field_count = 1U;
    memcpy(record->fields[0].name, "value", sizeof "value");
    result = ksec_secure_alloc(&record->fields[0].value, length);
    if (result != KSEC_OK) {
        ksec_owned_record_clear(record);
        return result;
    }
    memcpy(record->fields[0].value.data, value, length);
    return KSEC_OK;
}

static bool record_value_is(const ksec_store *store, const uint8_t id[16],
                            const char *expected) {
    size_t index;
    size_t length = strlen(expected);
    if (store == NULL) return false;
    for (index = 0; index < store->record_count; index++) {
        const ksec_owned_record *record = &store->records[index];
        if (sodium_memcmp(record->id, id, KSEC_RECORD_ID_BYTES) == 0
                && record->field_count == 1U
                && record->fields[0].value.len == length
                && sodium_memcmp(record->fields[0].value.data, expected,
                                 length) == 0) return true;
    }
    return false;
}

static int recover_store(const char *directory, const uint8_t master[32],
                         size_t *record_count, uint64_t *last_revision,
                         bool *torn_tail, const uint8_t *record_id,
                         const char *expected_value) {
    ksec_store store;
    ksec_vault_header header;
    ksec_result result;
    memset(&store, 0, sizeof store);
    store.lock_fd = -1;
    result = ksec_store_open(&store, directory, false);
    if (result != KSEC_OK) return -1;
    result = ksec_store_read_header(&store, &header);
    if (result == KSEC_OK) result = ksec_store_load(&store, &header, master);
    if (result == KSEC_OK && record_id != NULL && expected_value != NULL
            && !record_value_is(&store, record_id, expected_value)) {
        result = KSEC_ERR_INVALID;
    }
    if (result == KSEC_OK) {
        if (record_count != NULL) *record_count = store.record_count;
        if (last_revision != NULL) *last_revision = store.last_revision;
        if (torn_tail != NULL) *torn_tail = store.torn_tail;
    }
    ksec_store_close(&store);
    sodium_memzero(&header, sizeof header);
    return result == KSEC_OK ? 0 : -1;
}

static bool child_crashed_as_expected(pid_t child, int expected_status) {
    int status = 0;
    if (waitpid(child, &status, 0) != child) return false;
    return WIFEXITED(status) && WEXITSTATUS(status) == expected_status;
}

static int setup_header_store(const char *directory, ksec_vault_header *header,
                              uint8_t master[32]) {
    static const uint8_t passphrase[] = "generated-crash-passphrase";
    static const uint8_t recovery[] =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    ksec_store store;
    ksec_result result;
    if (mkdir(directory, 0700) != 0) return -1;
    memset(&store, 0, sizeof store);
    store.lock_fd = -1;
    result = ksec_store_open(&store, directory, false);
    if (result == KSEC_OK) {
        result = ksec_header_create(header, passphrase, sizeof passphrase - 1U,
                                    recovery, sizeof recovery - 1U,
                                    KSEC_ARGON_OPS_MIN, KSEC_ARGON_MEM_MIN,
                                    master);
    }
    if (result == KSEC_OK) result = ksec_store_write_header(&store, header);
    ksec_store_close(&store);
    return result == KSEC_OK ? 0 : -1;
}

static int setup_compaction_store(const char *header_store,
                                  const char *directory,
                                  const ksec_vault_header *header,
                                  const uint8_t master[32],
                                  const uint8_t first_id[16],
                                  const uint8_t second_id[16]) {
    ksec_store store;
    ksec_owned_record record;
    ksec_owned_record tombstone;
    ksec_result result;
    if (copy_store(header_store, directory, false) != 0) return -1;
    memset(&store, 0, sizeof store);
    store.lock_fd = -1;
    result = ksec_store_open(&store, directory, false);
    if (result == KSEC_OK) result = make_record(&record, first_id, "old-value");
    if (result == KSEC_OK) {
        result = ksec_store_append(&store, header, master, &record, false);
    }
    ksec_owned_record_clear(&record);
    if (result == KSEC_OK) result = make_record(&record, first_id, "new-value");
    if (result == KSEC_OK) {
        result = ksec_store_append(&store, header, master, &record, false);
    }
    ksec_owned_record_clear(&record);
    if (result == KSEC_OK) result = make_record(&record, second_id, "delete-me");
    if (result == KSEC_OK) {
        result = ksec_store_append(&store, header, master, &record, false);
    }
    ksec_owned_record_clear(&record);
    memset(&tombstone, 0, sizeof tombstone);
    memcpy(tombstone.id, second_id, KSEC_RECORD_ID_BYTES);
    memcpy(tombstone.owner, "kilix-secrets.test", sizeof "kilix-secrets.test");
    tombstone.object_type = KSEC_OBJECT_SECRET;
    if (result == KSEC_OK) {
        result = ksec_store_append(&store, header, master, &tombstone, true);
    }
    ksec_owned_record_clear(&tombstone);
    ksec_store_close(&store);
    return result == KSEC_OK ? 0 : -1;
}

static void test_header_crashes(check_state *checks, const char *root,
                                const char *baseline,
                                const ksec_vault_header *old_header,
                                const uint8_t master[32]) {
    static const ksec_test_store_point points[] = {
        KSEC_TEST_STORE_HEADER_OPEN, KSEC_TEST_STORE_HEADER_WRITE,
        KSEC_TEST_STORE_HEADER_FSYNC, KSEC_TEST_STORE_HEADER_CLOSE,
        KSEC_TEST_STORE_HEADER_RENAME, KSEC_TEST_STORE_HEADER_DIRSYNC
    };
    static const uint8_t passphrase[] = "generated-crash-passphrase";
    size_t index;
    for (index = 0; index < sizeof points / sizeof points[0]; index++) {
        char directory[4096];
        ksec_vault_header updated = *old_header;
        pid_t child;
        int count = snprintf(directory, sizeof directory, "%s/header-%zu", root,
                             index);
        CHECK(checks, count > 0 && (size_t)count < sizeof directory
                      && copy_store(baseline, directory, false) == 0,
              "header crash case is staged");
        CHECK(checks, ksec_header_confirm_recovery(&updated, master) == KSEC_OK,
              "replacement header is authenticated");
        child = fork();
        if (child == 0) {
            ksec_store store;
            memset(&store, 0, sizeof store);
            store.lock_fd = -1;
            if (ksec_store_open(&store, directory, false) != KSEC_OK) _exit(121);
            ksec_test_store_crash_after(points[index], 1U, 73);
            (void)ksec_store_write_header(&store, &updated);
            _exit(122);
        }
        CHECK(checks, child > 0 && child_crashed_as_expected(child, 73),
              "header writer exits at the selected boundary");
        {
            ksec_store store;
            ksec_vault_header recovered;
            uint8_t recovered_master[32];
            ksec_result result;
            memset(&store, 0, sizeof store);
            store.lock_fd = -1;
            result = ksec_store_open(&store, directory, false);
            if (result == KSEC_OK) result = ksec_store_read_header(&store, &recovered);
            if (result == KSEC_OK) {
                result = ksec_header_unlock(&recovered, KSEC_SLOT_PASSPHRASE,
                                            passphrase,
                                            sizeof passphrase - 1U,
                                            recovered_master);
            }
            CHECK(checks, result == KSEC_OK
                          && (recovered.generation == old_header->generation
                              || recovered.generation == updated.generation),
                  "header recovery selects one authenticated generation");
            sodium_memzero(recovered_master, sizeof recovered_master);
            sodium_memzero(&recovered, sizeof recovered);
            ksec_store_close(&store);
        }
    }
}

static void test_append_crashes(check_state *checks, const char *root,
                                const char *baseline,
                                const ksec_vault_header *header,
                                const uint8_t master[32],
                                const uint8_t record_id[16]) {
    static const ksec_test_store_point points[] = {
        KSEC_TEST_STORE_APPEND_OPEN, KSEC_TEST_STORE_APPEND_WRITE,
        KSEC_TEST_STORE_APPEND_FSYNC, KSEC_TEST_STORE_APPEND_CLOSE,
        KSEC_TEST_STORE_APPEND_DIRSYNC
    };
    size_t index;
    for (index = 0; index < sizeof points / sizeof points[0]; index++) {
        char directory[4096];
        pid_t child;
        size_t recovered_count = 99U;
        int count = snprintf(directory, sizeof directory, "%s/append-%zu", root,
                             index);
        CHECK(checks, count > 0 && (size_t)count < sizeof directory
                      && copy_store(baseline, directory, false) == 0,
              "append crash case is staged");
        child = fork();
        if (child == 0) {
            ksec_store store;
            ksec_owned_record record;
            memset(&store, 0, sizeof store);
            store.lock_fd = -1;
            if (ksec_store_open(&store, directory, false) != KSEC_OK
                    || make_record(&record, record_id, "append-value") != KSEC_OK) {
                _exit(123);
            }
            ksec_test_store_crash_after(points[index], 1U, 74);
            (void)ksec_store_append(&store, header, master, &record, false);
            _exit(124);
        }
        CHECK(checks, child > 0 && child_crashed_as_expected(child, 74),
              "append writer exits at the selected boundary");
        CHECK(checks, recover_store(directory, master, &recovered_count, NULL,
                                    NULL, NULL, NULL) == 0
                      && (recovered_count == 0U || recovered_count == 1U),
              "append recovery exposes either the old or committed state");
    }
}

static void test_compaction_crashes(check_state *checks, const char *root,
                                    const char *baseline,
                                    const ksec_vault_header *header,
                                    const uint8_t master[32],
                                    const uint8_t record_id[16]) {
    static const struct {
        ksec_test_store_point point;
        unsigned int occurrence;
    } cases[] = {
        {KSEC_TEST_STORE_COMPACT_OPEN, 1U},
        {KSEC_TEST_STORE_COMPACT_WRITE, 1U},
        {KSEC_TEST_STORE_COMPACT_WRITE, 2U},
        {KSEC_TEST_STORE_COMPACT_FSYNC, 1U},
        {KSEC_TEST_STORE_COMPACT_CLOSE, 1U},
        {KSEC_TEST_STORE_COMPACT_RENAME, 1U},
        {KSEC_TEST_STORE_COMPACT_DIRSYNC, 1U}
    };
    size_t index;
    for (index = 0; index < sizeof cases / sizeof cases[0]; index++) {
        char directory[4096];
        pid_t child;
        size_t recovered_count = 0U;
        uint64_t revision = 0U;
        int count = snprintf(directory, sizeof directory, "%s/compact-%zu", root,
                             index);
        CHECK(checks, count > 0 && (size_t)count < sizeof directory
                      && copy_store(baseline, directory, true) == 0,
              "compaction crash case is staged");
        child = fork();
        if (child == 0) {
            ksec_store store;
            ksec_vault_header loaded;
            memset(&store, 0, sizeof store);
            store.lock_fd = -1;
            if (ksec_store_open(&store, directory, false) != KSEC_OK
                    || ksec_store_read_header(&store, &loaded) != KSEC_OK
                    || ksec_store_load(&store, &loaded, master) != KSEC_OK) {
                _exit(125);
            }
            ksec_test_store_crash_after(cases[index].point,
                                        cases[index].occurrence, 75);
            (void)ksec_store_compact(&store, header, master);
            _exit(126);
        }
        CHECK(checks, child > 0 && child_crashed_as_expected(child, 75),
              "compactor exits at the selected boundary");
        CHECK(checks, recover_store(directory, master, &recovered_count,
                                    &revision, NULL, record_id,
                                    "new-value") == 0
                      && recovered_count == 1U && revision == 4U,
              "compaction recovery preserves the exact live revision");
    }
}

static void test_storage_failures(check_state *checks, const char *root,
                                  const char *header_baseline,
                                  const char *compact_baseline,
                                  const ksec_vault_header *header,
                                  const uint8_t master[32],
                                  const uint8_t first_id[16],
                                  const uint8_t append_id[16]) {
    char directory[4096];
    char path[4096];
    ksec_store store;
    ksec_owned_record record;
    size_t recovered_count = 0U;
    bool torn = false;
    int count;

    count = snprintf(directory, sizeof directory, "%s/short-append", root);
    CHECK(checks, count > 0 && (size_t)count < sizeof directory
                  && copy_store(header_baseline, directory, false) == 0,
          "partial append case is staged");
    memset(&store, 0, sizeof store);
    store.lock_fd = -1;
    CHECK(checks, ksec_store_open(&store, directory, false) == KSEC_OK
                  && make_record(&record, append_id, "partial-value") == KSEC_OK,
          "partial append store opens");
    ksec_test_store_fail_at(KSEC_TEST_STORE_APPEND_WRITE, 1U, ENOSPC, 17U);
    CHECK(checks, ksec_store_append(&store, header, master, &record, false)
                  == KSEC_ERR_IO && store.torn_tail,
          "partial append fails closed and poisons the writer");
    ksec_owned_record_clear(&record);
    ksec_store_close(&store);
    ksec_test_store_fault_reset();
    CHECK(checks, recover_store(directory, master, &recovered_count, NULL,
                                &torn, NULL, NULL) == 0
                  && recovered_count == 0U && torn,
          "partial append recovers only the prior state and marks a torn tail");

    count = snprintf(directory, sizeof directory, "%s/enospc-append", root);
    CHECK(checks, count > 0 && (size_t)count < sizeof directory
                  && copy_store(header_baseline, directory, false) == 0,
          "ENOSPC append case is staged");
    memset(&store, 0, sizeof store);
    store.lock_fd = -1;
    CHECK(checks, ksec_store_open(&store, directory, false) == KSEC_OK
                  && make_record(&record, append_id, "full-disk-value") == KSEC_OK,
          "ENOSPC append store opens");
    ksec_test_store_fail_at(KSEC_TEST_STORE_APPEND_WRITE, 1U, ENOSPC, 0U);
    CHECK(checks, ksec_store_append(&store, header, master, &record, false)
                  == KSEC_ERR_IO,
          "zero-byte ENOSPC append is refused");
    ksec_owned_record_clear(&record);
    ksec_store_close(&store);
    ksec_test_store_fault_reset();
    CHECK(checks, recover_store(directory, master, &recovered_count, NULL,
                                &torn, NULL, NULL) == 0
                  && recovered_count == 0U,
          "zero-byte ENOSPC leaves the prior state readable");

    count = snprintf(directory, sizeof directory, "%s/short-compact", root);
    CHECK(checks, count > 0 && (size_t)count < sizeof directory
                  && copy_store(compact_baseline, directory, true) == 0,
          "partial compaction case is staged");
    memset(&store, 0, sizeof store);
    store.lock_fd = -1;
    CHECK(checks, ksec_store_open(&store, directory, false) == KSEC_OK
                  && ksec_store_load(&store, header, master) == KSEC_OK,
          "partial compaction store opens");
    ksec_test_store_fail_at(KSEC_TEST_STORE_COMPACT_WRITE, 1U, ENOSPC, 19U);
    CHECK(checks, ksec_store_compact(&store, header, master) == KSEC_ERR_IO,
          "partial compact write is refused");
    ksec_store_close(&store);
    ksec_test_store_fault_reset();
    CHECK(checks, recover_store(directory, master, &recovered_count, NULL,
                                NULL, first_id, "new-value") == 0
                  && recovered_count == 1U,
          "partial compact write leaves the original journal intact");

    count = snprintf(directory, sizeof directory, "%s/stale-temp", root);
    CHECK(checks, count > 0 && (size_t)count < sizeof directory
                  && copy_store(compact_baseline, directory, true) == 0
                  && make_path(path, sizeof path, directory,
                               ".journal.ksj.tmp.stale") == 0,
          "stale temporary case is staged");
    {
        int stale = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC
                               | O_NOFOLLOW, 0600);
        CHECK(checks, stale >= 0 && close(stale) == 0,
              "stale temporary file is created safely");
    }
    memset(&store, 0, sizeof store);
    store.lock_fd = -1;
    CHECK(checks, ksec_store_open(&store, directory, false) == KSEC_OK
                  && ksec_store_load(&store, header, master) == KSEC_OK
                  && ksec_store_compact(&store, header, master) == KSEC_OK,
          "unique compaction temporary ignores a stale predecessor");
    ksec_store_close(&store);

    count = snprintf(directory, sizeof directory, "%s/concurrent", root);
    CHECK(checks, count > 0 && (size_t)count < sizeof directory
                  && copy_store(header_baseline, directory, false) == 0,
          "concurrent writer case is staged");
    {
        ksec_store first;
        ksec_store second;
        memset(&first, 0, sizeof first);
        memset(&second, 0, sizeof second);
        first.lock_fd = -1;
        second.lock_fd = -1;
        CHECK(checks, ksec_store_open(&first, directory, false) == KSEC_OK
                      && ksec_store_open(&second, directory, false)
                             == KSEC_ERR_BUSY,
              "second writer is refused by the non-following lock");
        ksec_store_close(&second);
        ksec_store_close(&first);
    }

    count = snprintf(directory, sizeof directory, "%s/read-only", root);
    CHECK(checks, count > 0 && (size_t)count < sizeof directory
                  && copy_store(compact_baseline, directory, true) == 0
                  && make_path(path, sizeof path, directory, "journal.ksj") == 0
                  && chmod(path, 0400) == 0,
          "read-only journal case is staged");
    memset(&store, 0, sizeof store);
    store.lock_fd = -1;
    CHECK(checks, ksec_store_open(&store, directory, false) == KSEC_OK
                  && ksec_store_load(&store, header, master) == KSEC_ERR_DENIED,
          "wrong-mode read-only journal is refused before mutation");
    ksec_store_close(&store);
    (void)chmod(path, 0600);
}

int main(void) {
    static const uint8_t first_id[16] = {
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };
    static const uint8_t second_id[16] = {
        0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
        0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f
    };
    static const uint8_t append_id[16] = {
        0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
        0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f
    };
    const char *temporary_root = getenv("TMPDIR");
    char root[4096];
    char header_baseline[4096];
    char compact_baseline[4096];
    ksec_vault_header header;
    uint8_t master[32];
    check_state checks = {0, 0};
    int count;
    if (temporary_root == NULL || temporary_root[0] != '/') {
        fprintf(stderr, "TMPDIR must be an absolute test scratch directory\n");
        return 2;
    }
    count = snprintf(root, sizeof root, "%s/ksec-crash.XXXXXX", temporary_root);
    if (count < 0 || (size_t)count >= sizeof root || mkdtemp(root) == NULL) {
        perror("mkdtemp");
        return 2;
    }
    if (ksec_crypto_initialize() != KSEC_OK
            || make_path(header_baseline, sizeof header_baseline, root,
                         "header-base") != 0
            || setup_header_store(header_baseline, &header, master) != 0
            || make_path(compact_baseline, sizeof compact_baseline, root,
                         "compact-base") != 0
            || setup_compaction_store(header_baseline, compact_baseline, &header,
                                      master, first_id, second_id) != 0) {
        fprintf(stderr, "crash fixture setup failed\n");
        (void)remove_tree(root);
        sodium_memzero(master, sizeof master);
        sodium_memzero(&header, sizeof header);
        return 2;
    }

    test_header_crashes(&checks, root, header_baseline, &header, master);
    test_append_crashes(&checks, root, header_baseline, &header, master,
                        append_id);
    test_compaction_crashes(&checks, root, compact_baseline, &header, master,
                            first_id);
    test_storage_failures(&checks, root, header_baseline, compact_baseline,
                          &header, master, first_id, append_id);

    sodium_memzero(master, sizeof master);
    sodium_memzero(&header, sizeof header);
    if (remove_tree(root) != 0) {
        perror("remove crash fixtures");
        return 2;
    }
    printf("crash/storage checks: %zu/%zu passed\n", checks.passed,
           checks.total);
    return checks.passed == checks.total ? 0 : 1;
}
