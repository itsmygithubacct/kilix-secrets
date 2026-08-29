#define _GNU_SOURCE

#include "session.h"

#include <systemd/sd-bus.h>
#include <systemd/sd-login.h>

#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

static int connect_bus(const char *address, sd_bus **out) {
    int result;
    if (address == NULL || out == NULL) return -1;
    result = sd_bus_new(out);
    if (result >= 0) result = sd_bus_set_address(*out, address);
    if (result >= 0) result = sd_bus_set_bus_client(*out, 1);
    if (result >= 0) result = sd_bus_start(*out);
    if (result < 0) {
        *out = sd_bus_unref(*out);
        return -1;
    }
    return 0;
}

static bool graphical_type(const char *type) {
    return type != NULL && (strcmp(type, "x11") == 0
        || strcmp(type, "wayland") == 0 || strcmp(type, "mir") == 0);
}

static int select_graphical_session(char **out_id, char **out_path) {
    char **sessions = NULL;
    int count;
    int index;
    if (out_id == NULL || out_path == NULL) return -1;
    *out_id = NULL;
    *out_path = NULL;
    count = sd_get_sessions(&sessions);
    if (count < 0) return -1;
    for (index = 0; index < count; index++) {
        uid_t uid;
        char *type = NULL;
        if (sd_session_get_uid(sessions[index], &uid) >= 0
                && sd_session_get_type(sessions[index], &type) >= 0
                && uid == getuid() && graphical_type(type)) {
            *out_id = strdup(sessions[index]);
            free(type);
            if (*out_id == NULL
                    || sd_bus_path_encode("/org/freedesktop/login1/session",
                                          *out_id, out_path) < 0) {
                free(*out_id);
                *out_id = NULL;
            }
            break;
        }
        free(type);
    }
    for (index = 0; index < count; index++) free(sessions[index]);
    free(sessions);
    return *out_id != NULL && *out_path != NULL ? 0 : -1;
}

static int pump_for_lock(ksec_session_monitor *monitor,
                         unsigned int attempts) {
    unsigned int attempt;
    for (attempt = 0U; attempt < attempts; attempt++) {
        struct pollfd descriptor;
        int processed = ksec_session_monitor_process(monitor);
        if (processed != 0) return -1;
        if (ksec_session_monitor_take_lock(monitor)) return 1;
        descriptor.fd = ksec_session_monitor_fd(monitor);
        descriptor.events = ksec_session_monitor_events(monitor);
        descriptor.revents = 0;
        if (descriptor.fd < 0 || descriptor.events == 0
                || poll(&descriptor, 1U, 10) < 0) return -1;
    }
    return 0;
}

static int pump_for_failure(ksec_session_monitor *monitor,
                            unsigned int attempts) {
    unsigned int attempt;
    for (attempt = 0U; attempt < attempts; attempt++) {
        struct pollfd descriptor;
        if (ksec_session_monitor_process(monitor) != 0) return 1;
        descriptor.fd = ksec_session_monitor_fd(monitor);
        descriptor.events = ksec_session_monitor_events(monitor);
        descriptor.revents = 0;
        if (descriptor.fd < 0 || descriptor.events == 0
                || poll(&descriptor, 1U, 10) < 0) return -1;
    }
    return 0;
}

static int emit_locked_hint(sd_bus *bus, const char *path, bool locked) {
    sd_bus_message *message = NULL;
    int value = locked ? 1 : 0;
    int result;
    result = sd_bus_message_new_signal(
            bus, &message, path, "org.freedesktop.DBus.Properties",
            "PropertiesChanged");
    if (result >= 0) {
        result = sd_bus_message_append(
                message, "s", "org.freedesktop.login1.Session");
    }
    if (result >= 0) {
        result = sd_bus_message_open_container(message, SD_BUS_TYPE_ARRAY,
                                               "{sv}");
    }
    if (result >= 0) {
        result = sd_bus_message_open_container(message,
                                               SD_BUS_TYPE_DICT_ENTRY, "sv");
    }
    if (result >= 0) result = sd_bus_message_append(message, "s", "LockedHint");
    if (result >= 0) {
        result = sd_bus_message_open_container(message, SD_BUS_TYPE_VARIANT,
                                               "b");
    }
    if (result >= 0) result = sd_bus_message_append(message, "b", value);
    if (result >= 0) result = sd_bus_message_close_container(message);
    if (result >= 0) result = sd_bus_message_close_container(message);
    if (result >= 0) result = sd_bus_message_close_container(message);
    if (result >= 0) {
        result = sd_bus_message_open_container(message, SD_BUS_TYPE_ARRAY,
                                               "s");
    }
    if (result >= 0) result = sd_bus_message_close_container(message);
    if (result >= 0) result = sd_bus_send(bus, message, NULL);
    if (result >= 0) result = sd_bus_flush(bus);
    message = sd_bus_message_unref(message);
    return result < 0 ? -1 : 0;
}

static int emit_malformed_properties(sd_bus *bus, const char *path) {
    sd_bus_message *message = NULL;
    int result = sd_bus_message_new_signal(
            bus, &message, path, "org.freedesktop.DBus.Properties",
            "PropertiesChanged");
    if (result >= 0) {
        result = sd_bus_message_append(
                message, "s", "org.freedesktop.login1.Session");
    }
    if (result >= 0) result = sd_bus_send(bus, message, NULL);
    if (result >= 0) result = sd_bus_flush(bus);
    message = sd_bus_message_unref(message);
    return result < 0 ? -1 : 0;
}

int main(int argc, char **argv) {
    const char *address;
    char *session_id = NULL;
    char *session_path = NULL;
    char *missing_path = NULL;
    sd_bus *service = NULL;
    sd_bus *adversary = NULL;
    ksec_session_monitor *monitor = NULL;
    check_state checks = {0U, 0U};
    size_t tracked = 0U;
    int result;
    if (argc != 2) {
        fprintf(stderr, "usage: test-session BUS-ADDRESS\n");
        return 2;
    }
    address = argv[1];
    if (select_graphical_session(&session_id, &session_path) != 0
            || sd_bus_path_encode("/org/freedesktop/login1/session",
                                  "ksec_missing_session",
                                  &missing_path) < 0
            || connect_bus(address, &service) != 0
            || sd_bus_request_name(service, "org.freedesktop.login1", 0U) < 0
            || connect_bus(address, &adversary) != 0
            || ksec_session_monitor_open_at(&monitor, getuid(), address) != 0) {
        fprintf(stderr, "isolated session harness setup failed\n");
        result = 2;
        goto out;
    }
    tracked = ksec_session_monitor_tracked(monitor);
    CHECK(&checks, tracked > 0U && tracked <= KSEC_MAX_GRAPHICAL_SESSIONS,
          "authenticated monitor inventories a bounded graphical session set");

    result = sd_bus_emit_signal(
            adversary, session_path, "org.freedesktop.login1.Session",
            "Lock", "");
    if (result >= 0) result = sd_bus_flush(adversary);
    CHECK(&checks, result >= 0 && pump_for_lock(monitor, 20U) == 0,
          "same-UID non-owner signal cannot impersonate logind");

    result = sd_bus_emit_signal(
            service, missing_path, "org.freedesktop.login1.Session",
            "Lock", "");
    if (result >= 0) result = sd_bus_flush(service);
    CHECK(&checks, result >= 0 && pump_for_lock(monitor, 20U) == 0,
          "authenticated lock for an untracked non-session is ignored");

    result = sd_bus_emit_signal(
            service, session_path, "org.freedesktop.login1.Session",
            "Lock", "");
    if (result >= 0) result = sd_bus_flush(service);
    CHECK(&checks, result >= 0 && pump_for_lock(monitor, 100U) == 1
                  && !ksec_session_monitor_take_lock(monitor),
          "authenticated graphical Lock produces one consumable global lock");

    CHECK(&checks, emit_locked_hint(service, session_path, false) == 0
                  && pump_for_lock(monitor, 20U) == 0,
          "LockedHint false never unlocks or creates a lock transition");
    CHECK(&checks, emit_locked_hint(service, session_path, true) == 0
                  && pump_for_lock(monitor, 100U) == 1,
          "authenticated LockedHint true creates a global lock transition");

    result = sd_bus_emit_signal(
            service, "/org/freedesktop/login1",
            "org.freedesktop.login1.Manager", "SessionRemoved", "so",
            session_id, session_path);
    if (result >= 0) result = sd_bus_flush(service);
    CHECK(&checks, result >= 0 && pump_for_lock(monitor, 100U) == 1
                  && ksec_session_monitor_tracked(monitor) + 1U == tracked,
          "authenticated tracked-session teardown locks and removes one session");

    result = sd_bus_emit_signal(
            service, "/org/freedesktop/login1",
            "org.freedesktop.login1.Manager", "SessionNew", "so",
            session_id, session_path);
    if (result >= 0) result = sd_bus_flush(service);
    CHECK(&checks, result >= 0 && pump_for_lock(monitor, 20U) == 0
                  && ksec_session_monitor_tracked(monitor) == tracked,
          "authenticated SessionNew restores the real graphical inventory only");

    CHECK(&checks, emit_malformed_properties(service, session_path) == 0
                  && pump_for_failure(monitor, 100U) == 1,
          "malformed authenticated session event fails the monitor closed");
    result = checks.passed == checks.total ? 0 : 1;
    printf("session-monitor checks: %zu/%zu passed\n", checks.passed,
           checks.total);
out:
    ksec_session_monitor_close(monitor);
    adversary = sd_bus_unref(adversary);
    service = sd_bus_unref(service);
    free(missing_path);
    free(session_path);
    free(session_id);
    return result;
}
