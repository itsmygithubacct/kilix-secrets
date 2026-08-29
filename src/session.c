#define _GNU_SOURCE

#include "session.h"

#include <systemd/sd-bus.h>
#include <systemd/sd-login.h>

#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    KSEC_SESSION_ID_BYTES = 128,
    KSEC_SESSION_PATH_BYTES = 256
};

typedef struct {
    char id[KSEC_SESSION_ID_BYTES];
    char path[KSEC_SESSION_PATH_BYTES];
} tracked_session;

struct ksec_session_monitor {
    sd_bus *bus;
    sd_bus_slot *session_new_slot;
    sd_bus_slot *session_removed_slot;
    sd_bus_slot *lock_slot;
    sd_bus_slot *properties_slot;
    uid_t uid;
    tracked_session sessions[KSEC_MAX_GRAPHICAL_SESSIONS];
    size_t session_count;
    bool lock_pending;
    bool failed;
};

static bool graphical_type(const char *type) {
    return type != NULL && (strcmp(type, "x11") == 0
        || strcmp(type, "wayland") == 0 || strcmp(type, "mir") == 0);
}

static int graphical_session_for_uid(const char *id, uid_t uid) {
    char *type = NULL;
    uid_t observed_uid;
    int result = 0;
    if (id == NULL || sd_session_get_uid(id, &observed_uid) < 0
            || sd_session_get_type(id, &type) < 0) {
        free(type);
        return -1;
    }
    if (observed_uid == uid && graphical_type(type)) result = 1;
    free(type);
    return result;
}

static ssize_t find_session(const ksec_session_monitor *monitor,
                            const char *id) {
    size_t index;
    if (monitor == NULL || id == NULL) return -1;
    for (index = 0U; index < monitor->session_count; index++) {
        if (strcmp(monitor->sessions[index].id, id) == 0) {
            return (ssize_t)index;
        }
    }
    return -1;
}

static int add_session(ksec_session_monitor *monitor, const char *id,
                       const char *path) {
    tracked_session *entry;
    char *encoded_path = NULL;
    const char *selected_path = path;
    size_t id_len;
    size_t path_len;
    int result = -1;
    if (monitor == NULL || id == NULL || find_session(monitor, id) >= 0) return 0;
    if (selected_path == NULL) {
        if (sd_bus_path_encode("/org/freedesktop/login1/session", id,
                               &encoded_path) < 0) goto out;
        selected_path = encoded_path;
    }
    id_len = strlen(id);
    path_len = strlen(selected_path);
    if (id_len == 0U || id_len >= KSEC_SESSION_ID_BYTES
            || path_len == 0U || path_len >= KSEC_SESSION_PATH_BYTES
            || monitor->session_count >= KSEC_MAX_GRAPHICAL_SESSIONS) goto out;
    entry = &monitor->sessions[monitor->session_count++];
    memcpy(entry->id, id, id_len + 1U);
    memcpy(entry->path, selected_path, path_len + 1U);
    result = 0;
out:
    free(encoded_path);
    return result;
}

static void remove_session(ksec_session_monitor *monitor, size_t index) {
    if (monitor == NULL || index >= monitor->session_count) return;
    if (index + 1U < monitor->session_count) {
        memmove(&monitor->sessions[index], &monitor->sessions[index + 1U],
                (monitor->session_count - index - 1U)
                    * sizeof monitor->sessions[0]);
    }
    monitor->session_count--;
    memset(&monitor->sessions[monitor->session_count], 0,
           sizeof monitor->sessions[0]);
}

static bool tracked_path_or_graphical(ksec_session_monitor *monitor,
                                      const char *path) {
    char *id = NULL;
    ssize_t position;
    int graphical;
    if (monitor == NULL || path == NULL
            || sd_bus_path_decode(path, "/org/freedesktop/login1/session",
                                  &id) < 0 || id == NULL) {
        free(id);
        return false;
    }
    position = find_session(monitor, id);
    if (position >= 0) {
        free(id);
        return true;
    }
    graphical = graphical_session_for_uid(id, monitor->uid);
    if (graphical > 0 && add_session(monitor, id, path) != 0) {
        monitor->failed = true;
        graphical = -1;
    }
    free(id);
    return graphical > 0;
}

static int session_new(sd_bus_message *message, void *userdata,
                       sd_bus_error *error) {
    ksec_session_monitor *monitor = userdata;
    const char *id = NULL;
    const char *path = NULL;
    int graphical;
    (void)error;
    if (monitor == NULL || sd_bus_message_read(message, "so", &id, &path) < 0) {
        if (monitor != NULL) monitor->failed = true;
        return 0;
    }
    graphical = graphical_session_for_uid(id, monitor->uid);
    if (graphical > 0 && add_session(monitor, id, path) != 0) {
        monitor->failed = true;
    }
    return 0;
}

static int session_removed(sd_bus_message *message, void *userdata,
                           sd_bus_error *error) {
    ksec_session_monitor *monitor = userdata;
    const char *id = NULL;
    const char *path = NULL;
    ssize_t position;
    (void)error;
    if (monitor == NULL || sd_bus_message_read(message, "so", &id, &path) < 0) {
        if (monitor != NULL) monitor->failed = true;
        return 0;
    }
    (void)path;
    position = find_session(monitor, id);
    if (position >= 0) {
        monitor->lock_pending = true;
        remove_session(monitor, (size_t)position);
    }
    return 0;
}

static int session_lock(sd_bus_message *message, void *userdata,
                        sd_bus_error *error) {
    ksec_session_monitor *monitor = userdata;
    const char *path;
    (void)error;
    path = sd_bus_message_get_path(message);
    if (monitor == NULL || path == NULL) {
        if (monitor != NULL) monitor->failed = true;
        return 0;
    }
    if (tracked_path_or_graphical(monitor, path)) monitor->lock_pending = true;
    return 0;
}

static int session_properties(sd_bus_message *message, void *userdata,
                              sd_bus_error *error) {
    ksec_session_monitor *monitor = userdata;
    const char *interface = NULL;
    const char *path;
    int entered;
    bool locked = false;
    (void)error;
    path = sd_bus_message_get_path(message);
    if (monitor == NULL || path == NULL
            || sd_bus_message_read(message, "s", &interface) < 0
            || interface == NULL) {
        if (monitor != NULL) monitor->failed = true;
        return 0;
    }
    if (strcmp(interface, "org.freedesktop.login1.Session") != 0) return 0;
    entered = sd_bus_message_enter_container(message, SD_BUS_TYPE_ARRAY, "{sv}");
    if (entered <= 0) {
        monitor->failed = true;
        return 0;
    }
    for (;;) {
        const char *property = NULL;
        int item = sd_bus_message_enter_container(message,
                                                  SD_BUS_TYPE_DICT_ENTRY,
                                                  "sv");
        if (item < 0) { monitor->failed = true; break; }
        if (item == 0) break;
        if (sd_bus_message_read(message, "s", &property) < 0
                || property == NULL) {
            monitor->failed = true;
            break;
        }
        if (strcmp(property, "LockedHint") == 0) {
            int value = 0;
            if (sd_bus_message_enter_container(message, SD_BUS_TYPE_VARIANT,
                                               "b") <= 0
                    || sd_bus_message_read(message, "b", &value) < 0
                    || sd_bus_message_exit_container(message) < 0) {
                monitor->failed = true;
                break;
            }
            locked = value != 0;
        } else if (sd_bus_message_skip(message, "v") < 0) {
            monitor->failed = true;
            break;
        }
        if (sd_bus_message_exit_container(message) < 0) {
            monitor->failed = true;
            break;
        }
    }
    if (!monitor->failed && sd_bus_message_exit_container(message) < 0) {
        monitor->failed = true;
    }
    if (locked && tracked_path_or_graphical(monitor, path)) {
        monitor->lock_pending = true;
    }
    return 0;
}

static int inventory_sessions(ksec_session_monitor *monitor) {
    char **sessions = NULL;
    int count;
    int index;
    int result = 0;
    if (monitor == NULL) return -1;
    count = sd_get_sessions(&sessions);
    if (count < 0) return -1;
    for (index = 0; index < count; index++) {
        int graphical = graphical_session_for_uid(sessions[index], monitor->uid);
        if (graphical > 0 && add_session(monitor, sessions[index], NULL) != 0) {
            result = -1;
        }
        free(sessions[index]);
    }
    free(sessions);
    return result;
}

static int session_monitor_open(ksec_session_monitor **out, uid_t uid,
                                const char *bus_address) {
    ksec_session_monitor *monitor;
    int result;
    const char *stage = "allocation";
    if (out == NULL) return -1;
    monitor = calloc(1U, sizeof *monitor);
    if (monitor == NULL) return -1;
    monitor->uid = uid;
    stage = "system-bus connection";
    if (bus_address == NULL) {
        result = sd_bus_open_system(&monitor->bus);
    } else {
        result = sd_bus_new(&monitor->bus);
        if (result >= 0) result = sd_bus_set_address(monitor->bus, bus_address);
        if (result >= 0) result = sd_bus_set_bus_client(monitor->bus, 1);
        if (result >= 0) result = sd_bus_start(monitor->bus);
    }
    if (result < 0) goto fail;
    stage = "new-session subscription";
    result = sd_bus_match_signal(
        monitor->bus, &monitor->session_new_slot, "org.freedesktop.login1",
        "/org/freedesktop/login1", "org.freedesktop.login1.Manager",
        "SessionNew", session_new, monitor);
    if (result < 0) goto fail;
    stage = "removed-session subscription";
    result = sd_bus_match_signal(
        monitor->bus, &monitor->session_removed_slot,
        "org.freedesktop.login1", "/org/freedesktop/login1",
        "org.freedesktop.login1.Manager", "SessionRemoved", session_removed,
        monitor);
    if (result < 0) goto fail;
    stage = "lock subscription";
    result = sd_bus_add_match(
        monitor->bus, &monitor->lock_slot,
        "type='signal',sender='org.freedesktop.login1',"
        "path_namespace='/org/freedesktop/login1/session',"
        "interface='org.freedesktop.login1.Session',member='Lock'",
        session_lock, monitor);
    if (result < 0) goto fail;
    stage = "property subscription";
    result = sd_bus_add_match(
        monitor->bus, &monitor->properties_slot,
        "type='signal',sender='org.freedesktop.login1',"
        "path_namespace='/org/freedesktop/login1/session',"
        "interface='org.freedesktop.DBus.Properties',"
        "member='PropertiesChanged'",
        session_properties, monitor);
    if (result < 0) goto fail;
    stage = "session inventory";
    if (inventory_sessions(monitor) != 0) { result = -1; goto fail; }
    stage = "subscription flush";
    result = sd_bus_flush(monitor->bus);
    if (result < 0) goto fail;
    stage = "monitor descriptor";
    result = sd_bus_get_fd(monitor->bus);
    if (result < 0) goto fail;
    *out = monitor;
    return 0;
fail:
    fprintf(stderr, "kilix-secretsd: session monitor %s failed (%d)\n",
            stage, result);
    ksec_session_monitor_close(monitor);
    return -1;
}

int ksec_session_monitor_open(ksec_session_monitor **out, uid_t uid) {
    return session_monitor_open(out, uid, NULL);
}

#ifdef KSEC_TESTING
int ksec_session_monitor_open_at(ksec_session_monitor **out, uid_t uid,
                                 const char *bus_address) {
    if (bus_address == NULL || bus_address[0] == '\0') return -1;
    return session_monitor_open(out, uid, bus_address);
}
#endif

void ksec_session_monitor_close(ksec_session_monitor *monitor) {
    if (monitor == NULL) return;
    monitor->properties_slot = sd_bus_slot_unref(monitor->properties_slot);
    monitor->lock_slot = sd_bus_slot_unref(monitor->lock_slot);
    monitor->session_removed_slot =
        sd_bus_slot_unref(monitor->session_removed_slot);
    monitor->session_new_slot = sd_bus_slot_unref(monitor->session_new_slot);
    monitor->bus = sd_bus_unref(monitor->bus);
    memset(monitor, 0, sizeof *monitor);
    free(monitor);
}

int ksec_session_monitor_fd(ksec_session_monitor *monitor) {
    return monitor == NULL || monitor->bus == NULL
        ? -1 : sd_bus_get_fd(monitor->bus);
}

short ksec_session_monitor_events(ksec_session_monitor *monitor) {
    int events = monitor == NULL || monitor->bus == NULL
        ? -1 : sd_bus_get_events(monitor->bus);
    if (events < 0 || (events & ~(POLLIN | POLLOUT)) != 0) return 0;
    return events == 0 ? POLLIN : (short)events;
}

int ksec_session_monitor_process(ksec_session_monitor *monitor) {
    int result;
    if (monitor == NULL || monitor->bus == NULL || monitor->failed) return -1;
    do {
        result = sd_bus_process(monitor->bus, NULL);
    } while (result > 0 && !monitor->failed);
    return result < 0 || monitor->failed ? -1 : 0;
}

bool ksec_session_monitor_take_lock(ksec_session_monitor *monitor) {
    bool pending;
    if (monitor == NULL) return false;
    pending = monitor->lock_pending;
    monitor->lock_pending = false;
    return pending;
}

size_t ksec_session_monitor_tracked(const ksec_session_monitor *monitor) {
    return monitor == NULL ? 0U : monitor->session_count;
}
