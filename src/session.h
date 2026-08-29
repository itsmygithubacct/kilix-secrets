#ifndef KSEC_SESSION_H
#define KSEC_SESSION_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#define KSEC_MAX_GRAPHICAL_SESSIONS 64U

typedef struct ksec_session_monitor ksec_session_monitor;

int ksec_session_monitor_open(ksec_session_monitor **out, uid_t uid);
#ifdef KSEC_TESTING
int ksec_session_monitor_open_at(ksec_session_monitor **out, uid_t uid,
                                 const char *bus_address);
#endif
void ksec_session_monitor_close(ksec_session_monitor *monitor);
int ksec_session_monitor_fd(ksec_session_monitor *monitor);
short ksec_session_monitor_events(ksec_session_monitor *monitor);
int ksec_session_monitor_process(ksec_session_monitor *monitor);
bool ksec_session_monitor_take_lock(ksec_session_monitor *monitor);
size_t ksec_session_monitor_tracked(const ksec_session_monitor *monitor);

#endif
