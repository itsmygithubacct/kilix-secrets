#define _GNU_SOURCE

#include "internal.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

typedef struct {
    const char *socket_path;
    const char *app_id;
    int argc;
    char **argv;
} cli_request;

static void usage(FILE *stream) {
    fprintf(stream,
            "usage: kilix-secrets [--socket PATH] [--app APP] COMMAND [ARGS]\n"
            "commands:\n"
            "  init [--secret-fd N] [--recovery-fd N]\n"
            "  unlock [--recovery] [--secret-fd N]\n"
            "  lock\n"
            "  passwd [--secret-fd N]\n"
            "  add --type TYPE --label LABEL --field NAME [--secret-fd N]\n"
            "  run RECORD FIELD -- COMMAND [ARG ...]\n"
            "  list\n"
            "  delete RECORD\n"
            "  compact\n"
            "  doctor\n");
}

static int parse_fd(const char *text, int *out) {
    char *end = NULL;
    long value;
    errno = 0;
    value = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value < 0 || value > INT_MAX) {
        return -1;
    }
    *out = (int)value;
    return 0;
}

static int prompt_secret_fd(const char *prompt, size_t minimum) {
    int tty = -1;
    int fd = -1;
    struct termios original;
    struct termios hidden;
    bool changed = false;
    ksec_secure_buffer input = {0};
    size_t length = 0;
    tty = open("/dev/tty", O_RDWR | O_CLOEXEC | O_NOCTTY);
    if (tty < 0 || tcgetattr(tty, &original) != 0) goto fail;
    hidden = original;
    hidden.c_lflag &= (tcflag_t)~ECHO;
    if (tcsetattr(tty, TCSAFLUSH, &hidden) != 0) goto fail;
    changed = true;
    if (ksec_write_all(tty, prompt, strlen(prompt)) != 0
            || ksec_secure_alloc(&input, 1025U) != KSEC_OK) goto fail;
    while (length < 1025U) {
        uint8_t byte;
        ssize_t count = read(tty, &byte, 1U);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) goto fail;
        if (byte == (uint8_t)'\n' || byte == (uint8_t)'\r') break;
        input.data[length++] = byte;
    }
    if (minimum == 0U || length < minimum || length > 1024U) goto fail;
    if (tcsetattr(tty, TCSAFLUSH, &original) != 0) goto fail;
    changed = false;
    (void)ksec_write_all(tty, "\n", 1U);
    (void)close(tty);
    tty = -1;
    fd = memfd_create("ksec-cli-input", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (fd < 0 || ksec_write_all(fd, input.data, length) != 0
            || lseek(fd, 0, SEEK_SET) != 0
            || fcntl(fd, F_ADD_SEALS,
                     F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE) != 0) {
        goto fail;
    }
    ksec_secure_free(&input);
    return fd;
fail:
    if (changed) (void)tcsetattr(tty, TCSAFLUSH, &original);
    if (tty >= 0) {
        (void)ksec_write_all(tty, "\n", 1U);
        (void)close(tty);
    }
    if (fd >= 0) (void)close(fd);
    ksec_secure_free(&input);
    return -1;
}

static uint32_t command_verbs(const char *command) {
    if (strcmp(command, "init") == 0) return KSEC_VERB_CREATE | KSEC_VERB_READ;
    if (strcmp(command, "add") == 0) return KSEC_VERB_CREATE;
    if (strcmp(command, "unlock") == 0 || strcmp(command, "lock") == 0) return KSEC_VERB_READ;
    if (strcmp(command, "passwd") == 0) return KSEC_VERB_REPLACE;
    if (strcmp(command, "run") == 0) return KSEC_VERB_USE;
    if (strcmp(command, "list") == 0) return KSEC_VERB_LIST_OWN;
    if (strcmp(command, "delete") == 0) return KSEC_VERB_DELETE;
    if (strcmp(command, "compact") == 0) return KSEC_VERB_REPLACE;
    if (strcmp(command, "doctor") == 0) return KSEC_VERB_DOCTOR;
    return 0U;
}

static int receive_fd(int socket_fd) {
    char marker;
    uint8_t control[CMSG_SPACE(sizeof(int))];
    struct iovec iov;
    struct msghdr message;
    struct cmsghdr *cmsg;
    ssize_t count;
    memset(&message, 0, sizeof message);
    memset(control, 0, sizeof control);
    iov.iov_base = &marker;
    iov.iov_len = 1U;
    message.msg_iov = &iov;
    message.msg_iovlen = 1U;
    message.msg_control = control;
    message.msg_controllen = sizeof control;
    do {
        count = recvmsg(socket_fd, &message, MSG_CMSG_CLOEXEC);
    } while (count < 0 && errno == EINTR);
    if (count != 1 || marker != 'C' || (message.msg_flags & MSG_CTRUNC) != 0) return -1;
    cmsg = CMSG_FIRSTHDR(&message);
    if (cmsg == NULL || CMSG_NXTHDR(&message, cmsg) != NULL
            || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS
            || cmsg->cmsg_len != CMSG_LEN(sizeof(int))) return -1;
    {
        int fd;
        memcpy(&fd, CMSG_DATA(cmsg), sizeof fd);
        return fd;
    }
}

static int send_fd(int socket_fd, int passed_fd) {
    char marker = 'C';
    uint8_t control[CMSG_SPACE(sizeof(int))];
    struct iovec iov;
    struct msghdr message;
    struct cmsghdr *cmsg;
    memset(&message, 0, sizeof message);
    memset(control, 0, sizeof control);
    iov.iov_base = &marker;
    iov.iov_len = 1U;
    message.msg_iov = &iov;
    message.msg_iovlen = 1U;
    message.msg_control = control;
    message.msg_controllen = sizeof control;
    cmsg = CMSG_FIRSTHDR(&message);
    if (cmsg == NULL) return -1;
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &passed_fd, sizeof passed_fd);
    return sendmsg(socket_fd, &message, MSG_NOSIGNAL) == 1 ? 0 : -1;
}

static int worker_command(const cli_request *request, int capability_fd) {
    const char *command = request->argv[0];
    ksec_client *client = NULL;
    ksec_result result = ksec_connect_at(&client, request->socket_path, capability_fd);
    int exit_code = 1;
    if (result != KSEC_OK) {
        fprintf(stderr, "kilix-secrets: %s\n", ksec_result_string(result));
        return 1;
    }
    if (strcmp(command, "init") == 0) {
        int secret_fd = -1;
        int recovery_fd = -1;
        bool recovery_explicit = false;
        int index;
        for (index = 1; index < request->argc; index++) {
            if (index + 1 < request->argc
                    && strcmp(request->argv[index], "--secret-fd") == 0
                    && secret_fd < 0) {
                if (parse_fd(request->argv[++index], &secret_fd) != 0) {
                    result = KSEC_ERR_INVALID;
                    goto init_out;
                }
            } else if (index + 1 < request->argc
                    && strcmp(request->argv[index], "--recovery-fd") == 0
                    && recovery_fd < 0) {
                if (parse_fd(request->argv[++index], &recovery_fd) != 0) {
                    result = KSEC_ERR_INVALID;
                    goto init_out;
                }
                recovery_explicit = true;
            } else {
                result = KSEC_ERR_INVALID;
                goto init_out;
            }
        }
        if (secret_fd < 0) secret_fd = prompt_secret_fd("New passphrase: ", 8U);
        if (recovery_fd < 0) {
            recovery_fd = open("/dev/tty", O_WRONLY | O_CLOEXEC | O_NOCTTY);
            if (recovery_fd >= 0) {
                static const char warning[] =
                    "Recovery secret (record it offline; it will not be shown again):\n";
                if (ksec_write_all(recovery_fd, warning, sizeof warning - 1U) != 0) {
                    (void)close(recovery_fd);
                    recovery_fd = -1;
                }
            }
        }
        if (secret_fd < 0 || recovery_fd < 0) result = KSEC_ERR_INVALID;
        else {
            result = ksec_vault_init(client, secret_fd, recovery_fd);
            if (result == KSEC_OK
                    && ksec_write_all(recovery_fd, "\n", 1U) != 0) result = KSEC_ERR_IO;
        }
init_out:
        if (secret_fd > STDERR_FILENO) (void)close(secret_fd);
        if (recovery_fd > STDERR_FILENO) (void)close(recovery_fd);
        if (result == KSEC_OK && !recovery_explicit) {
            static const char confirmation[] =
                "Vault remains locked until `kilix-secrets unlock --recovery` confirms the recorded secret.\n";
            (void)ksec_write_all(STDERR_FILENO, confirmation, sizeof confirmation - 1U);
        }
    } else if (strcmp(command, "unlock") == 0) {
        ksec_slot_type slot = KSEC_SLOT_PASSPHRASE;
        int secret_fd = -1;
        bool recovery_seen = false;
        int index;
        for (index = 1; index < request->argc; index++) {
            if (strcmp(request->argv[index], "--recovery") == 0 && !recovery_seen) {
                slot = KSEC_SLOT_RECOVERY;
                recovery_seen = true;
            } else if (index + 1 < request->argc
                    && strcmp(request->argv[index], "--secret-fd") == 0
                    && secret_fd < 0) {
                if (parse_fd(request->argv[++index], &secret_fd) != 0) {
                    secret_fd = -1;
                    result = KSEC_ERR_INVALID;
                    break;
                }
            } else {
                result = KSEC_ERR_INVALID;
                break;
            }
        }
        if (result == KSEC_OK && secret_fd < 0) {
            secret_fd = prompt_secret_fd(slot == KSEC_SLOT_RECOVERY
                                         ? "Recovery secret: " : "Passphrase: ",
                                         slot == KSEC_SLOT_RECOVERY ? 64U : 8U);
        }
        if (secret_fd < 0) result = KSEC_ERR_INVALID;
        else if (result == KSEC_OK) {
            result = ksec_unlock(client, slot, secret_fd);
        }
        if (secret_fd > STDERR_FILENO) (void)close(secret_fd);
    } else if (strcmp(command, "lock") == 0 && request->argc == 1) {
        result = ksec_lock(client);
    } else if (strcmp(command, "passwd") == 0) {
        int secret_fd = -1;
        if (request->argc == 3
                && strcmp(request->argv[1], "--secret-fd") == 0
                && parse_fd(request->argv[2], &secret_fd) == 0) {
            result = KSEC_OK;
        } else if (request->argc == 1) {
            secret_fd = prompt_secret_fd("New passphrase: ", 8U);
            result = secret_fd < 0 ? KSEC_ERR_INVALID : KSEC_OK;
        } else {
            result = KSEC_ERR_INVALID;
        }
        if (result == KSEC_OK) {
            result = ksec_change_passphrase(client, secret_fd);
        }
        if (secret_fd > STDERR_FILENO) (void)close(secret_fd);
    } else if (strcmp(command, "add") == 0) {
        const char *type = NULL;
        const char *label = NULL;
        const char *field_name = NULL;
        int secret_fd = -1;
        int index;
        ksec_secure_buffer value = {0};
        uint8_t record_id[KSEC_RECORD_ID_BYTES];
        for (index = 1; index < request->argc; index++) {
            if (index + 1 < request->argc && strcmp(request->argv[index], "--type") == 0) type = request->argv[++index];
            else if (index + 1 < request->argc && strcmp(request->argv[index], "--label") == 0) label = request->argv[++index];
            else if (index + 1 < request->argc && strcmp(request->argv[index], "--field") == 0) field_name = request->argv[++index];
            else if (index + 1 < request->argc && strcmp(request->argv[index], "--secret-fd") == 0) {
                if (parse_fd(request->argv[++index], &secret_fd) != 0) secret_fd = -1;
            } else { result = KSEC_ERR_INVALID; goto add_out; }
        }
        if (secret_fd < 0) secret_fd = prompt_secret_fd("Secret value: ", 1U);
        if (type == NULL || label == NULL || field_name == NULL || secret_fd < 0
                || ksec_secure_alloc(&value, KSEC_MAX_SECRET_BYTES) != KSEC_OK) {
            result = KSEC_ERR_INVALID;
            goto add_out;
        }
        {
            size_t length = 0;
            for (;;) {
                ssize_t count = read(secret_fd, value.data + length, value.len - length);
                if (count < 0 && errno == EINTR) continue;
                if (count < 0) { result = KSEC_ERR_IO; goto add_out; }
                if (count == 0) break;
                length += (size_t)count;
                if (length == value.len) {
                    uint8_t extra;
                    count = read(secret_fd, &extra, 1U);
                    sodium_memzero(&extra, sizeof extra);
                    if (count != 0) { result = KSEC_ERR_LIMIT; goto add_out; }
                    break;
                }
            }
            while (length > 0U && (value.data[length - 1U] == (uint8_t)'\n'
                    || value.data[length - 1U] == (uint8_t)'\r')) length--;
            if (length == 0U) { result = KSEC_ERR_INVALID; goto add_out; }
            value.len = length;
        }
        {
            ksec_field field = {field_name, value.data, value.len};
            ksec_record record = {request->app_id, type, label, 0U, &field, 1U};
            result = ksec_put(client, &record, record_id);
        }
        if (result == KSEC_OK) {
            char id_hex[KSEC_RECORD_ID_BYTES * 2U + 1U];
            char line[KSEC_RECORD_ID_BYTES * 2U + 1U];
            ksec_hex_encode(record_id, KSEC_RECORD_ID_BYTES, id_hex);
            memcpy(line, id_hex, KSEC_RECORD_ID_BYTES * 2U);
            line[KSEC_RECORD_ID_BYTES * 2U] = '\n';
            if (ksec_write_all(STDOUT_FILENO, line, sizeof line) != 0) {
                result = KSEC_ERR_IO;
            }
            sodium_memzero(line, sizeof line);
            sodium_memzero(id_hex, sizeof id_hex);
        }
add_out:
        if (secret_fd > STDERR_FILENO) (void)close(secret_fd);
        ksec_secure_free(&value);
        sodium_memzero(record_id, sizeof record_id);
    } else if (strcmp(command, "run") == 0 && request->argc >= 5
            && strcmp(request->argv[3], "--") == 0) {
        uint8_t id[KSEC_RECORD_ID_BYTES];
        int secret_fd = -1;
        if (ksec_hex_decode(request->argv[1], id, sizeof id) != 0) result = KSEC_ERR_INVALID;
        else {
            char fd_text[32];
            int written;
            secret_fd = memfd_create("ksec-consumer-secret", MFD_CLOEXEC);
            if (secret_fd < 0) result = KSEC_ERR_IO;
            else result = ksec_get_to_fd(client, id, request->argv[2], secret_fd);
            if (result == KSEC_OK && (lseek(secret_fd, 0, SEEK_SET) != 0
                    || ksec_set_cloexec(secret_fd, false) != 0)) result = KSEC_ERR_IO;
            written = snprintf(fd_text, sizeof fd_text, "%d", secret_fd);
            if (result == KSEC_OK && (written < 0 || (size_t)written >= sizeof fd_text
                    || setenv("KILIX_SECRET_FD", fd_text, 1) != 0)) result = KSEC_ERR_IO;
            if (result == KSEC_OK) {
                execvp(request->argv[4], request->argv + 4);
                result = KSEC_ERR_IO;
            }
        }
        if (secret_fd >= 0) (void)close(secret_fd);
        sodium_memzero(id, sizeof id);
    } else if (strcmp(command, "list") == 0 && request->argc == 1) {
        result = ksec_list_to_fd(client, STDOUT_FILENO);
    } else if (strcmp(command, "delete") == 0 && request->argc == 2) {
        uint8_t id[KSEC_RECORD_ID_BYTES];
        if (ksec_hex_decode(request->argv[1], id, sizeof id) != 0) result = KSEC_ERR_INVALID;
        else result = ksec_delete(client, id);
        sodium_memzero(id, sizeof id);
    } else if (strcmp(command, "compact") == 0 && request->argc == 1) {
        result = ksec_compact(client);
    } else if (strcmp(command, "doctor") == 0 && request->argc == 1) {
        result = ksec_doctor_to_fd(client, STDOUT_FILENO);
    } else {
        result = KSEC_ERR_INVALID;
    }
    if (result == KSEC_OK) exit_code = 0;
    else fprintf(stderr, "kilix-secrets: %s\n", ksec_result_string(result));
    ksec_client_free(client);
    return exit_code;
}

static int supervise(const cli_request *request, uint32_t verbs) {
    int control[2];
    pid_t child;
    int status = 0;
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, control) != 0) return 1;
    child = fork();
    if (child < 0) {
        (void)close(control[0]);
        (void)close(control[1]);
        return 1;
    }
    if (child == 0) {
        int capability_fd;
        (void)close(control[0]);
        capability_fd = receive_fd(control[1]);
        (void)close(control[1]);
        if (capability_fd < 0) _exit(1);
        _exit(worker_command(request, capability_fd));
    }
    (void)close(control[1]);
    {
        int capability_fd = -1;
        ksec_result result = ksec_supervisor_mint(request->socket_path, child,
                                                  request->app_id, verbs, 300U,
                                                  &capability_fd);
        if (result != KSEC_OK || send_fd(control[0], capability_fd) != 0) {
            if (result != KSEC_OK) {
                fprintf(stderr, "kilix-secrets: %s\n", ksec_result_string(result));
            } else {
                fprintf(stderr, "kilix-secrets: capability delivery failed\n");
            }
            (void)kill(child, SIGTERM);
        }
        if (capability_fd >= 0) (void)close(capability_fd);
    }
    (void)close(control[0]);
    if (waitpid(child, &status, 0) != child) return 1;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return 1;
}

int main(int argc, char **argv) {
    const char *runtime = getenv("XDG_RUNTIME_DIR");
    char default_socket[4096];
    cli_request request;
    int index = 1;
    uint32_t verbs;
    int count;
    if (ksec_crypto_initialize() != KSEC_OK) return 1;
    memset(&request, 0, sizeof request);
    request.app_id = "kilix-secrets";
    while (index < argc) {
        if (index + 1 < argc && strcmp(argv[index], "--socket") == 0) {
            request.socket_path = argv[index + 1];
            index += 2;
        } else if (index + 1 < argc && strcmp(argv[index], "--app") == 0) {
            request.app_id = argv[index + 1];
            index += 2;
        } else break;
    }
    if (request.socket_path == NULL) {
        if (runtime == NULL) { usage(stderr); return 2; }
        count = snprintf(default_socket, sizeof default_socket,
                         "%s/kilix-secrets/control.sock", runtime);
        if (count < 0 || (size_t)count >= sizeof default_socket) return 2;
        request.socket_path = default_socket;
    }
    if (index >= argc || ksec_validate_app_id(request.app_id) != 0) {
        usage(stderr);
        return 2;
    }
    request.argc = argc - index;
    request.argv = argv + index;
    verbs = command_verbs(request.argv[0]);
    if (verbs == 0U) { usage(stderr); return 2; }
    return supervise(&request, verbs);
}
