#define _GNU_SOURCE

#include "internal.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
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
            "  add --type TYPE --label LABEL --field NAME [--secret-fd N] [--raw]\n"
            "  replace RECORD --field NAME [--secret-fd N] [--raw]\n"
            "  get RECORD FIELD (--output FILE | --output-fd N)\n"
            "  show RECORD\n"
            "  grant RECORD APP --verbs read,use[,replace,delete,list-own]\n"
            "  revoke RECORD APP\n"
            "  copy RECORD FIELD [--clear-seconds N]\n"
            "  run RECORD FIELD -- COMMAND [ARG ...]\n"
            "  list\n"
            "  dataset-create --label LABEL\n"
            "  seal RECORD --name NAME --revision N --input FILE|- --output FILE|-\n"
            "  unseal RECORD --name NAME --input FILE|- --output FILE|-\n"
            "  status\n"
            "  delete RECORD --confirm RECORD\n"
            "  rotate [--passphrase-fd N] [--recovery-fd N]\n"
            "  export --output FILE [--secret-fd N]\n"
            "  import --input FILE [--secret-fd N]\n"
            "  reset --confirm " KSEC_RESET_CONFIRMATION
                " [--secret-fd N] [--recovery-fd N]\n"
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

static int parse_u64(const char *text, uint64_t *out) {
    char *end = NULL;
    unsigned long long value;
    if (text == NULL || out == NULL || text[0] < '0' || text[0] > '9') return -1;
    errno = 0;
    value = strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0') return -1;
    *out = (uint64_t)value;
    return 0;
}

static int parse_seconds(const char *text, unsigned int *out) {
    char *end = NULL;
    unsigned long value;
    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value > 60U) return -1;
    *out = (unsigned int)value;
    return 0;
}

static int parse_grant_verbs(const char *text, uint32_t *out) {
    const char *cursor = text;
    uint32_t verbs = 0U;
    if (text == NULL || text[0] == '\0' || out == NULL) return -1;
    while (*cursor != '\0') {
        const char *comma = strchr(cursor, ',');
        size_t length = comma == NULL ? strlen(cursor) : (size_t)(comma - cursor);
        uint32_t verb;
        if (length == 4U && memcmp(cursor, "read", 4U) == 0) {
            verb = KSEC_VERB_READ;
        } else if (length == 7U && memcmp(cursor, "replace", 7U) == 0) {
            verb = KSEC_VERB_REPLACE;
        } else if (length == 6U && memcmp(cursor, "delete", 6U) == 0) {
            verb = KSEC_VERB_DELETE;
        } else if (length == 8U && memcmp(cursor, "list-own", 8U) == 0) {
            verb = KSEC_VERB_LIST_OWN;
        } else if (length == 3U && memcmp(cursor, "use", 3U) == 0) {
            verb = KSEC_VERB_USE;
        } else {
            return -1;
        }
        if ((verbs & verb) != 0U) return -1;
        verbs |= verb;
        if (comma == NULL) break;
        cursor = comma + 1U;
        if (*cursor == '\0') return -1;
    }
    *out = verbs;
    return verbs == 0U ? -1 : 0;
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
    if (strcmp(command, "add") == 0 || strcmp(command, "dataset-create") == 0) {
        return KSEC_VERB_CREATE;
    }
    if (strcmp(command, "unlock") == 0 || strcmp(command, "lock") == 0) return KSEC_VERB_READ;
    if (strcmp(command, "status") == 0) return KSEC_VERB_READ;
    if (strcmp(command, "seal") == 0 || strcmp(command, "unseal") == 0) return KSEC_VERB_USE;
    if (strcmp(command, "get") == 0) return KSEC_VERB_READ | KSEC_VERB_USE;
    if (strcmp(command, "replace") == 0) return KSEC_VERB_REPLACE | KSEC_VERB_LIST_OWN;
    if (strcmp(command, "passwd") == 0) return KSEC_VERB_REPLACE;
    if (strcmp(command, "run") == 0) return KSEC_VERB_USE;
    if (strcmp(command, "copy") == 0) return KSEC_VERB_USE;
    if (strcmp(command, "list") == 0) return KSEC_VERB_LIST_OWN;
    if (strcmp(command, "show") == 0) return KSEC_VERB_LIST_OWN;
    if (strcmp(command, "grant") == 0 || strcmp(command, "revoke") == 0) {
        return KSEC_VERB_REPLACE;
    }
    if (strcmp(command, "delete") == 0) return KSEC_VERB_DELETE;
    if (strcmp(command, "compact") == 0 || strcmp(command, "rotate") == 0) {
        return KSEC_VERB_REPLACE;
    }
    if (strcmp(command, "export") == 0) return KSEC_VERB_READ;
    if (strcmp(command, "import") == 0) return KSEC_VERB_REPLACE;
    if (strcmp(command, "reset") == 0) return KSEC_VERB_REPLACE;
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

static void unlink_exact_created_file(const char *path, int fd) {
    struct stat descriptor_status;
    struct stat path_status;
    if (path != NULL && fd >= 0 && fstat(fd, &descriptor_status) == 0
            && lstat(path, &path_status) == 0
            && S_ISREG(path_status.st_mode)
            && descriptor_status.st_dev == path_status.st_dev
            && descriptor_status.st_ino == path_status.st_ino) {
        (void)unlink(path);
    }
}

static int wait_provider(pid_t child) {
    struct timespec pause = {0, 100000000L};
    unsigned int attempt;
    int status = 0;
    for (attempt = 0U; attempt < 100U; attempt++) {
        pid_t result = waitpid(child, &status, WNOHANG);
        if (result == child) {
            return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
        }
        if (result < 0 && errno != EINTR) return -1;
        (void)nanosleep(&pause, NULL);
    }
    (void)kill(child, SIGTERM);
    for (attempt = 0U; attempt < 10U; attempt++) {
        pid_t result = waitpid(child, &status, WNOHANG);
        if (result == child) return -1;
        if (result < 0 && errno != EINTR) return -1;
        (void)nanosleep(&pause, NULL);
    }
    (void)kill(child, SIGKILL);
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
    return -1;
}

static int write_provider_input(int fd, const uint8_t *data, size_t length) {
    size_t offset = 0U;
    unsigned int attempts = 0U;
    int flags;
    if (fd < 0 || (data == NULL && length > 0U)) return -1;
    flags = fcntl(fd, F_GETFL);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) return -1;
    while (offset < length && attempts < 100U) {
        ssize_t count = write(fd, data + offset, length - offset);
        if (count > 0) {
            offset += (size_t)count;
            continue;
        }
        if (count < 0 && errno == EINTR) continue;
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd descriptor = {fd, POLLOUT, 0};
            int ready = poll(&descriptor, 1U, 100);
            if (ready < 0 && errno == EINTR) continue;
            if (ready < 0 || (ready > 0
                    && (descriptor.revents & (POLLERR | POLLHUP | POLLNVAL))
                        != 0)) return -1;
            attempts++;
            continue;
        }
        return -1;
    }
    return offset == length ? 0 : -1;
}

static int clipboard_provider_set(const uint8_t *data, size_t length) {
    int input[2] = {-1, -1};
    pid_t child;
    int result = -1;
    if ((data == NULL && length > 0U) || pipe2(input, O_CLOEXEC) != 0) return -1;
    child = fork();
    if (child < 0) goto out;
    if (child == 0) {
        int null_fd;
        (void)signal(SIGPIPE, SIG_DFL);
        (void)close(input[1]);
        null_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
        if (null_fd < 0) {
            (void)close(input[0]);
            _exit(126);
        }
        if (dup2(input[0], STDIN_FILENO) < 0
                || dup2(null_fd, STDOUT_FILENO) < 0) {
            (void)close(input[0]);
            (void)close(null_fd);
            _exit(126);
        }
        (void)close(input[0]);
        (void)close(null_fd);
        execlp("kitty", "kitty", "+kitten", "clipboard",
               "--wait-for-completion", (char *)NULL);
        _exit(127);
    }
    (void)close(input[0]);
    input[0] = -1;
    if (write_provider_input(input[1], data, length) == 0
            && close(input[1]) == 0) {
        input[1] = -1;
        result = wait_provider(child);
    } else {
        (void)close(input[1]);
        input[1] = -1;
        (void)kill(child, SIGTERM);
        (void)wait_provider(child);
    }
out:
    if (input[0] >= 0) (void)close(input[0]);
    if (input[1] >= 0) (void)close(input[1]);
    return result;
}

static int clipboard_provider_get(ksec_secure_buffer *output) {
    int pipe_fds[2] = {-1, -1};
    pid_t child;
    size_t total = 0U;
    unsigned int attempts = 0U;
    bool eof = false;
    int read_result = 0;
    int result = -1;
    if (output == NULL || pipe2(pipe_fds, O_CLOEXEC) != 0) return -1;
    if (ksec_secure_alloc(output, KSEC_MAX_SECRET_BYTES + 1U) != KSEC_OK) {
        goto out;
    }
    child = fork();
    if (child < 0) goto out;
    if (child == 0) {
        int null_fd;
        (void)signal(SIGPIPE, SIG_DFL);
        (void)close(pipe_fds[0]);
        null_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (null_fd < 0) {
            (void)close(pipe_fds[1]);
            _exit(126);
        }
        if (dup2(null_fd, STDIN_FILENO) < 0
                || dup2(pipe_fds[1], STDOUT_FILENO) < 0) {
            (void)close(null_fd);
            (void)close(pipe_fds[1]);
            _exit(126);
        }
        (void)close(null_fd);
        (void)close(pipe_fds[1]);
        execlp("kitty", "kitty", "+kitten", "clipboard",
               "--get-clipboard", (char *)NULL);
        _exit(127);
    }
    (void)close(pipe_fds[1]);
    pipe_fds[1] = -1;
    while (total < output->len && !eof && attempts < 100U) {
        struct pollfd descriptor = {pipe_fds[0], POLLIN, 0};
        int ready = poll(&descriptor, 1U, 100);
        ssize_t count;
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) { read_result = -1; break; }
        if (ready == 0) { attempts++; continue; }
        if ((descriptor.revents & (POLLERR | POLLNVAL)) != 0) {
            read_result = -1;
            break;
        }
        if ((descriptor.revents & (POLLIN | POLLHUP)) == 0) continue;
        count = read(pipe_fds[0], output->data + total,
                     output->len - total);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) { read_result = -1; break; }
        if (count == 0) { eof = true; break; }
        total += (size_t)count;
    }
    if (!eof) read_result = -1;
    if (close(pipe_fds[0]) != 0) read_result = -1;
    pipe_fds[0] = -1;
    if (read_result != 0) (void)kill(child, SIGTERM);
    if (wait_provider(child) == 0 && read_result == 0
            && total <= KSEC_MAX_SECRET_BYTES) {
        output->len = total;
        result = 0;
    }
out:
    if (pipe_fds[0] >= 0) (void)close(pipe_fds[0]);
    if (pipe_fds[1] >= 0) (void)close(pipe_fds[1]);
    if (result != 0) ksec_secure_free(output);
    return result;
}

static ksec_result copy_to_clipboard(ksec_client *client,
                                     const uint8_t record_id[16],
                                     const char *field,
                                     unsigned int clear_seconds) {
    static const char warning[] =
        "WARNING: clipboard contents and history may expose this secret; "
        "clearing is best-effort and is not guaranteed.\n";
    static const char changed[] =
        "Clipboard changed before clearing; the newer contents were left intact.\n";
    static const char cleared[] =
        "Clipboard clear attempted; history or another client may retain the secret.\n";
    static const char unavailable[] =
        "The active Kitty clipboard provider was unavailable; clipboard state could not be verified.\n";
    ksec_secure_buffer secret = {0};
    ksec_secure_buffer observed = {0};
    size_t secret_len = 0U;
    unsigned int remaining;
    ksec_result result;
    if (ksec_write_all(STDERR_FILENO, warning, sizeof warning - 1U) != 0) {
        return KSEC_ERR_IO;
    }
    result = ksec_secure_alloc(&secret, KSEC_MAX_SECRET_BYTES);
    if (result != KSEC_OK) return result;
    result = ksec_get_buf(client, record_id, field, secret.data, secret.len,
                          &secret_len);
    if (result != KSEC_OK) goto out;
    secret.len = secret_len;
    if (clipboard_provider_set(secret.data, secret.len) != 0) {
        (void)ksec_write_all(STDERR_FILENO, unavailable,
                             sizeof unavailable - 1U);
        result = KSEC_ERR_IO;
        goto out;
    }
    remaining = clear_seconds;
    while (remaining > 0U) remaining = sleep(remaining);
    if (clipboard_provider_get(&observed) != 0) {
        (void)ksec_write_all(STDERR_FILENO, unavailable,
                             sizeof unavailable - 1U);
        result = KSEC_ERR_IO;
        goto out;
    }
    if (observed.len != secret.len
            || !ksec_safe_equal(observed.data, secret.data, secret.len)) {
        (void)ksec_write_all(STDERR_FILENO, changed, sizeof changed - 1U);
        result = KSEC_OK;
        goto out;
    }
    if (clipboard_provider_set(NULL, 0U) != 0) {
        (void)ksec_write_all(STDERR_FILENO, unavailable,
                             sizeof unavailable - 1U);
        result = KSEC_ERR_IO;
        goto out;
    }
    (void)ksec_write_all(STDERR_FILENO, cleared, sizeof cleared - 1U);
    result = KSEC_OK;
out:
    ksec_secure_free(&observed);
    ksec_secure_free(&secret);
    return result;
}

enum {
    CLI_FAIL_NONE = 0,
    CLI_FAIL_USAGE = 1,
    CLI_FAIL_TERMINAL = 2
};

static int assign_text(char *destination, size_t destination_size,
                       const char *value, size_t value_length) {
    if (destination == NULL || value == NULL || value_length == 0U
            || value_length >= destination_size) return -1;
    memcpy(destination, value, value_length);
    destination[value_length] = '\0';
    return 0;
}

/* 1 when fd is a terminal, 0 when it is not, -1 when the check itself fails. */
static int terminal_status(int fd) {
    int result;
    if (fd < 0) return -1;
    errno = 0;
    result = isatty(fd);
    if (result == 1) return 1;
    if (errno == EBADF) return -1;
    return 0;
}

static ksec_result read_secret_fd(int fd, bool keep_trailing,
                                  ksec_secure_buffer *value, size_t *secret_len) {
    size_t length = 0U;
    ksec_result result;
    if (fd < 0 || value == NULL || value->data != NULL || secret_len == NULL) {
        return KSEC_ERR_INVALID;
    }
    result = ksec_secure_alloc(value, KSEC_MAX_SECRET_BYTES);
    if (result != KSEC_OK) return result;
    for (;;) {
        ssize_t count = read(fd, value->data + length, value->len - length);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) {
            ksec_secure_free(value);
            return KSEC_ERR_IO;
        }
        if (count == 0) break;
        length += (size_t)count;
        if (length == value->len) {
            uint8_t extra;
            do {
                count = read(fd, &extra, 1U);
            } while (count < 0 && errno == EINTR);
            sodium_memzero(&extra, sizeof extra);
            if (count < 0) {
                ksec_secure_free(value);
                return KSEC_ERR_IO;
            }
            if (count != 0) {
                ksec_secure_free(value);
                return KSEC_ERR_LIMIT;
            }
            break;
        }
    }
    if (!keep_trailing) {
        size_t end = length;
        while (length > 0U && (value->data[length - 1U] == (uint8_t)'\n'
                || value->data[length - 1U] == (uint8_t)'\r')) {
            length--;
        }
        if (length < end) sodium_memzero(value->data + length, end - length);
    }
    if (length == 0U) {
        ksec_secure_free(value);
        return KSEC_ERR_INVALID;
    }
    /* value->len stays the allocation size so ksec_secure_free unlocks it all. */
    *secret_len = length;
    return KSEC_OK;
}

static ksec_result write_record_id(const uint8_t record_id[KSEC_RECORD_ID_BYTES]) {
    char id_hex[KSEC_RECORD_ID_BYTES * 2U + 1U];
    char line[KSEC_RECORD_ID_BYTES * 2U + 2U];
    ksec_hex_encode(record_id, KSEC_RECORD_ID_BYTES, id_hex);
    memcpy(line, id_hex, KSEC_RECORD_ID_BYTES * 2U);
    line[KSEC_RECORD_ID_BYTES * 2U] = '\n';
    if (ksec_write_all(STDOUT_FILENO, line, KSEC_RECORD_ID_BYTES * 2U + 1U) != 0) {
        sodium_memzero(line, sizeof line);
        sodium_memzero(id_hex, sizeof id_hex);
        return KSEC_ERR_IO;
    }
    sodium_memzero(line, sizeof line);
    sodium_memzero(id_hex, sizeof id_hex);
    return KSEC_OK;
}

static int open_input_path(const char *path, int *fd, bool *owned) {
    if (path == NULL || path[0] == '\0' || fd == NULL || owned == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (strcmp(path, "-") == 0) {
        *fd = STDIN_FILENO;
        *owned = false;
        return 0;
    }
    *fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (*fd < 0) return -1;
    *owned = true;
    return 0;
}

static int open_exclusive_output(const char *path, int *fd, bool *owned,
                                 bool *created) {
    if (path == NULL || path[0] == '\0' || fd == NULL || owned == NULL
            || created == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (strcmp(path, "-") == 0) {
        *fd = STDOUT_FILENO;
        *owned = false;
        *created = false;
        return 0;
    }
    *fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (*fd < 0) return -1;
    if (fchmod(*fd, 0600) != 0) {
        int saved = errno;
        unlink_exact_created_file(path, *fd);
        (void)close(*fd);
        *fd = -1;
        errno = saved;
        return -1;
    }
    *owned = true;
    *created = true;
    return 0;
}

static ksec_result load_show_metadata(ksec_client *client,
                                      const uint8_t record_id[KSEC_RECORD_ID_BYTES],
                                      char owner[KSEC_MAX_APP_ID + 1U],
                                      char type[KSEC_MAX_TYPE + 1U],
                                      char label[KSEC_MAX_LABEL + 1U],
                                      uint64_t *expires_at) {
    char buffer[8192];
    size_t length = 0U;
    size_t cursor = 0U;
    bool saw_owner = false;
    bool saw_type = false;
    bool saw_label = false;
    bool saw_expiry = false;
    int fd = -1;
    ksec_result result;
    memset(buffer, 0, sizeof buffer);
    if (owner != NULL) owner[0] = '\0';
    if (type != NULL) type[0] = '\0';
    if (label != NULL) label[0] = '\0';
    if (client == NULL || record_id == NULL || owner == NULL || type == NULL
            || label == NULL || expires_at == NULL) return KSEC_ERR_INVALID;
    fd = memfd_create("ksec-cli-show", MFD_CLOEXEC);
    if (fd < 0) return KSEC_ERR_IO;
    result = ksec_show_to_fd(client, record_id, fd);
    if (result != KSEC_OK) goto out;
    if (lseek(fd, 0, SEEK_SET) != 0) {
        result = KSEC_ERR_IO;
        goto out;
    }
    for (;;) {
        ssize_t count;
        if (length == sizeof buffer) {
            result = KSEC_ERR_LIMIT;
            goto out;
        }
        count = read(fd, buffer + length, sizeof buffer - length);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) {
            result = KSEC_ERR_IO;
            goto out;
        }
        if (count == 0) break;
        length += (size_t)count;
    }
    if (length == 0U) {
        result = KSEC_ERR_INVALID;
        goto out;
    }
    while (cursor < length) {
        size_t end = cursor;
        size_t equals = 0U;
        bool found_equals = false;
        size_t key_len;
        const char *value;
        size_t value_len;
        while (end < length && buffer[end] != '\n') {
            if (buffer[end] == '\0' || buffer[end] == '\r') {
                result = KSEC_ERR_INVALID;
                goto out;
            }
            if (!found_equals && buffer[end] == '=') {
                equals = end;
                found_equals = true;
            }
            end++;
        }
        if (end == length || !found_equals || equals == cursor) {
            result = KSEC_ERR_INVALID;
            goto out;
        }
        key_len = equals - cursor;
        value = buffer + equals + 1U;
        value_len = end - (equals + 1U);
        if (key_len == 5U && memcmp(buffer + cursor, "owner", 5) == 0) {
            if (saw_owner
                    || assign_text(owner, KSEC_MAX_APP_ID + 1U, value, value_len) != 0) {
                result = KSEC_ERR_INVALID;
                goto out;
            }
            saw_owner = true;
        } else if (key_len == 4U && memcmp(buffer + cursor, "type", 4) == 0) {
            if (saw_type
                    || assign_text(type, KSEC_MAX_TYPE + 1U, value, value_len) != 0) {
                result = KSEC_ERR_INVALID;
                goto out;
            }
            saw_type = true;
        } else if (key_len == 5U && memcmp(buffer + cursor, "label", 5) == 0) {
            if (saw_label
                    || assign_text(label, KSEC_MAX_LABEL + 1U, value, value_len) != 0) {
                result = KSEC_ERR_INVALID;
                goto out;
            }
            saw_label = true;
        } else if (key_len == 10U && memcmp(buffer + cursor, "expires_at", 10) == 0) {
            char text[32];
            if (saw_expiry || value_len == 0U || value_len >= sizeof text) {
                result = KSEC_ERR_INVALID;
                goto out;
            }
            memcpy(text, value, value_len);
            text[value_len] = '\0';
            if (parse_u64(text, expires_at) != 0) {
                result = KSEC_ERR_INVALID;
                goto out;
            }
            sodium_memzero(text, sizeof text);
            saw_expiry = true;
        }
        cursor = end + 1U;
    }
    if (!saw_owner || !saw_type || !saw_label || !saw_expiry
            || ksec_validate_app_id(owner) != 0
            || ksec_validate_name(type, KSEC_MAX_TYPE) != 0
            || ksec_validate_name(label, KSEC_MAX_LABEL) != 0) {
        result = KSEC_ERR_INVALID;
    }
out:
    if (fd >= 0) (void)close(fd);
    sodium_memzero(buffer, sizeof buffer);
    if (result != KSEC_OK) {
        sodium_memzero(owner, KSEC_MAX_APP_ID + 1U);
        sodium_memzero(type, KSEC_MAX_TYPE + 1U);
        sodium_memzero(label, KSEC_MAX_LABEL + 1U);
        *expires_at = 0U;
    }
    return result;
}

static ksec_result command_add(const cli_request *request, ksec_client *client,
                               int *failure) {
    const char *type = NULL;
    const char *label = NULL;
    const char *field_name = NULL;
    int secret_fd = -1;
    bool raw = false;
    bool saw_secret_fd = false;
    int index;
    ksec_secure_buffer value = {0};
    size_t secret_len = 0U;
    uint8_t record_id[KSEC_RECORD_ID_BYTES];
    ksec_result result = KSEC_OK;
    memset(record_id, 0, sizeof record_id);
    for (index = 1; index < request->argc; index++) {
        if (index + 1 < request->argc && strcmp(request->argv[index], "--type") == 0
                && type == NULL) {
            type = request->argv[++index];
        } else if (index + 1 < request->argc
                && strcmp(request->argv[index], "--label") == 0 && label == NULL) {
            label = request->argv[++index];
        } else if (index + 1 < request->argc
                && strcmp(request->argv[index], "--field") == 0 && field_name == NULL) {
            field_name = request->argv[++index];
        } else if (index + 1 < request->argc
                && strcmp(request->argv[index], "--secret-fd") == 0
                && !saw_secret_fd) {
            saw_secret_fd = true;
            if (parse_fd(request->argv[++index], &secret_fd) != 0) {
                *failure = CLI_FAIL_USAGE;
                result = KSEC_ERR_INVALID;
                goto out;
            }
        } else if (strcmp(request->argv[index], "--raw") == 0 && !raw) {
            raw = true;
        } else {
            *failure = CLI_FAIL_USAGE;
            result = KSEC_ERR_INVALID;
            goto out;
        }
    }
    if (type == NULL || label == NULL || field_name == NULL) {
        *failure = CLI_FAIL_USAGE;
        result = KSEC_ERR_INVALID;
        goto out;
    }
    if (ksec_validate_name(type, KSEC_MAX_TYPE) != 0
            || ksec_validate_name(label, KSEC_MAX_LABEL) != 0
            || ksec_validate_name(field_name, KSEC_MAX_FIELD_NAME) != 0) {
        result = KSEC_ERR_INVALID;
        goto out;
    }
    if (!saw_secret_fd) secret_fd = prompt_secret_fd("Secret value: ", 1U);
    if (secret_fd < 0) {
        result = KSEC_ERR_INVALID;
        goto out;
    }
    result = read_secret_fd(secret_fd, raw, &value, &secret_len);
    if (result != KSEC_OK) goto out;
    {
        ksec_field field = {field_name, value.data, secret_len};
        ksec_record record = {
            request->app_id, type, label, 0U, &field, 1U, NULL, 0U
        };
        result = ksec_put(client, &record, record_id);
    }
    if (result == KSEC_OK) result = write_record_id(record_id);
out:
    if (secret_fd > STDERR_FILENO) (void)close(secret_fd);
    ksec_secure_free(&value);
    sodium_memzero(record_id, sizeof record_id);
    return result;
}

static ksec_result command_replace(const cli_request *request, ksec_client *client,
                                   int *failure) {
    const char *record_text = NULL;
    const char *field_name = NULL;
    int secret_fd = -1;
    bool raw = false;
    bool saw_secret_fd = false;
    int index;
    char owner[KSEC_MAX_APP_ID + 1U];
    char type[KSEC_MAX_TYPE + 1U];
    char label[KSEC_MAX_LABEL + 1U];
    uint64_t expires_at = 0U;
    ksec_secure_buffer value = {0};
    size_t secret_len = 0U;
    uint8_t record_id[KSEC_RECORD_ID_BYTES];
    ksec_result result = KSEC_OK;
    memset(owner, 0, sizeof owner);
    memset(type, 0, sizeof type);
    memset(label, 0, sizeof label);
    memset(record_id, 0, sizeof record_id);
    for (index = 1; index < request->argc; index++) {
        const char *arg = request->argv[index];
        if (index + 1 < request->argc && strcmp(arg, "--field") == 0
                && field_name == NULL) {
            field_name = request->argv[++index];
        } else if (index + 1 < request->argc && strcmp(arg, "--secret-fd") == 0
                && !saw_secret_fd) {
            saw_secret_fd = true;
            if (parse_fd(request->argv[++index], &secret_fd) != 0) {
                *failure = CLI_FAIL_USAGE;
                result = KSEC_ERR_INVALID;
                goto out;
            }
        } else if (strcmp(arg, "--raw") == 0 && !raw) {
            raw = true;
        } else if (record_text == NULL && arg[0] != '-') {
            record_text = arg;
        } else {
            *failure = CLI_FAIL_USAGE;
            result = KSEC_ERR_INVALID;
            goto out;
        }
    }
    if (record_text == NULL || field_name == NULL) {
        *failure = CLI_FAIL_USAGE;
        result = KSEC_ERR_INVALID;
        goto out;
    }
    if (ksec_hex_decode(record_text, record_id, sizeof record_id) != 0
            || ksec_validate_name(field_name, KSEC_MAX_FIELD_NAME) != 0) {
        result = KSEC_ERR_INVALID;
        goto out;
    }
    result = load_show_metadata(client, record_id, owner, type, label, &expires_at);
    if (result != KSEC_OK) goto out;
    if (!saw_secret_fd) secret_fd = prompt_secret_fd("Secret value: ", 1U);
    if (secret_fd < 0) {
        result = KSEC_ERR_INVALID;
        goto out;
    }
    result = read_secret_fd(secret_fd, raw, &value, &secret_len);
    if (result != KSEC_OK) goto out;
    {
        ksec_field field = {field_name, value.data, secret_len};
        ksec_record record = {
            owner, type, label, expires_at, &field, 1U, NULL, 0U
        };
        result = ksec_replace(client, record_id, &record);
    }
out:
    if (secret_fd > STDERR_FILENO) (void)close(secret_fd);
    ksec_secure_free(&value);
    sodium_memzero(owner, sizeof owner);
    sodium_memzero(type, sizeof type);
    sodium_memzero(label, sizeof label);
    sodium_memzero(record_id, sizeof record_id);
    return result;
}

static ksec_result command_get(const cli_request *request, ksec_client *client,
                               int *failure) {
    const char *record_text = NULL;
    const char *field_name = NULL;
    const char *output_path = NULL;
    int output_fd = -1;
    bool saw_output_fd = false;
    bool output_owned = false;
    bool output_created = false;
    int index;
    uint8_t record_id[KSEC_RECORD_ID_BYTES];
    ksec_result result = KSEC_OK;
    memset(record_id, 0, sizeof record_id);
    for (index = 1; index < request->argc; index++) {
        const char *arg = request->argv[index];
        if (index + 1 < request->argc && strcmp(arg, "--output") == 0
                && output_path == NULL && !saw_output_fd) {
            output_path = request->argv[++index];
        } else if (index + 1 < request->argc && strcmp(arg, "--output-fd") == 0
                && !saw_output_fd && output_path == NULL) {
            saw_output_fd = true;
            if (parse_fd(request->argv[++index], &output_fd) != 0) {
                *failure = CLI_FAIL_USAGE;
                result = KSEC_ERR_INVALID;
                goto out;
            }
        } else if (arg[0] != '-' && record_text == NULL) {
            record_text = arg;
        } else if (arg[0] != '-' && field_name == NULL) {
            field_name = arg;
        } else {
            *failure = CLI_FAIL_USAGE;
            result = KSEC_ERR_INVALID;
            goto out;
        }
    }
    if (record_text == NULL || field_name == NULL
            || (output_path == NULL && !saw_output_fd)) {
        *failure = CLI_FAIL_USAGE;
        result = KSEC_ERR_INVALID;
        goto out;
    }
    if (output_path != NULL
            && (output_path[0] == '\0' || strcmp(output_path, "-") == 0)) {
        *failure = CLI_FAIL_USAGE;
        result = KSEC_ERR_INVALID;
        goto out;
    }
    if (ksec_hex_decode(record_text, record_id, sizeof record_id) != 0
            || ksec_validate_name(field_name, KSEC_MAX_FIELD_NAME) != 0) {
        result = KSEC_ERR_INVALID;
        goto out;
    }
    if (output_path != NULL) {
        if (open_exclusive_output(output_path, &output_fd, &output_owned,
                                  &output_created) != 0) {
            result = errno == EEXIST ? KSEC_ERR_EXISTS : KSEC_ERR_IO;
            goto out;
        }
    }
    {
        int tty = terminal_status(output_fd);
        if (tty < 0) {
            result = KSEC_ERR_IO;
            goto out;
        }
        if (tty == 1) {
            *failure = CLI_FAIL_TERMINAL;
            result = KSEC_ERR_INVALID;
            goto out;
        }
    }
    /* The library writes output_fd only after the daemon returns KSEC_OK. */
    result = ksec_get_to_fd(client, record_id, field_name, output_fd);
out:
    if (result != KSEC_OK && output_created) {
        unlink_exact_created_file(output_path, output_fd);
    }
    if (output_owned && output_fd >= 0 && close(output_fd) != 0 && result == KSEC_OK) {
        result = KSEC_ERR_IO;
    }
    sodium_memzero(record_id, sizeof record_id);
    return result;
}

static ksec_result command_dataset_create(const cli_request *request,
                                          ksec_client *client, int *failure) {
    const char *label = NULL;
    uint8_t record_id[KSEC_RECORD_ID_BYTES];
    int index;
    ksec_result result;
    memset(record_id, 0, sizeof record_id);
    for (index = 1; index < request->argc; index++) {
        if (index + 1 < request->argc && strcmp(request->argv[index], "--label") == 0
                && label == NULL) {
            label = request->argv[++index];
        } else {
            *failure = CLI_FAIL_USAGE;
            sodium_memzero(record_id, sizeof record_id);
            return KSEC_ERR_INVALID;
        }
    }
    if (label == NULL) {
        *failure = CLI_FAIL_USAGE;
        sodium_memzero(record_id, sizeof record_id);
        return KSEC_ERR_INVALID;
    }
    if (ksec_validate_name(label, KSEC_MAX_LABEL) != 0) {
        sodium_memzero(record_id, sizeof record_id);
        return KSEC_ERR_INVALID;
    }
    result = ksec_dataset_create(client, label, record_id);
    if (result == KSEC_OK) result = write_record_id(record_id);
    sodium_memzero(record_id, sizeof record_id);
    return result;
}

static ksec_result write_revision_line(uint64_t revision) {
    char line[64];
    int written = snprintf(line, sizeof line, "revision=%llu\n",
                           (unsigned long long)revision);
    if (written < 0 || (size_t)written >= sizeof line
            || ksec_write_all(STDERR_FILENO, line, (size_t)written) != 0) {
        return KSEC_ERR_IO;
    }
    return KSEC_OK;
}

static ksec_result command_seal(const cli_request *request, ksec_client *client,
                                int *failure, bool unseal) {
    const char *record_text = NULL;
    const char *name = NULL;
    const char *revision_text = NULL;
    const char *input_path = NULL;
    const char *output_path = NULL;
    uint8_t record_id[KSEC_RECORD_ID_BYTES];
    uint64_t revision = 0U;
    int input_fd = -1;
    int output_fd = -1;
    bool input_owned = false;
    bool output_owned = false;
    bool output_created = false;
    int index;
    ksec_result result = KSEC_OK;
    memset(record_id, 0, sizeof record_id);
    for (index = 1; index < request->argc; index++) {
        const char *arg = request->argv[index];
        if (index + 1 < request->argc && strcmp(arg, "--name") == 0 && name == NULL) {
            name = request->argv[++index];
        } else if (!unseal && index + 1 < request->argc
                && strcmp(arg, "--revision") == 0 && revision_text == NULL) {
            revision_text = request->argv[++index];
        } else if (index + 1 < request->argc && strcmp(arg, "--input") == 0
                && input_path == NULL) {
            input_path = request->argv[++index];
        } else if (index + 1 < request->argc && strcmp(arg, "--output") == 0
                && output_path == NULL) {
            output_path = request->argv[++index];
        } else if (record_text == NULL && arg[0] != '-') {
            record_text = arg;
        } else {
            *failure = CLI_FAIL_USAGE;
            result = KSEC_ERR_INVALID;
            goto out;
        }
    }
    if (record_text == NULL || name == NULL || input_path == NULL
            || output_path == NULL || (!unseal && revision_text == NULL)
            || input_path[0] == '\0' || output_path[0] == '\0') {
        *failure = CLI_FAIL_USAGE;
        result = KSEC_ERR_INVALID;
        goto out;
    }
    if (ksec_hex_decode(record_text, record_id, sizeof record_id) != 0
            || ksec_validate_name(name, KSEC_MAX_DATASET_NAME) != 0
            || (!unseal && parse_u64(revision_text, &revision) != 0)) {
        result = KSEC_ERR_INVALID;
        goto out;
    }
    if (open_input_path(input_path, &input_fd, &input_owned) != 0) {
        result = KSEC_ERR_IO;
        goto out;
    }
    if (open_exclusive_output(output_path, &output_fd, &output_owned,
                              &output_created) != 0) {
        result = errno == EEXIST ? KSEC_ERR_EXISTS : KSEC_ERR_IO;
        goto out;
    }
    if (unseal && !output_owned) {
        int tty = terminal_status(output_fd);
        if (tty < 0) {
            result = KSEC_ERR_IO;
            goto out;
        }
        if (tty == 1) {
            *failure = CLI_FAIL_TERMINAL;
            result = KSEC_ERR_INVALID;
            goto out;
        }
    }
    /* output_fd is written only after the daemon returns KSEC_OK. */
    if (unseal) {
        uint64_t actual = 0U;
        result = ksec_unseal_fd(client, record_id, name, input_fd, output_fd,
                                &actual);
        if (result == KSEC_OK) result = write_revision_line(actual);
    } else {
        result = ksec_seal_fd(client, record_id, name, revision, input_fd,
                              output_fd);
    }
out:
    if (result != KSEC_OK && output_created) {
        unlink_exact_created_file(output_path, output_fd);
    }
    if (input_owned && input_fd >= 0 && close(input_fd) != 0 && result == KSEC_OK) {
        result = KSEC_ERR_IO;
    }
    if (output_owned && output_fd >= 0 && close(output_fd) != 0 && result == KSEC_OK) {
        result = KSEC_ERR_IO;
    }
    sodium_memzero(record_id, sizeof record_id);
    return result;
}

static ksec_result command_status(const cli_request *request, ksec_client *client,
                                  int *failure) {
    uint32_t flags = 0U;
    uint32_t known = KSEC_STATUS_INITIALIZED | KSEC_STATUS_RECOVERY_CONFIRMED
            | KSEC_STATUS_UNLOCKED;
    char line[80];
    int written;
    ksec_result result;
    if (request->argc != 1) {
        *failure = CLI_FAIL_USAGE;
        return KSEC_ERR_INVALID;
    }
    result = ksec_status(client, &flags);
    if (result != KSEC_OK) return result;
    if ((flags & ~known) != 0U) return KSEC_ERR_PROTOCOL;
    written = snprintf(line, sizeof line,
                       "initialized=%s recovery_confirmed=%s unlocked=%s\n",
                       (flags & KSEC_STATUS_INITIALIZED) != 0U ? "yes" : "no",
                       (flags & KSEC_STATUS_RECOVERY_CONFIRMED) != 0U ? "yes" : "no",
                       (flags & KSEC_STATUS_UNLOCKED) != 0U ? "yes" : "no");
    if (written < 0 || (size_t)written >= sizeof line
            || ksec_write_all(STDOUT_FILENO, line, (size_t)written) != 0) {
        return KSEC_ERR_IO;
    }
    return KSEC_OK;
}

static int worker_command(const cli_request *request, int capability_fd) {
    const char *command = request->argv[0];
    ksec_client *client = NULL;
    ksec_result result = ksec_connect_at(&client, request->socket_path, capability_fd);
    int failure = CLI_FAIL_NONE;
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
        result = command_add(request, client, &failure);
    } else if (strcmp(command, "replace") == 0) {
        result = command_replace(request, client, &failure);
    } else if (strcmp(command, "get") == 0) {
        result = command_get(request, client, &failure);
    } else if (strcmp(command, "dataset-create") == 0) {
        result = command_dataset_create(request, client, &failure);
    } else if (strcmp(command, "seal") == 0) {
        result = command_seal(request, client, &failure, false);
    } else if (strcmp(command, "unseal") == 0) {
        result = command_seal(request, client, &failure, true);
    } else if (strcmp(command, "status") == 0) {
        result = command_status(request, client, &failure);
    } else if (strcmp(command, "copy") == 0
            && (request->argc == 3 || request->argc == 5)) {
        uint8_t id[KSEC_RECORD_ID_BYTES];
        unsigned int clear_seconds = 30U;
        if (request->argc == 5
                && (strcmp(request->argv[3], "--clear-seconds") != 0
                    || parse_seconds(request->argv[4], &clear_seconds) != 0)) {
            result = KSEC_ERR_INVALID;
        } else if (ksec_hex_decode(request->argv[1], id, sizeof id) != 0) {
            result = KSEC_ERR_INVALID;
        } else {
            result = copy_to_clipboard(client, id, request->argv[2],
                                       clear_seconds);
        }
        sodium_memzero(id, sizeof id);
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
                (void)signal(SIGPIPE, SIG_DFL);
                execvp(request->argv[4], request->argv + 4);
                result = KSEC_ERR_IO;
            }
        }
        if (secret_fd >= 0) (void)close(secret_fd);
        sodium_memzero(id, sizeof id);
    } else if (strcmp(command, "list") == 0 && request->argc == 1) {
        result = ksec_list_to_fd(client, STDOUT_FILENO);
    } else if (strcmp(command, "show") == 0 && request->argc == 2) {
        uint8_t id[KSEC_RECORD_ID_BYTES];
        if (ksec_hex_decode(request->argv[1], id, sizeof id) != 0) {
            result = KSEC_ERR_INVALID;
        } else {
            result = ksec_show_to_fd(client, id, STDOUT_FILENO);
        }
        sodium_memzero(id, sizeof id);
    } else if (strcmp(command, "grant") == 0 && request->argc == 5
            && strcmp(request->argv[3], "--verbs") == 0) {
        uint8_t id[KSEC_RECORD_ID_BYTES];
        uint32_t verbs = 0U;
        if (ksec_hex_decode(request->argv[1], id, sizeof id) != 0
                || parse_grant_verbs(request->argv[4], &verbs) != 0) {
            result = KSEC_ERR_INVALID;
        } else {
            result = ksec_grant_record(client, id, request->argv[2], verbs);
        }
        sodium_memzero(id, sizeof id);
    } else if (strcmp(command, "revoke") == 0 && request->argc == 3) {
        uint8_t id[KSEC_RECORD_ID_BYTES];
        if (ksec_hex_decode(request->argv[1], id, sizeof id) != 0) {
            result = KSEC_ERR_INVALID;
        } else {
            result = ksec_revoke_record(client, id, request->argv[2]);
        }
        sodium_memzero(id, sizeof id);
    } else if (strcmp(command, "delete") == 0 && request->argc == 4
            && strcmp(request->argv[2], "--confirm") == 0) {
        uint8_t id[KSEC_RECORD_ID_BYTES];
        uint8_t confirmation[KSEC_RECORD_ID_BYTES];
        if (ksec_hex_decode(request->argv[1], id, sizeof id) != 0
                || ksec_hex_decode(request->argv[3], confirmation,
                                   sizeof confirmation) != 0
                || !ksec_safe_equal(id, confirmation, sizeof id)) {
            result = KSEC_ERR_INVALID;
        } else {
            result = ksec_delete(client, id);
        }
        sodium_memzero(id, sizeof id);
        sodium_memzero(confirmation, sizeof confirmation);
    } else if (strcmp(command, "rotate") == 0) {
        int passphrase_fd = -1;
        int recovery_fd = -1;
        int index;
        for (index = 1; index < request->argc; index++) {
            if (index + 1 < request->argc
                    && strcmp(request->argv[index], "--passphrase-fd") == 0
                    && passphrase_fd < 0) {
                if (parse_fd(request->argv[++index], &passphrase_fd) != 0) {
                    result = KSEC_ERR_INVALID;
                    goto rotate_out;
                }
            } else if (index + 1 < request->argc
                    && strcmp(request->argv[index], "--recovery-fd") == 0
                    && recovery_fd < 0) {
                if (parse_fd(request->argv[++index], &recovery_fd) != 0) {
                    result = KSEC_ERR_INVALID;
                    goto rotate_out;
                }
            } else {
                result = KSEC_ERR_INVALID;
                goto rotate_out;
            }
        }
        if (passphrase_fd < 0) {
            passphrase_fd = prompt_secret_fd("Current passphrase: ", 8U);
        }
        if (recovery_fd < 0) {
            recovery_fd = prompt_secret_fd("Recovery secret: ", 64U);
        }
        if (passphrase_fd < 0 || recovery_fd < 0) result = KSEC_ERR_INVALID;
        else result = ksec_rotate_master(client, passphrase_fd, recovery_fd);
rotate_out:
        if (passphrase_fd > STDERR_FILENO) (void)close(passphrase_fd);
        if (recovery_fd > STDERR_FILENO) (void)close(recovery_fd);
        if (result == KSEC_OK) {
            static const char notice[] =
                "Master key rotated; the prior encrypted generation is retained for explicit recovery.\n";
            (void)ksec_write_all(STDERR_FILENO, notice, sizeof notice - 1U);
        }
    } else if (strcmp(command, "export") == 0) {
        const char *output_path = NULL;
        int secret_fd = -1;
        int output_fd = -1;
        int index;
        for (index = 1; index < request->argc; index++) {
            if (index + 1 < request->argc
                    && strcmp(request->argv[index], "--output") == 0
                    && output_path == NULL) {
                output_path = request->argv[++index];
            } else if (index + 1 < request->argc
                    && strcmp(request->argv[index], "--secret-fd") == 0
                    && secret_fd < 0) {
                if (parse_fd(request->argv[++index], &secret_fd) != 0) {
                    result = KSEC_ERR_INVALID;
                    goto export_out;
                }
            } else {
                result = KSEC_ERR_INVALID;
                goto export_out;
            }
        }
        if (output_path == NULL || output_path[0] == '\0') {
            result = KSEC_ERR_INVALID;
            goto export_out;
        }
        output_fd = open(output_path,
                         O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                         0600);
        if (output_fd < 0) {
            result = errno == EEXIST ? KSEC_ERR_EXISTS : KSEC_ERR_IO;
            goto export_out;
        }
        if (secret_fd < 0) {
            secret_fd = prompt_secret_fd(
                    "Backup passphrase or recovery secret: ", 8U);
        }
        if (secret_fd < 0) result = KSEC_ERR_INVALID;
        else result = ksec_export_backup(client, secret_fd, output_fd);
export_out:
        if (result != KSEC_OK && output_fd >= 0) {
            unlink_exact_created_file(output_path, output_fd);
        }
        if (output_fd >= 0 && close(output_fd) != 0 && result == KSEC_OK) {
            result = KSEC_ERR_IO;
        }
        if (secret_fd > STDERR_FILENO) (void)close(secret_fd);
        if (result == KSEC_OK) {
            static const char notice[] =
                "Encrypted backup created; its passphrase or recovery secret is required for restore.\n";
            (void)ksec_write_all(STDERR_FILENO, notice, sizeof notice - 1U);
        }
    } else if (strcmp(command, "import") == 0) {
        const char *input_path = NULL;
        int secret_fd = -1;
        int input_fd = -1;
        int index;
        for (index = 1; index < request->argc; index++) {
            if (index + 1 < request->argc
                    && strcmp(request->argv[index], "--input") == 0
                    && input_path == NULL) {
                input_path = request->argv[++index];
            } else if (index + 1 < request->argc
                    && strcmp(request->argv[index], "--secret-fd") == 0
                    && secret_fd < 0) {
                if (parse_fd(request->argv[++index], &secret_fd) != 0) {
                    result = KSEC_ERR_INVALID;
                    goto import_out;
                }
            } else {
                result = KSEC_ERR_INVALID;
                goto import_out;
            }
        }
        if (input_path == NULL || input_path[0] == '\0') {
            result = KSEC_ERR_INVALID;
            goto import_out;
        }
        input_fd = open(input_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (input_fd < 0) {
            result = KSEC_ERR_IO;
            goto import_out;
        }
        if (secret_fd < 0) {
            secret_fd = prompt_secret_fd(
                    "Backup passphrase or recovery secret: ", 8U);
        }
        if (secret_fd < 0) result = KSEC_ERR_INVALID;
        else result = ksec_import_backup(client, secret_fd, input_fd);
import_out:
        if (input_fd >= 0) (void)close(input_fd);
        if (secret_fd > STDERR_FILENO) (void)close(secret_fd);
        if (result == KSEC_OK) {
            static const char notice[] =
                "Backup restored and vault locked. Restoring an older valid backup is an explicit rollback; portable storage has no trusted rollback counter.\n";
            (void)ksec_write_all(STDERR_FILENO, notice, sizeof notice - 1U);
        }
    } else if (strcmp(command, "reset") == 0) {
        const char *confirmation = NULL;
        int secret_fd = -1;
        int recovery_fd = -1;
        int index;
        for (index = 1; index < request->argc; index++) {
            if (index + 1 < request->argc
                    && strcmp(request->argv[index], "--confirm") == 0
                    && confirmation == NULL) {
                confirmation = request->argv[++index];
            } else if (index + 1 < request->argc
                    && strcmp(request->argv[index], "--secret-fd") == 0
                    && secret_fd < 0) {
                if (parse_fd(request->argv[++index], &secret_fd) != 0) {
                    result = KSEC_ERR_INVALID;
                    goto reset_out;
                }
            } else if (index + 1 < request->argc
                    && strcmp(request->argv[index], "--recovery-fd") == 0
                    && recovery_fd < 0) {
                if (parse_fd(request->argv[++index], &recovery_fd) != 0) {
                    result = KSEC_ERR_INVALID;
                    goto reset_out;
                }
            } else {
                result = KSEC_ERR_INVALID;
                goto reset_out;
            }
        }
        if (confirmation == NULL
                || strcmp(confirmation, KSEC_RESET_CONFIRMATION) != 0) {
            result = KSEC_ERR_INVALID;
            goto reset_out;
        }
        if (secret_fd < 0) {
            secret_fd = prompt_secret_fd("New vault passphrase: ", 8U);
        }
        if (recovery_fd < 0) {
            recovery_fd = open("/dev/tty", O_WRONLY | O_CLOEXEC | O_NOCTTY);
            if (recovery_fd >= 0) {
                static const char warning[] =
                    "New recovery secret (record it offline; reset loses the prior identity):\n";
                if (ksec_write_all(recovery_fd, warning,
                                   sizeof warning - 1U) != 0) {
                    (void)close(recovery_fd);
                    recovery_fd = -1;
                }
            }
        }
        if (secret_fd < 0 || recovery_fd < 0) result = KSEC_ERR_INVALID;
        else {
            result = ksec_reset_vault(client, confirmation, secret_fd,
                                      recovery_fd);
            if (result == KSEC_OK
                    && ksec_write_all(recovery_fd, "\n", 1U) != 0) {
                result = KSEC_ERR_IO;
            }
        }
reset_out:
        if (secret_fd > STDERR_FILENO) (void)close(secret_fd);
        if (recovery_fd > STDERR_FILENO) (void)close(recovery_fd);
        if (result == KSEC_OK) {
            static const char notice[] =
                "Vault reset created a new identity and retained the displaced encrypted vault. All peers require revocation or re-pairing. The new vault remains locked until recovery confirmation.\n";
            (void)ksec_write_all(STDERR_FILENO, notice,
                                 sizeof notice - 1U);
        }
    } else if (strcmp(command, "compact") == 0 && request->argc == 1) {
        result = ksec_compact(client);
    } else if (strcmp(command, "doctor") == 0 && request->argc == 1) {
        result = ksec_doctor_to_fd(client, STDOUT_FILENO);
    } else {
        result = KSEC_ERR_INVALID;
    }
    if (failure == CLI_FAIL_USAGE) {
        usage(stderr);
        ksec_client_free(client);
        return 2;
    }
    if (failure == CLI_FAIL_TERMINAL) {
        static const char message[] =
            "kilix-secrets: refusing to write to a terminal\n";
        (void)ksec_write_all(STDERR_FILENO, message, sizeof message - 1U);
        ksec_client_free(client);
        return 1;
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
    if (ksec_crypto_initialize() != KSEC_OK || signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        return 1;
    }
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
