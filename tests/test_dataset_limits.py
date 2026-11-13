#!/usr/bin/env python3
"""Sealed-dataset size, memory and responsiveness limits.

Private daemon, same shape as tests/test_integration.py. A 64 MiB seal and
unseal must keep the daemon's RssAnon growth within 8 MiB. One byte past
either size limit must fail with KSEC_ERR_LIMIT. The client calls are a small
driver compiled from the public API into TEST_TMPDIR.
"""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import secrets
import select
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time


KSEC_OK = 0
KSEC_ERR_LIMIT = 6
APP_ID = "kilix-secrets.test"
DATASET_LABEL = "ledger-key"
DATASET_NAME = "ledger"
# docs/SEALED-DATASETS.md section 4. k = ceil(67108864 / 65536) = 1024.
# This dataset: 92 + 18 + 6 + 67108864 + 17 * 1024 = 67126388.
# Maximum sealed file (64-byte owner, 128-byte name):
# 92 + 64 + 128 + 67108864 + 17 * 1024 = 67126556.
PLAINTEXT_BYTES = 67108864
SEALED_BYTES = 67126388
MAX_SEALED_BYTES = 67126556
OVER_SEALED_BYTES = 67126557
REVISION = 0x0102030405060708
RSS_BOUND_KIB = 8192
STATUS_BOUND_SECONDS = 5.0
# Byte at offset i is (i * 131 + 17) mod 256. These three are literals.
BYTE_AT_0 = 17
BYTE_AT_1000 = 201
BYTE_AT_LAST = 142
CYCLE = bytes(((index * 131 + 17) & 0xFF) for index in range(256))
BLOCK = CYCLE * 256


DRIVER_SOURCE = r"""
#define _GNU_SOURCE

#include "kilix_secrets.h"

#include <sodium.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

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
    if (count != 1 || marker != 'C' || (message.msg_flags & MSG_CTRUNC) != 0) {
        return -1;
    }
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

static int hex_nibble(char ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

static int hex_decode_16(const char *text, uint8_t out[KSEC_RECORD_ID_BYTES]) {
    size_t index;
    if (text == NULL || strlen(text) != KSEC_RECORD_ID_BYTES * 2U) return -1;
    for (index = 0; index < KSEC_RECORD_ID_BYTES; index++) {
        int high = hex_nibble(text[index * 2U]);
        int low = hex_nibble(text[index * 2U + 1U]);
        if (high < 0 || low < 0) return -1;
        out[index] = (uint8_t)(((unsigned int)high << 4) | (unsigned int)low);
    }
    return 0;
}

static void hex_encode_16(const uint8_t in[KSEC_RECORD_ID_BYTES], char out[33]) {
    static const char digits[] = "0123456789abcdef";
    size_t index;
    for (index = 0; index < KSEC_RECORD_ID_BYTES; index++) {
        out[index * 2U] = digits[in[index] >> 4];
        out[index * 2U + 1U] = digits[in[index] & 0x0fU];
    }
    out[32] = '\0';
}

static int parse_u64(const char *text, uint64_t *out) {
    char *end = NULL;
    unsigned long long value;
    errno = 0;
    value = strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0') return -1;
    *out = (uint64_t)value;
    return 0;
}

static double elapsed_since(const struct timespec *start) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1.0;
    return (double)(now.tv_sec - start->tv_sec)
        + (double)(now.tv_nsec - start->tv_nsec) / 1000000000.0;
}

static void emit_result(ksec_result code, double seconds, uint64_t revision,
                        uint32_t flags, const char *record_hex) {
    printf("RESULT %d %.6f %" PRIu64 " %" PRIu32 " %s\n",
           (int)code, seconds, revision, flags,
           record_hex != NULL ? record_hex : "-");
    fflush(stdout);
}

static int fail_setup(ksec_client *client, const char *what) {
    printf("SETUP %s\n", what);
    fflush(stdout);
    ksec_client_free(client);
    return 2;
}

static int open_pair(const char *input, const char *output,
                     int *in_fd, int *out_fd) {
    *in_fd = open(input, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (*in_fd < 0) return -1;
    *out_fd = open(output, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                   0600);
    if (*out_fd < 0) {
        (void)close(*in_fd);
        *in_fd = -1;
        return -1;
    }
    return 0;
}

static int worker(const char *socket_path, const char *op, int argc,
                  char **argv, int capability_fd) {
    ksec_client *client = NULL;
    ksec_result result = ksec_connect_at(&client, socket_path, capability_fd);
    struct timespec started;
    if (result != KSEC_OK) {
        emit_result(result, 0.0, 0U, 0U, NULL);
        return 0;
    }
    if (strcmp(op, "doctor") == 0 && argc == 4) {
        int sink = open("/dev/null", O_WRONLY | O_CLOEXEC);
        if (sink < 0) return fail_setup(client, "doctor-sink");
        if (clock_gettime(CLOCK_MONOTONIC, &started) != 0) {
            (void)close(sink);
            return fail_setup(client, "clock");
        }
        result = ksec_doctor_to_fd(client, sink);
        (void)close(sink);
        emit_result(result, elapsed_since(&started), 0U, 0U, NULL);
        ksec_client_free(client);
        return 0;
    }
    if (strcmp(op, "create") == 0 && argc == 5) {
        uint8_t record_id[KSEC_RECORD_ID_BYTES];
        char rendered[33];
        memset(record_id, 0, sizeof record_id);
        if (clock_gettime(CLOCK_MONOTONIC, &started) != 0) {
            return fail_setup(client, "clock");
        }
        result = ksec_dataset_create(client, argv[4], record_id);
        hex_encode_16(record_id, rendered);
        emit_result(result, elapsed_since(&started), 0U, 0U,
                    result == KSEC_OK ? rendered : NULL);
        sodium_memzero(record_id, sizeof record_id);
        ksec_client_free(client);
        return 0;
    }
    if (strcmp(op, "seal") == 0 && argc == 9) {
        uint8_t record_id[KSEC_RECORD_ID_BYTES];
        uint64_t revision = 0U;
        int in_fd = -1;
        int out_fd = -1;
        if (hex_decode_16(argv[4], record_id) != 0
                || parse_u64(argv[6], &revision) != 0) {
            sodium_memzero(record_id, sizeof record_id);
            return fail_setup(client, "seal-args");
        }
        if (open_pair(argv[7], argv[8], &in_fd, &out_fd) != 0) {
            sodium_memzero(record_id, sizeof record_id);
            return fail_setup(client, "seal-open");
        }
        printf("SEALING\n");
        fflush(stdout);
        if (clock_gettime(CLOCK_MONOTONIC, &started) != 0) {
            (void)close(in_fd);
            (void)close(out_fd);
            sodium_memzero(record_id, sizeof record_id);
            return fail_setup(client, "clock");
        }
        result = ksec_seal_fd(client, record_id, argv[5], revision, in_fd, out_fd);
        (void)close(in_fd);
        (void)close(out_fd);
        emit_result(result, elapsed_since(&started), 0U, 0U, NULL);
        sodium_memzero(record_id, sizeof record_id);
        ksec_client_free(client);
        return 0;
    }
    if (strcmp(op, "unseal") == 0 && argc == 8) {
        uint8_t record_id[KSEC_RECORD_ID_BYTES];
        uint64_t revision = 0U;
        int in_fd = -1;
        int out_fd = -1;
        if (hex_decode_16(argv[4], record_id) != 0) {
            sodium_memzero(record_id, sizeof record_id);
            return fail_setup(client, "unseal-args");
        }
        if (open_pair(argv[6], argv[7], &in_fd, &out_fd) != 0) {
            sodium_memzero(record_id, sizeof record_id);
            return fail_setup(client, "unseal-open");
        }
        if (clock_gettime(CLOCK_MONOTONIC, &started) != 0) {
            (void)close(in_fd);
            (void)close(out_fd);
            sodium_memzero(record_id, sizeof record_id);
            return fail_setup(client, "clock");
        }
        result = ksec_unseal_fd(client, record_id, argv[5], in_fd, out_fd,
                                &revision);
        (void)close(in_fd);
        (void)close(out_fd);
        emit_result(result, elapsed_since(&started), revision, 0U, NULL);
        sodium_memzero(record_id, sizeof record_id);
        ksec_client_free(client);
        return 0;
    }
    if (strcmp(op, "status") == 0 && argc == 4) {
        uint32_t flags = 0U;
        char go = 0;
        ssize_t count;
        printf("READY\n");
        fflush(stdout);
        do {
            count = read(STDIN_FILENO, &go, 1);
        } while (count < 0 && errno == EINTR);
        if (count != 1) return fail_setup(client, "status-go");
        if (clock_gettime(CLOCK_MONOTONIC, &started) != 0) {
            return fail_setup(client, "clock");
        }
        result = ksec_status(client, &flags);
        emit_result(result, elapsed_since(&started), 0U, flags, NULL);
        ksec_client_free(client);
        return 0;
    }
    return fail_setup(client, "op");
}

static uint32_t verbs_for(const char *op) {
    if (strcmp(op, "create") == 0) return KSEC_VERB_CREATE;
    if (strcmp(op, "seal") == 0 || strcmp(op, "unseal") == 0) return KSEC_VERB_USE;
    if (strcmp(op, "doctor") == 0 || strcmp(op, "status") == 0) {
        return KSEC_VERB_DOCTOR;
    }
    return 0U;
}

static int expected_argc(const char *op) {
    if (strcmp(op, "doctor") == 0 || strcmp(op, "status") == 0) return 4;
    if (strcmp(op, "create") == 0) return 5;
    if (strcmp(op, "unseal") == 0) return 8;
    if (strcmp(op, "seal") == 0) return 9;
    return -1;
}

int main(int argc, char **argv) {
    int control[2] = {-1, -1};
    pid_t child;
    int wait_status = 0;
    uint32_t verbs;
    if (argc < 4 || expected_argc(argv[3]) != argc) return 2;
    verbs = verbs_for(argv[3]);
    if (verbs == 0U || sodium_init() < 0
            || signal(SIGPIPE, SIG_IGN) == SIG_ERR) return 2;
    /* Unbuffered, so the parent test sees SEALING and READY immediately.
     * The child _exit avoids running libsodium atexit handlers twice. */
    if (setvbuf(stdout, NULL, _IONBF, 0) != 0) return 2;
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, control) != 0) {
        return 2;
    }
    child = fork();
    if (child < 0) {
        (void)close(control[0]);
        (void)close(control[1]);
        return 2;
    }
    if (child == 0) {
        int capability_fd;
        int code;
        (void)close(control[0]);
        capability_fd = receive_fd(control[1]);
        (void)close(control[1]);
        if (capability_fd < 0) {
            printf("SETUP receive\n");
            fflush(stdout);
            _exit(2);
        }
        code = worker(argv[2], argv[3], argc, argv, capability_fd);
        _exit(code);
    }
    (void)close(control[1]);
    {
        int capability_fd = -1;
        ksec_result result = ksec_supervisor_mint(argv[2], child, argv[1], verbs,
                                                  300U, &capability_fd);
        if (result != KSEC_OK || capability_fd < 0
                || send_fd(control[0], capability_fd) != 0) {
            printf("SETUP mint %d\n", (int)result);
            fflush(stdout);
            (void)kill(child, SIGTERM);
            if (capability_fd >= 0) (void)close(capability_fd);
            (void)close(control[0]);
            (void)waitpid(child, &wait_status, 0);
            return 2;
        }
        (void)close(capability_fd);
    }
    (void)close(control[0]);
    if (waitpid(child, &wait_status, 0) != child) return 1;
    if (WIFEXITED(wait_status)) return WEXITSTATUS(wait_status);
    if (WIFSIGNALED(wait_status)) return 128 + WTERMSIG(wait_status);
    return 1;
}
"""


class Checks:
    def __init__(self) -> None:
        self.total = 0
        self.failed = 0

    def check(self, condition: bool, message: str) -> None:
        self.total += 1
        if not condition:
            self.failed += 1
            print(f"FAIL dataset-limits: {message}", file=sys.stderr)


def secret_pipe(value: bytes) -> int:
    read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
    try:
        offset = 0
        while offset < len(value):
            offset += os.write(write_fd, value[offset:])
    finally:
        os.close(write_fd)
    return read_fd


def run_cli(cli: Path, socket_path: Path, app_id: str, arguments: list[str],
            input_value: bytes | None = None,
            environment: dict[str, str] | None = None) -> subprocess.CompletedProcess[bytes]:
    descriptor = -1
    command = [str(cli), "--socket", str(socket_path), "--app", app_id, *arguments]
    pass_fds: tuple[int, ...] = ()
    if input_value is not None:
        descriptor = secret_pipe(input_value)
        command.extend(["--secret-fd", str(descriptor)])
        pass_fds = (descriptor,)
    try:
        return subprocess.run(command, check=False, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, pass_fds=pass_fds,
                              timeout=90, env=environment)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def run_init(cli: Path, socket_path: Path, app_id: str,
             passphrase: bytes) -> tuple[subprocess.CompletedProcess[bytes], bytes]:
    secret_fd = secret_pipe(passphrase)
    recovery_read, recovery_write = os.pipe2(os.O_CLOEXEC)
    command = [str(cli), "--socket", str(socket_path), "--app", app_id, "init",
               "--secret-fd", str(secret_fd), "--recovery-fd", str(recovery_write)]
    try:
        completed = subprocess.run(command, check=False, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE,
                                   pass_fds=(secret_fd, recovery_write), timeout=90)
    finally:
        os.close(secret_fd)
        os.close(recovery_write)
    chunks: list[bytes] = []
    while True:
        chunk = os.read(recovery_read, 256)
        if not chunk:
            break
        chunks.append(chunk)
    os.close(recovery_read)
    return completed, b"".join(chunks).strip()


def wait_for_socket(socket_path: Path, process: subprocess.Popen[bytes]) -> bool:
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return False
        try:
            status = socket_path.lstat()
        except FileNotFoundError:
            time.sleep(0.02)
            continue
        if stat.S_ISSOCK(status.st_mode):
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            try:
                probe.connect(str(socket_path))
                return True
            except (ConnectionRefusedError, FileNotFoundError):
                pass
            finally:
                probe.close()
        time.sleep(0.02)
    return False


def start_daemon(daemon: Path, socket_path: Path,
                 data_dir: Path) -> subprocess.Popen[bytes]:
    process = subprocess.Popen(
        [str(daemon), "--socket", str(socket_path), "--data-dir", str(data_dir),
         "--development-kdf-ops", "3", "--development-kdf-mem-mib", "256",
         "--idle-seconds", "300"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE, close_fds=True,
    )
    if not wait_for_socket(socket_path, process):
        process.kill()
        process.wait(timeout=5)
        error = process.stderr.read() if process.stderr is not None else b""
        raise RuntimeError(f"daemon did not create socket (stderr bytes={len(error)})")
    return process


def stop_daemon(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    if process.stderr is not None:
        process.stderr.close()


def status_operation_exists(repository: Path) -> bool:
    text = (repository / "src" / "client.c").read_text(encoding="utf-8")
    start = text.find("ksec_result ksec_status(")
    if start < 0:
        return False
    return "PLACEHOLDER (lane L3)" not in text[start:start + 600]


def needs_sanitizer(library: Path) -> bool:
    return b"libasan.so" in library.read_bytes()


def compile_driver(build_dir: Path, repository: Path, root: Path) -> Path:
    source = root / "dataset-limits-driver.c"
    binary = root / "dataset-limits-driver"
    source.write_text(DRIVER_SOURCE, encoding="utf-8")
    cflags = subprocess.run(["pkg-config", "--cflags", "libsodium"],
                            check=True, capture_output=True, text=True).stdout.split()
    libs = subprocess.run(["pkg-config", "--libs", "libsodium"],
                          check=True, capture_output=True, text=True).stdout.split()
    sanitize = needs_sanitizer(build_dir / "libkilix-secrets.so.0")
    sanitize_flags = (["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
                      if sanitize else [])
    command = [
        os.environ.get("CC", "cc"), "-std=c11", "-O1", "-g",
        "-Wall", "-Wextra", "-Wpedantic", "-Wconversion", "-Wshadow",
        "-Wstrict-prototypes", "-Wmissing-prototypes", "-Wformat=2", "-Werror",
        *sanitize_flags, *cflags, f"-I{repository / 'include'}",
        "-o", str(binary), str(source), str(build_dir / "libkilix-secrets.a"),
        *libs, *sanitize_flags,
    ]
    completed = subprocess.run(command, check=False, capture_output=True, text=True)
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise RuntimeError(f"driver compile failed: {detail[-1200:]}")
    binary.chmod(0o700)
    return binary


def rss_anon_kib(pid: int) -> int:
    for line in Path(f"/proc/{pid}/status").read_text(encoding="ascii").splitlines():
        if line.startswith("RssAnon:"):
            return int(line.split()[1])
    raise RuntimeError(f"RssAnon missing for pid {pid}")


class RssSampler:
    def __init__(self, pid: int) -> None:
        self.pid = pid
        self.max_kib = -1
        self.stop = threading.Event()
        self.error = ""
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        while not self.stop.is_set():
            try:
                value = rss_anon_kib(self.pid)
            except OSError as error:
                self.error = str(error)
                return
            if value > self.max_kib:
                self.max_kib = value
            self.stop.wait(0.02)

    def start(self) -> None:
        self.max_kib = rss_anon_kib(self.pid)
        self.thread.start()

    def finish(self) -> int:
        self.stop.set()
        self.thread.join(timeout=2)
        try:
            value = rss_anon_kib(self.pid)
        except OSError as error:
            self.error = str(error)
            return self.max_kib
        return max(self.max_kib, value)


def _drain(pipe: object, dest: bytearray) -> None:
    try:
        while True:
            chunk = pipe.read(4096)  # type: ignore[attr-defined]
            if not chunk:
                break
            dest.extend(chunk)
            if len(dest) > 131072:
                del dest[:65536]
    except (OSError, ValueError):
        return


class LineReader:
    def __init__(self, proc: subprocess.Popen[bytes]) -> None:
        if proc.stdout is None:
            raise RuntimeError("driver stdout is not a pipe")
        self.fd = proc.stdout.fileno()
        self.pending = bytearray()

    def readline(self, timeout: float) -> str | None:
        deadline = time.monotonic() + timeout
        while True:
            newline = self.pending.find(b"\n")
            if newline >= 0:
                line = self.pending[:newline]
                del self.pending[:newline + 1]
                return line.decode("ascii", errors="replace")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            try:
                ready, _, _ = select.select([self.fd], [], [], remaining)
            except InterruptedError:
                continue
            if not ready:
                return None
            try:
                chunk = os.read(self.fd, 4096)
            except InterruptedError:
                continue
            if not chunk:
                if not self.pending:
                    return None
                line = bytes(self.pending)
                self.pending.clear()
                return line.decode("ascii", errors="replace")
            self.pending.extend(chunk)


class Client:
    def __init__(self, proc: subprocess.Popen[bytes]) -> None:
        self.proc = proc
        self.reader = LineReader(proc)
        self.stderr_buf = bytearray()
        self.stderr_thread = threading.Thread(
            target=_drain, args=(proc.stderr, self.stderr_buf), daemon=True)
        self.stderr_thread.start()
        self.lines: list[str] = []
        self.finished = False
        self.saved = (-1, "")

    def wait_for(self, timeout: float, predicate) -> str | None:
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            line = self.reader.readline(remaining)
            if line is None:
                return None
            self.lines.append(line)
            if predicate(line):
                return line

    def kill(self) -> None:
        if self.proc.poll() is not None:
            return
        try:
            os.killpg(self.proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        try:
            self.proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(self.proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            self.proc.wait(timeout=5)

    def finish(self, timeout: float) -> tuple[int, str]:
        if self.finished:
            return self.saved
        self.finished = True
        try:
            self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.kill()
        if self.proc.stdin is not None and not self.proc.stdin.closed:
            self.proc.stdin.close()
        self.stderr_thread.join(timeout=2)
        code = self.proc.returncode if self.proc.returncode is not None else -1
        self.saved = (code, self.stderr_buf.decode("utf-8", errors="replace"))
        return self.saved


def start_client(binary: Path, socket_path: Path, args: list[str],
                 feed_stdin: bool) -> Client:
    proc = subprocess.Popen(
        [str(binary), APP_ID, str(socket_path), *args],
        stdin=subprocess.PIPE if feed_stdin else subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        bufsize=0, start_new_session=True, close_fds=True,
    )
    return Client(proc)


def parse_result(line: str | None) -> tuple[int, float, int, int, str] | None:
    if line is None:
        return None
    parts = line.split()
    if len(parts) != 6 or parts[0] != "RESULT":
        return None
    try:
        return (int(parts[1]), float(parts[2]), int(parts[3]),
                int(parts[4]), parts[5])
    except ValueError:
        return None


def tail(text: str, limit: int = 600) -> str:
    text = " ".join(text.split())
    if len(text) <= limit:
        return text
    return text[-limit:]


def call_client(binary: Path, socket_path: Path, args: list[str],
                timeout: float) -> tuple[tuple[int, float, int, int, str] | None, int, str, list[str]]:
    client = start_client(binary, socket_path, args, False)
    line = client.wait_for(
        timeout, lambda item: item.startswith("RESULT") or item.startswith("SETUP"))
    code, stderr = client.finish(10)
    parsed = parse_result(line)
    return parsed, code, stderr, client.lines


def write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        wrote = os.write(fd, view)
        if wrote <= 0:
            raise OSError("short write")
        view = view[wrote:]


def write_plaintext(path: Path) -> str:
    digest = hashlib.sha256()
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC, 0o600)
    try:
        for _ in range(PLAINTEXT_BYTES // len(BLOCK)):
            write_all(fd, BLOCK)
            digest.update(BLOCK)
    finally:
        os.close(fd)
    return digest.hexdigest()


def sparse_file(path: Path, size: int) -> None:
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC, 0o600)
    try:
        os.ftruncate(fd, size)
    finally:
        os.close(fd)


def file_size(path: Path) -> int:
    if not path.is_file() or path.is_symlink():
        return -1
    return path.stat().st_size


def read_byte(path: Path, offset: int) -> int:
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        os.lseek(fd, offset, os.SEEK_SET)
        data = os.read(fd, 1)
    finally:
        os.close(fd)
    if len(data) != 1:
        raise OSError(f"short read at {offset}")
    return data[0]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def remove_tree(root: Path, scratch: Path, checks: Checks) -> None:
    resolved = root.resolve()
    parent = scratch.resolve()
    if resolved.parent == parent and resolved.name.startswith("k7."):
        shutil.rmtree(resolved)
    else:
        checks.check(False, "refused unsafe dataset-limits cleanup path")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-dir", required=True)
    options = parser.parse_args()
    build_dir = Path(options.build_dir).resolve()
    repository = Path(__file__).resolve().parent.parent
    daemon = build_dir / "kilix-secretsd"
    cli = build_dir / "kilix-secrets"
    scratch = Path(os.environ.get("TMPDIR", ""))
    checks = Checks()
    checks.check(scratch.is_absolute() and scratch.is_dir() and not scratch.is_symlink(),
                 "TMPDIR is an absolute, existing, non-symlink directory")
    checks.check(len(APP_ID) == 18 and len(DATASET_NAME) == 6
                 and CYCLE[0] == BYTE_AT_0
                 and CYCLE[1000 % 256] == BYTE_AT_1000
                 and CYCLE[(PLAINTEXT_BYTES - 1) % 256] == BYTE_AT_LAST,
                 "fixture names and pattern bytes match the literals")
    root = Path(tempfile.mkdtemp(prefix="k7.", dir=scratch))
    runtime = root / "runtime"
    socket_path = runtime / "kilix-secrets" / "control.sock"
    data_dir = root / "data"
    runtime.mkdir(mode=0o700)
    process: subprocess.Popen[bytes] | None = None
    daemon_stderr = bytearray()
    daemon_thread: threading.Thread | None = None
    passphrase = bytearray(secrets.token_bytes(32))
    recovery = bytearray()
    seal_seconds = -1.0
    unseal_seconds = -1.0
    status_text = "not run"
    rss_delta = -1
    clients: list[Client] = []
    try:
        binary = compile_driver(build_dir, repository, root)
        checks.check(binary.is_file(), "limits driver compiles from the public API")
        process = start_daemon(daemon, socket_path, data_dir)
        if process.stderr is not None:
            daemon_thread = threading.Thread(
                target=_drain, args=(process.stderr, daemon_stderr), daemon=True)
            daemon_thread.start()
        checks.check(process.poll() is None, "daemon remains running")
        initialized, rendered = run_init(cli, socket_path, APP_ID, bytes(passphrase))
        recovery.extend(rendered)
        checks.check(initialized.returncode == 0, "initialization succeeds")
        checks.check(len(recovery) == 64 and all(chr(byte) in "0123456789abcdef"
                                                 for byte in recovery),
                     "initialization returns one 64-byte recovery rendering")
        confirmed = run_cli(cli, socket_path, APP_ID, ["unlock", "--recovery"],
                            bytes(recovery))
        checks.check(confirmed.returncode == 0,
                     "recovery re-entry confirms custody and unlocks")

        doctor, doctor_code, doctor_err, _ = call_client(
            binary, socket_path, ["doctor"], 30)
        checks.check(doctor is not None and doctor_code == 0 and doctor[0] == KSEC_OK,
                     "activated capability reaches doctor "
                     f"(exit={doctor_code} line={doctor} {tail(doctor_err)})")

        created, create_code, create_err, _ = call_client(
            binary, socket_path, ["create", DATASET_LABEL], 30)
        record_hex = created[4] if created is not None else ""
        checks.check(created is not None and create_code == 0 and created[0] == KSEC_OK
                     and len(record_hex) == 32
                     and all(character in "0123456789abcdef" for character in record_hex),
                     "dataset create returns one 16-byte record id "
                     f"(exit={create_code} line={created} {tail(create_err)})")
        created_ok = (created is not None and create_code == 0 and created[0] == KSEC_OK
                      and len(record_hex) == 32
                      and all(character in "0123456789abcdef" for character in record_hex))
        if created_ok:
            plain = root / "plain.bin"
            sealed = root / "sealed.bin"
            unsealed = root / "unsealed.bin"
            plain_hash = write_plaintext(plain)
            checks.check(file_size(plain) == PLAINTEXT_BYTES,
                         "plaintext fixture is 67108864 bytes")
            checks.check(read_byte(plain, 0) == BYTE_AT_0
                         and read_byte(plain, 1000) == BYTE_AT_1000
                         and read_byte(plain, PLAINTEXT_BYTES - 1) == BYTE_AT_LAST,
                         "plaintext fixture matches the literal pattern bytes")

            status_client: Client | None = None
            ready = None
            if status_operation_exists(repository):
                status_client = start_client(binary, socket_path, ["status"], True)
                clients.append(status_client)
                ready = status_client.wait_for(30, lambda item: item == "READY"
                                                or item.startswith("SETUP")
                                                or item.startswith("RESULT"))
                checks.check(ready == "READY",
                             f"status client is connected before the seal ({ready})")
            else:
                print("status during seal: skipped (MERGED-L3 is not in this tree)")
                status_text = "skipped (MERGED-L3 is not in this tree)"

            time.sleep(0.05)
            baseline = rss_anon_kib(process.pid)
            sampler = RssSampler(process.pid)
            sampler.start()
            seal_client = start_client(
                binary, socket_path,
                ["seal", record_hex, DATASET_NAME, str(REVISION), str(plain), str(sealed)],
                False)
            clients.append(seal_client)
            sealing = seal_client.wait_for(
                60, lambda item: item == "SEALING" or item.startswith("SETUP")
                or item.startswith("RESULT"))
            checks.check(sealing == "SEALING", f"seal reports it has started ({sealing})")
            if (sealing == "SEALING" and ready == "READY"
                    and status_client is not None
                    and status_client.proc.stdin is not None):
                status_client.proc.stdin.write(b"G")
                status_client.proc.stdin.flush()
                status_line = status_client.wait_for(
                    30, lambda item: item.startswith("RESULT") or item.startswith("SETUP"))
                status_parsed = parse_result(status_line)
                status_code, status_err = status_client.finish(10)
                clients.remove(status_client)
                if status_parsed is None:
                    checks.check(False, f"status during seal produced no result "
                                 f"(exit={status_code} {status_line} {tail(status_err)})")
                    status_text = "no result"
                else:
                    status_seconds = status_parsed[1]
                    status_text = f"{status_seconds:.3f}"
                    checks.check(status_code == 0 and status_parsed[0] == KSEC_OK,
                                 "status during seal returns ok "
                                 f"(code={status_parsed[0]} {tail(status_err)})")
                    checks.check(status_parsed[3] == 7,
                                 "status during seal reports initialized, "
                                 "recovery-confirmed and unlocked "
                                 f"(flags={status_parsed[3]})")
                    checks.check(status_seconds < STATUS_BOUND_SECONDS,
                                 "status during seal is answered within 5 seconds "
                                 f"({status_seconds:.3f}s)")
            if sealing == "SEALING":
                seal_line = seal_client.wait_for(
                    180, lambda item: item.startswith("RESULT") or item.startswith("SETUP"))
            elif sealing is not None and sealing.startswith("RESULT"):
                seal_line = sealing
            else:
                seal_line = None
            seal_parsed = parse_result(seal_line)
            seal_code, seal_err = seal_client.finish(15)
            clients.remove(seal_client)
            if seal_parsed is not None:
                seal_seconds = seal_parsed[1]
            checks.check(seal_parsed is not None and seal_code == 0
                         and seal_parsed[0] == KSEC_OK,
                         "64 MiB seal returns ok "
                         f"(exit={seal_code} line={seal_line} {tail(seal_err)})")
            checks.check(file_size(sealed) == SEALED_BYTES,
                         f"sealed file is {SEALED_BYTES} bytes (saw {file_size(sealed)})")

            if seal_parsed is not None and seal_parsed[0] == KSEC_OK:
                unseal_parsed, unseal_code, unseal_err, _ = call_client(
                    binary, socket_path,
                    ["unseal", record_hex, DATASET_NAME, str(sealed), str(unsealed)],
                    180)
                if unseal_parsed is not None:
                    unseal_seconds = unseal_parsed[1]
                checks.check(unseal_parsed is not None and unseal_code == 0
                             and unseal_parsed[0] == KSEC_OK,
                             "64 MiB unseal returns ok "
                             f"(exit={unseal_code} line={unseal_parsed} {tail(unseal_err)})")
                checks.check(unseal_parsed is not None and unseal_parsed[2] == REVISION,
                             f"unseal reports revision {REVISION} "
                             f"(saw {None if unseal_parsed is None else unseal_parsed[2]})")
                checks.check(file_size(unsealed) == PLAINTEXT_BYTES,
                             "unsealed plaintext is 67108864 bytes "
                             f"(saw {file_size(unsealed)})")
                if file_size(unsealed) == PLAINTEXT_BYTES:
                    checks.check(read_byte(unsealed, 0) == BYTE_AT_0
                                 and read_byte(unsealed, 1000) == BYTE_AT_1000
                                 and read_byte(unsealed, PLAINTEXT_BYTES - 1) == BYTE_AT_LAST,
                                 "unsealed plaintext matches the literal pattern bytes")
                    checks.check(sha256_file(unsealed) == plain_hash,
                                 "unsealed plaintext matches the sealed input")

            over_plain = root / "over-plain.bin"
            over_out = root / "over-seal-out.bin"
            sparse_file(over_plain, PLAINTEXT_BYTES + 1)
            over_seal, over_code, over_err, _ = call_client(
                binary, socket_path,
                ["seal", record_hex, DATASET_NAME, "2", str(over_plain), str(over_out)],
                180)
            checks.check(over_seal is not None and over_code == 0
                         and over_seal[0] == KSEC_ERR_LIMIT,
                         "64 MiB + 1 seal returns LIMIT "
                         f"(exit={over_code} line={over_seal} {tail(over_err)})")
            checks.check(file_size(over_out) == 0,
                         "failed oversize seal writes nothing "
                         f"(saw {file_size(over_out)})")

            too_long = root / "too-long.bin"
            too_long_out = root / "too-long-out.bin"
            sparse_file(too_long, OVER_SEALED_BYTES)
            over_unseal, long_code, long_err, _ = call_client(
                binary, socket_path,
                ["unseal", record_hex, DATASET_NAME, str(too_long), str(too_long_out)],
                180)
            checks.check(over_unseal is not None and long_code == 0
                         and over_unseal[0] == KSEC_ERR_LIMIT,
                         "over-long sealed file unseal returns LIMIT "
                         f"(exit={long_code} line={over_unseal} {tail(long_err)})")
            checks.check(file_size(too_long_out) == 0,
                         "failed over-long unseal writes nothing "
                         f"(saw {file_size(too_long_out)})")

            peak = sampler.finish()
            rss_delta = peak - baseline if peak >= 0 else -1
            checks.check(sampler.error == "" and rss_delta <= RSS_BOUND_KIB,
                         "daemon RssAnon grows by no more than 8192 KiB "
                         f"(baseline={baseline} peak={peak} delta={rss_delta} "
                         f"{sampler.error})")
            checks.check(process.poll() is None, "daemon remains running after the limits")
    except Exception as error:
        checks.check(False, f"dataset limits aborted: {error}")
    finally:
        for client in clients:
            client.kill()
            client.finish(5)
        passphrase[:] = b"\x00" * len(passphrase)
        recovery[:] = b"\x00" * len(recovery)
        if process is not None:
            stop_daemon(process)
        if daemon_thread is not None:
            daemon_thread.join(timeout=2)
        remove_tree(root, scratch, checks)
    print(f"dataset limit checks: {checks.total - checks.failed}/{checks.total} passed")
    print(f"seal seconds: {seal_seconds:.3f}; unseal seconds: {unseal_seconds:.3f}; "
          f"RssAnon delta KiB: {rss_delta}/{RSS_BOUND_KIB}; "
          f"status seconds: {status_text}")
    return 0 if checks.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
