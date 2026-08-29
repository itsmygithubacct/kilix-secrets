#define _GNU_SOURCE

#include "internal.h"

#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void close_received_rights(struct msghdr *message) {
    struct cmsghdr *cmsg;
    if (message == NULL) return;
    for (cmsg = CMSG_FIRSTHDR(message); cmsg != NULL;
            cmsg = CMSG_NXTHDR(message, cmsg)) {
        size_t bytes;
        size_t index;
        int *fds;
        if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS
                || cmsg->cmsg_len < CMSG_LEN(0)) continue;
        bytes = cmsg->cmsg_len - CMSG_LEN(0);
        fds = (int *)CMSG_DATA(cmsg);
        for (index = 0; index < bytes / sizeof(int); index++) {
            (void)close(fds[index]);
        }
    }
}

ksec_result ksec_packet_encode(const ksec_packet_header *header,
                               const uint8_t *payload, uint8_t *output,
                               size_t output_size, size_t *output_length) {
    size_t total;
    if (header == NULL || output == NULL || output_length == NULL
            || header->version != KSEC_PROTOCOL_VERSION
            || header->operation < KSEC_OP_ACTIVATE || header->operation > KSEC_OP_COMPACT
            || header->flags != 0U || header->payload_len > KSEC_PROTOCOL_MAX_PAYLOAD
            || (header->payload_len > 0U && payload == NULL)) return KSEC_ERR_INVALID;
    total = KSEC_PROTOCOL_HEADER_BYTES + header->payload_len;
    if (output_size < total) return KSEC_ERR_LIMIT;
    ksec_put_u32(output, KSEC_PROTOCOL_MAGIC);
    ksec_put_u16(output + 4U, header->version);
    ksec_put_u16(output + 6U, header->operation);
    ksec_put_u32(output + 8U, header->flags);
    ksec_put_u64(output + 12U, header->request_id);
    ksec_put_u32(output + 20U, header->payload_len);
    if (header->payload_len > 0U) memcpy(output + KSEC_PROTOCOL_HEADER_BYTES,
                                         payload, header->payload_len);
    *output_length = total;
    return KSEC_OK;
}

ksec_result ksec_packet_decode(const uint8_t *input, size_t input_length,
                               ksec_packet_header *header,
                               const uint8_t **payload) {
    if (input == NULL || header == NULL || payload == NULL
            || input_length < KSEC_PROTOCOL_HEADER_BYTES
            || ksec_get_u32(input) != KSEC_PROTOCOL_MAGIC) return KSEC_ERR_PROTOCOL;
    header->version = ksec_get_u16(input + 4U);
    header->operation = ksec_get_u16(input + 6U);
    header->flags = ksec_get_u32(input + 8U);
    header->request_id = ksec_get_u64(input + 12U);
    header->payload_len = ksec_get_u32(input + 20U);
    if (header->version != KSEC_PROTOCOL_VERSION || header->flags != 0U
            || header->operation < KSEC_OP_ACTIVATE || header->operation > KSEC_OP_COMPACT
            || header->payload_len > KSEC_PROTOCOL_MAX_PAYLOAD
            || input_length != KSEC_PROTOCOL_HEADER_BYTES + header->payload_len) {
        return KSEC_ERR_PROTOCOL;
    }
    *payload = input + KSEC_PROTOCOL_HEADER_BYTES;
    return KSEC_OK;
}

ksec_result ksec_send_packet(int fd, const ksec_packet_header *header,
                             const uint8_t *payload, int passed_fd) {
    uint8_t packet[KSEC_PROTOCOL_MAX_PACKET];
    uint8_t control[CMSG_SPACE(sizeof(int))];
    size_t packet_len = 0;
    struct iovec iov;
    struct msghdr message;
    ksec_result result = ksec_packet_encode(header, payload, packet, sizeof packet,
                                            &packet_len);
    if (result != KSEC_OK) return result;
    memset(&message, 0, sizeof message);
    memset(control, 0, sizeof control);
    iov.iov_base = packet;
    iov.iov_len = packet_len;
    message.msg_iov = &iov;
    message.msg_iovlen = 1U;
    if (passed_fd >= 0) {
        struct cmsghdr *cmsg;
        message.msg_control = control;
        message.msg_controllen = sizeof control;
        cmsg = CMSG_FIRSTHDR(&message);
        if (cmsg == NULL) return KSEC_ERR_PROTOCOL;
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cmsg), &passed_fd, sizeof passed_fd);
    }
    for (;;) {
        ssize_t count = sendmsg(fd, &message, MSG_NOSIGNAL);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0 || (size_t)count != packet_len) return KSEC_ERR_IO;
        break;
    }
    sodium_memzero(packet, sizeof packet);
    return KSEC_OK;
}

ksec_result ksec_recv_packet(int fd, ksec_packet_header *header, uint8_t *payload,
                             size_t payload_size, int *received_fd) {
    uint8_t packet[KSEC_PROTOCOL_MAX_PACKET];
    uint8_t control[CMSG_SPACE(sizeof(int) * 2U)];
    struct iovec iov;
    struct msghdr message;
    const uint8_t *decoded_payload = NULL;
    struct cmsghdr *cmsg;
    ssize_t count;
    int found_fd = -1;
    ksec_result result;
    if (header == NULL || payload == NULL || received_fd == NULL) return KSEC_ERR_INVALID;
    memset(&message, 0, sizeof message);
    memset(control, 0, sizeof control);
    iov.iov_base = packet;
    iov.iov_len = sizeof packet;
    message.msg_iov = &iov;
    message.msg_iovlen = 1U;
    message.msg_control = control;
    message.msg_controllen = sizeof control;
    do {
        count = recvmsg(fd, &message, MSG_CMSG_CLOEXEC);
    } while (count < 0 && errno == EINTR);
    if (count <= 0) return count == 0 ? KSEC_ERR_NOT_FOUND : KSEC_ERR_IO;
    if ((message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0) {
        close_received_rights(&message);
        return KSEC_ERR_PROTOCOL;
    }
    result = ksec_packet_decode(packet, (size_t)count, header, &decoded_payload);
    if (result != KSEC_OK || header->payload_len > payload_size) {
        close_received_rights(&message);
        return KSEC_ERR_PROTOCOL;
    }
    for (cmsg = CMSG_FIRSTHDR(&message); cmsg != NULL; cmsg = CMSG_NXTHDR(&message, cmsg)) {
        size_t bytes;
        size_t fd_count;
        size_t index;
        int *fds;
        if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS
                || cmsg->cmsg_len < CMSG_LEN(sizeof(int))) {
            close_received_rights(&message);
            return KSEC_ERR_PROTOCOL;
        }
        bytes = cmsg->cmsg_len - CMSG_LEN(0);
        if (bytes == 0U || bytes % sizeof(int) != 0U) {
            close_received_rights(&message);
            return KSEC_ERR_PROTOCOL;
        }
        fd_count = bytes / sizeof(int);
        fds = (int *)CMSG_DATA(cmsg);
        for (index = 0; index < fd_count; index++) {
            if (found_fd < 0) found_fd = fds[index];
            else {
                close_received_rights(&message);
                return KSEC_ERR_PROTOCOL;
            }
        }
    }
    if (header->payload_len > 0U) memcpy(payload, decoded_payload, header->payload_len);
    sodium_memzero(packet, sizeof packet);
    *received_fd = found_fd;
    return KSEC_OK;
}
