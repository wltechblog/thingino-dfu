/**
 * Remote client - sends commands to dfu-remote daemon over TCP
 *
 * All firmware data is sent over the wire. The daemon never loads
 * firmware from its own filesystem.
 */

#include "remote.h"
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include "tdfu/dfu.h"
#include "tdfu/protocol.h"
#include "tdfu/tdfu.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#ifndef _SSIZE_T_DEFINED
typedef int ssize_t;
#endif
#define MSG_NOSIGNAL 0
#define CLOSE_SOCKET closesocket
static int wsa_initialized = 0;
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#define CLOSE_SOCKET close
#endif

/* Simple CRC32 (avoids zlib dependency on Windows). Resumable form so the
 * read path can checksum a streamed payload chunk by chunk: seed with
 * 0xFFFFFFFF, feed chunks, finalize with ~crc. */
static uint32_t remote_crc32_update(uint32_t crc, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++)
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
    }
    return crc;
}

static uint32_t remote_crc32(const uint8_t *data, size_t len) {
    return ~remote_crc32_update(0xFFFFFFFF, data, len);
}

static int remote_fd = -1;

static int net_send_all(int fd, const void *buf, size_t len) {
    const uint8_t *p = buf;
    while (len > 0) {
        ssize_t n = send(fd, (const char *)p, (int)len, MSG_NOSIGNAL);
        if (n <= 0)
            return -1;
        p += n;
        len -= n;
    }
    return 0;
}

static int net_recv_all(int fd, void *buf, size_t len) {
    uint8_t *p = buf;
    while (len > 0) {
        ssize_t n = recv(fd, (char *)p, (int)len, 0);
        if (n <= 0)
            return -1;
        p += n;
        len -= n;
    }
    return 0;
}

int remote_connect(const char *host, int port, const char *token) {
#ifdef _WIN32
    if (!wsa_initialized) {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            fprintf(stderr, "WSAStartup failed\n");
            return -1;
        }
        wsa_initialized = 1;
    }
#endif
    struct addrinfo hints = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM};
    struct addrinfo *result;
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    if (getaddrinfo(host, port_str, &hints, &result) != 0) {
        fprintf(stderr, "Failed to resolve host: %s\n", host);
        return -1;
    }

    /* Try each address getaddrinfo returned. It orders IPv6 ahead of IPv4 per
     * RFC 6724, so this prefers v6 and only falls back to v4 when v6 does not
     * connect - a dual-stacked host works either way. */
    remote_fd = -1;
    for (struct addrinfo *rp = result; rp != NULL; rp = rp->ai_next) {
        int fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0)
            continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            remote_fd = fd;
            break;
        }
        CLOSE_SOCKET(fd);
    }

    freeaddrinfo(result);

    if (remote_fd < 0) {
        fprintf(stderr, "Failed to connect to %s:%d\n", host, port);
        return -1;
    }

    /* Send auth handshake if token provided */
    if (token) {
        uint8_t token_len = (uint8_t)strlen(token);
        uint8_t auth_hdr[6];
        uint32_t magic = tdfu_htonl(TDFU_PROTO_MAGIC);
        memcpy(auth_hdr, &magic, 4);
        auth_hdr[4] = TDFU_PROTO_VERSION;
        auth_hdr[5] = token_len;
        if (net_send_all(remote_fd, auth_hdr, 6) < 0 || net_send_all(remote_fd, token, token_len) < 0) {
            fprintf(stderr, "Failed to send auth token\n");
            CLOSE_SOCKET(remote_fd);
            remote_fd = -1;
            return -1;
        }
        /* Read auth response */
        tdfu_resp_header_t resp;
        if (net_recv_all(remote_fd, &resp, sizeof(resp)) < 0 || resp.status != RESP_OK) {
            /* Read error payload if present */
            uint32_t err_len = tdfu_ntohl(resp.payload_len);
            if (err_len > 0 && err_len < 256) {
                char err[256] = {0};
                net_recv_all(remote_fd, err, err_len);
                fprintf(stderr, "Auth failed: %s\n", err);
            } else {
                fprintf(stderr, "Auth failed\n");
            }
            CLOSE_SOCKET(remote_fd);
            remote_fd = -1;
            return -1;
        }
        /* Drain auth OK payload */
        uint32_t ok_len = tdfu_ntohl(resp.payload_len);
        if (ok_len > 0 && ok_len < 256) {
            char buf[256];
            net_recv_all(remote_fd, buf, ok_len);
        }
    }

    return 0;
}

void remote_disconnect(void) {
    if (remote_fd >= 0) {
        CLOSE_SOCKET(remote_fd);
        remote_fd = -1;
    }
}

static int send_command(uint8_t cmd, const void *payload, uint32_t len) {
    tdfu_msg_header_t hdr = {
        .magic = tdfu_htonl(TDFU_PROTO_MAGIC),
        .version = TDFU_PROTO_VERSION,
        .command = cmd,
        .payload_len = tdfu_htonl(len),
    };
    if (net_send_all(remote_fd, &hdr, sizeof(hdr)) < 0)
        return -1;
    if (len > 0 && payload) {
        if (net_send_all(remote_fd, payload, len) < 0)
            return -1;
    }
    return 0;
}

/* Display (or drain) one intermediate RESP_PROGRESS / RESP_LOG frame whose
 * header has already been read. Returns 0 to keep reading, -1 on a dead
 * socket. Shared by recv_response and recv_read_to_file. */
static int handle_intermediate_frame(uint8_t status, uint32_t plen) {
    if (plen > 0 && plen < 65536) {
        uint8_t *data = malloc(plen + 1);
        if (data && net_recv_all(remote_fd, data, plen) == 0) {
            if (status == RESP_LOG) {
                /* Raw log output — print directly like local mode */
                data[plen] = '\0';
                fprintf(stderr, "%s", (char *)data);
            } else if (plen >= 4) {
                /* Legacy progress: [1:percent][1:stage][2:msg_len][msg] */
                uint8_t percent = data[0];
                uint16_t msg_len = ((uint16_t)data[2] << 8) | data[3];
                if (4u + msg_len <= plen) {
                    data[4 + msg_len] = '\0';
                    fprintf(stderr, "\r[%3d%%] %s", percent, (char *)(data + 4));
                }
            }
        }
        free(data);
    } else if (plen > 0) {
        /* Drain oversized payload to keep stream in sync */
        uint8_t drain[1024];
        uint32_t remaining = plen;
        while (remaining > 0) {
            uint32_t chunk = remaining < sizeof(drain) ? remaining : sizeof(drain);
            if (net_recv_all(remote_fd, drain, chunk) < 0)
                return -1;
            remaining -= chunk;
        }
    }
    return 0;
}

/**
 * Receive response, handling RESP_PROGRESS messages inline.
 * Progress messages are printed to stderr and the function
 * keeps reading until a final RESP_OK or RESP_ERROR arrives.
 */
static int recv_response(uint8_t *status, uint8_t **payload, uint32_t *payload_len) {
    for (;;) {
        tdfu_resp_header_t hdr;
        if (net_recv_all(remote_fd, &hdr, sizeof(hdr)) < 0)
            return -1;
        if (tdfu_ntohl(hdr.magic) != TDFU_PROTO_MAGIC)
            return -1;

        uint32_t plen = tdfu_ntohl(hdr.payload_len);

        if (hdr.status == RESP_PROGRESS || hdr.status == RESP_LOG) {
            if (handle_intermediate_frame(hdr.status, plen) < 0)
                return -1;
            continue; /* keep reading for final response */
        }

        /* Final response (OK or ERROR) */
        *status = hdr.status;
        *payload_len = plen;

        if (plen >= TDFU_MAX_PAYLOAD) {
            /* Refusing the payload but returning 0 with *payload NULL used to
             * look like success to callers, which then dereferenced NULL
             * (a T40XP remote read: alt 0 is the whole 256MB NAND). Drain to
             * keep the stream coherent and fail loudly instead; bulk reads go
             * through recv_read_to_file, which streams instead of buffering. */
            fprintf(stderr, "Response payload too large (%u bytes)\n", plen);
            uint8_t drain[4096];
            uint32_t remaining = plen;
            while (remaining > 0) {
                uint32_t chunk = remaining < sizeof(drain) ? remaining : sizeof(drain);
                if (net_recv_all(remote_fd, drain, chunk) < 0)
                    break;
                remaining -= chunk;
            }
            *payload = NULL;
            return -1;
        }

        if (*payload_len > 0) {
            *payload = malloc(*payload_len + 1);
            if (!*payload)
                return -1;
            if (net_recv_all(remote_fd, *payload, *payload_len) < 0) {
                free(*payload);
                *payload = NULL;
                return -1;
            }
            (*payload)[*payload_len] = '\0';
        } else {
            *payload = NULL;
        }

        return 0;
    } /* for(;;) */
}

/* Receive a CMD_READ response, streaming the firmware payload straight into
 * out_path instead of buffering it in RAM. A NAND loader's alt 0 is the whole
 * chip (256 MiB on a T40XP), far past TDFU_MAX_PAYLOAD - recv_response refuses
 * that (and before it did, handed the caller a NULL payload that was
 * dereferenced). The payload's last 4 bytes are the CRC32 of the data before
 * them; the file is deleted on any failure. Returns 0 with *out_bytes set. */
static int recv_read_to_file(const char *out_path, uint64_t *out_bytes) {
    for (;;) {
        tdfu_resp_header_t hdr;
        if (net_recv_all(remote_fd, &hdr, sizeof(hdr)) < 0)
            return -1;
        if (tdfu_ntohl(hdr.magic) != TDFU_PROTO_MAGIC)
            return -1;

        uint32_t plen = tdfu_ntohl(hdr.payload_len);

        if (hdr.status == RESP_PROGRESS || hdr.status == RESP_LOG) {
            if (handle_intermediate_frame(hdr.status, plen) < 0)
                return -1;
            continue;
        }

        if (hdr.status != RESP_OK) {
            /* RESP_ERROR carries a short message */
            char msg[512] = "unknown";
            uint32_t mlen = plen < sizeof(msg) - 1 ? plen : sizeof(msg) - 1;
            if (mlen > 0 && net_recv_all(remote_fd, msg, mlen) == 0)
                msg[mlen] = '\0';
            fprintf(stderr, "Read failed: %s\n", msg);
            return -1;
        }

        if (plen < 4) {
            fprintf(stderr, "Read response too short\n");
            return -1;
        }

        uint64_t data_len = (uint64_t)plen - 4;
        FILE *f = fopen(out_path, "wb");
        if (!f) {
            fprintf(stderr, "Failed to open output file: %s\n", out_path);
            return -1;
        }

        uint8_t buf[65536];
        uint32_t crc = 0xFFFFFFFF;
        uint64_t remaining = data_len;
        while (remaining > 0) {
            uint32_t chunk = remaining < sizeof(buf) ? (uint32_t)remaining : (uint32_t)sizeof(buf);
            if (net_recv_all(remote_fd, buf, chunk) < 0) {
                fprintf(stderr, "Lost connection during read\n");
                fclose(f);
                remove(out_path);
                return -1;
            }
            crc = remote_crc32_update(crc, buf, chunk);
            if (fwrite(buf, 1, chunk, f) != chunk) {
                fprintf(stderr, "Short write to %s\n", out_path);
                fclose(f);
                remove(out_path);
                return -1;
            }
            remaining -= chunk;
        }
        fclose(f);

        uint8_t crc_buf[4];
        if (net_recv_all(remote_fd, crc_buf, 4) < 0) {
            remove(out_path);
            return -1;
        }
        uint32_t expected_crc = ((uint32_t)crc_buf[0] << 24) | ((uint32_t)crc_buf[1] << 16) |
                                ((uint32_t)crc_buf[2] << 8) | crc_buf[3];
        if (~crc != expected_crc) {
            fprintf(stderr, "Read data CRC32 mismatch\n");
            remove(out_path);
            return -1;
        }

        *out_bytes = data_len;
        return 0;
    }
}

/* Helper: read a file into a malloc'd buffer */
static int read_file(const char *path, uint8_t **data, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f)
        return -1;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    if (sz < 0) {
        fclose(f);
        return -1;
    }
    fseek(f, 0, SEEK_SET);
    *data = malloc(sz);
    if (!*data) {
        fclose(f);
        return -1;
    }
    if (fread(*data, 1, sz, f) != (size_t)sz) {
        free(*data);
        *data = NULL;
        fclose(f);
        return -1;
    }
    fclose(f);
    *len = sz;
    return 0;
}

/* Helper: write 4 bytes big-endian */
static void write_be32(uint8_t *p, uint32_t v) {
    p[0] = (v >> 24) & 0xFF;
    p[1] = (v >> 16) & 0xFF;
    p[2] = (v >> 8) & 0xFF;
    p[3] = v & 0xFF;
}

int remote_list_devices(void) {
    if (send_command(CMD_DISCOVER, NULL, 0) < 0)
        return -1;

    uint8_t status;
    uint8_t *payload = NULL;
    uint32_t payload_len = 0;
    if (recv_response(&status, &payload, &payload_len) < 0)
        return -1;

    if (status != RESP_OK) {
        fprintf(stderr, "Error: %s\n", payload ? (char *)payload : "unknown");
        free(payload);
        return -1;
    }

    int count = payload_len / sizeof(tdfu_device_entry_t);
    tdfu_device_entry_t *entries = (tdfu_device_entry_t *)payload;

    printf("Found %d device(s) (remote):\n", count);
    printf("Index | Bus | Addr | Vendor  | Product | Stage    | Variant\n");
    printf("------|-----|------|---------|---------|----------|--------\n");

    for (int i = 0; i < count; i++) {
        /* wire stage: 0=bootrom, 1=firmware, 2=DFU gadget */
        const char *stage = entries[i].stage == 1 ? "firmware" : entries[i].stage == 2 ? "dfu" : "bootrom";
        printf("  %3d | %3d | %4d | 0x%04X  | 0x%04X  | %-8s | %s\n", i, entries[i].bus, entries[i].address,
               tdfu_ntohs(entries[i].vendor), tdfu_ntohs(entries[i].product), stage,
               tdfu_variant_to_string((tdfu_variant_t)entries[i].variant));
    }

    free(payload);
    return 0;
}

int remote_diag(int device_index) {
    uint8_t idx = (uint8_t)device_index;
    if (send_command(CMD_DIAG, &idx, 1) < 0)
        return -1;

    uint8_t status;
    uint8_t *payload = NULL;
    uint32_t payload_len = 0;
    if (recv_response(&status, &payload, &payload_len) < 0)
        return -1;

    if (status != RESP_OK) {
        fprintf(stderr, "Error: %s\n", payload ? (char *)payload : "unknown");
        free(payload);
        return -1;
    }

    /* payload is the formatted diagnostics text (not NUL-terminated on the wire). */
    printf("\n%.*s\n", (int)payload_len, payload ? (char *)payload : "");
    free(payload);
    return 0;
}

const char *remote_detect_variant(int device_index) {
    if (send_command(CMD_DISCOVER, NULL, 0) < 0)
        return NULL;

    uint8_t status;
    uint8_t *payload = NULL;
    uint32_t payload_len = 0;
    if (recv_response(&status, &payload, &payload_len) < 0)
        return NULL;

    if (status != RESP_OK) {
        free(payload);
        return NULL;
    }

    int count = (int)(payload_len / sizeof(tdfu_device_entry_t));
    if (device_index >= count) {
        fprintf(stderr, "Device index %d out of range (found %d devices)\n", device_index, count);
        free(payload);
        return NULL;
    }

    tdfu_device_entry_t *entries = (tdfu_device_entry_t *)payload;
    const char *name = tdfu_variant_to_string((tdfu_variant_t)entries[device_index].variant);
    free(payload);
    return name;
}

/* Return the USB stage of a remote device by index: 0 = bootrom,
 * 1 = firmware/DFU gadget, or -1 on error / out of range. Lets a bare
 * -w decide whether it must bootstrap first. */
int remote_device_stage(int device_index) {
    if (send_command(CMD_DISCOVER, NULL, 0) < 0)
        return -1;

    uint8_t status;
    uint8_t *payload = NULL;
    uint32_t payload_len = 0;
    if (recv_response(&status, &payload, &payload_len) < 0)
        return -1;

    if (status != RESP_OK) {
        free(payload);
        return -1;
    }

    int count = (int)(payload_len / sizeof(tdfu_device_entry_t));
    if (device_index < 0 || device_index >= count) {
        free(payload);
        return -1;
    }

    tdfu_device_entry_t *entries = (tdfu_device_entry_t *)payload;
    int stage = entries[device_index].stage;
    free(payload);
    return stage;
}

/**
 * Bootstrap a remote device over the wire.
 *
 * The daemon USB-boots firmware/dfu/<soc>/ itself, so by default the client
 * sends only the device index + variant. If the user passed both --spl and
 * --uboot, those blobs are streamed and the daemon uses them instead (skipping
 * SoC detection), matching local --spl/--uboot.
 *
 * Payload: [1:device_index][1:variant_len][N:variant_str]
 *          optionally [4:spl_len][spl][4:uboot_len][uboot]
 */
int remote_bootstrap(int device_index, const char *cpu_variant, const char *firmware_dir, const char *spl_file,
                     const char *uboot_file) {
    (void)firmware_dir;
    size_t vlen = cpu_variant ? strlen(cpu_variant) : 0;
    if (vlen > 63)
        vlen = 63;

    uint8_t *spl = NULL, *uboot = NULL;
    size_t spl_len = 0, uboot_len = 0;
    bool override = spl_file && spl_file[0] && uboot_file && uboot_file[0];
    if (override) {
        if (read_file(spl_file, &spl, &spl_len) < 0) {
            fprintf(stderr, "Failed to read --spl file: %s\n", spl_file);
            return -1;
        }
        if (read_file(uboot_file, &uboot, &uboot_len) < 0) {
            fprintf(stderr, "Failed to read --uboot file: %s\n", uboot_file);
            free(spl);
            return -1;
        }
    }

    size_t plen = 2 + vlen + (override ? 4 + spl_len + 4 + uboot_len : 0);
    uint8_t *payload = malloc(plen);
    if (!payload) {
        free(spl);
        free(uboot);
        return -1;
    }
    uint8_t *q = payload;
    *q++ = (uint8_t)device_index;
    *q++ = (uint8_t)vlen;
    if (vlen) {
        memcpy(q, cpu_variant, vlen);
        q += vlen;
    }
    if (override) {
        write_be32(q, (uint32_t)spl_len);
        q += 4;
        memcpy(q, spl, spl_len);
        q += spl_len;
        write_be32(q, (uint32_t)uboot_len);
        q += 4;
        memcpy(q, uboot, uboot_len);
        q += uboot_len;
        printf("Sending custom SPL (%zu B) + U-Boot (%zu B) to daemon\n", spl_len, uboot_len);
    }
    free(spl);
    free(uboot);

    int sc = send_command(CMD_BOOTSTRAP, payload, (uint32_t)plen);
    free(payload);
    if (sc < 0)
        return -1;
    uint8_t st = 0;
    uint8_t *resp = NULL;
    uint32_t rl = 0;
    if (recv_response(&st, &resp, &rl) < 0) {
        fprintf(stderr, "Lost connection during bootstrap\n");
        return -1;
    }
    if (st != RESP_OK) {
        fprintf(stderr, "Bootstrap failed: %s\n", resp ? (char *)resp : "unknown");
        free(resp);
        return -1;
    }
    printf("Bootstrap completed successfully (remote DFU)\n");
    free(resp);
    return 0;
}

/* Send a CMD_WRITE with an in-memory payload targeting the given alt. Backs
 * both the firmware write (file contents -> default/explicit alt) and the
 * whole-chip erase (wipe token -> the loader's "erase" alt). `what` labels
 * the completion message. */
static int remote_send_write(int device_index, const char *cpu_variant, const uint8_t *fw_data, size_t fw_len,
                             const char *alt, bool verify, const char *what) {
    uint32_t fw_crc = remote_crc32(fw_data, fw_len);

    /* variant is optional (DFU write passes none - the daemon resolves the alt) */
    const char *variant = cpu_variant ? cpu_variant : "";
    size_t variant_len = strlen(variant);
    /* alt selector: empty = daemon default (alt 0 = flash); name/num targets it */
    const char *alt_s = alt ? alt : "";
    size_t alt_len = strlen(alt_s);
    /* Trailing [1:verify] byte is optional in the wire format (older daemons
     * stop after the CRC); only append it when verify is requested. */
    size_t payload_len = 2 + variant_len + 1 + alt_len + 4 + fw_len + 4 + (verify ? 1 : 0);
    uint8_t *payload = malloc(payload_len);
    if (!payload)
        return -1;

    uint8_t *p = payload;
    *p++ = (uint8_t)device_index;
    *p++ = (uint8_t)variant_len;
    memcpy(p, variant, variant_len);
    p += variant_len;
    *p++ = (uint8_t)alt_len;
    memcpy(p, alt_s, alt_len);
    p += alt_len;
    write_be32(p, fw_len);
    p += 4;
    memcpy(p, fw_data, fw_len);
    p += fw_len;
    write_be32(p, fw_crc);
    p += 4;
    if (verify)
        *p++ = 1;

    if (send_command(CMD_WRITE, payload, payload_len) < 0) {
        free(payload);
        return -1;
    }
    free(payload);

    uint8_t resp_status;
    uint8_t *resp = NULL;
    uint32_t resp_len = 0;
    if (recv_response(&resp_status, &resp, &resp_len) < 0) {
        fprintf(stderr, "Lost connection during %s\n", what);
        return -1;
    }

    if (resp_status != RESP_OK) {
        fprintf(stderr, "%s failed: %s\n", what, resp ? (char *)resp : "unknown");
        free(resp);
        return -1;
    }

    printf("%s completed successfully (remote)\n", what);
    free(resp);
    return 0;
}

/**
 * Write firmware to remote device.
 *
 * Payload format:
 *   [1:device_idx][1:variant_len][N:variant][1:alt_len][N:alt]
 *   [4:fw_len][fw_data][4:crc32][1:verify (optional)]
 */
int remote_write_firmware(int device_index, const char *cpu_variant, const char *firmware_file, const char *alt,
                          bool verify) {
    uint8_t *fw_data = NULL;
    size_t fw_len = 0;
    if (read_file(firmware_file, &fw_data, &fw_len) < 0) {
        fprintf(stderr, "Failed to read firmware file: %s\n", firmware_file);
        return -1;
    }

    printf("Sending firmware to remote daemon:\n");
    printf("  File: %s (%zu bytes)\n", firmware_file, fw_len);

    int rc = remote_send_write(device_index, cpu_variant, fw_data, fw_len, alt, verify, "Firmware write");
    free(fw_data);
    return rc;
}

/* Whole-chip erase: the wipe token to the loader's "erase" alt is just a tiny
 * CMD_WRITE, so any daemon that can write can erase - only the loader must be
 * new enough to expose the alt. */
int remote_erase(int device_index) {
    printf("Erasing the whole flash (remote)... this takes a while\n");
    return remote_send_write(device_index, NULL, (const uint8_t *)TDFU_DFU_ERASE_TOKEN,
                             strlen(TDFU_DFU_ERASE_TOKEN), TDFU_DFU_ERASE_ALT, false, "Erase");
}

/* Reboot the SoC (daemon runs tdfu_dfu_reboot, which tolerates the reset
 * disconnect). Its own command, not a token CMD_WRITE like erase, because the
 * device drops off mid-write and a plain write would report that as failure. */
int remote_reboot(int device_index) {
    uint8_t idx = (uint8_t)device_index;
    if (send_command(CMD_REBOOT, &idx, 1) < 0)
        return -1;

    uint8_t status;
    uint8_t *payload = NULL;
    uint32_t payload_len = 0;
    if (recv_response(&status, &payload, &payload_len) < 0)
        return -1;
    if (status != RESP_OK) {
        fprintf(stderr, "Error: %s\n", payload ? (char *)payload : "unknown");
        free(payload);
        return -1;
    }
    free(payload);
    printf("Reboot triggered (remote)\n");
    return 0;
}

/**
 * Read firmware from remote device.
 *
 * Sends CMD_READ with [1:device_idx][4:offset][4:length]
 * Response contains [fw_data][4:crc32]
 */
int remote_read_firmware(int device_index, const char *output_file, const char *alt) {
    /* alt selector: empty = daemon default (alt 0 = flash); name/num targets it.
     * The daemon uploads the whole selected alt, so no offset/length here. */
    const char *alt_s = alt ? alt : "";
    size_t alt_len = strlen(alt_s);

    printf("Reading firmware from remote device%s%s...\n",
           alt_s[0] ? " alt " : "", alt_s);

    /* Payload: [idx][variant_len=0][alt_len][alt] */
    uint8_t payload[3 + 64];
    int n = 0;
    payload[n++] = (uint8_t)device_index;
    payload[n++] = 0;
    payload[n++] = (uint8_t)alt_len;
    memcpy(payload + n, alt_s, alt_len);
    n += (int)alt_len;

    if (send_command(CMD_READ, payload, (uint32_t)n) < 0)
        return -1;

    /* Stream to the file: a NAND alt can be the whole 256MB chip. */
    uint64_t data_len = 0;
    if (recv_read_to_file(output_file, &data_len) < 0)
        return -1;

    printf("Read complete: %llu bytes saved to %s (CRC OK)\n", (unsigned long long)data_len, output_file);
    return 0;
}
