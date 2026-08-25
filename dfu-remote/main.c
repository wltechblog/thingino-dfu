/**
 * dfu-remote - daemon that provides USB device access over TCP
 *
 * Started manually on the machine with physical USB access.
 * Listens on TCP port, accepts one client at a time, dispatches
 * commands to libtdfu.
 */

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include "tdfu/tdfu.h"
#include "tdfu/protocol.h"
#include "tdfu/dfu.h"
#include "tdfu/diag.h"
#include "platform.h"
#include "ws.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#ifdef _WIN32
#ifndef _SSIZE_T_DEFINED
typedef int ssize_t;
#endif
typedef int socklen_t;
#define MSG_NOSIGNAL 0
#define CLOSE_SOCKET closesocket
#define SHUT_RDWR    SD_BOTH
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <strings.h> /* strncasecmp */
#define CLOSE_SOCKET close
#endif

#ifdef _WIN32
#define strncasecmp _strnicmp
#endif

/* Simple CRC32 (avoids zlib dependency on Windows) */
static uint32_t remote_crc32(const uint8_t *data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++)
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
    }
    return ~crc;
}

static volatile int g_running = 1;
static volatile int g_cancel = 0;
bool g_debug_enabled = false;

/* Daemon state */
static const char *g_state = "idle";
static const char *g_auth_token = NULL; /* NULL = no auth required */

static int g_server_fd = -1;
static int g_log_client_fd = -1; /* client fd for log forwarding */

/* When non-NULL, the current client speaks WebSocket; net_send_all/net_recv_all
 * route through the frame codec instead of the raw socket. Single client at a
 * time, so a global is sufficient. */
static ws_conn_t *g_ws = NULL;

/* When non-NULL, the current client is an HTTP POST (the fetch() transport: the
 * request body holds one TDFU command, the chunked response body streams the
 * TDFU reply). net_recv_all reads from the buffered body, net_send_all writes
 * HTTP chunks. This is the path the browser flasher uses - Chrome's Local
 * Network Access exempts fetch({targetAddressSpace:'local'}) from mixed content,
 * which WebSocket can't do yet. */
typedef struct {
    int fd;
    const uint8_t *body;
    size_t blen;
    size_t bpos;
} http_conn_t;
static http_conn_t *g_http = NULL;

static void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
    /* Close server socket to unblock accept() */
    if (g_server_fd >= 0) {
        shutdown(g_server_fd, SHUT_RDWR);
        CLOSE_SOCKET(g_server_fd);
        g_server_fd = -1;
    }
}

/* ------------------------------------------------------------------ */
/* Network helpers                                                     */
/* ------------------------------------------------------------------ */

static int raw_send_all(int fd, const void *buf, size_t len) {
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

static int raw_recv_all(int fd, void *buf, size_t len) {
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

static int net_send_all(int fd, const void *buf, size_t len) {
    if (g_ws)
        return ws_send(g_ws, buf, len);
    if (g_http) {
        /* HTTP chunked-transfer encoding: <hex-len>\r\n<data>\r\n */
        char h[24];
        int hl = snprintf(h, sizeof(h), "%zx\r\n", len);
        if (raw_send_all(fd, h, (size_t)hl) < 0)
            return -1;
        if (len > 0 && raw_send_all(fd, buf, len) < 0)
            return -1;
        return raw_send_all(fd, "\r\n", 2);
    }
    return raw_send_all(fd, buf, len);
}

static int net_recv_all(int fd, void *buf, size_t len) {
    if (g_ws)
        return ws_recv(g_ws, buf, len);
    if (g_http) {
        if (g_http->bpos + len > g_http->blen)
            return -1;
        memcpy(buf, g_http->body + g_http->bpos, len);
        g_http->bpos += len;
        return 0;
    }
    return raw_recv_all(fd, buf, len);
}

static int send_response(int fd, uint8_t status, const void *payload, uint32_t len) {
    tdfu_resp_header_t hdr = {
        .magic = tdfu_htonl(TDFU_PROTO_MAGIC),
        .version = TDFU_PROTO_VERSION,
        .status = status,
        .payload_len = tdfu_htonl(len),
    };
    if (net_send_all(fd, &hdr, sizeof(hdr)) < 0)
        return -1;
    if (len > 0 && payload) {
        if (net_send_all(fd, payload, len) < 0)
            return -1;
    }
    return 0;
}

static int send_error(int fd, const char *msg) {
    return send_response(fd, RESP_ERROR, msg, strlen(msg));
}

static int send_ok(int fd, const void *payload, uint32_t len) {
    return send_response(fd, RESP_OK, payload, len);
}

/* Forward library log output to the connected client as RESP_LOG */
static void daemon_log_hook(const char *msg, size_t len) {
    /* Always print locally on daemon stderr */
    fwrite(msg, 1, len, stderr);
    /* Forward to client if connected */
    if (g_log_client_fd >= 0) {
        send_response(g_log_client_fd, RESP_LOG, msg, (uint32_t)len);
    }
}

/* ------------------------------------------------------------------ */
/* Command handlers                                                    */
/* ------------------------------------------------------------------ */

/* Cache of the SoC detected at the bootrom stage, keyed by USB port path. A DFU
 * gadget (a108:4d44) is past the bootrom and can't be re-probed, so we report the
 * remembered SoC for it - and because the key is the physical port path (stable
 * across the bootrom->DFU re-enumeration), it stays correct with several devices
 * connected. A client that connects after a device was already bootstrapped still
 * sees the real SoC. Cleared only by a daemon restart. */
#define VCACHE_N 16
static struct {
    bool valid;
    uint8_t bus, depth, port[7];
    tdfu_variant_t variant;
} g_vcache[VCACHE_N];

static bool vcache_same_port(int i, const tdfu_device_info_t *d) {
    return g_vcache[i].valid && d->port_depth > 0 && g_vcache[i].bus == d->bus &&
           g_vcache[i].depth == d->port_depth && memcmp(g_vcache[i].port, d->port_numbers, d->port_depth) == 0;
}
static void vcache_put(const tdfu_device_info_t *d, tdfu_variant_t v) {
    if (d->port_depth == 0)
        return; /* no port path -> can't correlate to the DFU re-enumeration */
    int slot = -1;
    for (int i = 0; i < VCACHE_N; i++) {
        if (vcache_same_port(i, d)) { slot = i; break; }
        if (slot < 0 && !g_vcache[i].valid) slot = i;
    }
    if (slot < 0) slot = 0;
    g_vcache[slot].valid = true;
    g_vcache[slot].bus = d->bus;
    g_vcache[slot].depth = d->port_depth;
    memcpy(g_vcache[slot].port, d->port_numbers, sizeof(g_vcache[slot].port));
    g_vcache[slot].variant = v;
}
static bool vcache_get(const tdfu_device_info_t *d, tdfu_variant_t *out) {
    for (int i = 0; i < VCACHE_N; i++)
        if (vcache_same_port(i, d)) { *out = g_vcache[i].variant; return true; }
    return false;
}

static int handle_discover(int client_fd) {
    usb_manager_t manager = {0};
    if (usb_manager_init(&manager) != TDFU_SUCCESS) {
        return send_error(client_fd, "USB init failed");
    }

    tdfu_device_info_t *devices = NULL;
    int count = 0;
    usb_manager_find_devices(&manager, &devices, &count);

    /* Build response: array of device entries */
    size_t resp_len = count * sizeof(tdfu_device_entry_t);
    tdfu_device_entry_t *entries = calloc(count, sizeof(tdfu_device_entry_t));
    if (!entries && count > 0) {
        free(devices);
        usb_manager_cleanup(&manager);
        return send_error(client_fd, "out of memory");
    }

    for (int i = 0; i < count; i++) {
        entries[i].bus = devices[i].bus;
        entries[i].address = devices[i].address;
        entries[i].vendor = tdfu_htons(devices[i].vendor);
        entries[i].product = tdfu_htons(devices[i].product);
        entries[i].stage = devices[i].stage;
        entries[i].variant = devices[i].variant;

        /* For bootrom devices, run SoC auto-detect to get true variant */
        if (devices[i].stage == 0) {
            usb_device_t *dev = NULL;
            if (usb_manager_open_device(&manager, &devices[i], &dev) == TDFU_SUCCESS) {
                tdfu_variant_t detected = TDFU_VARIANT_T31X;
                if (protocol_detect_soc(dev, &detected) == TDFU_SUCCESS) {
                    entries[i].variant = (uint8_t)detected;
                    vcache_put(&devices[i], detected); /* remember by port path for the DFU stage */
                    DEBUG_PRINT("Discover: device %d auto-detected as %s\n", i, tdfu_variant_to_string(detected));
                }
                usb_device_close(dev);
            }
        } else if (devices[i].stage == TDFU_STAGE_DFU) {
            /* DFU gadget: past the bootrom, can't re-probe. Report the SoC detected
             * on this same physical port before it was bootstrapped into DFU. */
            tdfu_variant_t cached;
            if (vcache_get(&devices[i], &cached)) {
                entries[i].variant = (uint8_t)cached;
                DEBUG_PRINT("Discover: device %d DFU gadget -> remembered SoC %s\n", i,
                            tdfu_variant_to_string(cached));
            }
        }
    }

    int rc = send_ok(client_fd, entries, resp_len);

    free(entries);
    free(devices);
    usb_manager_cleanup(&manager);
    return rc;
}

/* Read big-endian u32 from buffer */
static uint32_t read_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

/* Stage a received blob to a fresh temp file (name written to path_out). Returns
 * 0 on success, -1 on failure; the caller removes the file. Used to hand a
 * client-streamed --spl/--uboot to tdfu_dfu_bootstrap, which takes file paths. */
static int stage_temp_blob(char *path_out, size_t path_sz, const uint8_t *data, uint32_t len) {
#ifdef _WIN32
    snprintf(path_out, path_sz, "%s\\tdfu-blob-tmp.bin", getenv("TEMP") ? getenv("TEMP") : ".");
#else
    snprintf(path_out, path_sz, "/tmp/tdfu-blob-XXXXXX");
    int fd = mkstemp(path_out);
    if (fd < 0)
        return -1;
    close(fd);
#endif
    FILE *f = fopen(path_out, "wb");
    if (!f)
        return -1;
    if (fwrite(data, 1, len, f) != len) {
        fclose(f);
        remove(path_out);
        return -1;
    }
    fclose(f);
    return 0;
}

/**
 * Handle CMD_BOOTSTRAP - bootrom -> U-Boot DFU gadget.
 *
 * Payload: [1:device_idx][1:variant_len][N:variant]
 *          optional: [4:spl_len][spl][4:uboot_len][uboot]
 *          both blobs together => use them and skip SoC detect; absent =>
 *          USB-boot firmware/dfu/<soc>/{spl,uboot}.bin from firmware_dir.
 */
/* Resolve which DFU alt to target for a remote read/write. Single-alt gadgets
 * (the common Ingenic "flash" case) resolve automatically; otherwise the first
 * alt is used. Returns the alt number, or -1 if the gadget isn't present.
 *
 * Right after a bootstrap the gadget may still be re-enumerating (the bootrom ->
 * U-Boot DFU transition, sometimes with a USB reset to recover an unresponsive
 * gadget). Re-probe for up to ~30 s - libusb re-scans on each call - so a
 * one-shot `-w` (bootstrap + write) and `-b -w` don't race the re-enumeration
 * window and fail with a spurious "Device not found". The interactive local
 * path waits indefinitely (wait_for_device); the daemon can't block a client
 * forever, but 30 s comfortably covers a loader whose board_late_init probes
 * MMC/NAND before bringing up the DFU gadget (~8-10 s to DFU-ready). */
static int dfu_pick_alt(usb_manager_t *manager, int device_index, const char *alt_sel) {
    tdfu_dfu_info_t info;
    for (int attempt = 0; attempt < 120; attempt++) {
        if (tdfu_dfu_probe(manager, device_index, &info) == TDFU_SUCCESS) {
            /* An explicit selector (--alt, name or number) wins; otherwise
             * the first alt - alt 0 is the boot flash on our loaders, so the
             * default stays NOR/NAND and the SD must be asked for by name. */
            if (alt_sel && *alt_sel)
                return tdfu_dfu_find_alt(&info, alt_sel);
            return info.alt_count > 0 ? info.alts[0].alt : -1;
        }
        usleep(250000); /* 250 ms; ~30 s total */
    }
    return -1;
}

static int handle_bootstrap(int client_fd, const uint8_t *payload, uint32_t len, const char *firmware_dir) {
    if (len < 2)
        return send_error(client_fd, "payload too short");

    const uint8_t *p = payload;
    const uint8_t *end = payload + len;

    uint8_t device_index = *p++;
    uint8_t variant_len = *p++;
    if (p + variant_len > end)
        return send_error(client_fd, "bad variant length");

    char variant_str[64] = {0};
    size_t variant_copy = variant_len < sizeof(variant_str) ? variant_len : sizeof(variant_str) - 1;
    memcpy(variant_str, p, variant_copy);
    p += variant_len;

    /* Optional client-supplied SPL + U-Boot (DFU --spl/--uboot streamed over the
     * wire): [4:spl_len][spl][4:uboot_len][uboot]. Both-or-neither, mirroring the
     * local explicit_files path; absent => use firmware/dfu/<soc>/. */
    char spl_tmp[64] = {0}, uboot_tmp[64] = {0};
    const char *spl_override = NULL, *uboot_override = NULL;
    if (p < end) {
        if (p + 4 > end)
            return send_error(client_fd, "bad SPL override length");
        uint32_t spl_len = read_be32(p);
        p += 4;
        if (spl_len == 0 || p + spl_len > end)
            return send_error(client_fd, "bad SPL override");
        const uint8_t *spl_data = p;
        p += spl_len;
        if (p + 4 > end)
            return send_error(client_fd, "bad U-Boot override length");
        uint32_t uboot_len = read_be32(p);
        p += 4;
        if (uboot_len == 0 || p + uboot_len > end)
            return send_error(client_fd, "bad U-Boot override");
        const uint8_t *uboot_data = p;
        p += uboot_len;
        if (stage_temp_blob(spl_tmp, sizeof(spl_tmp), spl_data, spl_len) != 0)
            return send_error(client_fd, "failed to stage SPL override");
        if (stage_temp_blob(uboot_tmp, sizeof(uboot_tmp), uboot_data, uboot_len) != 0) {
            remove(spl_tmp);
            return send_error(client_fd, "failed to stage U-Boot override");
        }
        spl_override = spl_tmp;
        uboot_override = uboot_tmp;
        printf("Bootstrap: custom SPL %u B + U-Boot %u B from client\n", spl_len, uboot_len);
    }

    g_state = "bootstrapping";
    g_cancel = 0;
    printf("Bootstrap request: device=%d, cpu=%s, firmware_dir=%s%s\n", device_index, variant_str, firmware_dir,
           spl_override ? " (custom SPL/U-Boot)" : "");

    usb_manager_t manager = {0};
    if (usb_manager_init(&manager) != TDFU_SUCCESS) {
        if (spl_tmp[0])
            remove(spl_tmp);
        if (uboot_tmp[0])
            remove(uboot_tmp);
        return send_error(client_fd, "USB init failed");
    }

    g_log_client_fd = client_fd;
    /* DFU: bootrom -> U-Boot DFU gadget. Custom SPL/U-Boot (if supplied)
     * override firmware/dfu/<soc>/ and skip SoC detection. */
    tdfu_error_t result = tdfu_dfu_bootstrap(&manager, device_index, firmware_dir,
                                             variant_str[0] ? variant_str : NULL, spl_override, uboot_override);
    g_log_client_fd = -1;

    usb_manager_cleanup(&manager);

    g_state = "idle";
    if (spl_tmp[0])
        remove(spl_tmp);
    if (uboot_tmp[0])
        remove(uboot_tmp);
    if (result != TDFU_SUCCESS) {
        char msg[128];
        snprintf(msg, sizeof(msg), "bootstrap failed: %s", tdfu_error_to_string(result));
        return send_error(client_fd, msg);
    }

    return send_ok(client_fd, "OK", 2);
}

/**
 * Handle CMD_WRITE - write firmware to device flash.
 *
 * Payload:
 *   [1:device_idx][1:variant_len][N:variant]
 *   [4:fw_len][fw_data][4:crc32]
 */
static int handle_write(int client_fd, const uint8_t *payload, uint32_t len) {
    if (len < 2)
        return send_error(client_fd, "payload too short");

    const uint8_t *p = payload;
    const uint8_t *end = payload + len;

    uint8_t device_index = *p++;
    uint8_t variant_len = *p++;
    if (p + variant_len > end)
        return send_error(client_fd, "bad variant length");

    char variant_str[64] = {0};
    if (variant_len >= sizeof(variant_str))
        variant_len = sizeof(variant_str) - 1;
    memcpy(variant_str, p, variant_len);
    p += variant_len;

    /* DFU alt selector (name or number; empty = default alt 0 = flash). */
    char alt_str[32] = {0};
    if (p >= end)
        return send_error(client_fd, "missing alt field");
    uint8_t alt_len = *p++;
    if (p + alt_len > end)
        return send_error(client_fd, "bad alt length");
    memcpy(alt_str, p, alt_len < sizeof(alt_str) ? alt_len : sizeof(alt_str) - 1);
    p += alt_len;

    /* Parse firmware binary + CRC32 */
    if (p + 4 > end)
        return send_error(client_fd, "missing firmware length");
    uint32_t fw_len = read_be32(p);
    p += 4;
    if (p + fw_len + 4 > end)
        return send_error(client_fd, "firmware data truncated");
    const uint8_t *fw_data = p;
    p += fw_len;
    uint32_t fw_crc_expected = read_be32(p);
    p += 4;

    /* Optional trailing [1:verify] byte (absent from older clients). */
    int do_verify = (p < end && *p != 0) ? 1 : 0;

    /* Verify CRC32 */
    uint32_t fw_crc = remote_crc32(fw_data, fw_len);
    if (fw_crc != fw_crc_expected)
        return send_error(client_fd, "firmware CRC32 mismatch");

    /* A wipe-token write to the "erase" alt IS the whole-chip erase (the
     * remote protocol has no erase command - "any daemon that can write can
     * erase"). Route it to tdfu_dfu_erase instead of the generic download:
     * that path polls the long erase manifest with grace and then verifies
     * the flash actually reads blank, where the generic path could report
     * success for a token download the loader refused. */
    if (strcmp(alt_str, TDFU_DFU_ERASE_ALT) == 0 && fw_len == strlen(TDFU_DFU_ERASE_TOKEN) &&
        memcmp(fw_data, TDFU_DFU_ERASE_TOKEN, fw_len) == 0) {
        g_state = "erasing";
        g_cancel = 0;
        printf("Erase request: device=%d (token write to \"%s\")\n", device_index, alt_str);

        usb_manager_t emgr = {0};
        if (usb_manager_init(&emgr) != TDFU_SUCCESS)
            return send_error(client_fd, "USB init failed");
        g_log_client_fd = client_fd;
        /* Same post-bootstrap re-enumeration wait as a write: a one-shot
         * "--erase -w" sends this on the heels of the bootstrap, before the
         * gadget is back on the bus. dfu_pick_alt re-probes for up to ~30s. */
        if (dfu_pick_alt(&emgr, device_index, NULL) < 0) {
            g_log_client_fd = -1;
            usb_manager_cleanup(&emgr);
            g_state = "idle";
            return send_error(client_fd, "erase failed: device not found");
        }
        tdfu_error_t er = tdfu_dfu_erase(&emgr, device_index);
        g_log_client_fd = -1;
        usb_manager_cleanup(&emgr);
        g_state = "idle";
        if (er != TDFU_SUCCESS) {
            char msg[128];
            snprintf(msg, sizeof(msg), "erase failed: %s", tdfu_error_to_string(er));
            return send_error(client_fd, msg);
        }
        return send_ok(client_fd, "OK", 2);
    }

    g_state = "writing";
    g_cancel = 0;
    printf("Write request: device=%d, cpu=%s, firmware=%u bytes (CRC OK)\n", device_index, variant_str, fw_len);

    /* Write firmware to temp file */
    char tmpfile[256];
#ifdef _WIN32
    snprintf(tmpfile, sizeof(tmpfile), "%s\\tdfu-fw-tmp.bin", getenv("TEMP") ? getenv("TEMP") : ".");
#else
    snprintf(tmpfile, sizeof(tmpfile), "/tmp/tdfu-fw-XXXXXX");
    int tmpfd = mkstemp(tmpfile);
    if (tmpfd < 0)
        return send_error(client_fd, "failed to create temp file");
    close(tmpfd);
#endif
    {
        FILE *tmpf = fopen(tmpfile, "wb");
        if (!tmpf)
            return send_error(client_fd, "failed to create temp file");
        if (fwrite(fw_data, 1, fw_len, tmpf) != fw_len) {
            fclose(tmpf);
            remove(tmpfile);
            return send_error(client_fd, "failed to write temp file");
        }
        fclose(tmpf);
    }

    usb_manager_t manager = {0};
    if (usb_manager_init(&manager) != TDFU_SUCCESS) {
        remove(tmpfile);
        return send_error(client_fd, "USB init failed");
    }

    g_log_client_fd = client_fd;
    /* DFU: download to the requested alt (default alt 0 = flash). */
    int alt = dfu_pick_alt(&manager, device_index, alt_str[0] ? alt_str : NULL);
    tdfu_error_t result = (alt < 0) ? TDFU_ERROR_DEVICE_NOT_FOUND
                                    : tdfu_dfu_download(&manager, device_index, alt, tmpfile);

    uint64_t mismatch_off = 0;
    if (result == TDFU_SUCCESS && do_verify) {
        g_state = "verifying";
        printf("Verify request: device=%d, alt=%d\n", device_index, alt);
        result = tdfu_dfu_verify(&manager, device_index, alt, tmpfile, &mismatch_off);
    }
    g_log_client_fd = -1;

    remove(tmpfile);
    usb_manager_cleanup(&manager);

    g_state = "idle";
    if (result != TDFU_SUCCESS) {
        char msg[160];
        if (result == TDFU_ERROR_VERIFY)
            snprintf(msg, sizeof(msg), "verify failed at offset 0x%08llX", (unsigned long long)mismatch_off);
        else
            snprintf(msg, sizeof(msg), "write failed: %s", tdfu_error_to_string(result));
        return send_error(client_fd, msg);
    }

    return send_ok(client_fd, "OK", 2);
}

/**
 * Handle CMD_READ - read firmware from device flash.
 *
 * Payload: [1:device_idx][1:variant_len][N:variant]
 */
static int handle_read(int client_fd, const uint8_t *payload, uint32_t len) {
    if (len < 2)
        return send_error(client_fd, "payload too short");

    const uint8_t *p = payload;
    const uint8_t *end = payload + len;

    uint8_t device_index = *p++;
    uint8_t variant_len = *p++;
    if (p + variant_len > end)
        return send_error(client_fd, "bad variant length");

    char variant_str[64] = {0};
    if (variant_len >= sizeof(variant_str))
        variant_len = sizeof(variant_str) - 1;
    memcpy(variant_str, p, variant_len);
    p += variant_len;

    /* DFU alt selector (name or number; empty = default alt 0 = flash). */
    char alt_str[32] = {0};
    if (p < end) {
        uint8_t alt_len = *p++;
        if (p + alt_len > end)
            return send_error(client_fd, "bad alt length");
        memcpy(alt_str, p, alt_len < sizeof(alt_str) ? alt_len : sizeof(alt_str) - 1);
        p += alt_len;
    }

    const char *force_cpu = variant_len > 0 ? variant_str : NULL;
    printf("Read request: device=%d, cpu=%s\n", device_index, force_cpu ? force_cpu : "(auto)");

    /* Read into a temp file, then send contents back */
    char tmpfile[256];
#ifdef _WIN32
    snprintf(tmpfile, sizeof(tmpfile), "%s\\tdfu-read-tmp.bin", getenv("TEMP") ? getenv("TEMP") : ".");
#else
    {
        snprintf(tmpfile, sizeof(tmpfile), "/tmp/tdfu-read-XXXXXX");
        int tmpfd = mkstemp(tmpfile);
        if (tmpfd < 0)
            return send_error(client_fd, "failed to create temp file");
        close(tmpfd);
    }
#endif

    usb_manager_t manager = {0};
    if (usb_manager_init(&manager) != TDFU_SUCCESS) {
        remove(tmpfile);
        return send_error(client_fd, "USB init failed");
    }

    g_state = "reading";
    g_cancel = 0;
    g_log_client_fd = client_fd;
    /* DFU: upload the requested alt (default alt 0 = flash). */
    int alt = dfu_pick_alt(&manager, device_index, alt_str[0] ? alt_str : NULL);
    tdfu_error_t result = (alt < 0) ? TDFU_ERROR_DEVICE_NOT_FOUND
                                    : tdfu_dfu_upload(&manager, device_index, alt, tmpfile, 0);
    g_log_client_fd = -1;
    usb_manager_cleanup(&manager);

    if (result != TDFU_SUCCESS) {
        remove(tmpfile);
        g_state = "idle";
        char msg[128];
        snprintf(msg, sizeof(msg), "read failed: %s", tdfu_error_to_string(result));
        return send_error(client_fd, msg);
    }

    /* Read the temp file into memory */
    FILE *f = fopen(tmpfile, "rb");
    if (!f) {
        remove(tmpfile);
        g_state = "idle";
        return send_error(client_fd, "failed to open read output");
    }
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (file_size <= 0) {
        fclose(f);
        remove(tmpfile);
        g_state = "idle";
        return send_error(client_fd, "read returned empty data");
    }

    uint8_t *read_data = malloc(file_size);
    if (!read_data) {
        fclose(f);
        remove(tmpfile);
        g_state = "idle";
        return send_error(client_fd, "out of memory");
    }
    if (fread(read_data, 1, file_size, f) != (size_t)file_size) {
        free(read_data);
        fclose(f);
        remove(tmpfile);
        g_state = "idle";
        return send_error(client_fd, "failed to read firmware data");
    }
    fclose(f);
    remove(tmpfile);

    printf("Read complete: %ld bytes\n", file_size);

    /* Send data + CRC32 back */
    uint32_t data_crc = remote_crc32(read_data, file_size);
    size_t resp_len = file_size + 4;
    uint8_t *resp = malloc(resp_len);
    if (!resp) {
        free(read_data);
        g_state = "idle";
        return send_error(client_fd, "out of memory");
    }
    memcpy(resp, read_data, file_size);
    resp[file_size] = (data_crc >> 24) & 0xFF;
    resp[file_size + 1] = (data_crc >> 16) & 0xFF;
    resp[file_size + 2] = (data_crc >> 8) & 0xFF;
    resp[file_size + 3] = data_crc & 0xFF;

    int rc = send_ok(client_fd, resp, resp_len);
    free(resp);
    free(read_data);
    g_state = "idle";
    return rc;
}

static int handle_status(int client_fd) {
    return send_ok(client_fd, g_state, strlen(g_state));
}

static int handle_cancel(int client_fd) {
    g_cancel = 1;
    return send_ok(client_fd, "OK", 2);
}

/* Handle CMD_DIAG - read-only eFuse/secure-boot readout. Payload: [1:device_idx].
 * Responds with the formatted diagnostics text (same as local --diag). */
static int handle_diag(int client_fd, const uint8_t *payload, uint32_t len) {
    uint8_t device_index = (len >= 1) ? payload[0] : 0;

    usb_manager_t manager = {0};
    if (usb_manager_init(&manager) != TDFU_SUCCESS)
        return send_error(client_fd, "USB init failed");

    tdfu_diag_info_t info;
    tdfu_error_t r = tdfu_diag(&manager, device_index, &info);
    usb_manager_cleanup(&manager);
    if (r != TDFU_SUCCESS)
        return send_error(client_fd, tdfu_error_to_string(r));

    char report[8192];
    tdfu_diag_format(&info, report, sizeof(report));
    return send_ok(client_fd, report, (uint32_t)strlen(report));
}

/* Handle CMD_REBOOT - reset the SoC via the loader's "reboot" alt. Payload:
 * [1:device_idx]. The device drops off the bus as it resets, which
 * tdfu_dfu_reboot() treats as success (same as the local path). */
static int handle_reboot(int client_fd, const uint8_t *payload, uint32_t len) {
    uint8_t device_index = (len >= 1) ? payload[0] : 0;

    usb_manager_t manager = {0};
    if (usb_manager_init(&manager) != TDFU_SUCCESS)
        return send_error(client_fd, "USB init failed");

    tdfu_error_t r = tdfu_dfu_reboot(&manager, device_index);
    usb_manager_cleanup(&manager);
    if (r != TDFU_SUCCESS)
        return send_error(client_fd, tdfu_error_to_string(r));
    return send_ok(client_fd, NULL, 0);
}

/* ------------------------------------------------------------------ */
/* Client connection handler                                           */
/* ------------------------------------------------------------------ */

/* Dispatch one already-parsed command. */
static int dispatch_command(int fd, uint8_t command, const uint8_t *payload, uint32_t payload_len,
                            const char *firmware_dir) {
    switch (command) {
    case CMD_DISCOVER:
        return handle_discover(fd);
    case CMD_BOOTSTRAP:
        return handle_bootstrap(fd, payload, payload_len, firmware_dir);
    case CMD_WRITE:
        return handle_write(fd, payload, payload_len);
    case CMD_READ:
        return handle_read(fd, payload, payload_len);
    case CMD_STATUS:
        return handle_status(fd);
    case CMD_CANCEL:
        return handle_cancel(fd);
    case CMD_DIAG:
        return handle_diag(fd, payload, payload_len);
    case CMD_REBOOT:
        return handle_reboot(fd, payload, payload_len);
    default:
        return send_error(fd, "unknown command");
    }
}

/* Read one TDFU command (header + payload) via net_recv_all (works over raw TCP,
 * WebSocket, or the HTTP body buffer) and dispatch it. Returns the handler rc
 * (0 ok, <0 stop) or -2 when the stream is exhausted. */
static int process_one_command(int fd, const char *firmware_dir) {
    tdfu_msg_header_t hdr;
    if (net_recv_all(fd, &hdr, sizeof(hdr)) < 0)
        return -2;
    if (tdfu_ntohl(hdr.magic) != TDFU_PROTO_MAGIC) {
        send_error(fd, "bad magic");
        return -1;
    }
    if (hdr.version != TDFU_PROTO_VERSION) {
        send_error(fd, "version mismatch");
        return -1;
    }
    uint32_t payload_len = tdfu_ntohl(hdr.payload_len);
    if (payload_len > TDFU_MAX_PAYLOAD) {
        send_error(fd, "payload too large");
        return -1;
    }
    uint8_t *payload = NULL;
    if (payload_len > 0) {
        payload = malloc(payload_len);
        if (!payload) {
            send_error(fd, "out of memory");
            return -1;
        }
        if (net_recv_all(fd, payload, payload_len) < 0) {
            free(payload);
            return -2;
        }
    }
    int rc = dispatch_command(fd, hdr.command, payload, payload_len, firmware_dir);
    free(payload);
    return rc;
}

static void handle_client(int client_fd, const char *firmware_dir) {
    printf("Client connected\n");
    g_tdfu_log_hook = daemon_log_hook;

    /* Authentication handshake if token is configured */
    if (g_auth_token) {
        /* Expect: [4:magic][1:version][1:token_len][N:token] */
        uint8_t auth_hdr[6];
        if (net_recv_all(client_fd, auth_hdr, 6) < 0) {
            printf("Auth: failed to read handshake\n");
            return;
        }
        uint32_t raw_magic;
        memcpy(&raw_magic, auth_hdr, 4);
        uint32_t magic = tdfu_ntohl(raw_magic);
        if (magic != TDFU_PROTO_MAGIC || auth_hdr[4] != TDFU_PROTO_VERSION) {
            send_error(client_fd, "auth: bad handshake");
            return;
        }
        uint8_t token_len = auth_hdr[5];
        char token[256] = {0};
        if (token_len > 0) {
            if (net_recv_all(client_fd, token, token_len) < 0) {
                printf("Auth: failed to read token\n");
                return;
            }
        }
        /* Constant-time comparison to avoid timing side channel */
        size_t token_slen = strlen(token);
        size_t expected_slen = strlen(g_auth_token);
        volatile uint8_t diff = 0;
        for (size_t ci = 0; ci < expected_slen; ci++)
            diff |= (uint8_t)(ci < token_slen ? token[ci] : 0xFF) ^ (uint8_t)g_auth_token[ci];
        if (diff != 0 || token_slen != expected_slen) {
            send_error(client_fd, "auth: invalid token");
            printf("Auth: rejected (wrong token)\n");
            return;
        }
        /* Send OK to confirm auth */
        send_ok(client_fd, "OK", 2);
        printf("Auth: accepted\n");
    }

    while (g_running) {
        int rc = process_one_command(client_fd, firmware_dir);
        if (rc < 0)
            break;
    }

    g_tdfu_log_hook = NULL;
    g_log_client_fd = -1;
    printf("Client disconnected\n");
}

/* Handle one HTTP POST request: the body carries a single TDFU command, and the
 * chunked response streams the TDFU reply (progress/log frames then OK/ERROR).
 * This is the path the browser flasher uses via fetch({targetAddressSpace}). */
static void handle_http(int client_fd, const char *firmware_dir) {
    printf("HTTP client\n");

    /* Read request line + headers (up to the blank line). */
    char req[8192];
    size_t n = 0;
    while (n < sizeof(req) - 1) {
        char ch;
        if (raw_recv_all(client_fd, &ch, 1) < 0)
            return;
        req[n++] = ch;
        if (n >= 4 && memcmp(req + n - 4, "\r\n\r\n", 4) == 0)
            break;
    }
    req[n] = '\0';

    long clen = 0;
    char token[256] = {0};
    for (char *p = req; *p; p++) {
        if (strncasecmp(p, "Content-Length:", 15) == 0) {
            clen = atol(p + 15);
        } else if (strncasecmp(p, "X-Auth-Token:", 13) == 0) {
            const char *v = p + 13;
            while (*v == ' ')
                v++;
            size_t k = 0;
            while (*v && *v != '\r' && *v != '\n' && k < sizeof(token) - 1)
                token[k++] = *v++;
            token[k] = '\0';
        }
    }
    if (clen < 0 || clen > (long)TDFU_MAX_PAYLOAD) {
        const char *r = "HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\n\r\n";
        raw_send_all(client_fd, r, strlen(r));
        return;
    }

    uint8_t *body = NULL;
    if (clen > 0) {
        body = malloc((size_t)clen);
        if (!body || raw_recv_all(client_fd, body, (size_t)clen) < 0) {
            free(body);
            return;
        }
    }

    if (g_auth_token) {
        size_t tl = strlen(token), el = strlen(g_auth_token);
        volatile uint8_t diff = 0;
        for (size_t ci = 0; ci < el; ci++)
            diff |= (uint8_t)(ci < tl ? token[ci] : 0xFF) ^ (uint8_t)g_auth_token[ci];
        if (diff != 0 || tl != el) {
            const char *r = "HTTP/1.1 403 Forbidden\r\nAccess-Control-Allow-Origin: *\r\n"
                            "Access-Control-Allow-Private-Network: true\r\nContent-Length: 0\r\n\r\n";
            raw_send_all(client_fd, r, strlen(r));
            free(body);
            return;
        }
    }

    const char *preamble = "HTTP/1.1 200 OK\r\n"
                           "Access-Control-Allow-Origin: *\r\n"
                           "Access-Control-Allow-Private-Network: true\r\n"
                           "Content-Type: application/octet-stream\r\n"
                           "Cache-Control: no-store\r\n"
                           "Transfer-Encoding: chunked\r\n"
                           "\r\n";
    if (raw_send_all(client_fd, preamble, strlen(preamble)) < 0) {
        free(body);
        return;
    }

    http_conn_t hc = {.fd = client_fd, .body = body, .blen = (size_t)(clen > 0 ? clen : 0), .bpos = 0};
    g_http = &hc;
    g_tdfu_log_hook = daemon_log_hook;
    g_log_client_fd = client_fd;
    process_one_command(client_fd, firmware_dir);
    g_tdfu_log_hook = NULL;
    g_log_client_fd = -1;
    g_http = NULL;

    raw_send_all(client_fd, "0\r\n\r\n", 5); /* terminating chunk */
    free(body);
    printf("HTTP request done\n");
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */

static void print_usage(const char *name) {
    printf("dfu-remote - thingino-dfu remote daemon\n");
    printf("Usage: %s [options]\n\n", name);
    printf("Options:\n");
    printf("  -p, --port <port>         Listen port (default: %d)\n", TDFU_DEFAULT_PORT);
    printf("  --firmware-dir <dir>      Firmware root directory (default: ./firmware)\n");
    printf("  --token <secret>          Require auth token from clients\n");
    printf("  -d, --debug               Enable debug output\n");
    printf("  -h, --help                Show this help\n");
}

/* Resolve firmware directory relative to this binary's location */
static const char *resolve_firmware_dir(const char *argv0) {
    static char buf[4096];
#ifdef _WIN32
    DWORD len = GetModuleFileNameA(NULL, buf, sizeof(buf));
    if (len > 0 && len < sizeof(buf)) {
        char *sep = strrchr(buf, '\\');
        if (sep) {
            snprintf(sep + 1, sizeof(buf) - (sep + 1 - buf), "firmware");
            return buf;
        }
    }
#else
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (len > 0) {
        buf[len] = '\0';
        char *sep = strrchr(buf, '/');
        if (sep) {
            snprintf(sep + 1, sizeof(buf) - (sep + 1 - buf), "firmware");
            return buf;
        }
    }
#endif
    (void)argv0;
    return "./firmware";
}

int main(int argc, char **argv) {
    int port = TDFU_DEFAULT_PORT;
    const char *firmware_dir = resolve_firmware_dir(argv[0]);

    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--port") == 0) && i + 1 < argc) {
            port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--firmware-dir") == 0 && i + 1 < argc) {
            firmware_dir = argv[++i];
        } else if (strcmp(argv[i], "--token") == 0 && i + 1 < argc) {
            g_auth_token = argv[++i];
        } else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--debug") == 0) {
            g_debug_enabled = true;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }

#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }
#endif

    signal(SIGINT, signal_handler);
#ifndef _WIN32
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);
#endif

    /* Create listening socket. Prefer AF_INET6 with IPV6_V6ONLY cleared so one
     * socket serves both families - IPv4 peers arrive as v4-mapped addresses.
     * Only fall back to AF_INET where IPv6 is unavailable. */
    int server_fd;
    bool server_v6 = true;

    server_fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (server_fd < 0) {
        server_v6 = false;
        server_fd = socket(AF_INET, SOCK_STREAM, 0);
    }
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));

    int bind_rc;
    if (server_v6) {
        int v6only = 0;
        setsockopt(server_fd, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&v6only, sizeof(v6only));

        struct sockaddr_in6 addr6 = {
            .sin6_family = AF_INET6,
            .sin6_port = htons(port),
            .sin6_addr = IN6ADDR_ANY_INIT,
        };
        bind_rc = bind(server_fd, (struct sockaddr *)&addr6, sizeof(addr6));
    } else {
        struct sockaddr_in addr = {
            .sin_family = AF_INET,
            .sin_port = htons(port),
            .sin_addr.s_addr = INADDR_ANY,
        };
        bind_rc = bind(server_fd, (struct sockaddr *)&addr, sizeof(addr));
    }

    if (bind_rc < 0) {
        perror("bind");
        CLOSE_SOCKET(server_fd);
        return 1;
    }

    if (listen(server_fd, 1) < 0) {
        perror("listen");
        CLOSE_SOCKET(server_fd);
        return 1;
    }

    g_server_fd = server_fd;

    printf("dfu-remote listening on port %d\n", port);
    printf("Firmware directory: %s\n", firmware_dir);

    while (g_running) {
        struct sockaddr_storage client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            break;
        }

        char client_host[INET6_ADDRSTRLEN] = "?";
        char client_port[8] = "?";
        getnameinfo((struct sockaddr *)&client_addr, client_len, client_host, sizeof(client_host), client_port,
                    sizeof(client_port), NI_NUMERICHOST | NI_NUMERICSERV);
        printf("Connection from %s:%s\n", client_host, client_port);

        /* Peek the first byte to tell a browser WebSocket client (HTTP "GET" /
         * "OPTIONS" preflight) from a raw-TCP CLI/Android client (TDFU magic,
         * starts with 'T'). */
        char peek[8] = {0};
        int pn = (int)recv(client_fd, peek, sizeof(peek) - 1, MSG_PEEK);
        if (pn >= 1 && peek[0] == 'G') {
            ws_conn_t ws = {.fd = client_fd, .frame_remaining = 0, .mask_pos = 0};
            if (ws_handshake(client_fd) == 0) {
                printf("WebSocket client\n");
                g_ws = &ws;
                handle_client(client_fd, firmware_dir);
                g_ws = NULL;
            } else {
                printf("WebSocket handshake failed\n");
            }
        } else if (pn >= 1 && peek[0] == 'P') {
            handle_http(client_fd, firmware_dir); /* fetch() POST transport */
        } else if (pn >= 1 && peek[0] == 'O') {
            ws_preflight(client_fd); /* Local Network Access / CORS preflight */
        } else {
            handle_client(client_fd, firmware_dir);
        }
        CLOSE_SOCKET(client_fd);
    }

    if (g_server_fd >= 0)
        CLOSE_SOCKET(g_server_fd);
    printf("\ndfu-remote stopped\n");
    return 0;
}
