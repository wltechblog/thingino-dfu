/**
 * DFU backend - host-side USB DFU 1.1 for devices in U-Boot DFU mode.
 *
 * Plain DFU 1.1 only (no DfuSe). Medium-agnostic: the host just moves bytes
 * to/from named alt-settings; where they land (SPI NOR / SPI NAND / MMC /
 * MTD / ...) is decided by the device's U-Boot dfu_alt_info.
 *
 * Built on usb_device_control_transfer() for the class requests, so it works
 * over any of libtdfu's USB backends that implement control transfers.
 * Device discovery + descriptor parsing use libusb directly (native/Android);
 * the WebUSB shim needs equivalents for full web support.
 */

#include "tdfu/tdfu.h"
#include "tdfu/dfu.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ----- DFU class requests (USB DFU 1.1, section 3) ----- */
#define DFU_DETACH    0
#define DFU_DNLOAD    1
#define DFU_UPLOAD    2
#define DFU_GETSTATUS 3
#define DFU_CLRSTATUS 4
#define DFU_GETSTATE  5
#define DFU_ABORT     6

/* bmRequestType: class request, recipient = interface */
#define DFU_BMREQ_OUT 0x21 /* host -> device */
#define DFU_BMREQ_IN  0xA1 /* device -> host */

/* DFU states (GETSTATUS bState) */
enum {
    DFU_STATE_appIDLE = 0,
    DFU_STATE_appDETACH,
    DFU_STATE_dfuIDLE,
    DFU_STATE_dfuDNLOAD_SYNC,
    DFU_STATE_dfuDNBUSY,
    DFU_STATE_dfuDNLOAD_IDLE,
    DFU_STATE_dfuMANIFEST_SYNC,
    DFU_STATE_dfuMANIFEST,
    DFU_STATE_dfuMANIFEST_WAIT_RESET,
    DFU_STATE_dfuUPLOAD_IDLE,
    DFU_STATE_dfuERROR,
};

#define DFU_STATUS_OK 0x00

/* DFU functional descriptor + interface identifiers */
#define DFU_FUNC_DESC_TYPE     0x21
#define DFU_INTERFACE_CLASS    0xFE /* application specific */
#define DFU_INTERFACE_SUBCLASS 0x01 /* DFU */

typedef struct {
    uint8_t bStatus;
    uint32_t bwPollTimeout; /* milliseconds (24-bit) */
    uint8_t bState;
    uint8_t iString;
} dfu_status_t;

/* ====================================================================== */
/* Class requests                                                          */
/* ====================================================================== */

static tdfu_error_t dfu_get_status(usb_device_t *dev, uint16_t iface, dfu_status_t *st) {
    uint8_t buf[6];
    int got = 0;
    tdfu_error_t r = usb_device_control_transfer(dev, DFU_BMREQ_IN, DFU_GETSTATUS, 0, iface, buf, sizeof(buf), &got);
    if (r != TDFU_SUCCESS)
        return r;
    if (got != 6)
        return TDFU_ERROR_PROTOCOL;
    st->bStatus = buf[0];
    st->bwPollTimeout = (uint32_t)buf[1] | ((uint32_t)buf[2] << 8) | ((uint32_t)buf[3] << 16);
    st->bState = buf[4];
    st->iString = buf[5];
    return TDFU_SUCCESS;
}

static tdfu_error_t dfu_clr_status(usb_device_t *dev, uint16_t iface) {
    return usb_device_control_transfer(dev, DFU_BMREQ_OUT, DFU_CLRSTATUS, 0, iface, NULL, 0, NULL);
}

static tdfu_error_t dfu_abort(usb_device_t *dev, uint16_t iface) {
    return usb_device_control_transfer(dev, DFU_BMREQ_OUT, DFU_ABORT, 0, iface, NULL, 0, NULL);
}

/* DNLOAD blocks get a long USB timeout: when the block before crossed the
 * loader's DFU buffer boundary (dfu_bufsiz, 2 MiB), the loader flushes the
 * whole buffer to flash inside the request context and NAKs the next setup
 * for the duration. A T40XP NAND flush exceeds the 5s default, so the host
 * abandoned the transfer mid-data-stage, the device recorded errSTALLEDPKT,
 * and the write died at exactly 2 MiB ("DFU download stalled"). The timeout
 * only matters on genuine failure, so long is safe. */
#define DFU_DNLOAD_TIMEOUT_MS 30000

static tdfu_error_t dfu_dnload(usb_device_t *dev, uint16_t iface, uint16_t block, const uint8_t *data, uint16_t len) {
    return usb_device_control_transfer_to(dev, DFU_BMREQ_OUT, DFU_DNLOAD, block, iface, (uint8_t *)data, len, NULL,
                                          DFU_DNLOAD_TIMEOUT_MS);
}

static tdfu_error_t dfu_upload_block(usb_device_t *dev, uint16_t iface, uint16_t block, uint8_t *data, uint16_t len,
                                     int *got) {
    return usb_device_control_transfer(dev, DFU_BMREQ_IN, DFU_UPLOAD, block, iface, data, len, got);
}

/* Drive the device back to dfuIDLE (clear errors / abort a stuck transfer).
 * Bails immediately if GET_STATUS itself fails: that means the gadget is
 * unresponsive (a dwc2 EP0 wedge after an interrupted DNLOAD), and the caller
 * recovers with a USB reset rather than wasting 5s timeouts on aborts that also
 * hang. On a responsive device (e.g. dfuERROR after a stale-sequence STALL),
 * GET_STATUS succeeds and we clear it normally. */
static tdfu_error_t dfu_make_idle(usb_device_t *dev, uint16_t iface) {
    dfu_status_t st;
    for (int retry = 0; retry < 3; retry++) {
        tdfu_error_t gr = dfu_get_status(dev, iface, &st);
        if (gr != TDFU_SUCCESS) {
            LOG_DEBUG("make_idle: GET_STATUS failed (%s)\n", tdfu_error_to_string(gr));
            return gr;
        }
        LOG_DEBUG("make_idle: try %d -> state=%u status=%u\n", retry, st.bState, st.bStatus);
        if (st.bState == DFU_STATE_dfuIDLE)
            return TDFU_SUCCESS;
        if (st.bState == DFU_STATE_dfuERROR)
            dfu_clr_status(dev, iface);
        else
            dfu_abort(dev, iface);
    }
    LOG_DEBUG("make_idle: not idle after 3 tries (last state=%u) -> PROTOCOL\n", st.bState);
    return TDFU_ERROR_PROTOCOL;
}

/* Poll GETSTATUS, honoring bwPollTimeout while the device is busy. Returns
 * the settled status in *st. Critical for slow NAND/NOR erase+write.
 *
 * grace_retries forgives that many CONSECUTIVE failed GETSTATUS transfers
 * before giving up. A loader erasing a whole chip can hold off EP0 past the
 * 5s control-transfer timeout without being dead; failing on the first
 * swallowed poll aborts the operation into the USB-reset recovery, whose
 * retry then lands on a device that is still busy (the T40XP whole-chip
 * erase: reset mid-manifest -> re-sent token refused as "bad token" while
 * the first erase completes anyway). Pass 0 for the historic fail-fast
 * behavior - reboot depends on it (its post-ZLP poll failing IS the reset
 * happening), and the short per-block write/read waits keep it too. */
static tdfu_error_t dfu_poll_until_ready_grace(usb_device_t *dev, uint16_t iface, dfu_status_t *st,
                                               int grace_retries) {
    int failures = 0;
    for (int i = 0; i < 1000; i++) {
        tdfu_error_t r = dfu_get_status(dev, iface, st);
        if (r != TDFU_SUCCESS) {
            if (failures < grace_retries) {
                failures++;
                LOG_DEBUG("GETSTATUS lost while device busy (%d/%d) - retrying, not resetting\n", failures,
                          grace_retries);
                tdfu_sleep_milliseconds(500);
                continue;
            }
            return r;
        }
        failures = 0;
        if (st->bStatus != DFU_STATUS_OK)
            return TDFU_ERROR_PROTOCOL;
        if (st->bState != DFU_STATE_dfuDNBUSY && st->bState != DFU_STATE_dfuMANIFEST)
            return TDFU_SUCCESS;
        if (st->bwPollTimeout)
            tdfu_sleep_milliseconds(st->bwPollTimeout);
    }
    return TDFU_ERROR_TIMEOUT;
}

static tdfu_error_t dfu_poll_until_ready(usb_device_t *dev, uint16_t iface, dfu_status_t *st) {
    return dfu_poll_until_ready_grace(dev, iface, st, 0);
}

/* How many consecutive lost GETSTATUS polls to forgive. Each costs the 5s
 * control-transfer timeout + 500ms backoff.
 *
 * Erase manifest: 36 covers ~3 minutes of EP0 silence - enough for a
 * whole-chip erase of the largest parts we ship loaders for (a 256 MiB
 * T40XP NAND takes tens of seconds).
 *
 * Write blocks: 12 (~1 minute) rides out the loader's DFU-buffer flush to
 * flash between blocks. */
#define DFU_ERASE_GRACE_RETRIES 36
#define DFU_WRITE_GRACE_RETRIES 12

/* ====================================================================== */
/* Descriptor parsing + device discovery                                  */
/* ====================================================================== */

/* Standard GET_DESCRIPTOR (device-to-host, standard, device). Returns the
 * number of bytes read, or -1. Uses only control transfers, so it works over
 * native libusb and the WebUSB shim alike. */
static int dfu_get_descriptor(usb_device_t *dev, uint8_t type, uint8_t index, uint16_t langid, uint8_t *buf,
                              uint16_t len) {
    int got = 0;
    tdfu_error_t r =
        usb_device_control_transfer(dev, 0x80, 0x06, (uint16_t)((type << 8) | index), langid, buf, len, &got);
    return (r == TDFU_SUCCESS) ? got : -1;
}

/* Read a USB string descriptor (index) as ASCII (best-effort from UTF-16LE). */
static void dfu_get_string(usb_device_t *dev, uint8_t index, char *out, size_t outsz) {
    out[0] = '\0';
    if (!index)
        return;
    uint8_t buf[256];
    int n = dfu_get_descriptor(dev, 0x03 /* STRING */, index, 0x0409, buf, sizeof(buf));
    if (n < 2 || buf[1] != 0x03)
        return;
    int chars = (buf[0] - 2) / 2;
    size_t o = 0;
    for (int i = 0; i < chars && (size_t)(2 + i * 2 + 1) < (size_t)n && o + 1 < outsz; i++) {
        uint16_t ch = (uint16_t)buf[2 + i * 2] | ((uint16_t)buf[2 + i * 2 + 1] << 8);
        out[o++] = (ch && ch < 0x80) ? (char)ch : '?';
    }
    out[o] = '\0';
}

/* Read the full active configuration descriptor (including class-specific
 * descriptors like the DFU functional descriptor) into buf. Returns length. */
static int dfu_read_config(usb_device_t *dev, uint8_t *buf, uint16_t cap) {
    uint8_t hdr[9];
    if (dfu_get_descriptor(dev, 0x02 /* CONFIGURATION */, 0, 0, hdr, sizeof(hdr)) < 4)
        return -1;
    uint16_t total = (uint16_t)hdr[2] | ((uint16_t)hdr[3] << 8);
    if (total < 4 || total > cap)
        return -1;
    int n = dfu_get_descriptor(dev, 0x02, 0, 0, buf, total);
    return (n >= 4) ? n : -1;
}

/* Does this raw config descriptor expose a DFU interface (class 0xFE/sub 1)? */
static bool dfu_config_is_dfu(const uint8_t *cfg, int total) {
    for (int pos = 0; pos + 2 <= total;) {
        uint8_t blen = cfg[pos];
        if (blen < 2 || pos + blen > total)
            break;
        if (cfg[pos + 1] == 0x04 /* INTERFACE */ && blen >= 9 && cfg[pos + 5] == DFU_INTERFACE_CLASS &&
            cfg[pos + 6] == DFU_INTERFACE_SUBCLASS)
            return true;
        pos += blen;
    }
    return false;
}

static tdfu_error_t dfu_read_info(usb_device_t *dev, tdfu_dfu_info_t *info) {
    memset(info, 0, sizeof(*info));
    info->transfer_size = 1024; /* default if no functional descriptor is present */

    uint8_t cfg[1024];
    int total = dfu_read_config(dev, cfg, sizeof(cfg));
    if (total < 4)
        return TDFU_ERROR_PROTOCOL;

    /* Walk the raw config descriptor: collect DFU alt-settings (+ names) and
     * the DFU functional descriptor (wTransferSize / bcdDFU). */
    for (int pos = 0; pos + 2 <= total;) {
        uint8_t blen = cfg[pos], btype = cfg[pos + 1];
        if (blen < 2 || pos + blen > total)
            break;
        if (btype == 0x04 /* INTERFACE */ && blen >= 9 && cfg[pos + 5] == DFU_INTERFACE_CLASS &&
            cfg[pos + 6] == DFU_INTERFACE_SUBCLASS && info->alt_count < TDFU_DFU_MAX_ALTS) {
            info->interface = cfg[pos + 2];
            tdfu_dfu_alt_t *a = &info->alts[info->alt_count++];
            a->alt = cfg[pos + 3];
            dfu_get_string(dev, cfg[pos + 8] /* iInterface */, a->name, sizeof(a->name));
        } else if (btype == DFU_FUNC_DESC_TYPE && blen >= 9) {
            info->attributes = cfg[pos + 2];
            info->transfer_size = (uint16_t)cfg[pos + 5] | ((uint16_t)cfg[pos + 6] << 8);
            info->bcd_dfu = (uint16_t)cfg[pos + 7] | ((uint16_t)cfg[pos + 8] << 8);
        }
        pos += blen;
    }

    if (info->alt_count == 0) {
        LOG_ERROR("No DFU interface found - is the device in U-Boot DFU mode?\n");
        return TDFU_ERROR_DEVICE_NOT_FOUND;
    }
    if (info->transfer_size == 0)
        info->transfer_size = 1024;
    return TDFU_SUCCESS;
}

/* Open the index-th Ingenic device that exposes a DFU interface. Restricted to
 * Ingenic VIDs (so we never open unrelated USB devices), and the DFU interface
 * is confirmed by reading the config descriptor over a control transfer - the
 * same path works on native libusb and the WebUSB shim. */
static tdfu_error_t dfu_open_device(usb_manager_t *manager, int index, usb_device_t **out) {
    /* Guard on `initialized`, not `context`: the WebUSB shim leaves context
     * NULL (and ignores it) while the manager is fully initialized. */
    if (!manager || !manager->initialized)
        return TDFU_ERROR_INIT_FAILED;

    libusb_device **list = NULL;
    ssize_t cnt = libusb_get_device_list(manager->context, &list);
    if (cnt < 0)
        return TDFU_ERROR_INIT_FAILED;

    LOG_DEBUG("dfu_open_device: scanning %zd USB devices for a DFU interface\n", cnt);
    usb_device_t *found = NULL;
    int match = 0;
    bool access_denied = false;
    for (ssize_t i = 0; i < cnt && !found; i++) {
        struct libusb_device_descriptor dd;
        if (libusb_get_device_descriptor(list[i], &dd) != 0)
            continue;
        if (dd.idVendor != 0x601A && dd.idVendor != 0xA108)
            continue;

        libusb_device_handle *handle = NULL;
        int orc = libusb_open(list[i], &handle);
        if (orc != 0 || !handle) {
            if (orc == LIBUSB_ERROR_ACCESS) {
                access_denied = true;
                LOG_ERROR("Cannot open %04x:%04x: OS denied USB access. Grant access to this device "
                          "(Linux: udev rule for this VID:PID; Windows: bind WinUSB via Zadig), then "
                          "replug and reconnect.\n",
                          dd.idVendor, dd.idProduct);
            } else {
                LOG_WARN("Cannot open %04x:%04x (libusb error %d)\n", dd.idVendor, dd.idProduct, orc);
            }
            continue;
        }

        usb_device_t probe = {0};
        probe.handle = handle;
        probe.context = manager->context;
        uint8_t cfg[512];
        int n = dfu_read_config(&probe, cfg, sizeof(cfg));
        int isdfu = (n >= 4) && dfu_config_is_dfu(cfg, n);
        LOG_DEBUG("dfu scan: %04x:%04x config=%d bytes, is_dfu=%d\n", dd.idVendor, dd.idProduct, n, isdfu);
        if (isdfu && match++ == index) {
            usb_device_t *dev = (usb_device_t *)calloc(1, sizeof(*dev));
            if (!dev) {
                libusb_close(handle);
                libusb_free_device_list(list, 1);
                return TDFU_ERROR_MEMORY;
            }
            dev->handle = handle;
            dev->context = manager->context;
            dev->closed = false;
            found = dev;
        } else {
            libusb_close(handle);
        }
    }
    libusb_free_device_list(list, 1);

    if (!found)
        return access_denied ? TDFU_ERROR_OPEN_FAILED : TDFU_ERROR_DEVICE_NOT_FOUND;
    *out = found;
    return TDFU_SUCCESS;
}

static void dfu_close_device(usb_device_t *dev, int iface) {
    if (!dev)
        return;
    if (dev->handle) {
        libusb_release_interface(dev->handle, iface);
        libusb_close(dev->handle);
    }
    free(dev);
}

/* Recover a wedged DFU gadget with a USB bus reset. An interrupted control-OUT
 * (a DFU DNLOAD - e.g. a browser reload mid-write) leaves the dwc2 UDC's EP0
 * stuck so it stops answering control transfers entirely; a bus reset re-inits
 * the gadget's endpoints (verified on A1/T31). The wedged device can't be
 * confirmed as DFU through its config descriptor (that read hangs too), so it
 * is matched by Ingenic VID only. Returns true if a device was reset. */
static bool dfu_reset_device(usb_manager_t *manager, int device_index) {
    if (!manager || !manager->initialized)
        return false;
    libusb_device **list = NULL;
    ssize_t cnt = libusb_get_device_list(manager->context, &list);
    if (cnt < 0)
        return false;
    bool did_reset = false;
    int match = 0;
    for (ssize_t i = 0; i < cnt; i++) {
        struct libusb_device_descriptor dd;
        if (libusb_get_device_descriptor(list[i], &dd) != 0)
            continue;
        if (dd.idVendor != 0x601A && dd.idVendor != 0xA108)
            continue;
        if (match++ != device_index)
            continue;
        libusb_device_handle *h = NULL;
        if (libusb_open(list[i], &h) == 0 && h) {
            LOG_WARN("DFU gadget unresponsive - issuing a USB reset to recover\n");
            libusb_reset_device(h);
            libusb_close(h);
            did_reset = true;
        }
        break;
    }
    libusb_free_device_list(list, 1);
    if (did_reset)
        tdfu_sleep_milliseconds(1500); /* let the gadget re-enumerate */
    return did_reset;
}

/* Errors that signal a device-comms failure a USB reset might clear (vs. a
 * local error like FILE_IO/MEMORY where a reset would be pointless). */
static bool dfu_err_recoverable(tdfu_error_t r) {
    return r == TDFU_ERROR_TRANSFER_FAILED || r == TDFU_ERROR_TRANSFER_TIMEOUT || r == TDFU_ERROR_TIMEOUT ||
           r == TDFU_ERROR_PROTOCOL || r == TDFU_ERROR_DEVICE_NOT_FOUND || r == TDFU_ERROR_OPEN_FAILED;
}

/* SET_INTERFACE (host-to-device, standard, interface) to select the alt. */
static tdfu_error_t dfu_set_interface(usb_device_t *dev, uint16_t iface, uint16_t alt) {
    return usb_device_control_transfer(dev, 0x01, 0x0B, alt, iface, NULL, 0, NULL);
}

/* Set the device configuration (the driverless DFU gadget often has none set,
 * which makes claim fail), claim the DFU interface, and select the alt.
 * multi_alt: whether the interface exposes more than one alt (info->alt_count
 * > 1) - decides if SET_INTERFACE is issued for alt 0 too. */
static tdfu_error_t dfu_claim_alt_ex(usb_device_t *dev, int iface, int alt, bool multi_alt) {
    uint8_t hdr[9];
    int cfgval = 1;
    if (dfu_get_descriptor(dev, 0x02, 0, 0, hdr, sizeof(hdr)) >= 6)
        cfgval = hdr[5]; /* bConfigurationValue */

    int cur = 0;
    if (libusb_get_configuration(dev->handle, &cur) != 0 || cur != cfgval)
        libusb_set_configuration(dev->handle, cfgval);

    if (libusb_claim_interface(dev->handle, iface) != 0) {
        LOG_ERROR("Failed to claim DFU interface %d\n", iface);
        return TDFU_ERROR_OPEN_FAILED;
    }
    /* SET_INTERFACE is only required to switch to a NON-default alt. A single-alt
     * interface (U-Boot's DFU gadget) is allowed by USB 9.4.10 to STALL it, and
     * over WebUSB that STALL wedges EP0 - breaking every following GET_STATUS /
     * UPLOAD. So never issue it for the default alt 0 on those.
     *
     * On a MULTI-alt gadget the skip is a bug: after an erase (which selected
     * the "erase" virt alt), "claiming alt 0" without SET_INTERFACE leaves the
     * erase alt live, and the following image write's first block lands on it
     * ("dfu erase: bad token") - only the error-recovery USB reset put the
     * device back on alt 0. Multi-alt gadgets accept SET_INTERFACE by
     * definition (switching onto the other alts already relies on it), so
     * issue it for alt 0 whenever there is more than one alt. */
    if ((alt != 0 || multi_alt) && dfu_set_interface(dev, (uint16_t)iface, (uint16_t)alt) != TDFU_SUCCESS) {
        LOG_ERROR("Failed to select DFU alt setting %d\n", alt);
        return TDFU_ERROR_PROTOCOL;
    }
    return TDFU_SUCCESS;
}

/* ====================================================================== */
/* Public API                                                              */
/* ====================================================================== */

/* Lightweight, non-destructive presence check for the U-Boot DFU gadget
 * (a108:4d44): a VID:PID device-list scan only - no open, no probe, no reset -
 * so it is safe to poll (e.g. for --wait) without disturbing a bootrom that may
 * also be present. */
bool tdfu_dfu_gadget_present(usb_manager_t *manager) {
    if (!manager || !manager->initialized)
        return false;
    libusb_device **list = NULL;
    ssize_t cnt = libusb_get_device_list(manager->context, &list);
    if (cnt < 0)
        return false;
    bool found = false;
    for (ssize_t i = 0; i < cnt && !found; i++) {
        struct libusb_device_descriptor dd;
        if (libusb_get_device_descriptor(list[i], &dd) != 0)
            continue;
        if (dd.idVendor != 0x601A && dd.idVendor != 0xA108)
            continue;
        /* The standard DFU gadget PID, or any Ingenic device exposing a DFU
         * interface (class 0xFE/sub 0x01) - the latter catches a gadget that
         * shares the bootrom PID (0xC309). */
        if (dd.idProduct == 0x4D44 || usb_dev_has_dfu_interface(list[i]))
            found = true;
    }
    libusb_free_device_list(list, 1);
    return found;
}

static tdfu_error_t dfu_probe_impl(usb_manager_t *manager, int device_index, tdfu_dfu_info_t *info) {
    usb_device_t *dev = NULL;
    tdfu_error_t r = dfu_open_device(manager, device_index, &dev);
    if (r != TDFU_SUCCESS)
        return r;
    r = dfu_read_info(dev, info);
    dfu_close_device(dev, info->interface);
    return r;
}

/* Probe with the same wedge-recovery as the transfers: native callers probe
 * BEFORE reading/writing, and a gadget wedged by an interrupted DNLOAD fails
 * the probe's descriptor read - so USB-reset and retry once. (On the WebUSB
 * shim the probe is served from the cached config and succeeds anyway.) */
tdfu_error_t tdfu_dfu_probe(usb_manager_t *manager, int device_index, tdfu_dfu_info_t *info) {
    if (!info)
        return TDFU_ERROR_INVALID_PARAMETER;
    tdfu_error_t r = dfu_probe_impl(manager, device_index, info);
    if (r != TDFU_SUCCESS && dfu_err_recoverable(r) && dfu_reset_device(manager, device_index))
        r = dfu_probe_impl(manager, device_index, info);
    return r;
}

int tdfu_dfu_find_alt(const tdfu_dfu_info_t *info, const char *name_or_num) {
    if (!info || !name_or_num)
        return -1;
    for (int i = 0; i < info->alt_count; i++) {
        if (strcmp(info->alts[i].name, name_or_num) == 0)
            return info->alts[i].alt;
    }
    /* fall back to a decimal alt number */
    char *end = NULL;
    long n = strtol(name_or_num, &end, 10);
    if (end && *end == '\0') {
        for (int i = 0; i < info->alt_count; i++)
            if (info->alts[i].alt == (int)n)
                return (int)n;
    }
    return -1;
}

/* Default alt when the user gave none. Loaders grew a second alt ("erase"),
 * so "exactly one alt -> take it" alone no longer covers the common case;
 * prefer the boot flash by its well-known name. */
int tdfu_dfu_default_alt(const tdfu_dfu_info_t *info) {
    if (!info)
        return -1;
    int alt = tdfu_dfu_find_alt(info, "flash");
    if (alt >= 0)
        return alt;
    return info->alt_count == 1 ? info->alts[0].alt : -1;
}

/* ====================================================================== */
/* Device-level DFU read/write: operate on an already-open usb_device_t.   */
/* Used by the manager-based wrappers (after dfu_open_device) AND by the    */
/* Android JNI (which wraps an OS-provided fd - no manager enumeration).    */
/* alt < 0 selects the single/first alt setting. The caller owns dev.       */
/* ====================================================================== */

tdfu_error_t tdfu_dfu_write_device(usb_device_t *dev, int alt, const char *path) {
    tdfu_dfu_info_t info;
    uint8_t *data = NULL;
    size_t len = 0;

    tdfu_error_t r = dfu_read_info(dev, &info);
    if (r != TDFU_SUCCESS)
        return r;
    if (alt < 0)
        alt = info.alt_count > 0 ? info.alts[0].alt : 0;
    r = dfu_claim_alt_ex(dev, info.interface, alt, info.alt_count > 1);
    if (r != TDFU_SUCCESS)
        return r;

    r = load_file(path, &data, &len);
    if (r != TDFU_SUCCESS) {
        LOG_ERROR("Failed to read %s\n", path);
        return r;
    }

    LOG_DEBUG("DFU download: %s -> alt %d (%zu bytes, %u-byte blocks)\n", path, alt, len, info.transfer_size);

    /* A reload mid-transfer can leave U-Boot expecting a stale block sequence.
     * The first block-0 write trips its cleanup + STALL, so on a block-0 failure
     * we clear the error and retry once. */
    uint16_t block = 0;
    size_t offset = 0;
    dfu_status_t st;
    for (int attempt = 0; attempt < 2; attempt++) {
        if (dfu_make_idle(dev, info.interface) != TDFU_SUCCESS) {
            LOG_ERROR("Device not in a DFU-idle state\n");
            r = TDFU_ERROR_PROTOCOL;
            break;
        }
        block = 0;
        offset = 0;
        r = TDFU_SUCCESS;
        while (offset < len) {
            uint16_t chunk = (len - offset > info.transfer_size) ? info.transfer_size : (uint16_t)(len - offset);
            r = dfu_dnload(dev, info.interface, block, data + offset, chunk);
            if (r != TDFU_SUCCESS)
                break;
            /* Grace: a post-block GETSTATUS can be swallowed while the loader
             * flushes its DFU buffer to flash (EP0 held off past the 5s
             * transfer timeout). The device is busy, not gone. */
            r = dfu_poll_until_ready_grace(dev, info.interface, &st, DFU_WRITE_GRACE_RETRIES);
            if (r != TDFU_SUCCESS) {
                LOG_ERROR("DFU download stalled at %zu/%zu (status %u, state %u)\n", offset, len, st.bStatus,
                          st.bState);
                break;
            }
            offset += chunk;
            block++;
            LOG_INFO("\r  %zu/%zu bytes (%d%%)", offset, len, (int)(offset * 100 / len));
        }
        if (r == TDFU_SUCCESS || block != 0)
            break; /* done, or a genuine mid-stream error (not a stale sequence) */
        LOG_WARN("DFU download: clearing a stale transaction (reload mid-transfer?) and retrying\n");
    }

    if (r == TDFU_SUCCESS) {
        /* zero-length DNLOAD signals end-of-transfer, then manifest. The
         * manifest is where the final buffer flush runs - and where the erase
         * executes when this download carried the wipe token to the "erase"
         * alt (the remote path drives erase as a plain token write), so it
         * gets the full erase-sized grace. */
        r = dfu_dnload(dev, info.interface, block, NULL, 0);
        if (r == TDFU_SUCCESS)
            r = dfu_poll_until_ready_grace(dev, info.interface, &st, DFU_ERASE_GRACE_RETRIES);
        LOG_INFO("\n");
        if (r == TDFU_SUCCESS)
            LOG_INFO("DFU download complete\n");
    }

    free(data);
    return r;
}

/* Read the first flash block back and require it blank (0xFF). An erased NOR
 * or NAND reads blank, so anything else means the erase did not actually run.
 * Some erase failure modes are silent on the wire (a garbled token download is
 * refused by the loader without the manifest status going to dfuERROR), so
 * status alone must not be trusted before letting a write land on flash that
 * may not be erased. */
static tdfu_error_t dfu_erase_blank_check(usb_device_t *dev, const tdfu_dfu_info_t *info) {
    uint16_t len = info->transfer_size ? info->transfer_size : 4096;
    if (len > 4096)
        len = 4096;
    uint8_t *buf = malloc(len);
    if (!buf)
        return TDFU_ERROR_MEMORY;

    /* Alt 0 is the boot flash on every loader we ship (the same convention
     * the read/write paths' "alt -1 -> first alt" default relies on). */
    tdfu_error_t r = dfu_claim_alt_ex(dev, info->interface, 0, info->alt_count > 1);
    if (r == TDFU_SUCCESS)
        r = dfu_make_idle(dev, info->interface);
    int got = 0;
    if (r == TDFU_SUCCESS)
        r = dfu_upload_block(dev, info->interface, 0, buf, len, &got);
    if (r == TDFU_SUCCESS) {
        if (got <= 0) {
            r = TDFU_ERROR_PROTOCOL;
        } else {
            for (int i = 0; i < got; i++) {
                if (buf[i] != 0xFF) {
                    LOG_ERROR("Erase verification FAILED: flash not blank at offset %d "
                              "(0x%02X) - the erase did not run\n",
                              i, buf[i]);
                    r = TDFU_ERROR_VERIFY;
                    break;
                }
            }
        }
    }
    /* Close the probe transaction. The one-block upload leaves U-Boot's read
     * transaction inited with the sequence counter at 1, and what ABORT does
     * about that depends on the loader:
     *
     * - Loaders with u-boot 3d4848fe0dc ("usb: gadget: f_dfu: clean the
     *   entity transaction when the host abandons it") clean the entity on
     *   ABORT. The re-probe below then simply reads block 0 of a fresh
     *   transaction - silently - and the second ABORT closes that too.
     *
     * - Older loaders keep the entity's counter across ABORT, so the next
     *   transfer's block 0 would be refused ("Wrong sequence number! [1]
     *   [0]") and cost the caller its stale-transaction retry. For them the
     *   re-probe trips the read path's deliberate mismatch self-heal: one
     *   benign wrong-sequence line on the loader console, a cleared status,
     *   and a pristine entity.
     *
     * Either way the entity is clean when this returns. */
    if (r == TDFU_SUCCESS) {
        int drop = 0;
        dfu_abort(dev, info->interface);
        if (dfu_upload_block(dev, info->interface, 0, buf, len, &drop) == TDFU_SUCCESS)
            dfu_abort(dev, info->interface); /* fixed loader: close the re-probe */
        else
            dfu_clr_status(dev, info->interface); /* old loader: clear the mismatch STALL */
    } else {
        dfu_abort(dev, info->interface);
    }
    free(buf);
    return r;
}

/* Whole-chip erase: download the wipe token to the loader's "erase" alt.
 * The loader answers GETSTATUS with state dfuMANIFEST + bwPollTimeout 500ms
 * for the seconds the erase takes, so the normal poll loop just waits it
 * out. Loaders without the alt (pre-erase builds) fail up front. */
tdfu_error_t tdfu_dfu_erase_device(usb_device_t *dev) {
    static const char token[] = TDFU_DFU_ERASE_TOKEN;
    tdfu_dfu_info_t info;
    dfu_status_t st;

    tdfu_error_t r = dfu_read_info(dev, &info);
    if (r != TDFU_SUCCESS)
        return r;
    int alt = tdfu_dfu_find_alt(&info, TDFU_DFU_ERASE_ALT);
    if (alt < 0) {
        LOG_ERROR("This loader has no \"%s\" alt - update the DFU loader firmware\n", TDFU_DFU_ERASE_ALT);
        return TDFU_ERROR_INVALID_PARAMETER;
    }
    r = dfu_claim_alt_ex(dev, info.interface, alt, info.alt_count > 1);
    if (r != TDFU_SUCCESS)
        return r;

    if (dfu_make_idle(dev, info.interface) != TDFU_SUCCESS) {
        LOG_ERROR("Device not in a DFU-idle state\n");
        return TDFU_ERROR_PROTOCOL;
    }

    LOG_INFO("Erasing the whole flash (alt %d)... this takes a while\n", alt);
    r = dfu_dnload(dev, info.interface, 0, (const uint8_t *)token, (uint16_t)strlen(token));
    if (r != TDFU_SUCCESS)
        return r;
    r = dfu_poll_until_ready_grace(dev, info.interface, &st, DFU_ERASE_GRACE_RETRIES);
    if (r != TDFU_SUCCESS)
        return r;
    /* zero-length DNLOAD ends the transfer; the erase runs in the manifest
     * phase that follows, so this poll is the one that actually waits - and
     * the one that must survive the loader going EP0-silent mid-erase. */
    r = dfu_dnload(dev, info.interface, 1, NULL, 0);
    if (r != TDFU_SUCCESS)
        return r;
    r = dfu_poll_until_ready_grace(dev, info.interface, &st, DFU_ERASE_GRACE_RETRIES);
    if (r != TDFU_SUCCESS)
        return r;
    if (st.bStatus != DFU_STATUS_OK || st.bState == DFU_STATE_dfuERROR) {
        LOG_ERROR("Erase failed on the device (status %u, state %u)\n", st.bStatus, st.bState);
        return TDFU_ERROR_PROTOCOL;
    }
    /* Manifest OK is necessary but not sufficient - prove the flash is blank. */
    r = dfu_erase_blank_check(dev, &info);
    if (r == TDFU_SUCCESS)
        LOG_INFO("Erase complete (verified blank)\n");
    return r;
}

tdfu_error_t tdfu_dfu_reboot_device(usb_device_t *dev) {
    static const char token[] = TDFU_DFU_REBOOT_TOKEN;
    tdfu_dfu_info_t info;
    dfu_status_t st;

    tdfu_error_t r = dfu_read_info(dev, &info);
    if (r != TDFU_SUCCESS)
        return r;
    int alt = tdfu_dfu_find_alt(&info, TDFU_DFU_REBOOT_ALT);
    if (alt < 0) {
        LOG_ERROR("This loader has no \"%s\" alt - update the DFU loader firmware\n", TDFU_DFU_REBOOT_ALT);
        return TDFU_ERROR_INVALID_PARAMETER;
    }
    r = dfu_claim_alt_ex(dev, info.interface, alt, info.alt_count > 1);
    if (r != TDFU_SUCCESS)
        return r;
    if (dfu_make_idle(dev, info.interface) != TDFU_SUCCESS) {
        LOG_ERROR("Device not in a DFU-idle state\n");
        return TDFU_ERROR_PROTOCOL;
    }

    LOG_INFO("Rebooting the device (alt %d)...\n", alt);
    r = dfu_dnload(dev, info.interface, 0, (const uint8_t *)token, (uint16_t)strlen(token));
    if (r != TDFU_SUCCESS)
        return r;
    r = dfu_poll_until_ready(dev, info.interface, &st);
    if (r != TDFU_SUCCESS)
        return r;
    /* Zero-length DNLOAD ends the transfer and moves the loader to dfuMANIFEST.
     * Crucially the manifest only advances (-> flush_medium -> do_reset) while
     * the host polls GETSTATUS: that pump drives f_dfu's manifest state machine,
     * exactly as erase relies on. So we MUST poll after the ZLP - it then fails
     * as the device drops off the bus resetting, and that IS the reboot. */
    dfu_dnload(dev, info.interface, 1, NULL, 0);
    dfu_poll_until_ready(dev, info.interface, &st);
    LOG_INFO("Reboot triggered\n");
    return TDFU_SUCCESS;
}

tdfu_error_t tdfu_dfu_read_device(usb_device_t *dev, int alt, const char *path, uint32_t size) {
    tdfu_dfu_info_t info;

    LOG_DEBUG("dfu_read_device: reading DFU descriptors...\n");
    tdfu_error_t r = dfu_read_info(dev, &info);
    if (r != TDFU_SUCCESS)
        return r;
    if (alt < 0)
        alt = info.alt_count > 0 ? info.alts[0].alt : 0;
    LOG_DEBUG("dfu_read_device: descriptors ok (xfer=%u alts=%d); claiming alt %d...\n", info.transfer_size,
              info.alt_count, alt);
    r = dfu_claim_alt_ex(dev, info.interface, alt, info.alt_count > 1);
    if (r != TDFU_SUCCESS)
        return r;
    LOG_DEBUG("dfu_read_device: interface/alt claimed; beginning upload\n");

    FILE *f = fopen(path, "wb");
    if (!f) {
        LOG_ERROR("Failed to create %s\n", path);
        return TDFU_ERROR_FILE_IO;
    }

    LOG_INFO("DFU upload: alt %d -> %s\n", alt, path);
    LOG_DEBUG("DFU upload: transfer_size=%u bcdDFU=0x%04x %d alt(s) iface=%d\n", info.transfer_size, info.bcd_dfu,
              info.alt_count, info.interface);

    uint8_t *buf = (uint8_t *)malloc(info.transfer_size);
    if (!buf) {
        fclose(f);
        return TDFU_ERROR_MEMORY;
    }

    /* See tdfu_dfu_write_device: a block-0 failure means a stale transaction -
     * the failed request resets it, so CLRSTATUS (make_idle) + retry recovers. */
    uint16_t block = 0;
    uint32_t total = 0;
    for (int attempt = 0; attempt < 2; attempt++) {
        if (dfu_make_idle(dev, info.interface) != TDFU_SUCCESS) {
            r = TDFU_ERROR_PROTOCOL;
            break;
        }
        rewind(f);
        block = 0;
        total = 0;
        r = TDFU_SUCCESS;
        for (;;) {
            int got = 0;
            r = dfu_upload_block(dev, info.interface, block, buf, info.transfer_size, &got);
            if (r != TDFU_SUCCESS) {
                LOG_DEBUG("upload: block %u transfer failed (%s) after %u bytes\n", block,
                          tdfu_error_to_string(r), total);
                break;
            }
            if (got > 0) {
                if (fwrite(buf, 1, got, f) != (size_t)got) {
                    r = TDFU_ERROR_FILE_IO;
                    break;
                }
                total += got;
                LOG_INFO("\r  %u bytes", total);
            }
            block++;
            if (got < (int)info.transfer_size) {
                LOG_DEBUG("upload: short block %u got=%d (transfer_size=%u) -> end of upload, total=%u\n",
                          block - 1, got, info.transfer_size, total);
                break; /* short block = end of upload */
            }
            if (size && total >= size)
                break;
        }
        if (r == TDFU_SUCCESS || block != 0)
            break; /* done, or a genuine mid-stream error (not a stale sequence) */
        LOG_WARN("DFU upload: clearing a stale transaction (reload mid-transfer?) and retrying\n");
    }
    LOG_INFO("\n");
    if (r == TDFU_SUCCESS)
        LOG_INFO("DFU upload complete: %u bytes\n", total);

    free(buf);
    fclose(f);
    return r;
}

/* Verify flash contents against a source image: stream a DFU upload of the
 * same alt and memcmp block-by-block, stopping at the image length (so an 8 MB
 * image on a 16 MB part reads only 8 MB). On mismatch, *mismatch_off gets the
 * offset of the first differing byte - far more diagnostic than a pass/fail
 * (e.g. 0x40000 fingerprints the env-sector overlap). Never retried by the
 * caller's reset path: TDFU_ERROR_VERIFY means the data differs, not that the
 * transfer failed. */
tdfu_error_t tdfu_dfu_verify_device(usb_device_t *dev, int alt, const char *path, uint64_t *mismatch_off) {
    tdfu_dfu_info_t info;
    uint8_t *data = NULL;
    size_t len = 0;

    if (mismatch_off)
        *mismatch_off = (uint64_t)-1;

    tdfu_error_t r = dfu_read_info(dev, &info);
    if (r != TDFU_SUCCESS)
        return r;
    if (alt < 0)
        alt = info.alt_count > 0 ? info.alts[0].alt : 0;
    r = dfu_claim_alt_ex(dev, info.interface, alt, info.alt_count > 1);
    if (r != TDFU_SUCCESS)
        return r;

    r = load_file(path, &data, &len);
    if (r != TDFU_SUCCESS) {
        LOG_ERROR("Failed to read %s\n", path);
        return r;
    }
    if (len == 0) {
        free(data);
        return TDFU_ERROR_INVALID_PARAMETER;
    }

    LOG_INFO("DFU verify: alt %d vs %s (%zu bytes, %u-byte blocks)\n", alt, path, len, info.transfer_size);

    uint8_t *buf = (uint8_t *)malloc(info.transfer_size);
    if (!buf) {
        free(data);
        return TDFU_ERROR_MEMORY;
    }

    /* See tdfu_dfu_read_device: a block-0 failure means a stale transaction -
     * clear and retry once. A mismatch is never retried. */
    uint16_t block = 0;
    size_t total = 0;
    for (int attempt = 0; attempt < 2; attempt++) {
        if (dfu_make_idle(dev, info.interface) != TDFU_SUCCESS) {
            r = TDFU_ERROR_PROTOCOL;
            break;
        }
        block = 0;
        total = 0;
        r = TDFU_SUCCESS;
        while (total < len) {
            int got = 0;
            r = dfu_upload_block(dev, info.interface, block, buf, info.transfer_size, &got);
            if (r != TDFU_SUCCESS) {
                LOG_DEBUG("verify: block %u transfer failed (%s) after %zu bytes\n", block, tdfu_error_to_string(r),
                          total);
                break;
            }
            size_t want = len - total;
            size_t cmp = (size_t)got < want ? (size_t)got : want;
            size_t diff = tdfu_first_diff(buf, data + total, cmp);
            if (diff < cmp) {
                if (mismatch_off)
                    *mismatch_off = (uint64_t)(total + diff);
                LOG_INFO("\n");
                LOG_ERROR("Verify FAILED at offset 0x%08zX (wrote 0x%02X, read back 0x%02X)\n", total + diff,
                          data[total + diff], buf[diff]);
                r = TDFU_ERROR_VERIFY;
                break;
            }
            total += cmp;
            LOG_INFO("\r  %zu/%zu bytes (%d%%)", total, len, (int)(total * 100 / len));
            block++;
            if (got < (int)info.transfer_size && total < len) {
                /* device ended the upload before the image length */
                if (mismatch_off)
                    *mismatch_off = (uint64_t)total;
                LOG_INFO("\n");
                LOG_ERROR("Verify FAILED: device returned only %zu of %zu bytes\n", total, len);
                r = TDFU_ERROR_VERIFY;
                break;
            }
        }
        if (r == TDFU_SUCCESS || r == TDFU_ERROR_VERIFY || block != 0)
            break; /* done, mismatch, or a genuine mid-stream error (not a stale sequence) */
        LOG_WARN("DFU verify: clearing a stale transaction (reload mid-transfer?) and retrying\n");
    }
    if (r == TDFU_SUCCESS) {
        LOG_INFO("\n");
        LOG_INFO("Verify OK: %zu bytes match\n", len);
    }

    free(buf);
    free(data);
    return r;
}

static tdfu_error_t dfu_download_impl(usb_manager_t *manager, int device_index, int alt, const char *path) {
    usb_device_t *dev = NULL;
    tdfu_error_t r = dfu_open_device(manager, device_index, &dev);
    if (r != TDFU_SUCCESS)
        return r;
    r = tdfu_dfu_write_device(dev, alt, path);
    dfu_close_device(dev, 0);
    return r;
}

static tdfu_error_t dfu_upload_impl(usb_manager_t *manager, int device_index, int alt, const char *path,
                                    uint32_t size) {
    usb_device_t *dev = NULL;
    tdfu_error_t r = dfu_open_device(manager, device_index, &dev);
    if (r != TDFU_SUCCESS)
        return r;
    r = tdfu_dfu_read_device(dev, alt, path, size);
    dfu_close_device(dev, 0);
    return r;
}

/* Public download/upload: run the operation, and if it fails with a device-comms
 * error (a wedged gadget after an interrupted transfer), USB-reset the device and
 * retry once. The reset re-inits the dwc2 EP0 that an interrupted DNLOAD leaves
 * stuck; the retry's own make_idle + stale-sequence handling does the rest. */
tdfu_error_t tdfu_dfu_download(usb_manager_t *manager, int device_index, int alt, const char *path) {
    tdfu_error_t r = dfu_download_impl(manager, device_index, alt, path);
    if (r != TDFU_SUCCESS && dfu_err_recoverable(r) && dfu_reset_device(manager, device_index))
        r = dfu_download_impl(manager, device_index, alt, path);
    return r;
}

tdfu_error_t tdfu_dfu_upload(usb_manager_t *manager, int device_index, int alt, const char *path, uint32_t size) {
    tdfu_error_t r = dfu_upload_impl(manager, device_index, alt, path, size);
    if (r != TDFU_SUCCESS && dfu_err_recoverable(r) && dfu_reset_device(manager, device_index))
        r = dfu_upload_impl(manager, device_index, alt, path, size);
    return r;
}

static tdfu_error_t dfu_erase_impl(usb_manager_t *manager, int device_index) {
    usb_device_t *dev = NULL;
    tdfu_error_t r = dfu_open_device(manager, device_index, &dev);
    if (r != TDFU_SUCCESS)
        return r;
    r = tdfu_dfu_erase_device(dev);
    dfu_close_device(dev, 0);
    return r;
}

/* Erase is idempotent, so it gets the same USB-reset-and-retry-once recovery
 * as download/upload. */
tdfu_error_t tdfu_dfu_erase(usb_manager_t *manager, int device_index) {
    tdfu_error_t r = dfu_erase_impl(manager, device_index);
    if (r != TDFU_SUCCESS && dfu_err_recoverable(r) && dfu_reset_device(manager, device_index))
        r = dfu_erase_impl(manager, device_index);
    return r;
}

static tdfu_error_t dfu_reboot_impl(usb_manager_t *manager, int device_index) {
    usb_device_t *dev = NULL;
    tdfu_error_t r = dfu_open_device(manager, device_index, &dev);
    if (r != TDFU_SUCCESS)
        return r;
    r = tdfu_dfu_reboot_device(dev);
    dfu_close_device(dev, 0);
    return r;
}

/* A recoverable comms failure before the reset is armed gets the same
 * USB-reset-and-retry-once recovery as erase; once the reset fires the device
 * function returns success, so no retry runs. */
tdfu_error_t tdfu_dfu_reboot(usb_manager_t *manager, int device_index) {
    tdfu_error_t r = dfu_reboot_impl(manager, device_index);
    if (r != TDFU_SUCCESS && dfu_err_recoverable(r) && dfu_reset_device(manager, device_index))
        r = dfu_reboot_impl(manager, device_index);
    return r;
}

static tdfu_error_t dfu_verify_impl(usb_manager_t *manager, int device_index, int alt, const char *path,
                                    uint64_t *mismatch_off) {
    usb_device_t *dev = NULL;
    tdfu_error_t r = dfu_open_device(manager, device_index, &dev);
    if (r != TDFU_SUCCESS)
        return r;
    r = tdfu_dfu_verify_device(dev, alt, path, mismatch_off);
    dfu_close_device(dev, 0);
    return r;
}

tdfu_error_t tdfu_dfu_verify(usb_manager_t *manager, int device_index, int alt, const char *path,
                             uint64_t *mismatch_off) {
    tdfu_error_t r = dfu_verify_impl(manager, device_index, alt, path, mismatch_off);
    /* dfu_err_recoverable excludes TDFU_ERROR_VERIFY: only comms failures get
     * the USB-reset retry, a data mismatch is final. */
    if (r != TDFU_SUCCESS && dfu_err_recoverable(r) && dfu_reset_device(manager, device_index))
        r = dfu_verify_impl(manager, device_index, alt, path, mismatch_off);
    return r;
}

/* ====================================================================== */
/* Bootrom -> DFU bootstrap (port of tools/t31-usbboot.py)                 */
/* ====================================================================== */

/* USB-boot load addresses - the same for every Ingenic SoC we target. The
 * t31-usbboot.py --ddr-config / --exec-size / address knobs are unused. */
#define DFU_SPL_ADDR   0x80001000u /* SPL load address */
#define DFU_SPL_ENTRY  0x80001800u /* SPL entry (past the 0x800 signature) */
#define DFU_UBOOT_ADDR 0x80100000u /* U-Boot load + entry address */

/* Map a detected SoC variant to its firmware/dfu/<dir> name. Loaders are now
 * per-variant (t20n, t20x, t40xp, ...), so the dir == the variant string for
 * every variant except the family/grade enum values that have no 1:1 loader -
 * those fall back to the closest per-variant loader below. Public so the web
 * build can resolve the same dir the bootstrap will read from MEMFS (the JS
 * side must fetch the loader there first) - one source of truth, no drift. */
const char *tdfu_dfu_variant_dir(tdfu_variant_t v) {
    switch (v) {
    case TDFU_VARIANT_T10:
        /* T10 has no EFUSE sub-SoC grade to refine the family, and only T10L
         * silicon has ever been seen - default the family to t10l. */
        return "t10l";
    case TDFU_VARIANT_T20:
        return "t20n";
    case TDFU_VARIANT_T21:
        return "t21n";
    case TDFU_VARIANT_T23:
        return "t23n";
    case TDFU_VARIANT_T30:
        return "t30n";
    case TDFU_VARIANT_T31:
        return "t31n";
    case TDFU_VARIANT_T31ZX:
    case TDFU_VARIANT_T31AL:
        return "t31x"; /* DDR2 128 MB */
    case TDFU_VARIANT_T32:
        return "t32lq";
    case TDFU_VARIANT_T32_DDR3:
        return "t32vn"; /* conservative @350 DDR3 profile covers nq/vn/vx/xq */
    case TDFU_VARIANT_T40:
        return "t40n";
    case TDFU_VARIANT_T41:
    case TDFU_VARIANT_T41L:
        return "t41lq"; /* DDR2 */
    case TDFU_VARIANT_T41_DDR3:
    case TDFU_VARIANT_T41N:
    case TDFU_VARIANT_T41A:
    case TDFU_VARIANT_T41ZL:
    case TDFU_VARIANT_T41ZX:
        return "t41nq"; /* DDR3 */
    case TDFU_VARIANT_A1:
        return "a1n";
    default:
        return tdfu_variant_to_string(v);
    }
}

/* Device-level DFU bootstrap: USB-boot the given SPL + U-Boot on an already-open
 * bootrom device (mirrors t31-usbboot.py). The device then re-enumerates as a
 * DFU gadget. The caller owns dev. Used by tdfu_dfu_bootstrap and the Android
 * JNI (which provides its own fd-wrapped device). */
tdfu_error_t tdfu_dfu_bootstrap_device(usb_device_t *dev, const uint8_t *spl, size_t spl_len, const uint8_t *uboot,
                                       size_t uboot_len) {
    LOG_DEBUG("stage1: %zu bytes -> 0x%08x (entry 0x%08x)\n", spl_len, DFU_SPL_ADDR, DFU_SPL_ENTRY);
    tdfu_error_t r = bootstrap_load_data_to_memory(dev, spl, spl_len, DFU_SPL_ADDR);
    if (r != TDFU_SUCCESS)
        return r;
    r = protocol_prog_stage1(dev, DFU_SPL_ENTRY);
    if (r != TDFU_SUCCESS)
        return r;

    /* stage1 brings up clk+DDR and returns to the bootrom; let it settle. */
    tdfu_sleep_milliseconds(1000);

    LOG_DEBUG("stage2 U-Boot: %zu bytes -> 0x%08x\n", uboot_len, DFU_UBOOT_ADDR);
    r = bootstrap_load_data_to_memory(dev, uboot, uboot_len, DFU_UBOOT_ADDR);
    if (r != TDFU_SUCCESS)
        return r;
    protocol_flush_cache(dev);
    protocol_prog_stage2(dev, DFU_UBOOT_ADDR); /* tolerates the re-enumeration error */
    LOG_INFO("U-Boot starting; device will re-enumerate in DFU mode\n");
    return TDFU_SUCCESS;
}

/* Which loader the SoC detection picked. The web app logs its own
 * "DFU bootstrap for <SOC>..." line (and a custom SPL+U-Boot equivalent) before
 * calling in, so this doubles up there - and the custom paths it would print are
 * MEMFS temporaries that mean nothing to the user. On the CLI and the daemon it
 * is the only record of the chosen loader family, so keep it at INFO. */
#ifdef __EMSCRIPTEN__
#define LOG_BOOTSTRAP_PICK LOG_DEBUG
#else
#define LOG_BOOTSTRAP_PICK LOG_INFO
#endif

tdfu_error_t tdfu_dfu_bootstrap(usb_manager_t *manager, int device_index, const char *firmware_dir,
                                const char *force_cpu, const char *spl_override, const char *uboot_override) {
    tdfu_device_info_t *devs = NULL;
    int n = 0;
    usb_device_t *dev = NULL;
    uint8_t *spl = NULL, *uboot = NULL;
    size_t spl_len = 0, uboot_len = 0;
    char spl_path[512], uboot_path[512];
    tdfu_variant_t variant;
    const char *root = firmware_dir ? firmware_dir : "./firmware";
    bool explicit_files = spl_override && spl_override[0] && uboot_override && uboot_override[0];

    tdfu_error_t r = usb_manager_find_devices(manager, &devs, &n);
    if (r != TDFU_SUCCESS)
        return r;
    if (device_index < 0 || device_index >= n) {
        free(devs);
        return TDFU_ERROR_DEVICE_NOT_FOUND;
    }
    r = usb_manager_open_device(manager, &devs[device_index], &dev);
    free(devs);
    if (r != TDFU_SUCCESS)
        return r;
    usb_device_claim_interface(dev);

    /* Resolve the SPL + U-Boot images. Explicit --spl/--uboot override the
     * firmware-dir lookup and skip SoC detection entirely (like t31-usbboot.py);
     * otherwise detect the SoC and pick firmware/dfu/<soc>/{spl,uboot}.bin. */
    if (explicit_files) {
        snprintf(spl_path, sizeof(spl_path), "%s", spl_override);
        snprintf(uboot_path, sizeof(uboot_path), "%s", uboot_override);
        LOG_BOOTSTRAP_PICK("DFU bootstrap: --spl %s + --uboot %s\n", spl_path, uboot_path);
    } else {
        if (force_cpu) {
            variant = tdfu_variant_from_string(force_cpu);
        } else {
            r = protocol_detect_soc(dev, &variant);
            if (r != TDFU_SUCCESS) {
                LOG_ERROR("SoC auto-detect failed; pass --cpu <variant> (or --spl + --uboot)\n");
                usb_device_close(dev);
                free(dev);
                return r;
            }
        }
        const char *name = tdfu_dfu_variant_dir(variant);
        LOG_BOOTSTRAP_PICK("DFU bootstrap: SoC %s\n", name);
        /* Capped XBurst1 SoCs (T10/T20/T21/T30) USB-boot a TPL as stage1: it
         * brings up DDR in cache-as-RAM and returns to the bootrom, just like a
         * big-SPL SoC's SPL does. Their DRAM-resident SPL is NOR-only and unused
         * here. Prefer tpl.bin; fall back to spl.bin for the big-SPL SoCs. */
        snprintf(spl_path, sizeof(spl_path), "%s/dfu/%s/tpl.bin", root, name);
        if (firmware_file_check_readable(spl_path) != TDFU_SUCCESS)
            snprintf(spl_path, sizeof(spl_path), "%s/dfu/%s/spl.bin", root, name);
        snprintf(uboot_path, sizeof(uboot_path), "%s/dfu/%s/uboot.bin", root, name);
    }

    r = load_file(spl_path, &spl, &spl_len);
    if (r != TDFU_SUCCESS) {
        LOG_ERROR("Missing DFU SPL: %s\n", spl_path);
        goto out;
    }
    r = load_file(uboot_path, &uboot, &uboot_len);
    if (r != TDFU_SUCCESS) {
        LOG_ERROR("Missing DFU U-Boot: %s\n", uboot_path);
        goto out;
    }

    /* 3) USB-boot sequence (mirrors t31-usbboot.py). */
    r = tdfu_dfu_bootstrap_device(dev, spl, spl_len, uboot, uboot_len);

out:
    free(spl);
    free(uboot);
    usb_device_close(dev);
    free(dev);
    return r;
}
