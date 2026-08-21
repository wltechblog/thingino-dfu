/**
 * tdfu Core API Implementation
 *
 * Wraps the internal USB manager and DFU functions behind a clean
 * public interface.
 */

#include "tdfu/core.h"
#include "tdfu/constants.h"
#include "tdfu/tdfu.h"
#include "tdfu/dfu.h"
#include "tdfu/diag.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#ifdef _WIN32
#include <direct.h>
#include <io.h>
#define unlink _unlink
#define rmdir  _rmdir
#else
#include <unistd.h>
#endif

/* Internal state */
static usb_manager_t g_manager;
static tdfu_device_info_t *g_devices = NULL;
static int g_device_count = 0;
static bool g_initialized = false;

tdfu_error_t tdfu_init(void) {
    if (g_initialized)
        return TDFU_SUCCESS;

    tdfu_error_t result = usb_manager_init(&g_manager);
    if (result != TDFU_SUCCESS)
        return TDFU_ERROR_INIT_FAILED;

    g_initialized = true;
    return TDFU_SUCCESS;
}

void tdfu_cleanup(void) {
    free(g_devices);
    g_devices = NULL;
    g_device_count = 0;
    if (g_initialized) {
        usb_manager_cleanup(&g_manager);
        g_initialized = false;
    }
}

tdfu_error_t tdfu_discover_devices(tdfu_device_list_t *list) {
    if (!list)
        return TDFU_ERROR_INVALID_PARAMETER;
    if (!g_initialized)
        return TDFU_ERROR_INIT_FAILED;

    free(g_devices);
    g_devices = NULL;
    g_device_count = 0;

    tdfu_error_t result = usb_manager_find_devices(&g_manager, &g_devices, &g_device_count);
    if (result != TDFU_SUCCESS)
        return TDFU_ERROR_DEVICE_NOT_FOUND;

    list->count = g_device_count;
    list->devices = calloc(g_device_count, sizeof(tdfu_device_info_t));
    if (!list->devices && g_device_count > 0)
        return TDFU_ERROR_MEMORY;

    /* Public list now uses the canonical tdfu_device_info_t, so discovery
     * results copy directly (no field translation needed). */
    for (int i = 0; i < g_device_count; i++) {
        list->devices[i] = g_devices[i];
    }

    return TDFU_SUCCESS;
}

void tdfu_free_device_list(tdfu_device_list_t *list) {
    if (list) {
        free(list->devices);
        list->devices = NULL;
        list->count = 0;
    }
}

tdfu_error_t tdfu_set_device_variant(int device_index, tdfu_variant_t variant) {
    if (!g_initialized)
        return TDFU_ERROR_INIT_FAILED;
    if (device_index < 0 || device_index >= g_device_count)
        return TDFU_ERROR_INVALID_PARAMETER;
    g_devices[device_index].variant = (tdfu_variant_t)variant;
    return TDFU_SUCCESS;
}

/* tdfu_variant_to_string / tdfu_variant_from_string live in utils.c
 * (formerly processor_variant_to_string / string_to_processor_variant);
 * the facade no longer wraps them. */

#ifdef __EMSCRIPTEN__
/* Web/JS convenience wrappers for the DFU backend, bound to the core
 * g_manager. They take alt-setting names (or "") to avoid marshalling the
 * tdfu_dfu_info_t struct across the JS boundary. */
tdfu_error_t tdfu_web_dfu_bootstrap(int device_index, const char *firmware_dir, const char *force_cpu) {
    return tdfu_dfu_bootstrap(&g_manager, device_index, firmware_dir, force_cpu, NULL, NULL);
}

/* Bootstrap with caller-supplied SPL + U-Boot (both required). Mirrors the CLI
 * --spl/--uboot override: SoC detection is skipped, the given images are used
 * verbatim. The web app writes the user's files into MEMFS and passes the paths. */
tdfu_error_t tdfu_web_dfu_bootstrap_files(int device_index, const char *spl_path, const char *uboot_path) {
    return tdfu_dfu_bootstrap(&g_manager, device_index, "", NULL, spl_path, uboot_path);
}

/* Refine the SoC variant via the register-stub probe. The bootrom magic alone
 * can't tell T32 from T31 (both report "T31V"), nor the DDR grades apart, so the
 * web runs this after a bootrom-stage discover, before picking the DFU loader.
 * Returns the refined variant name, or "" on failure (caller keeps the magic). */
const char *tdfu_web_detect_soc(int device_index) {
    if (!g_initialized || device_index < 0 || device_index >= g_device_count)
        return "";
    usb_device_t *device = NULL;
    if (usb_manager_open_device(&g_manager, &g_devices[device_index], &device) != TDFU_SUCCESS)
        return "";
    tdfu_variant_t v = g_devices[device_index].variant;
    tdfu_error_t r = protocol_detect_soc(device, &v);
    usb_device_close(device);
    free(device);
    if (r != TDFU_SUCCESS)
        return "";
    g_devices[device_index].variant = v;
    return tdfu_variant_to_string(v);
}

/* Read-only eFuse / secure-boot diagnostics. Returns the formatted report text
 * (static buffer, valid until the next call), or an error line on failure. The
 * web app shows this verbatim in a dialog. */
const char *tdfu_web_diag(int device_index) {
    static char report[8192];
    tdfu_diag_info_t info;
    tdfu_error_t r = tdfu_diag(&g_manager, device_index, &info);
    if (r != TDFU_SUCCESS) {
        snprintf(report, sizeof(report), "Diag failed: %s\n", tdfu_error_to_string(r));
        return report;
    }
    tdfu_diag_format(&info, report, sizeof(report));
    return report;
}

static int web_dfu_resolve_alt(int device_index, const char *alt_name) {
    tdfu_dfu_info_t info;
    tdfu_error_t pr = tdfu_dfu_probe(&g_manager, device_index, &info);
    if (pr != TDFU_SUCCESS) {
        LOG_ERROR("DFU probe failed: %s\n", tdfu_error_to_string(pr));
        return -1;
    }
    LOG_DEBUG("DFU probe ok: %d alt setting(s), transfer size %u, DFU %x.%02x\n", info.alt_count, info.transfer_size,
              (info.bcd_dfu >> 8) & 0xff, info.bcd_dfu & 0xff);
    for (int i = 0; i < info.alt_count; i++)
        LOG_DEBUG("  alt %d: \"%s\"\n", info.alts[i].alt, info.alts[i].name);

    if (alt_name && alt_name[0]) {
        int a = tdfu_dfu_find_alt(&info, alt_name);
        if (a < 0)
            LOG_ERROR("DFU alt \"%s\" not found\n", alt_name);
        return a;
    }
    /* No explicit selection: default to the first alt-setting. The thingino DFU
     * loaders build dfu_alt_info as "<flash>=flash raw 0x0 0x<size>&mmc 0=sdcard
     * raw 0x0 0", so alt 0 is always the on-board boot flash and any later alt
     * (the SD card) is secondary. This matches the CLI / dfu-remote default of
     * alt 0 = flash - the web UI only ever writes the boot-flash image. (WebUSB
     * can't read the iInterface strings, so the names log as "".) */
    if (info.alt_count > 1)
        LOG_DEBUG("Device exposes %d alt settings; using alt %d (boot flash)\n", info.alt_count, info.alts[0].alt);
    return info.alts[0].alt;
}

tdfu_error_t tdfu_web_dfu_download(int device_index, const char *alt_name, const char *path) {
    int alt = web_dfu_resolve_alt(device_index, alt_name);
    if (alt < 0)
        return TDFU_ERROR_INVALID_PARAMETER;
    return tdfu_dfu_download(&g_manager, device_index, alt, path);
}

tdfu_error_t tdfu_web_dfu_upload(int device_index, const char *alt_name, const char *path, uint32_t size) {
    int alt = web_dfu_resolve_alt(device_index, alt_name);
    if (alt < 0)
        return TDFU_ERROR_INVALID_PARAMETER;
    return tdfu_dfu_upload(&g_manager, device_index, alt, path, size);
}

/* Verify the just-written flash against the MEMFS-staged image. Returns
 * TDFU_ERROR_VERIFY on mismatch; the JS side reads the offset from the log. */
tdfu_error_t tdfu_web_dfu_verify(int device_index, const char *alt_name, const char *path) {
    int alt = web_dfu_resolve_alt(device_index, alt_name);
    if (alt < 0)
        return TDFU_ERROR_INVALID_PARAMETER;
    return tdfu_dfu_verify(&g_manager, device_index, alt, path, NULL);
}

/* Reboot the SoC via the loader's "reboot" virt alt. tdfu_dfu_reboot finds the
 * alt itself and treats the reset disconnect as success. */
tdfu_error_t tdfu_web_reboot(int device_index) {
    return tdfu_dfu_reboot(&g_manager, device_index);
}
#endif /* __EMSCRIPTEN__ */
