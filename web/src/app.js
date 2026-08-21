/**
 * Thingino Web Flasher — Application Logic
 *
 * Loads the WASM module, drives the tdfu C API from JS,
 * and manages the UI state machine.
 */

import { RemoteClient } from './remote.js';
import { injectOverlay, overlayFilesFor } from './inject.js';

/* ------------------------------------------------------------------ */
/*  State                                                              */
/* ------------------------------------------------------------------ */

var Module = null;
var tdfuReady = false;
var currentState = 'idle';
var firmwareData = null;
var firmwareFileName = '';
var detectedVariant = -1;
var detectedVariantName = '';
var wasmBusy = false;

/* Optional user-supplied DFU bootloader (Advanced area). When BOTH are set, the
 * next DFU Bootstrap uses these instead of the bundled images and skips SoC
 * detection. Each is { name: string, data: Uint8Array } or null. */
var customSpl = null;
var customUboot = null;

/* Backend: 'dfu' (default) drives the on-device U-Boot DFU gadget; 'remote'
 * proxies to a dfu-remote daemon. Persisted across reloads. */
var backendMode = localStorage.getItem('tdfu_backend') || 'dfu';
var inDfuMode = false; /* connected device is a U-Boot DFU gadget (a108:4d44) */

/* Remote daemon (WebSocket) backend state. */
var remoteClient = null;
var remoteDevices = [];
var selectedRemoteIndex = 0;
var remoteUrl = localStorage.getItem('tdfu_remote_url') || '';
var remoteToken = localStorage.getItem('tdfu_remote_token') || '';

/* Verbose [DEBUG]/[shim] diagnostics are gated behind ?debug in the URL. The
 * shim reads window.__tdfu_debug; the C side is toggled via tdfu_web_set_debug()
 * once the module loads. Normal info/warn/error always show. */
var debugEnabled = localStorage.getItem('tdfu_debug') === '1' ||
    new URLSearchParams(location.search).has('debug') || /\bdebug\b/.test(location.hash);
window.__tdfu_debug = debugEnabled;

/* Read the flash back and compare after every write (opt-in; roughly doubles
 * flash time). Applies to both the DFU and remote backends. */
var verifyAfterWrite = localStorage.getItem('tdfu_verify') === '1';

/* Reboot the SoC after a successful write (opt-in). Fires the loader's "reboot"
 * alt via whichever backend flashed, so the box boots into what was flashed. */
var rebootAfterWrite = localStorage.getItem('tdfu_reboot') === '1';

/* Surface the Advanced (custom SPL/U-Boot) panel in the main view. Opt-in: the
 * bundled loaders are correct for every supported SoC, so this is an expert
 * escape hatch rather than a normal step. */
var advancedEnabled = localStorage.getItem('tdfu_advanced') === '1';

/* Surface the "Flash a prebuilt thingino release" panel in the main view. Opt-in,
 * so the default view stays a plain flash-the-file-I-picked flow. */
var releasesEnabled = localStorage.getItem('tdfu_releases') === '1';

/* Surface the "Pre-configure" panel (Wi-Fi / SSH / arbitrary overlay files) in the
 * main view. Opt-in, off by default — it's a power-user step. */
var injectEnabled = localStorage.getItem('tdfu_inject') === '1';

/**
 * Serialize all WASM async ccalls — Asyncify only supports one at a time.
 */
async function wasmCall(name, returnType, argTypes, args) {
    while (wasmBusy) {
        await new Promise(function(r) { setTimeout(r, 50); });
    }
    wasmBusy = true;
    try {
        return await Module.ccall(name, returnType, argTypes, args, {async: true});
    } finally {
        wasmBusy = false;
    }
}

/* firmware/dfu/<dir> for a detected variant. Resolved by the C
 * tdfu_dfu_variant_dir (via the tdfu_web_dfu_dir export), the same function the
 * bootstrap uses to read the loader from MEMFS - so the fetch path can't drift
 * from what the C side expects (it used to, as a hand-kept JS map). */
function dfuVariantDir(name) {
    return Module.ccall('tdfu_web_dfu_dir', 'string', ['string'], [name]) || name;
}

/* ------------------------------------------------------------------ */
/*  Logging                                                            */
/* ------------------------------------------------------------------ */

function log(msg, level) {
    level = level || 'info';
    if (level === 'debug' && !debugEnabled) return; // gated by the debug toggle
    var el = document.getElementById('log');
    var line = document.createElement('div');
    line.className = level;
    line.textContent = msg;
    el.appendChild(line);
    el.scrollTop = el.scrollHeight;
}

/* ------------------------------------------------------------------ */
/*  Progress                                                           */
/* ------------------------------------------------------------------ */

function showProgress(percent, label) {
    var container = document.getElementById('progress');
    container.classList.remove('d-none');
    var fill = document.getElementById('progress-fill');
    fill.classList.remove('progress-bar-striped', 'progress-bar-animated');
    fill.style.width = percent + '%';
    document.getElementById('progress-label').textContent = label || '';
}

/* Indeterminate progress (moving stripes) for operations whose total length the
 * browser can't know up front - e.g. a DFU upload, where the device decides how
 * much to send. The live byte count from the C side fills in the label. */
function showProgressBusy(label) {
    var container = document.getElementById('progress');
    container.classList.remove('d-none');
    var fill = document.getElementById('progress-fill');
    fill.classList.add('progress-bar-striped', 'progress-bar-animated');
    fill.style.width = '100%';
    document.getElementById('progress-label').textContent = label || '';
}

function hideProgress() {
    document.getElementById('progress').classList.add('d-none');
}

/* Runtime counterpart to data-i18n, for strings built in JS (dropdown options,
 * status lines) that I18N.apply() cannot reach. t() resolves against the current
 * language, falling back to English then to the key. */
function t(key, params) {
    return window.I18N ? I18N.t(key, params) : key;
}

/* Hex SHA-256 of a byte buffer via Web Crypto (available in the secure context
 * the flasher runs in). */
async function sha256Hex(data) {
    var digest = await crypto.subtle.digest('SHA-256', data);
    var bytes = new Uint8Array(digest);
    var hex = '';
    for (var i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, '0');
    return hex;
}

/* Log "SHA256: ..." for a just-saved buffer; quietly skip if unavailable. */
async function logSha256(data) {
    try {
        log('SHA256: ' + await sha256Hex(data));
    } catch (e) {
        console.warn('sha256 failed', e);
    }
}

/* Unique dump filename matching the Android app: firmware_<SOC>_<yyyyMMdd_HHmm>.bin */
function readFilename() {
    var soc = (detectedVariantName || '').toUpperCase() || 'DFU';
    var d = new Date();
    var p = function(n) { return String(n).padStart(2, '0'); };
    var ts = '' + d.getFullYear() + p(d.getMonth() + 1) + p(d.getDate()) + '_' + p(d.getHours()) + p(d.getMinutes());
    return 'firmware_' + soc + '_' + ts + '.bin';
}

/* ------------------------------------------------------------------ */
/*  UI State                                                           */
/* ------------------------------------------------------------------ */

function setState(state) {
    currentState = state;
    var badge = document.getElementById('status-badge');

    var labels = {
        idle: ['Idle', 'secondary'],
        connecting: ['Connecting...', 'warning'],
        detecting: ['Detecting...', 'warning'],
        bootstrapping: ['Bootstrapping...', 'warning'],
        writing: ['Writing...', 'warning'],
        reading: ['Reading...', 'warning'],
        done: ['Ready', 'success'],
        error: ['Error', 'danger'],
    };
    var info = labels[state] || ['Unknown', 'secondary'];
    badge.textContent = info[0];
    badge.className = 'badge bg-' + info[1] + ' ms-auto';

    var busy = ['connecting', 'detecting', 'bootstrapping', 'writing', 'reading'].indexOf(state) !== -1;
    var warn = document.getElementById('op-warning');
    if (['bootstrapping', 'writing', 'reading'].indexOf(state) !== -1) {
        warn.classList.remove('d-none');
    } else {
        warn.classList.add('d-none');
    }
    // Enable actions based on the actual workflow, not just "a device exists":
    //  - DFU backend: a bootrom must be BOOTSTRAPPED into the U-Boot DFU gadget
    //    before Read/Write work, so only Bootstrap is live with a bootrom, and
    //    only Read/Write are live once we're in DFU mode.
    //  - Remote backend: the daemon owns the bootstrap/flash flow, so once a
    //    device is discovered, Bootstrap/Read/Write are all live.
    var hasDevice = state === 'done';
    var dfu = backendMode === 'dfu';
    // Bootstrap only acts on a bootrom (a108:c309); Read/Write only once the
    // device is the DFU gadget. DFU and remote both gate on inDfuMode.
    var canBoot = hasDevice && !busy && !inDfuMode;
    var canRW = hasDevice && !busy && inDfuMode;

    // Settings is gated like every other action: saving it can switch backend,
    // which resets the state machine and disconnects a live remote transfer
    // mid-flash. A disabled button emits no hover events, so the "wait" tooltip
    // goes on the wrapper span; the balloon (data-help) resolves it either way.
    var settingsBtn = document.getElementById('btn-settings');
    if (settingsBtn) settingsBtn.disabled = busy;
    var settingsWrap = document.getElementById('btn-settings-wrap');
    if (settingsWrap) {
        if (busy) settingsWrap.setAttribute('title', window.I18N ? I18N.t('title_settings_busy') : '');
        else settingsWrap.removeAttribute('title');
    }

    document.getElementById('btn-connect').disabled = busy;
    document.getElementById('btn-bootstrap').disabled = !canBoot;
    document.getElementById('btn-write').disabled = !canRW;
    document.getElementById('btn-read').disabled = !canRW;
    // Info/diag reads the eFuse on a bootrom device (same stage as Bootstrap);
    // it also stays live post-bootstrap when there's a cached readout to show.
    document.getElementById('btn-diag').disabled = !(canBoot || (lastDiagText && !busy));

    updateReleaseFlash();

    // Glow the single "next action" so it's obvious what to click. In local DFU
    // mode with a bootrom attached, that's Bootstrap. The remote flow sets its
    // own Read/Bootstrap glow after discover/bootstrap, so clear Read on every
    // state change here and let those re-apply it.
    setAttention('btn-bootstrap', canBoot && dfu);
    setAttention('btn-read', false);
}

/* Gate the release panel's Flash button. Unlike Write it does not require
 * inDfuMode - it is one-click by design and bootstraps a bootrom itself - but it
 * does require a device to actually be there, exactly like every other action.
 * hasDevice is state === 'done', which is true for a connected local USB device
 * and for a device discovered by the remote daemon, and false before either. */
function updateReleaseFlash() {
    var btn = document.getElementById('rel-flash');
    if (!btn) return;
    var img = document.getElementById('rel-device');
    btn.disabled = !(currentState === 'done' && img && img.value);
}

/* Toggle the pulsing "click me" glow on a button. */
function setAttention(id, on) {
    var el = document.getElementById(id);
    if (el) el.classList.toggle('btn-attention', !!on);
}

function showDeviceInfo(soc, stage, vid, pid) {
    document.getElementById('device-disconnected').classList.add('d-none');
    document.getElementById('device-info').classList.remove('d-none');
    document.getElementById('info-soc').textContent = soc || '—';
    document.getElementById('info-stage').textContent = stage || '—';
    document.getElementById('info-vidpid').textContent =
        '0x' + vid.toString(16).padStart(4, '0') + ':0x' + pid.toString(16).padStart(4, '0');
}

/* ------------------------------------------------------------------ */
/*  MEMFS Firmware Loading                                             */
/* ------------------------------------------------------------------ */

/**
 * Fetch the DFU-capable SPL + U-Boot for a variant into MEMFS at
 * ./firmware/dfu/<dir>/ so tdfu_web_dfu_bootstrap can USB-boot them.
 */
async function loadDfuFirmwareToMemFS(variant) {
    var dir = dfuVariantDir(variant);
    var basePath = './firmware/dfu/' + dir;
    try { Module.FS.mkdir('./firmware'); } catch (e) { /* exists */ }
    try { Module.FS.mkdir('./firmware/dfu'); } catch (e) { /* exists */ }
    try { Module.FS.mkdir(basePath); } catch (e) { /* exists */ }

    // stage1 is tpl.bin on the capped XBurst1 SoCs (T10/T20/T21/T30) and spl.bin
    // on the big-SPL SoCs - mirror the tpl-first pick in dfu.c (tdfu_dfu_bootstrap)
    // so the C bootstrap finds the right stage1 in MEMFS. (A 404 on tpl.bin for a
    // big-SPL SoC is expected; we then fetch spl.bin.)
    var stage1 = 'tpl.bin';
    var s1 = await fetch('firmware/dfu/' + dir + '/tpl.bin');
    if (!s1.ok) {
        stage1 = 'spl.bin';
        s1 = await fetch('firmware/dfu/' + dir + '/spl.bin');
    }
    if (!s1.ok) {
        throw new Error('Failed to fetch dfu stage1 for ' + dir + ': ' + s1.status);
    }
    var s1data = new Uint8Array(await s1.arrayBuffer());
    Module.FS.writeFile(basePath + '/' + stage1, s1data);
    console.log('Loaded dfu stage1 ' + stage1 + ': ' + s1data.length + ' bytes');

    var ub = await fetch('firmware/dfu/' + dir + '/uboot.bin');
    if (!ub.ok) {
        throw new Error('Failed to fetch firmware/dfu/' + dir + '/uboot.bin: ' + ub.status);
    }
    var ubdata = new Uint8Array(await ub.arrayBuffer());
    Module.FS.writeFile(basePath + '/uboot.bin', ubdata);
    console.log('Loaded dfu uboot.bin: ' + ubdata.length + ' bytes');
}

/* ------------------------------------------------------------------ */
/*  Device discovery helper                                            */
/* ------------------------------------------------------------------ */

/**
 * Call tdfu_discover_devices and parse the first device's info.
 * Returns { bus, addr, vid, pid, stage, variant, variantName } or null.
 */
async function discoverDevices() {
    var listPtr = Module._malloc(8);
    console.log('ccall tdfu_discover_devices, listPtr=' + listPtr);
    var result = await wasmCall('tdfu_discover_devices', 'number', ['number'], [listPtr]);
    console.log('tdfu_discover_devices returned:', result);

    if (result !== 0) {
        console.log('discover FAILED with error', result);
        Module._free(listPtr);
        return null;
    }

    var devicesArrayPtr = Module.HEAPU32[listPtr >> 2];
    var count = Module.HEAPU32[(listPtr + 4) >> 2];
    console.log('devicesArrayPtr=' + devicesArrayPtr + ' count=' + count);

    if (count === 0) {
        Module.ccall('tdfu_free_device_list', null, ['number'], [listPtr]);
        Module._free(listPtr);
        return null;
    }

    // tdfu_device_info_t layout (16 bytes, packed):
    //   u8 bus, u8 address, u16 vendor_id, u16 product_id, 2 pad,
    //   i32 stage, i32 variant
    var base = devicesArrayPtr;
    var bus = Module.HEAPU8[base];
    var addr = Module.HEAPU8[base + 1];
    var vid = Module.HEAPU8[base + 2] | (Module.HEAPU8[base + 3] << 8);
    var pid = Module.HEAPU8[base + 4] | (Module.HEAPU8[base + 5] << 8);
    var stage = Module.HEAPU32[(base + 8) >> 2];
    var variant = Module.HEAPU32[(base + 12) >> 2];

    var namePtr = Module.ccall('tdfu_variant_to_string', 'number', ['number'], [variant]);
    var variantName = namePtr ? Module.UTF8ToString(namePtr) : 'unknown';

    Module.ccall('tdfu_free_device_list', null, ['number'], [listPtr]);
    Module._free(listPtr);

    return {
        bus: bus, addr: addr, vid: vid, pid: pid,
        stage: stage, variant: variant, variantName: variantName
    };
}

/* ------------------------------------------------------------------ */
/*  WASM Module Init                                                   */
/* ------------------------------------------------------------------ */

/* Route one libtdfu log line to the UI. Fed live by the C log hook
 * (Module.onLibLog, set in web_main.c) so '\r' progress updates arrive as they
 * happen; also used for Emscripten's own stderr. Progress is emitted as
 * repeated "\r  N/M bytes (P%)" lines (terminal overwrite): the live value goes
 * to the progress LABEL on the busy bar, matching the remote backend exactly
 * (the daemon sends no percent frames either, so remote is label-on-busy too). */
function routeCLog(text) {
    if (text.indexOf('\r') !== -1) {
        var pl = document.getElementById('progress-label');
        var tail = text.slice(text.lastIndexOf('\r') + 1).trim();
        if (pl && tail) pl.textContent = tail;
        text = text.slice(0, text.indexOf('\r'));
        if (!text.trim()) return;
    }
    if (text.startsWith('[DEBUG]') || text.startsWith('[shim]')) {
        log(text, 'debug');
    } else if (text.startsWith('[WARN]')) {
        log(text, 'warn');
    } else if (text.startsWith('[ERROR]')) {
        log(text, 'error');
    } else {
        log(text, 'info');
    }
}

async function initModule() {
    console.log('Loading WASM module...');

    try {
        Module = await createTdfuModule({
            // Version the tdfu.wasm URL to match the ?v= on the glue script tag
            // (vite.config.js): the /wasm/* names are fixed, and stale cached
            // copies have survived redeploys in the field. __APP_VERSION__ is
            // injected at build time by vite's define.
            locateFile: function(path, prefix) {
                var v = typeof __APP_VERSION__ !== 'undefined' ? __APP_VERSION__ : 'dev';
                return prefix + path + '?v=' + v;
            },
            // Emscripten's own stderr (asserts/aborts) - route it the same way.
            printErr: routeCLog,
            print: function(text) { log(text, 'info'); },
        });

        // Live libtdfu log hook: web_main.c's g_tdfu_log_hook calls
        // Module.onLibLog per message, bypassing Emscripten's newline-buffered
        // stderr so '\r' progress updates arrive live. Set on the resolved
        // instance (not the constructor arg, which Emscripten may not copy);
        // it only fires during operations, well after this point.
        Module.onLibLog = routeCLog;

        console.log('WASM module loaded (' +
            (Module.HEAPU8.length / 1024 / 1024).toFixed(1) + ' MB heap)');

        // Enable verbose C [DEBUG] logging only when ?debug is set.
        if (debugEnabled) {
            Module.ccall('tdfu_web_set_debug', null, ['number'], [1]);
            log('Debug logging enabled (?debug)', 'debug');
        }

        // {async:true} is required — tdfu_init calls libusb_init which is async
        var result = await wasmCall('tdfu_init', 'number', [], []);
        if (result !== 0) {
            log('tdfu_init failed: ' + result, 'error');
            return;
        }

        // Create /tmp for the C code's temp file operations
        try { Module.FS.mkdir('/tmp'); } catch (e) { /* exists */ }

        tdfuReady = true;

        // Display version: library version + build commit (v1.5.30-cc3f06a),
        // same format as the thingino image builder footer. The lib version
        // comes from the wasm and the sha from the JS bundle, so a stale
        // cached copy of either shows up here as a mismatched pair.
        var verPtr = Module.ccall('tdfu_get_version', 'number', [], []);
        var version = verPtr ? Module.UTF8ToString(verPtr) : 'dev';
        var sha = typeof __GIT_SHA__ !== 'undefined' ? __GIT_SHA__ : 'dev';
        var verEl = document.getElementById('version-num');
        if (verEl) verEl.textContent = 'v' + version + '-' + sha;

        log('Ready — click Connect Device to begin');
        // Nothing on initial load: auto-attach happens ONLY via the USB 'connect'
        // event (re-enumeration / hotplug of an already-authorized device).
    } catch (e) {
        log('Failed to initialize — check console for details', 'error');
        console.error(e);
    }
}

/* ------------------------------------------------------------------ */
/*  Connect Device                                                     */
/* ------------------------------------------------------------------ */

async function connectDevice() {
    lastDiagText = null; // fresh session: drop any cached Info from a prior device
    if (backendMode === 'remote') return doRemoteConnect();
    if (!tdfuReady) {
        log('Module not ready', 'warn');
        return;
    }

    setState('connecting');
    setAttention('btn-connect', false); // user is acting on the prompt
    log('Requesting USB device...');

    try {
        // Call WebUSB requestDevice directly — request permission for ALL
        // Ingenic VID:PID pairs (bootrom + firmware) so re-enumeration works
        var filters = [
            { vendorId: 0x601A, productId: 0x4770 },
            { vendorId: 0x601A, productId: 0xC309 },
            { vendorId: 0xA108, productId: 0xC309 },
            { vendorId: 0x601A, productId: 0x8887 },
            { vendorId: 0xA108, productId: 0x8887 },
            { vendorId: 0x601A, productId: 0x601E },
            { vendorId: 0xA108, productId: 0x601E },
            { vendorId: 0x601A, productId: 0x601A },
            { vendorId: 0xA108, productId: 0x601A },
            { vendorId: 0x601A, productId: 0x4D44 },
            { vendorId: 0xA108, productId: 0x4D44 },
        ];

        var device;
        try {
            device = await navigator.usb.requestDevice({ filters: filters });
        } catch (e) {
            log('No device selected', 'warn');
            setState('idle');
            return;
        }

        // Store on global so the libusb shim can find it in getDevices()
        if (!window._webusb_devices) window._webusb_devices = [];
        var already = window._webusb_devices.some(function(d) { return d === device; });
        if (!already) window._webusb_devices.push(device);

        console.log('Device selected: VID=0x' + device.vendorId.toString(16) +
            ' PID=0x' + device.productId.toString(16));

        // A U-Boot DFU gadget (a108:4d44) is ready to flash directly; it isn't
        // an Ingenic bootrom, so skip the SoC detect path.
        if (deviceIsDfuGadget(device)) {
            inDfuMode = true;
            showDeviceInfo(detectedVariantName ? detectedVariantName.toUpperCase() : '—', 'U-Boot DFU',
                       device.vendorId, device.productId);
            log('Device in U-Boot DFU mode — ready (Write to flash, Read to dump).');
            setState('done');
            return;
        }
        inDfuMode = false;

        setState('detecting');
        console.log('Discovering devices...');

        var info = await discoverDevices();
        if (!info) {
            log('No Ingenic devices found', 'warn');
            setState('idle');
            return;
        }

        // The bootrom magic can't distinguish every SoC (e.g. the T32 reports the
        // same "T31V" as the T31); for a bootrom device, upload the register probe
        // to get the true variant before we display/route. Falls back to the magic.
        if (info.stage === 0) {
            var refined = await wasmCall('tdfu_web_detect_soc', 'string', ['number'], [0]);
            if (refined && refined !== info.variantName) {
                log('SoC probe: ' + refined.toUpperCase(), 'debug');
                info.variantName = refined;
                info.variant = await wasmCall('tdfu_variant_from_string', 'number', ['string'], [refined]);
            }
        }

        detectedVariant = info.variant;
        detectedVariantName = info.variantName;

        var stageName = info.stage === 0 ? 'Bootrom' : 'Firmware';
        showDeviceInfo(info.variantName.toUpperCase(), stageName, info.vid, info.pid);
        log('Detected: ' + info.variantName.toUpperCase() + ' (' + stageName + ')');

        setState('done');
    } catch (e) {
        log('Connection error: ' + e.message, 'error');
        console.error(e);
        setState('error');
    }
}

/* Attach a device we ALREADY have permission for, with no chooser and no user
 * gesture. Driven by the 'connect' event and a getDevices() sweep at load.
 *
 * This is what removes the manual re-pick after a bootstrap: once the DFU
 * gadget (a108:4d44) has been authorized once, WebUSB persists that grant, so
 * when the device re-enumerates the 'connect' event fires and we wire it up
 * automatically. The very first authorization still needs one chooser click
 * (WebUSB won't surface a device that isn't present yet, and the PID changes
 * across re-enumeration). */

/* Recognize the U-Boot DFU gadget by its DFU interface (class 0xFE / subclass
 * 0x01) rather than only the 0x4D44 PID, so a gadget that shares the bootrom PID
 * (0xC309) is still detected. The gadget often has no active configuration set,
 * so scan device.configurations (all), not device.configuration. */
function deviceHasDfuInterface(device) {
    try {
        var cfgs = device.configurations || [];
        for (var c = 0; c < cfgs.length; c++) {
            var ifs = (cfgs[c] && cfgs[c].interfaces) || [];
            for (var i = 0; i < ifs.length; i++) {
                var alts = (ifs[i] && ifs[i].alternates) || [];
                for (var a = 0; a < alts.length; a++) {
                    if (alts[a].interfaceClass === 0xFE && alts[a].interfaceSubclass === 0x01) return true;
                }
            }
        }
    } catch (e) { /* ignore */ }
    return false;
}
function deviceIsDfuGadget(device) {
    return device.productId === 0x4D44 || deviceHasDfuInterface(device);
}

async function autoAttachDevice(device) {
    if (!tdfuReady || !device) { log('autoAttach: not ready', 'debug'); return; }
    if (device.vendorId !== 0x601A && device.vendorId !== 0xA108) {
        log('autoAttach: ignoring non-Ingenic 0x' + device.vendorId.toString(16), 'debug');
        return;
    }
    // Never hijack an operation in flight (read/write/bootstrap).
    if (currentState !== 'idle' && currentState !== 'done') {
        log('autoAttach: skipped, busy (' + currentState + ')', 'debug');
        return;
    }
    log('autoAttach: attaching 0x' + device.productId.toString(16) + ' (state ' + currentState + ')', 'debug');

    if (!window._webusb_devices) window._webusb_devices = [];
    if (!window._webusb_devices.some(function(d) { return d === device; }))
        window._webusb_devices.push(device);
    setAttention('btn-connect', false); // device is here; no manual re-pick needed

    if (deviceIsDfuGadget(device)) {
        inDfuMode = true;
        showDeviceInfo(detectedVariantName ? detectedVariantName.toUpperCase() : '—', 'U-Boot DFU',
                       device.vendorId, device.productId);
        log('Device reconnected in U-Boot DFU mode — ready (no re-pick needed).');
        setState('done');
        return;
    }

    // Bootrom / firmware stage: probe and show what it is.
    inDfuMode = false;
    setState('detecting');
    var info = await discoverDevices();
    if (!info) { setState('idle'); return; }
    detectedVariant = info.variant;
    detectedVariantName = info.variantName;
    var stageName = info.stage === 0 ? 'Bootrom' : 'Firmware';
    showDeviceInfo(info.variantName.toUpperCase(), stageName, info.vid, info.pid);
    log('Detected: ' + info.variantName.toUpperCase() + ' (' + stageName + ')');
    setState('done');
}

/* ------------------------------------------------------------------ */
/*  Bootstrap                                                          */
/* ------------------------------------------------------------------ */

async function doBootstrap() {
    if (backendMode === 'remote') return doRemoteBootstrap();
    if (!tdfuReady) return;
    return doDfuBootstrap();
}

/* ------------------------------------------------------------------ */
/*  Write Firmware                                                     */
/* ------------------------------------------------------------------ */

function selectFirmware() {
    document.getElementById('firmware-file').click();
}

function firmwareSelected(input) {
    if (!input.files || !input.files[0]) return;

    var file = input.files[0];
    firmwareFileName = file.name;

    var reader = new FileReader();
    reader.onload = function(e) {
        firmwareData = new Uint8Array(e.target.result);
        var sizeMB = (firmwareData.length / (1024 * 1024)).toFixed(2);
        document.getElementById('file-info').textContent =
            firmwareFileName + ' (' + sizeMB + ' MB)';
        log('Firmware loaded: ' + firmwareFileName + ' (' + sizeMB + ' MB)');

        // Auto-start write if device is in firmware stage
        doWrite();
    };
    reader.readAsArrayBuffer(file);
}

async function doWrite() {
    if (!(await applyOverlayInjection())) return;   // abort if injection was requested but failed
    if (backendMode === 'remote') { if (firmwareData) return doRemoteWrite(firmwareData); return; }
    if (!tdfuReady || !firmwareData) return;
    return doDfuWrite();
}

/* If the user entered any pre-configuration (Wi-Fi, SSH key), bake the
 * corresponding files into the loaded image's overlay (client-side, in the
 * browser) before flashing. Returns false to abort the flash only when an
 * injection was requested but failed - so it's never silently dropped. */
async function applyOverlayInjection() {
    if (!firmwareData) return true;
    if (!injectEnabled) return true;   // Pre-configure is disabled in Settings
    var ssid = ((document.getElementById('wifi-ssid') || {}).value || '').trim();
    var psk = (document.getElementById('wifi-psk') || {}).value || '';
    var sshKey = (document.getElementById('ssh-key') || {}).value || '';
    var files = overlayFilesFor({ ssid: ssid, psk: psk, sshKey: sshKey });

    // generic user-added files: each row is a target path + a local file
    var rows = document.querySelectorAll('#extra-files .xf-row');
    for (var i = 0; i < rows.length; i++) {
        var p = (rows[i].querySelector('.xf-path').value || '').trim();
        var f = rows[i].querySelector('.xf-file').files[0];
        if (!p && !f) continue;                       // untouched row - ignore
        if (!p || !f) {                               // half-filled - don't silently drop
            log('Overlay injection failed: each added file needs both a target path and a file.');
            alert(t('wifi_inject_failed') + '\n\n' + t('xf_incomplete'));
            return false;
        }
        files['/' + p.replace(/^\/+/, '')] = new Uint8Array(await f.arrayBuffer());
    }

    var names = Object.keys(files);
    if (!names.length) return true;
    try {
        log('Baking overlay files into the image (' + names.join(', ') + ')...');
        firmwareData = await injectOverlay(firmwareData, files);
        log('Overlay injected - flashing the customised image.');
        return true;
    } catch (e) {
        log('Overlay injection failed: ' + e.message);
        alert(t('wifi_inject_failed') + '\n\n' + e.message);
        return false;
    }
}

/* Append an empty "add a file" row (target path + file picker + remove button).
 * Placeholders/labels are set via t() so dynamically-added rows are localized. */
function addExtraFileRow() {
    var box = document.getElementById('extra-files');
    if (!box) return;
    var row = document.createElement('div');
    row.className = 'd-flex flex-wrap gap-2 mt-2 xf-row';
    var path = document.createElement('input');
    path.className = 'form-control form-control-sm xf-path';
    path.style.maxWidth = '16rem';
    path.setAttribute('autocomplete', 'off');
    path.placeholder = t('xf_path_ph');
    var file = document.createElement('input');
    file.type = 'file';
    file.className = 'form-control form-control-sm xf-file';
    file.style.maxWidth = '16rem';
    var del = document.createElement('button');
    del.type = 'button';
    del.className = 'btn btn-sm btn-outline-danger xf-del';
    del.textContent = '×';
    del.title = t('xf_remove');
    del.onclick = function () { row.remove(); };
    row.append(path, file, del);
    box.appendChild(row);
    path.focus();
}

/* ------------------------------------------------------------------ */
/*  Read Firmware                                                      */
/* ------------------------------------------------------------------ */

async function doRead() {
    if (backendMode === 'remote') return doRemoteRead();
    if (!tdfuReady) return;
    return doDfuRead();
}

/* ------------------------------------------------------------------ */
/*  Advanced: custom DFU bootloader (optional SPL + U-Boot upload)      */
/* ------------------------------------------------------------------ */

function toggleAdvanced(e) {
    if (e) e.preventDefault();
    var controls = document.getElementById('adv-controls');
    var chev = document.getElementById('adv-chevron');
    var hidden = controls.classList.toggle('d-none');
    if (chev) chev.className = hidden ? 'bi bi-chevron-right' : 'bi bi-chevron-down';
}

/* Flip a Select button between its idle (blue outline + file icon) and loaded
 * (solid green + check) look, so it's obvious which images are staged. */
function setSelectButtonLoaded(id, loaded) {
    var b = document.getElementById(id);
    if (!b) return;
    var icon = b.querySelector('i');
    if (loaded) {
        b.classList.remove('btn-outline-primary');
        b.classList.add('btn-success');
        if (icon) icon.className = 'bi bi-check-circle-fill me-1';
    } else {
        b.classList.remove('btn-success');
        b.classList.add('btn-outline-primary');
        if (icon) icon.className = 'bi bi-file-earmark-binary me-1';
    }
}

/* Read a chosen file into a { name, data } record and report it. */
function readCustomBootloaderFile(input, which) {
    if (!input.files || !input.files[0]) return;
    var file = input.files[0];
    var isSpl = which === 'spl';
    var infoId = isSpl ? 'custom-spl-info' : 'custom-uboot-info';
    var btnId = isSpl ? 'btn-sel-spl' : 'btn-sel-uboot';
    var label = isSpl ? 'SPL' : 'U-Boot';
    var reader = new FileReader();
    reader.onload = function(e) {
        var rec = { name: file.name, data: new Uint8Array(e.target.result) };
        if (isSpl) customSpl = rec; else customUboot = rec;
        document.getElementById(infoId).textContent =
            label + ': ' + file.name + ' (' + rec.data.length + ' bytes)';
        setSelectButtonLoaded(btnId, true);
        log('Custom ' + label + ' selected: ' + file.name + ' (' + rec.data.length + ' bytes)');
        if (customSpl && customUboot)
            log('Custom SPL + U-Boot ready — next Bootstrap will use them.', 'warn');
    };
    reader.readAsArrayBuffer(file);
}

function customSplSelected(input) { readCustomBootloaderFile(input, 'spl'); }
function customUbootSelected(input) { readCustomBootloaderFile(input, 'uboot'); }

function clearCustomBootloader() {
    customSpl = null;
    customUboot = null;
    document.getElementById('custom-spl-info').textContent = 'SPL: bundled';
    document.getElementById('custom-uboot-info').textContent = 'U-Boot: bundled';
    document.getElementById('custom-spl-file').value = '';
    document.getElementById('custom-uboot-file').value = '';
    setSelectButtonLoaded('btn-sel-spl', false);
    setSelectButtonLoaded('btn-sel-uboot', false);
    log('Custom bootloader cleared — using bundled DFU U-Boot.');
}

/* ------------------------------------------------------------------ */
/*  DFU backend flows (default)                                        */
/* ------------------------------------------------------------------ */

async function doDfuBootstrap() {
    var custom = !!(customSpl && customUboot);
    if (detectedVariant < 0 && !custom) { log('Connect a device in bootrom mode first', 'warn'); return; }
    setState('bootstrapping');
    showProgress(10, custom ? 'Loading custom U-Boot...' : 'Loading DFU U-Boot...');
    log(custom ? 'DFU bootstrap with custom SPL + U-Boot...'
               : 'DFU bootstrap for ' + detectedVariantName.toUpperCase() + '...');
    try {
        var rc;
        if (custom) {
            Module.FS.writeFile('/tmp/custom_spl.bin', customSpl.data);
            Module.FS.writeFile('/tmp/custom_uboot.bin', customUboot.data);
            showProgress(40, 'USB-booting custom U-Boot (DFU)...');
            rc = await wasmCall('tdfu_web_dfu_bootstrap_files', 'number',
                ['number', 'string', 'string'], [0, '/tmp/custom_spl.bin', '/tmp/custom_uboot.bin']);
            try { Module.FS.unlink('/tmp/custom_spl.bin'); } catch (e) { /* ignore */ }
            try { Module.FS.unlink('/tmp/custom_uboot.bin'); } catch (e) { /* ignore */ }
        } else {
            await loadDfuFirmwareToMemFS(detectedVariantName);
            showProgress(40, 'USB-booting U-Boot (DFU)...');
            rc = await wasmCall('tdfu_web_dfu_bootstrap', 'number',
                ['number', 'string', 'string'], [0, './firmware', detectedVariantName]);
        }
        if (rc !== 0) {
            log('DFU bootstrap failed: error ' + rc, 'error');
            hideProgress(); setState('error'); return;
        }
        showProgress(100, 'U-Boot DFU running');
        log('Device is re-enumerating as a U-Boot DFU gadget.');
        log('First time: click Connect and pick "USB download gadget" once. After that it reconnects automatically.', 'warn');
        setTimeout(hideProgress, 1500);
        document.getElementById('device-info').classList.add('d-none');
        document.getElementById('device-disconnected').classList.remove('d-none');
        setState('idle');
        // Auto-attach happens via the USB 'connect' event when the gadget
        // enumerates (only if it was authorized before). One-shot (NOT a poll):
        // if it hasn't auto-attached within a few seconds, the gadget isn't
        // authorized yet, so glow Connect to prompt the one-time manual pick.
        setTimeout(function() {
            if (currentState === 'idle' && !inDfuMode) setAttention('btn-connect', true);
        }, 3000);
    } catch (e) {
        log('DFU bootstrap error: ' + e.message, 'error');
        console.error(e); hideProgress(); setState('error');
    }
}

async function doDfuRead() {
    if (!inDfuMode) { log('Not a DFU device — bootstrap into DFU mode first', 'warn'); return; }
    setState('reading');
    showProgressBusy('Reading flash via DFU...');
    log('DFU upload (reading flash)...');
    try {
        var rc = await wasmCall('tdfu_web_dfu_upload', 'number',
            ['number', 'string', 'string', 'number'], [0, '', '/tmp/dfu-rd.bin', 0]);
        if (rc !== 0) { log('DFU read failed: error ' + rc, 'error'); hideProgress(); setState('error'); return; }
        var data = Module.FS.readFile('/tmp/dfu-rd.bin');
        try { Module.FS.unlink('/tmp/dfu-rd.bin'); } catch (e) { /* ignore */ }
        log('Read ' + data.length + ' bytes from flash (DFU)');
        var blob = new Blob([data], { type: 'application/octet-stream' });
        var url = URL.createObjectURL(blob);
        var fname = readFilename();
        var a = document.createElement('a'); a.href = url; a.download = fname; a.click();
        URL.revokeObjectURL(url);
        showProgress(100, 'Read complete'); log('Firmware saved as ' + fname);
        await logSha256(data);
        setTimeout(hideProgress, 1500); setState('done');
    } catch (e) {
        log('DFU read error: ' + e.message, 'error'); console.error(e); hideProgress(); setState('error');
    }
}

async function doDfuWrite() {
    if (!firmwareData) { log('Select a firmware file first', 'warn'); return; }
    if (!inDfuMode) { log('Not a DFU device — bootstrap into DFU mode first', 'warn'); return; }
    setState('writing');
    /* Snapshot the flashing options. The transfer below is a minutes-long await
     * with a live event loop, and these are module-scope globals - reading them
     * afterwards lets a change made mid-write retarget an operation that is
     * already running. The image is staged the same way, just below. */
    var doVerify = verifyAfterWrite, doReboot = rebootAfterWrite;
    showProgressBusy('Writing flash via DFU...');
    log('DFU download: ' + firmwareFileName + ' (' + firmwareData.length + ' bytes)...');
    try {
        Module.FS.writeFile('/tmp/dfu-wr.bin', firmwareData);
        var rc = await wasmCall('tdfu_web_dfu_download', 'number',
            ['number', 'string', 'string'], [0, '', '/tmp/dfu-wr.bin']);
        if (rc !== 0) {
            try { Module.FS.unlink('/tmp/dfu-wr.bin'); } catch (e) { /* ignore */ }
            log('DFU write failed: error ' + rc, 'error'); hideProgress(); setState('error'); return;
        }
        log('Firmware written via DFU!');
        // Verify: read the flash back and compare against the same staged image.
        if (doVerify) {
            showProgressBusy('Verifying flash via DFU...');
            log('DFU verify: reading back ' + firmwareData.length + ' bytes...');
            var vrc = await wasmCall('tdfu_web_dfu_verify', 'number',
                ['number', 'string', 'string'], [0, '', '/tmp/dfu-wr.bin']);
            try { Module.FS.unlink('/tmp/dfu-wr.bin'); } catch (e) { /* ignore */ }
            if (vrc !== 0) {
                log('DFU verify FAILED (error ' + vrc + ') — flash does not match', 'error');
                hideProgress(); setState('error'); return;
            }
            showProgress(100, 'Write + verify complete'); log('Verify OK: flash matches');
        } else {
            try { Module.FS.unlink('/tmp/dfu-wr.bin'); } catch (e) { /* ignore */ }
            showProgress(100, 'Write complete');
        }
        if (doReboot) {
            log('Rebooting the device...');
            try { await wasmCall('tdfu_web_reboot', 'number', ['number'], [0]); log('Reboot triggered'); }
            catch (e) { log('Reboot failed: ' + e, 'warn'); }
        }
        setTimeout(hideProgress, 1500); setState('done');
    } catch (e) {
        try { Module.FS.unlink('/tmp/dfu-wr.bin'); } catch (ue) { /* ignore */ }
        log('DFU write error: ' + e.message, 'error'); console.error(e); hideProgress(); setState('error');
    }
}

/* ------------------------------------------------------------------ */
/*  Info / diagnostics (read-only eFuse + secure-boot)                 */
/* ------------------------------------------------------------------ */

/* Last successful readout, cached so the Info button still works after the
 * device is bootstrapped out of bootrom (the eFuse can no longer be re-read).
 * Cleared when a new device connection starts. */
var lastDiagText = null;

async function doDiag() {
    // Already bootstrapped (DFU gadget): the eFuse can't be re-read, so show the
    // cached readout captured before the bootstrap.
    if (inDfuMode) {
        if (lastDiagText) showDiagModal(lastDiagText, true);
        else log('No cached info yet — click Info before bootstrapping.', 'warn');
        return;
    }
    var text = null;
    try {
        if (backendMode === 'remote') {
            if (!remoteReady()) { log('Connect to the daemon first', 'warn'); return; }
            log('Reading device info (eFuse) via daemon...');
            text = await remoteClient.diag(selectedRemoteIndex);
        } else {
            log('Reading device info (eFuse)...');
            text = await wasmCall('tdfu_web_diag', 'string', ['number'], [0]);
        }
    } catch (e) {
        log('Info error: ' + e.message, 'error'); console.error(e);
    }
    var ok = text && text.length && text.indexOf('Diag failed') !== 0;
    if (ok) {
        lastDiagText = text;
        showDiagModal(text, false);
    } else if (lastDiagText) {
        showDiagModal(lastDiagText, true);
    } else {
        showDiagModal(text && text.length ? text : 'Diag failed — see log.', false);
    }
}

function showDiagModal(text, cached) {
    document.getElementById('diag-output').textContent =
        cached ? text + '\n\n(cached — device is no longer in bootrom mode)' : text;
    document.getElementById('diag-overlay').classList.remove('d-none');
}

function closeDiag() {
    document.getElementById('diag-overlay').classList.add('d-none');
}

function copyDiag() {
    var text = document.getElementById('diag-output').textContent || '';
    if (navigator.clipboard)
        navigator.clipboard.writeText(text).then(function () { log('Info copied to clipboard'); }, function () {});
}

/* ------------------------------------------------------------------ */
/*  Opt-in help balloons (the ? button / Settings toggle; off default) */
/* ------------------------------------------------------------------ */

var helpMode = localStorage.getItem('tdfu_help') === '1';
var _helpBalloon = null, _helpHover = null;

function applyHelpMode() {
    document.body.classList.toggle('help-on', helpMode);
    var b = document.getElementById('btn-help');
    if (b) b.classList.toggle('help-active', helpMode);
    var s = document.getElementById('setting-help');
    if (s) s.checked = helpMode;
    // Suppress native title tooltips while help mode is on so they don't double
    // up with our balloons; restore them when it's off.
    var els = document.querySelectorAll('[data-help]');
    for (var i = 0; i < els.length; i++) {
        var el = els[i];
        if (helpMode && el.hasAttribute('title')) {
            el.setAttribute('data-saved-title', el.getAttribute('title'));
            el.removeAttribute('title');
        } else if (!helpMode && el.hasAttribute('data-saved-title')) {
            el.setAttribute('title', el.getAttribute('data-saved-title'));
            el.removeAttribute('data-saved-title');
        }
    }
    if (!helpMode) hideHelpBalloon();
}
function setHelp(on) {
    helpMode = !!on;
    localStorage.setItem('tdfu_help', helpMode ? '1' : '0');
    applyHelpMode();
}
function toggleHelp() { setHelp(!helpMode); }

/* Verbose diagnostics — Settings toggle, persisted (replaces the old ?debug). */
function setDebug(on) {
    debugEnabled = !!on;
    window.__tdfu_debug = debugEnabled;
    localStorage.setItem('tdfu_debug', debugEnabled ? '1' : '0');
    var s = document.getElementById('setting-debug');
    if (s) s.checked = debugEnabled;
    /* Module is module-scoped (this file is an ES module), so it is NOT on
     * window - reaching for window.Module here silently did nothing, and the
     * C-side [DEBUG] lines only ever came back after a page reload.
     *
     * Go through wasmCall, not a bare ccall: the module is built ASYNCIFY=1 and
     * every entry is serialized on wasmBusy, so a flip made while a transfer is
     * suspended queues until it finishes instead of re-entering the module. */
    if (Module && Module.ccall) {
        wasmCall('tdfu_web_set_debug', null, ['number'], [debugEnabled ? 1 : 0])
            .catch(function () { /* module not ready */ });
    }
    log('Debug logging ' + (debugEnabled ? 'enabled' : 'disabled'));
}

/* Verify-after-write — Settings toggle, persisted. */
function setVerify(on) {
    verifyAfterWrite = !!on;
    localStorage.setItem('tdfu_verify', verifyAfterWrite ? '1' : '0');
    var s = document.getElementById('setting-verify');
    if (s) s.checked = verifyAfterWrite;
}

/* Reboot-after-write — Settings toggle, persisted. */
function setReboot(on) {
    rebootAfterWrite = !!on;
    localStorage.setItem('tdfu_reboot', rebootAfterWrite ? '1' : '0');
    var s = document.getElementById('setting-reboot');
    if (s) s.checked = rebootAfterWrite;
}

/* Advanced (custom SPL/U-Boot) — Settings toggle, persisted. */
function setAdvanced(on) {
    advancedEnabled = !!on;
    localStorage.setItem('tdfu_advanced', advancedEnabled ? '1' : '0');
    var s = document.getElementById('setting-advanced');
    if (s) s.checked = advancedEnabled;
    applyAdvanced();
}

function applyAdvanced() {
    var adv = document.getElementById('adv-wrap');
    if (adv) adv.classList.toggle('d-none', !advancedEnabled);
    /* Hiding the panel must not leave a custom loader armed for the next
     * bootstrap: it would be used with nothing on screen saying so, and no way
     * to clear it. Turning Advanced off therefore drops any loaded override. */
    if (!advancedEnabled && (customSpl || customUboot)) clearCustomBootloader();
}

/* Prebuilt-release picker — Settings toggle, persisted. */
function setReleases(on) {
    releasesEnabled = !!on;
    localStorage.setItem('tdfu_releases', releasesEnabled ? '1' : '0');
    var s = document.getElementById('setting-releases');
    if (s) s.checked = releasesEnabled;
    applyReleases();
}

function applyReleases() {
    var rel = document.getElementById('rel-wrap');
    if (rel) rel.classList.toggle('d-none', !releasesEnabled);
}

/* Pre-configure (Wi-Fi / SSH / arbitrary overlay files) — Settings toggle, persisted. */
function setInject(on) {
    injectEnabled = !!on;
    localStorage.setItem('tdfu_inject', injectEnabled ? '1' : '0');
    var s = document.getElementById('setting-inject');
    if (s) s.checked = injectEnabled;
    applyInject();
}

function applyInject() {
    var el = document.getElementById('wifi-inject');
    if (el) el.classList.toggle('d-none', !injectEnabled);
}

/* Collapse/expand the Pre-configure panel, like Advanced and the release picker.
 * Purely cosmetic: whatever is typed in still gets injected when collapsed (and
 * applyOverlayInjection logs every file it bakes in), so nothing is hidden. */
function toggleInject(e) {
    if (e) e.preventDefault();
    var panel = document.getElementById('inject-panel');
    var chev = document.getElementById('inject-chevron');
    var hidden = panel.classList.toggle('d-none');
    if (chev) chev.className = hidden ? 'bi bi-chevron-right' : 'bi bi-chevron-down';
}

function hideHelpBalloon() {
    _helpHover = null;
    if (_helpBalloon) _helpBalloon.classList.remove('show');
}
function showHelpBalloon(el) {
    if (!_helpBalloon) {
        _helpBalloon = document.createElement('div');
        _helpBalloon.className = 'help-balloon';
        document.body.appendChild(_helpBalloon);
    }
    // data-help now holds an i18n key; resolve it (fall back to the raw value).
    _helpBalloon.textContent = window.I18N ? I18N.t(el.getAttribute('data-help')) : el.getAttribute('data-help');
    _helpBalloon.classList.add('show');
    var r = el.getBoundingClientRect();
    var bw = _helpBalloon.offsetWidth, bh = _helpBalloon.offsetHeight;
    var left = Math.min(Math.max(8, r.left), window.innerWidth - bw - 8);
    var top = r.bottom + 9, above = false;
    if (top + bh > window.innerHeight - 8) { top = r.top - bh - 9; above = true; } // flip above if it would overflow
    if (top < 8) top = 8;
    _helpBalloon.classList.toggle('above', above);
    _helpBalloon.style.left = left + 'px';
    _helpBalloon.style.top = top + 'px';
}

/* Track the topmost helpable element under the cursor. elementFromPoint respects
 * z-order (a control inside the Settings modal wins over anything behind it) and
 * still resolves disabled buttons, which don't emit their own hover events. */
document.addEventListener('mousemove', function (e) {
    if (!helpMode) return;
    var top = document.elementFromPoint(e.clientX, e.clientY);
    var el = top && top.closest ? top.closest('[data-help]') : null;
    if (el) { if (el !== _helpHover) { _helpHover = el; showHelpBalloon(el); } }
    else if (_helpHover) { hideHelpBalloon(); }
});

/* ------------------------------------------------------------------ */
/*  Remote daemon backend (dfu-remote over WebSocket)                  */
/* ------------------------------------------------------------------ */

/* Populate the remote device <select>, showing it only when more than one device
 * is connected to the daemon. */
function renderRemoteDevicePicker() {
    var row = document.getElementById('device-picker-row');
    var sel = document.getElementById('device-picker');
    if (!row || !sel) return;
    if (!remoteDevices || remoteDevices.length <= 1) { row.classList.add('d-none'); return; }
    sel.innerHTML = '';
    remoteDevices.forEach(function (x, i) {
        var stage = x.stage === 0 ? 'bootrom' : (x.stage === 2 ? 'DFU' : 'firmware');
        var opt = document.createElement('option');
        opt.value = String(i);
        opt.textContent = x.variantName.toUpperCase() + ' (' + stage + ') — bus ' + x.bus + ' addr ' + x.address;
        sel.appendChild(opt);
    });
    sel.value = String(selectedRemoteIndex);
    row.classList.remove('d-none');
}

/* Select the i-th discovered remote device and refresh the SoC/stage display and
 * which actions are live. */
function selectRemoteDevice(idx) {
    if (!remoteDevices || idx < 0 || idx >= remoteDevices.length) return;
    selectedRemoteIndex = idx;
    var d = remoteDevices[idx];
    detectedVariantName = d.variantName;
    detectedVariant = d.variant;
    inDfuMode = d.stage !== 0;
    showDeviceInfo(d.variantName.toUpperCase(),
        d.stage === 0 ? 'Bootrom' : (d.stage === 2 ? 'DFU' : 'Firmware'), d.vendor, d.product);
    var picker = document.getElementById('device-picker');
    if (picker) picker.value = String(idx);
    setState('done');
    setAttention(d.stage === 0 ? 'btn-bootstrap' : 'btn-read', true);
}

async function doRemoteConnect() {
    if (remoteClient && remoteClient.isConnected()) {
        remoteClient.disconnect();
        remoteClient = null;
        remoteDevices = [];
        log('Disconnected from daemon.');
        document.getElementById('device-info').classList.add('d-none');
        document.getElementById('device-disconnected').classList.remove('d-none');
        setState('idle');
        return;
    }
    if (!remoteUrl) { log('Set the daemon URL in Settings first.', 'warn'); openSettings(); return; }
    setState('connecting');
    setAttention('btn-connect', false);
    log('Connecting to ' + remoteUrl + ' ...');
    var client = new RemoteClient(
        function(m) {
            // DFU read/write progress arrives as repeated "\r  <N> bytes" frames
            // (terminal overwrite). Route the live value to the progress label
            // instead of appending thousands of log lines (mirrors printErr).
            if (m.indexOf('\r') !== -1) {
                var pl = document.getElementById('progress-label');
                var tail = m.slice(m.lastIndexOf('\r') + 1).trim();
                if (pl && tail) pl.textContent = tail;
                m = m.slice(0, m.indexOf('\r'));
                if (!m.trim()) return;
            }
            log(m.replace(/\n+$/, ''), 'info');
        },
        function(p, msg) { showProgress(p, msg || ''); },
        // Resolve a variant index to its name via the WASM (the C tdfu_variant_t
        // enum is the single source of truth). Never a hardcoded JS table: that
        // drifts as per-variant loaders are added and mis-bootstraps the SoC.
        function(v) {
            try {
                var ptr = Module.ccall('tdfu_variant_to_string', 'number', ['number'], [v]);
                return (ptr ? Module.UTF8ToString(ptr) : '') || 'unknown';
            } catch (e) { return 'unknown'; }
        }
    );
    try {
        await client.connect(remoteUrl, remoteToken || null);
    } catch (e) {
        log('Connection failed: ' + (e && e.message ? e.message : e), 'error');
        log('If Chrome blocked it, allow the "access your local network" prompt and retry.', 'warn');
        setState('error');
        return;
    }
    remoteClient = client;
    log('Connected. Discovering devices...');
    var devs = [];
    try { devs = await client.discover(); } catch (e) { log('Discover failed: ' + e.message, 'error'); }
    remoteDevices = devs;
    if (!devs.length) {
        log('No Ingenic devices found on the daemon.', 'warn');
        showDeviceInfo('—', 'no device', 0, 0);
        setState('idle');
        return;
    }
    selectedRemoteIndex = 0;
    renderRemoteDevicePicker();
    selectRemoteDevice(0); // sets state, the SoC/stage display, and the next-action glow
    log('Found ' + devs.length + ' device(s)' + (devs.length > 1 ? ' (pick one above)' : '') +
        '; using ' + devs[0].variantName.toUpperCase() + ' (' + devs[0].stageName + ').');
}

function remoteReady() {
    if (remoteClient && remoteClient.isConnected()) return true;
    log('Not connected to a daemon.', 'warn');
    return false;
}

async function doRemoteBootstrap() {
    if (!remoteReady()) return;
    // Snapshot devices already in DFU so we can pick out our re-enumerated gadget
    // among them afterward (correct even with several devices connected).
    var beforeDfu = remoteDevices.filter(function (x) { return x.stage !== 0; })
        .map(function (x) { return x.bus + ':' + x.address; });
    setState('bootstrapping');
    showProgressBusy('Bootstrapping via daemon...');
    log('Remote bootstrap for ' + (detectedVariantName || '').toUpperCase() + '...');
    try {
        var custom = !!(customSpl && customUboot);
        if (custom)
            log('Using custom SPL (' + customSpl.data.length + ' B) + U-Boot (' + customUboot.data.length + ' B)');
        var ok = await remoteClient.bootstrap(selectedRemoteIndex, detectedVariantName,
                                              custom ? customSpl.data : null, custom ? customUboot.data : null);
        if (!ok) { log('Remote bootstrap failed.', 'error'); hideProgress(); setState('error'); return; }
        log('Remote bootstrap complete.');
        // The device re-enumerates bootrom -> U-Boot DFU gadget, which takes a
        // few seconds. The daemon owns the USB (no browser reconnect, unlike
        // local WebUSB), so just poll discover until it reappears past bootrom -
        // then it's ready to Read/Write with no manual reconnect.
        showProgressBusy('Waiting for DFU gadget to re-enumerate...');
        var d = null;
        for (var i = 0; i < 20 && !d; i++) {
            await new Promise(function (r) { setTimeout(r, 700); });
            try {
                remoteDevices = await remoteClient.discover();
            } catch (e) { remoteDevices = []; }
            d = remoteDevices.find(function (x) {
                return x.stage !== 0 && beforeDfu.indexOf(x.bus + ':' + x.address) === -1;
            }) || null;
        }
        if (d) {
            // Re-point to the DFU gadget for Read/Write, but KEEP the SoC detected at
            // the bootrom stage. A DFU gadget is past the bootrom, so its SoC can't be
            // re-detected and its reported variant is just the default placeholder
            // (T31X) - don't overwrite the real one with it.
            selectedRemoteIndex = remoteDevices.indexOf(d);
            renderRemoteDevicePicker(); // the list changed (this device went bootrom -> DFU)
            inDfuMode = true; // now a DFU gadget: Bootstrap off, Read/Write on
            var soc = (detectedVariantName || d.variantName || 'dfu').toUpperCase();
            showDeviceInfo(soc, 'DFU', d.vendor, d.product);
            log('Device re-enumerated in DFU mode (' + soc + ') - ready to Read/Write.');
            showProgress(100, 'Ready');
            setTimeout(hideProgress, 1200);
            setState('done');
            setAttention('btn-read', true);
        } else {
            log('Device did not reappear as a DFU gadget after bootstrap; try Connect again.', 'warn');
            hideProgress();
            setState('done');
        }
    } catch (e) { log('Remote bootstrap error: ' + e.message, 'error'); hideProgress(); setState('error'); }
}

async function doRemoteRead() {
    if (!remoteReady()) return;
    setState('reading');
    showProgressBusy('Reading flash via daemon...');
    log('Remote read...');
    try {
        var data = await remoteClient.readFirmware(selectedRemoteIndex, detectedVariantName);
        if (!data) { log('Remote read failed.', 'error'); hideProgress(); setState('error'); return; }
        var fname = readFilename();
        var blob = new Blob([data], { type: 'application/octet-stream' });
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a'); a.href = url; a.download = fname; a.click();
        URL.revokeObjectURL(url);
        showProgress(100, 'Read complete');
        log('Read ' + data.length + ' bytes; saved as ' + fname);
        await logSha256(data);
        setTimeout(hideProgress, 1500);
        setState('done');
    } catch (e) { log('Remote read error: ' + e.message, 'error'); hideProgress(); setState('error'); }
}

async function doRemoteWrite(data) {
    if (!remoteReady()) return;
    /* Same guard doDfuWrite has: a bootrom exposes no DFU gadget, so the daemon
     * would sit waiting for one that never answers. Fail fast, don't hang. */
    if (!inDfuMode) { log('Not a DFU device — bootstrap into DFU mode first', 'warn'); return; }
    setState('writing');
    /* Snapshot the flashing options. The transfer below is a minutes-long await
     * with a live event loop, and these are module-scope globals - reading them
     * afterwards lets a change made mid-write retarget an operation that is
     * already running. The image is staged the same way, just below. */
    var doVerify = verifyAfterWrite, doReboot = rebootAfterWrite;
    showProgressBusy('Writing flash via daemon...');
    log('Remote write (' + data.length + ' bytes)' + (doVerify ? ' + verify...' : '...'));
    try {
        var ok = await remoteClient.writeFirmware(selectedRemoteIndex, detectedVariantName, data, doVerify);
        if (!ok) { log('Remote write failed.', 'error'); hideProgress(); setState('error'); return; }
        showProgress(100, doVerify ? 'Write + verify complete' : 'Write complete');
        log('Remote write complete.' + (doVerify ? ' Verify OK.' : ''));
        if (doReboot) {
            log('Rebooting the device (remote)...');
            try { await remoteClient.reboot(selectedRemoteIndex); log('Reboot triggered'); }
            catch (e) { log('Reboot failed: ' + e.message, 'warn'); }
        }
        setTimeout(hideProgress, 1500);
        setState('done');
    } catch (e) { log('Remote write error: ' + e.message, 'error'); hideProgress(); setState('error'); }
}

/* ------------------------------------------------------------------ */
/*  Settings (backend selection)                                       */
/* ------------------------------------------------------------------ */

function applyBackendMode(mode) {
    backendMode = (mode === 'remote') ? mode : 'dfu';
    localStorage.setItem('tdfu_backend', backendMode);
    var ind = document.getElementById('mode-indicator');
    if (ind) ind.textContent = backendMode === 'remote' ? 'Remote' : 'DFU';
    // The custom SPL/U-Boot override works in both backends, so its visibility is
    // owned solely by the Advanced setting (see applyAdvanced), not by the backend.
    // Leaving remote mode drops any open daemon connection.
    if (backendMode !== 'remote' && remoteClient) {
        remoteClient.disconnect();
        remoteClient = null;
        remoteDevices = [];
    }
    var cb = document.getElementById('btn-connect');
    if (cb) cb.innerHTML = backendMode === 'remote'
        ? '<i class="bi bi-hdd-network me-1"></i> Connect Daemon'
        : '<i class="bi bi-usb-symbol me-1"></i> Connect Device';
    setState(currentState); // re-evaluate which action buttons are live for this backend
}

function toggleRemoteFields() {
    var sel = document.getElementById('setting-remote');
    var rf = document.getElementById('remote-fields');
    if (rf) rf.classList.toggle('d-none', !(sel && sel.checked));
}

function openSettings() {
    var r = document.getElementById('setting-' + backendMode);
    if (r) r.checked = true;
    var u = document.getElementById('remote-url'); if (u) u.value = remoteUrl;
    var t = document.getElementById('remote-token'); if (t) t.value = remoteToken;
    var h = document.getElementById('setting-help'); if (h) h.checked = helpMode;
    var v = document.getElementById('setting-verify'); if (v) v.checked = verifyAfterWrite;
    var rb = document.getElementById('setting-reboot'); if (rb) rb.checked = rebootAfterWrite;
    var d = document.getElementById('setting-debug'); if (d) d.checked = debugEnabled;
    var a = document.getElementById('setting-advanced'); if (a) a.checked = advancedEnabled;
    var rl = document.getElementById('setting-releases'); if (rl) rl.checked = releasesEnabled;
    var ij = document.getElementById('setting-inject'); if (ij) ij.checked = injectEnabled;
    toggleRemoteFields();
    document.getElementById('settings-overlay').classList.remove('d-none');
}

function closeSettings() {
    document.getElementById('settings-overlay').classList.add('d-none');
}

/* Windows needs a WinUSB driver (via Zadig) before WebUSB can open the device,
 * so the driver prompt is only relevant there. */
function isWindows() {
    if (navigator.userAgentData && navigator.userAgentData.platform)
        return navigator.userAgentData.platform === 'Windows';
    return /win/i.test(navigator.platform || navigator.userAgent || '');
}

function openWindowsHelp() {
    document.getElementById('windows-help-overlay').classList.remove('d-none');
}

function closeWindowsHelp() {
    document.getElementById('windows-help-overlay').classList.add('d-none');
}

function saveSettings() {
    var sel = document.querySelector('input[name="backend-mode"]:checked');
    var mode = sel ? sel.value : 'dfu';
    if (mode === 'remote') {
        var u = document.getElementById('remote-url');
        var t = document.getElementById('remote-token');
        remoteUrl = (u ? u.value : '').trim();
        remoteToken = (t ? t.value : '').trim();
        localStorage.setItem('tdfu_remote_url', remoteUrl);
        localStorage.setItem('tdfu_remote_token', remoteToken);
    }
    var changed = mode !== backendMode;
    applyBackendMode(mode);
    log('Backend: ' + (backendMode === 'remote' ? 'Remote daemon (' + (remoteUrl || 'no URL set') + ')' : 'DFU'));
    if (changed) {
        detectedVariant = -1;
        detectedVariantName = '';
        inDfuMode = false;
        document.getElementById('device-info').classList.add('d-none');
        document.getElementById('device-disconnected').classList.remove('d-none');
        setState('idle');
    }
    closeSettings();
}

/* ------------------------------------------------------------------ */
/* ------------------------------------------------------------------ */
/*  Prebuilt thingino releases                                         */
/* ------------------------------------------------------------------ */

/* Where the firmware BYTES come from. GitHub release assets carry no
 * Access-Control-Allow-Origin, so a browser cannot fetch them directly - the
 * bytes must pass through a hop that adds the header. That hop is a Cloudflare
 * Worker (worker/src/index.js in this repo): it streams the asset through and
 * adds the header, refusing anything outside the thingino firmware allow-list.
 * Listing releases needs no hop - api.github.com does send CORS. */
var FW_PROXY = 'https://thingino-dfu-fw.thingino.workers.dev/fw';

var relAssets = {}; /* tag -> assets[] from the releases API */
var relLoaded = false;

function toggleReleases(e) {
    if (e) e.preventDefault();
    var panel = document.getElementById('rel-panel');
    var chev = document.getElementById('rel-chevron');
    var hidden = panel.classList.toggle('d-none');
    if (chev) chev.className = hidden ? 'bi bi-chevron-right' : 'bi bi-chevron-down';
    if (!hidden && !relLoaded) loadReleases();
}

/* (Re)build the release dropdown from relAssets, preserving the selection. Split
 * out of loadReleases so a language switch can retranslate the options without
 * hitting the API again. Object key order is insertion order: newest first. */
function renderReleaseOptions() {
    var sel = document.getElementById('rel-release');
    if (!sel) return;
    var keep = sel.value;
    sel.innerHTML = '';
    sel.appendChild(new Option(t('rel_select_release'), ''));
    Object.keys(relAssets).forEach(function(tag) {
        sel.appendChild(new Option(tag.replace('firmware-', ''), tag));
    });
    sel.value = keep;
}

/* List the firmware-<date> releases. api.github.com sends ACAO:*, so this is a
 * plain cross-origin fetch - no proxy involved. */
async function loadReleases() {
    var sel = document.getElementById('rel-release');
    try {
        var r = await fetch('https://api.github.com/repos/themactep/thingino-firmware/releases?per_page=30');
        if (!r.ok) throw new Error('HTTP ' + r.status);
        var rels = (await r.json()).filter(function(x) {
            return !x.draft && x.tag_name.indexOf('firmware-') === 0;
        });
        relAssets = {};
        rels.forEach(function(x) { relAssets[x.tag_name] = x.assets; });
        relLoaded = true;
        renderReleaseOptions();
        log('Found ' + rels.length + ' thingino firmware releases.');
    } catch (e) {
        sel.innerHTML = '';
        sel.appendChild(new Option(t('rel_load_error'), ''));
        log('Could not list releases: ' + e.message, 'error');
    }
}

/* Fill the device list for the selected release. The SoC is part of the asset
 * name (thingino-<vendor>_<model>_<soc>_<sensor>_<wifi>.bin), so the detected
 * SoC narrows ~160 images down to the handful that fit this board. */
function releaseChanged() {
    var tag = document.getElementById('rel-release').value;
    var dev = document.getElementById('rel-device');
    var info = document.getElementById('rel-info');
    var btn = document.getElementById('rel-flash');
    /* Survive a rebuild triggered by a language switch or the show-all tick. */
    var keep = dev.value;
    btn.disabled = true;

    if (!tag || !relAssets[tag]) {
        dev.disabled = true;
        dev.innerHTML = '';
        dev.appendChild(new Option(t('rel_pick_release'), ''));
        info.textContent = '';
        return;
    }

    var soc = (detectedVariantName || '').toLowerCase();
    var all = document.getElementById('rel-all').checked;
    var bins = relAssets[tag].filter(function(a) { return /\.bin$/.test(a.name); });
    var list = bins;
    if (soc && !all) {
        var re = new RegExp('_' + soc + '[._]'); /* _t31x_ or _t31x. */
        list = bins.filter(function(a) { return re.test(a.name.toLowerCase()); });
    }

    dev.disabled = false;
    dev.onchange = updateReleaseFlash;
    if (!list.length) {
        dev.innerHTML = '';
        dev.appendChild(new Option(t('rel_no_match'), ''));
        info.textContent = soc && !all
            ? t('rel_info_none_soc', { soc: soc.toUpperCase() })
            : t('rel_info_no_bins');
        return;
    }
    dev.innerHTML = '';
    dev.appendChild(new Option(t('rel_select_device'), ''));
    list.forEach(function(a) {
        dev.appendChild(new Option(
            a.name.replace(/^thingino-/, '').replace(/\.bin$/, '').replace(/_/g, ' '), a.name));
    });
    dev.value = keep; /* no-op if this release has no such image */
    updateReleaseFlash();

    /* Count last, so no translation has to agree with a plural. */
    info.textContent = (soc && !all
        ? t('rel_info_soc', { soc: soc.toUpperCase(), n: list.length })
        : t('rel_info_all', { n: list.length })) +
        (soc ? '' : ' ' + t('rel_info_connect'));
}

/* fetch() the image with a live progress bar. */
async function downloadWithProgress(url, label) {
    var r = await fetch(url);
    if (!r.ok) throw new Error('HTTP ' + r.status);
    var total = parseInt(r.headers.get('Content-Length') || '0', 10);
    var reader = r.body.getReader();
    var chunks = [], got = 0;
    for (;;) {
        var res = await reader.read();
        if (res.done) break;
        chunks.push(res.value);
        got += res.value.length;
        var mb = (got / 1048576).toFixed(1);
        if (total)
            showProgress(Math.floor(got * 100 / total), label + ' ' + mb + ' / ' + (total / 1048576).toFixed(1) + ' MB');
        else
            showProgressBusy(label + ' ' + mb + ' MB');
    }
    var out = new Uint8Array(got), off = 0;
    chunks.forEach(function(c) { out.set(c, off); off += c.length; });
    return out;
}

/* Every .bin ships a .bin.sha256sum next to it - verify before flashing. */
async function verifySha256(tag, name, data) {
    try {
        var r = await fetch(FW_PROXY + '?tag=' + encodeURIComponent(tag) +
                            '&name=' + encodeURIComponent(name + '.sha256sum'));
        if (!r.ok) {
            log('No sha256sum published for this image; skipping verification.', 'warn');
            return true;
        }
        /* thingino's .sha256sum starts with '#' comment lines, then the usual
         * "<hash>  <filename>" line - so skip comments, take the first hash. */
        var want = '';
        (await r.text()).split('\n').forEach(function(line) {
            line = line.trim();
            if (want || !line || line.charAt(0) === '#') return;
            var tok = line.split(/\s+/)[0].toLowerCase();
            if (/^[0-9a-f]{64}$/.test(tok)) want = tok;
        });
        if (!want) {
            log('Could not parse the published sha256sum; skipping verification.', 'warn');
            return true;
        }
        var got = (await sha256Hex(data)).toLowerCase();
        if (want !== got) {
            log('SHA256 mismatch: expected ' + want + ', got ' + got, 'error');
            return false;
        }
        return true;
    } catch (e) {
        log('SHA256 check skipped: ' + e.message, 'warn');
        return true;
    }
}

/* A bootrom has no DFU gadget to write to, so bootstrap it first. The Write
 * button is gated on inDfuMode, but Flash-from-release is one-click by design,
 * so it bootstraps on demand - same as a plain `thingino-dfu -w` on the CLI.
 * Returns true once the device is a DFU gadget. */
async function ensureDfuMode() {
    if (inDfuMode) return true;
    log('Device is in bootrom mode; bootstrapping into DFU first...');
    await doBootstrap();
    /* The remote bootstrap polls discover until the gadget re-enumerates and
     * sets inDfuMode itself. The local WebUSB path re-attaches asynchronously
     * via the 'connect' event, so give that a moment to land. */
    for (var i = 0; i < 40 && !inDfuMode; i++)
        await new Promise(function(r) { setTimeout(r, 500); });

    /* The gadget has only just enumerated. Starting a 16 MB download the instant
     * it appears races U-Boot's DFU coming fully up; a wedged transfer leaves a
     * stale block sequence behind (U-Boot then reports "Wrong sequence number"
     * on the next attempt). A short settle avoids that. */
    if (inDfuMode) await new Promise(function(r) { setTimeout(r, 1500); });
    return inDfuMode;
}

/* Download the chosen image, verify it, bootstrap if needed, then hand the bytes
 * to the normal write path - identical to picking a local file. */
async function flashFromRelease() {
    var tag = document.getElementById('rel-release').value;
    var name = document.getElementById('rel-device').value;
    if (!tag || !name) return;
    /* The button is gated on this too, but do not rely on the button alone: a
     * device can go away between the last render and the click. */
    if (currentState !== 'done') {
        log('Connect a device first.', 'warn');
        return;
    }

    var btn = document.getElementById('rel-flash');
    btn.disabled = true;
    try {
        log('Downloading ' + name + ' ...');
        var data = await downloadWithProgress(
            FW_PROXY + '?tag=' + encodeURIComponent(tag) + '&name=' + encodeURIComponent(name),
            t('rel_downloading'));

        if (!await verifySha256(tag, name, data)) {
            hideProgress();
            updateReleaseFlash();
            return; /* refuse to flash a corrupt download */
        }
        hideProgress();

        firmwareData = data;
        firmwareFileName = name;
        var sizeMB = (data.length / (1024 * 1024)).toFixed(2);
        document.getElementById('file-info').textContent = t('rel_file_ok', { name: name, size: sizeMB });
        log('Firmware loaded: ' + name + ' (' + sizeMB + ' MB), sha256 verified.');

        /* Bootstrap a bootrom target before writing, or the write has no gadget
         * to talk to (the daemon would just sit there waiting). */
        if (!await ensureDfuMode()) {
            log('Device did not enter DFU mode; not flashing.', 'error');
            updateReleaseFlash();
            return;
        }
        doWrite();
    } catch (e) {
        hideProgress();
        log('Download failed: ' + e.message, 'error');
        updateReleaseFlash();
    }
}

/* ------------------------------------------------------------------ */
/*  Init                                                               */
/* ------------------------------------------------------------------ */

// Expose handlers referenced by HTML onclick/onchange attributes
Object.assign(window, { connectDevice, doBootstrap, selectFirmware, firmwareSelected, doRead,
                        doDiag, closeDiag, copyDiag, toggleHelp, setHelp, setDebug, setVerify, setReboot, setAdvanced, setReleases,
                        openSettings, closeSettings, openWindowsHelp, closeWindowsHelp, saveSettings, toggleRemoteFields,
                        toggleAdvanced, customSplSelected, customUbootSelected, clearCustomBootloader,
                        selectRemoteDevice, toggleReleases, releaseChanged, flashFromRelease, addExtraFileRow,
                        setInject, toggleInject });

(function() {
    if (!navigator.usb) {
        document.getElementById('browser-warning').classList.remove('d-none');
        document.querySelector('.flasher-card').classList.add('d-none');
        return;
    }

    navigator.usb.addEventListener('connect', function(e) {
        var id = '0x' + e.device.vendorId.toString(16) + ':0x' + e.device.productId.toString(16);
        console.log('USB device connected: ' + id);
        log('USB connect event: ' + id, 'debug');
        // Re-attach automatically if we already have permission for it.
        autoAttachDevice(e.device);
    });
    navigator.usb.addEventListener('disconnect', function(e) {
        console.log('USB device disconnected: PID=0x' + e.device.productId.toString(16));
        if (window._webusb_devices)
            window._webusb_devices = window._webusb_devices.filter(function(d) { return d !== e.device; });
    });

    applyBackendMode(backendMode);
    applyAdvanced(); // restore the saved Advanced-panel preference (default off)
    applyReleases(); // restore the saved release-picker preference (default off)
    applyInject();   // restore the saved Pre-configure preference (default off)
    setState('idle');
    // The Windows-driver prompt only matters on Windows (WinUSB via Zadig);
    // the link is hidden by default and revealed here only on Windows.
    if (isWindows()) {
        var winLink = document.getElementById('windows-help-link');
        if (winLink) winLink.classList.remove('d-none');
    }
    // i18n: translate the static UI, build the language picker (in Settings), and
    // re-translate on a language switch. Help balloons resolve their key lazily in
    // showHelpBalloon(), so they pick up the new language on the next hover.
    if (window.I18N) {
        I18N.apply();
        I18N.selector('lang-slot');
        window.addEventListener('i18nchange', function () {
            I18N.apply();
            // I18N.apply() only reaches data-i18n elements. The release dropdowns
            // are built in JS, so they retranslate themselves here.
            if (relLoaded) { renderReleaseOptions(); releaseChanged(); }
        });
    }
    applyHelpMode(); // restore the saved help-hints preference (default off)
    initModule();
})();
