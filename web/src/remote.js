/**
 * HTTP client for the dfu-remote daemon (TDFU binary protocol over fetch()).
 *
 * Each command is one POST whose body is the TDFU command frame; the daemon
 * replies with a chunked stream of TDFU response frames (progress/log then
 * OK/ERROR), which we parse as a byte stream. fetch() is used (not WebSocket)
 * because Chrome's Local Network Access only exempts fetch({targetAddressSpace:
 * 'local'}) from mixed-content blocking - so the HTTPS flasher can reach a
 * local/LAN daemon over plain http:// with a one-time permission, no TLS.
 */

const MAGIC = 0x54444655; // "TDFU"
const VERSION = 1;
export const DEFAULT_PORT = 5050;

const CMD_DISCOVER = 0x01;
const CMD_BOOTSTRAP = 0x02;
const CMD_WRITE = 0x03;
const CMD_READ = 0x04;
const CMD_DIAG = 0x07;
const CMD_REBOOT = 0x08;

const RESP_OK = 0x00;
const RESP_ERROR = 0x01;
const RESP_PROGRESS = 0x02;
const RESP_LOG = 0x03;

/* No hardcoded variant-name table here: the daemon sends the tdfu_variant_t enum
 * index, and that index space grows as per-variant loaders are added, so the names
 * are resolved through the C tdfu_variant_to_string (passed in as variantResolver)
 * - the single source of truth - rather than a JS copy that silently drifts. */

/* CRC-32 (IEEE, reflected) - matches the daemon's remote_crc32 / zlib crc32. */
function crc32(bytes) {
    let crc = 0xffffffff;
    for (let i = 0; i < bytes.length; i++) {
        crc ^= bytes[i];
        for (let j = 0; j < 8; j++) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
    }
    return (~crc) >>> 0;
}

/* Accept ws://, wss://, http://, https:// or a bare host[:port]; the transport
 * is plain HTTP (LNA can't exempt ws://). */
function normalizeUrl(url) {
    url = (url || '').trim();
    if (url.startsWith('ws://')) url = 'http://' + url.slice(5);
    else if (url.startsWith('wss://')) url = 'https://' + url.slice(6);
    if (!/^https?:\/\//.test(url)) {
        /* A bare IPv6 literal has to be bracketed or the URL parser reads its
         * first colon as the port separator. Two or more colons means a v6
         * literal, since a bare host[:port] can only hold one. Pairing a
         * literal with a port is ambiguous unbracketed, so that case is the
         * user's to write as [addr]:port. */
        if (url.indexOf(':') !== url.lastIndexOf(':') && url[0] !== '[')
            url = '[' + url + ']';
        url = 'http://' + url;
    }
    return url;
}

export class RemoteClient {
    constructor(onLog, onProgress, variantResolver) {
        this.url = '';
        this.token = '';
        this.onLog = onLog || function () {};
        this.onProgress = onProgress || function () {};
        // Resolve a variant index -> name. The caller wires this to the C
        // tdfu_variant_to_string (via the WASM) so there is no hardcoded variant
        // table on the JS side to drift from the enum.
        this.variantResolver = variantResolver || function () { return 'unknown'; };
        this.connected = false;
    }

    async connect(url, token) {
        this.url = normalizeUrl(url);
        this.token = token || '';
        this.connected = true; // fetch() is stateless; the first command validates connectivity.
        return true;
    }

    disconnect() { this.connected = false; }
    isConnected() { return this.connected; }

    /* POST a TDFU command and parse the streamed TDFU responses, surfacing
     * PROGRESS/LOG, returning the OK payload (or null on ERROR). */
    async _command(command, payload) {
        const cmd = command;
        const pl = payload || new Uint8Array(0);
        const frame = new Uint8Array(10 + pl.length);
        const dv = new DataView(frame.buffer);
        dv.setUint32(0, MAGIC);
        frame[4] = VERSION;
        frame[5] = cmd;
        dv.setUint32(6, pl.length);
        frame.set(pl, 10);

        const headers = { 'Content-Type': 'application/octet-stream' };
        if (this.token) headers['X-Auth-Token'] = this.token;

        const resp = await fetch(this.url, {
            method: 'POST',
            headers,
            body: frame,
            // Tell Chrome this targets the local network so LNA exempts it from
            // mixed-content blocking (ignored by browsers without LNA).
            targetAddressSpace: 'local',
        });
        if (!resp.ok) throw new Error('HTTP ' + resp.status + ' ' + resp.statusText);
        if (!resp.body) throw new Error('no response body');

        const reader = resp.body.getReader();
        const queue = [];
        let queued = 0;
        let streamDone = false;
        const pump = async () => {
            const { done, value } = await reader.read();
            if (done) { streamDone = true; return false; }
            queue.push(value);
            queued += value.length;
            return true;
        };
        const readExact = async (n) => {
            while (queued < n) {
                if (!(await pump())) throw new Error('stream ended early');
            }
            const out = new Uint8Array(n);
            let o = 0;
            while (o < n) {
                const head = queue[0];
                const take = Math.min(head.length, n - o);
                out.set(head.subarray(0, take), o);
                o += take;
                queued -= take;
                if (take === head.length) queue.shift();
                else queue[0] = head.subarray(take);
            }
            return out;
        };

        for (;;) {
            const hdr = await readExact(10);
            const hv = new DataView(hdr.buffer, hdr.byteOffset, 10);
            if (hv.getUint32(0) !== MAGIC) throw new Error('bad response magic');
            const status = hdr[5];
            const plen = hv.getUint32(6);
            const body = plen > 0 ? await readExact(plen) : new Uint8Array(0);
            if (status === RESP_PROGRESS) {
                if (body.length >= 4) {
                    const percent = body[0];
                    const msgLen = (body[2] << 8) | body[3];
                    const msg = msgLen > 0 && body.length >= 4 + msgLen
                        ? new TextDecoder().decode(body.subarray(4, 4 + msgLen)) : '';
                    this.onProgress(percent, msg);
                }
            } else if (status === RESP_LOG) {
                this.onLog(new TextDecoder().decode(body));
            } else if (status === RESP_OK) {
                try { reader.cancel(); } catch (e) { /* ignore */ }
                return body;
            } else {
                const m = body.length ? new TextDecoder().decode(body) : 'unknown error';
                this.onLog('ERROR: ' + m + '\n');
                try { reader.cancel(); } catch (e) { /* ignore */ }
                return null;
            }
        }
    }

    async discover() {
        const payload = await this._command(CMD_DISCOVER);
        if (!payload) return [];
        const dv = new DataView(payload.buffer, payload.byteOffset, payload.length);
        const devs = [];
        for (let off = 0; off + 8 <= payload.length; off += 8) {
            const variant = dv.getUint8(off + 7);
            const stage = dv.getUint8(off + 6);
            devs.push({
                bus: dv.getUint8(off), address: dv.getUint8(off + 1),
                vendor: dv.getUint16(off + 2), product: dv.getUint16(off + 4),
                stage, variant,
                variantName: this.variantResolver(variant),
                stageName: stage === 0 ? 'bootrom' : (stage === 2 ? 'dfu' : 'firmware'),
            });
        }
        return devs;
    }

    async diag(deviceIndex) {
        const body = await this._command(CMD_DIAG, new Uint8Array([deviceIndex & 0xff]));
        if (!body) return null;
        return new TextDecoder().decode(body);
    }
    /* Reset the SoC (used after a flash). The daemon runs tdfu_dfu_reboot, which
     * tolerates the reset disconnect and replies OK. */
    async reboot(deviceIndex) {
        await this._command(CMD_REBOOT, new Uint8Array([deviceIndex & 0xff]));
        return true;
    }

    _variantPayload(deviceIndex, variant) {
        const vb = new TextEncoder().encode(variant || '');
        const p = new Uint8Array(2 + vb.length);
        p[0] = deviceIndex & 0xff;
        p[1] = vb.length;
        p.set(vb, 2);
        return p;
    }

    async bootstrap(deviceIndex, variant, splData, ubootData) {
        var base = this._variantPayload(deviceIndex, variant);
        // Optional custom SPL + U-Boot (both-or-neither), appended as the daemon
        // expects: [4:spl_len][spl][4:uboot_len][uboot], big-endian lengths.
        if (splData && ubootData) {
            var buf = new Uint8Array(base.length + 4 + splData.length + 4 + ubootData.length);
            buf.set(base, 0);
            var dv = new DataView(buf.buffer);
            var off = base.length;
            dv.setUint32(off, splData.length); off += 4;
            buf.set(splData, off); off += splData.length;
            dv.setUint32(off, ubootData.length); off += 4;
            buf.set(ubootData, off);
            return (await this._command(CMD_BOOTSTRAP, buf)) !== null;
        }
        return (await this._command(CMD_BOOTSTRAP, base)) !== null;
    }

    async readFirmware(deviceIndex, variant) {
        const resp = await this._command(CMD_READ, this._variantPayload(deviceIndex, variant));
        if (!resp || resp.length < 4) return null;
        const data = resp.subarray(0, resp.length - 4);
        const recvCrc = new DataView(resp.buffer, resp.byteOffset + resp.length - 4, 4).getUint32(0) >>> 0;
        if (crc32(data) !== recvCrc) { this.onLog('ERROR: CRC32 mismatch on read\n'); return null; }
        return data.slice();
    }

    async writeFirmware(deviceIndex, variant, firmwareData, verify) {
        const vb = new TextEncoder().encode(variant || '');
        // Wire format the daemon parses:
        //   [idx][variant_len][variant][alt_len][alt][fw_len][fw][crc][verify?]
        // alt is empty here (alt_len = 0 => daemon's default alt 0 = flash).
        // The trailing verify byte is optional (older daemons stop after crc).
        const buf = new Uint8Array(2 + vb.length + 1 + 4 + firmwareData.length + 4 + (verify ? 1 : 0));
        const dv = new DataView(buf.buffer);
        buf[0] = deviceIndex & 0xff;
        buf[1] = vb.length;
        buf.set(vb, 2);
        let off = 2 + vb.length;
        buf[off] = 0; // alt_len = 0
        off += 1;
        dv.setUint32(off, firmwareData.length);
        off += 4;
        buf.set(firmwareData, off);
        off += firmwareData.length;
        dv.setUint32(off, crc32(firmwareData));
        off += 4;
        if (verify) buf[off] = 1;
        return (await this._command(CMD_WRITE, buf)) !== null;
    }
}
