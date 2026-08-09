# thingino-dfu firmware proxy

A single-purpose Cloudflare Worker that lets the web flasher download a prebuilt
thingino firmware image from GitHub.

## Why it has to exist

GitHub serves release assets from a blob host that sends no
`Access-Control-Allow-Origin`, so a browser cannot read their bytes. That holds
for the `github.com/.../releases/download/...` link, for the signed URL it
redirects to, and for the REST asset endpoint (whose 302 *does* carry CORS, but
redirects to a blob that does not). Listing releases needs no help —
`api.github.com` sends CORS — so only the bytes need a hop.

This Worker is that hop: it fetches the asset server-side, where CORS does not
apply, and re-serves it with the header the browser needs.

## Contract

```
GET /fw?tag=firmware-2026-06-22&name=thingino-360_ap1pa3_t31x_gc4653.bin
GET /fw?tag=firmware-2026-06-22&name=thingino-360_ap1pa3_t31x_gc4653.bin.sha256sum
```

The body is streamed straight through, never buffered, so a 16 MB image costs
almost no CPU and no memory. `Content-Length` is passed through so the browser's
download bar stays determinate. Responses are edge-cached (`X-Fw-Cache: HIT` on a
repeat fetch), so a popular image is not re-pulled from GitHub every time.

Workers bill no egress, so the image transfer itself is free; a flash costs two
requests (the `.bin` and its `.sha256sum`) against the account-wide free budget.

## The allow-list is the security model

Only `firmware-*` release tags, and only `thingino-*.bin` / `.bin.sha256sum`
assets from `themactep/thingino-firmware`. Without that, this would be an open
proxy anyone could aim at any URL on someone else's bandwidth. Everything else
gets `400`.

## Deploy

```sh
npx wrangler deploy     # from this directory
npx wrangler tail       # live logs
```

Deployed at `https://thingino-dfu-fw.thingino.workers.dev`, which is what
`FW_PROXY` in `web/src/app.js` points to.

It is deliberately its own Worker rather than a route bolted onto
`thingino-image-builder`: that one owns D1, Durable Objects and a per-minute cron
for build orchestration, and a byte proxy needs none of it. Splitting them costs
nothing (the free request budget is account-wide) and keeps a bad deploy of one
from taking down the other.
