import { createHmac, timingSafeEqual } from "node:crypto";
import http from "node:http";
export const REPLAY_WINDOW_MS = 300_000;
export const SCHEMA_VERSION = 1;
export function signBridge(secret, body, nowMs = Date.now()) {
    const timestamp = String(nowMs);
    return { timestamp, signature: computeBridgeSignature(secret, timestamp, body) };
}
export function computeBridgeSignature(secret, timestamp, body) {
    return createHmac("sha256", secret).update(`${timestamp}.${body}`).digest("hex");
}
export function verifyBridge(secret, timestamp, body, signature, nowMs = Date.now()) {
    if (!secret || !timestamp || !signature)
        return false;
    const ts = Number(timestamp);
    if (!Number.isFinite(ts))
        return false;
    if (Math.abs(nowMs - ts) > REPLAY_WINDOW_MS)
        return false;
    const expected = Buffer.from(computeBridgeSignature(secret, timestamp, body), "utf8");
    const provided = Buffer.from(signature.toLowerCase(), "utf8");
    return expected.length === provided.length && timingSafeEqual(expected, provided);
}
export function parseInbound(body) {
    let raw;
    try {
        raw = JSON.parse(body);
    }
    catch {
        return { ok: false, error: "malformed json" };
    }
    if (typeof raw !== "object" || raw === null)
        return { ok: false, error: "body must be an object" };
    const m = raw;
    for (const key of ["tenantId", "conversationId", "activityId"]) {
        if (typeof m[key] !== "string" || m[key].length === 0) {
            return { ok: false, error: `${key} is required` };
        }
    }
    const sender = (typeof m.sender === "object" && m.sender !== null ? m.sender : {});
    return {
        ok: true,
        message: {
            tenantId: m.tenantId,
            bindingId: typeof m.bindingId === "string" && m.bindingId.length > 0 ? m.bindingId : undefined,
            conversationId: m.conversationId,
            activityId: m.activityId,
            scope: typeof m.scope === "string" ? m.scope : "personal",
            text: typeof m.text === "string" ? m.text : "",
            sender,
            attachments: Array.isArray(m.attachments) ? m.attachments : undefined,
            locale: typeof m.locale === "string" ? m.locale : undefined,
            cardAction: typeof m.cardAction === "object" && m.cardAction !== null ? m.cardAction : undefined,
        },
    };
}
export class SeenActivities {
    capacity;
    seen = new Map();
    constructor(capacity = 2048) {
        this.capacity = capacity;
    }
    markFirst(activityId) {
        if (this.seen.has(activityId))
            return false;
        this.seen.set(activityId, true);
        if (this.seen.size > this.capacity) {
            const oldest = this.seen.keys().next().value;
            if (oldest !== undefined)
                this.seen.delete(oldest);
        }
        return true;
    }
}
export function buildReply(inbound, text, kind = "message") {
    return {
        schemaVersion: SCHEMA_VERSION,
        tenantId: inbound.tenantId,
        ...(inbound.bindingId ? { bindingId: inbound.bindingId } : {}),
        conversationId: inbound.conversationId,
        replyToId: inbound.activityId,
        kind,
        ...(kind === "typing" ? {} : { text }),
        idempotencyKey: `${inbound.activityId}:${kind}`,
    };
}
export async function fetchAttachmentImages(attachments, opts) {
    const fetchFn = opts?.fetchFn ?? fetch;
    const maxBytes = opts?.maxBytes ?? 4 * 1024 * 1024;
    const maxImages = opts?.maxImages ?? 4;
    const images = [];
    for (const a of attachments ?? []) {
        if (images.length >= maxImages)
            break;
        if (a.kind !== "image" || a.relayable === false || !a.url)
            continue;
        if (!originAllowed(a.url, opts?.gatewayOrigin))
            continue;
        try {
            const res = await fetchFn(a.url, { signal: AbortSignal.timeout(10_000), redirect: "error" });
            if (!res.ok)
                continue;
            const mime = String(a.contentType ?? res.headers.get("content-type") ?? "").split(";")[0].trim().toLowerCase();
            if (!mime.startsWith("image/"))
                continue;
            const declared = Number(res.headers.get("content-length"));
            if (Number.isFinite(declared) && declared > maxBytes)
                continue;
            const buf = await readCapped(res, maxBytes);
            if (!buf || buf.length === 0)
                continue;
            images.push({ type: "image", data: buf.toString("base64"), mimeType: mime });
        }
        catch {
        }
    }
    return images;
}
export async function fetchAttachmentAudio(attachments, opts) {
    const fetchFn = opts?.fetchFn ?? fetch;
    const maxBytes = opts?.maxBytes ?? 16 * 1024 * 1024;
    const maxClips = opts?.maxClips ?? 2;
    const clips = [];
    for (const a of attachments ?? []) {
        if (clips.length >= maxClips)
            break;
        if (a.kind !== "audio" || a.relayable === false || !a.url)
            continue;
        if (!originAllowed(a.url, opts?.gatewayOrigin))
            continue;
        try {
            const res = await fetchFn(a.url, { signal: AbortSignal.timeout(20_000), redirect: "error" });
            if (!res.ok)
                continue;
            const mime = String(a.contentType ?? res.headers.get("content-type") ?? "")
                .split(";")[0]
                .trim()
                .toLowerCase();
            if (!mime.startsWith("audio/") && !mime.startsWith("video/"))
                continue;
            const declared = Number(res.headers.get("content-length"));
            if (Number.isFinite(declared) && declared > maxBytes)
                continue;
            const buf = await readCapped(res, maxBytes);
            if (!buf || buf.length === 0)
                continue;
            clips.push({ name: a.name ?? undefined, bytes: buf, mime });
        }
        catch {
        }
    }
    return clips;
}
function originAllowed(url, gatewayOrigin) {
    if (!gatewayOrigin)
        return true;
    try {
        return new URL(url).origin === new URL(gatewayOrigin).origin;
    }
    catch {
        return false;
    }
}
async function readCapped(res, maxBytes) {
    const body = res.body;
    if (!body)
        return null;
    const reader = body.getReader();
    const chunks = [];
    let total = 0;
    try {
        for (;;) {
            const { done, value } = await reader.read();
            if (done)
                break;
            if (!value)
                continue;
            total += value.byteLength;
            if (total > maxBytes) {
                await reader.cancel().catch(() => undefined);
                return null;
            }
            chunks.push(value);
        }
    }
    finally {
        reader.releaseLock?.();
    }
    return Buffer.concat(chunks.map((c) => Buffer.from(c)), total);
}
export async function postManagedMessage(opts) {
    const body = JSON.stringify({
        schemaVersion: SCHEMA_VERSION,
        tenantId: opts.tenantId,
        ...(opts.bindingId ? { bindingId: opts.bindingId } : {}),
        conversationId: opts.conversationId,
        text: opts.text,
        kind: "message",
        ...(opts.idempotencyKey ? { idempotencyKey: opts.idempotencyKey } : {}),
    });
    const { timestamp, signature } = signBridge(opts.chatSecret, body);
    try {
        const res = await (opts.fetchFn ?? fetch)(opts.gatewayReplyUrl, {
            method: "POST",
            headers: {
                "content-type": "application/json",
                "x-standin-timestamp": timestamp,
                "x-standin-signature": signature,
            },
            body,
            signal: AbortSignal.timeout(20_000),
        });
        return res.ok;
    }
    catch {
        return false;
    }
}
export class ManagedChatServer {
    cfg;
    deps;
    server;
    seen = new SeenActivities();
    chains = new Map();
    constructor(cfg, deps) {
        this.cfg = cfg;
        this.deps = deps;
    }
    async start() {
        const server = http.createServer((req, res) => {
            void this.handle(req, res).catch((err) => {
                void err;
                try {
                    if (!res.headersSent)
                        res.writeHead(400).end();
                }
                catch {
                }
            });
        });
        this.server = server;
        await new Promise((resolve, reject) => {
            server.once("error", reject);
            server.listen(this.cfg.port, this.cfg.bindAddress, () => resolve());
        });
        this.deps.log.info(`msteams managed chat: listening on ${this.cfg.bindAddress ?? "0.0.0.0"}:${this.cfg.port}${this.cfg.path}`);
    }
    stopped = false;
    async stop() {
        this.stopped = true;
        const server = this.server;
        this.server = undefined;
        if (server) {
            server.closeIdleConnections?.();
            await Promise.race([
                new Promise((resolve) => server.close(() => resolve())),
                new Promise((resolve) => setTimeout(resolve, ManagedChatServer.CLOSE_MS).unref?.()),
            ]);
            server.closeAllConnections?.();
        }
        const inflight = [...this.chains.values()];
        if (inflight.length > 0) {
            await Promise.race([
                Promise.allSettled(inflight),
                new Promise((resolve) => setTimeout(resolve, ManagedChatServer.DRAIN_MS).unref?.()),
            ]);
        }
        this.chains.clear();
    }
    static DRAIN_MS = 5000;
    static CLOSE_MS = 2000;
    async handle(req, res) {
        if (req.method !== "POST" || (req.url ?? "").split("?")[0] !== this.cfg.path) {
            res.writeHead(404).end();
            return;
        }
        const maxBody = 1024 * 1024;
        const declared = Number(req.headers["content-length"]);
        if (Number.isFinite(declared) && declared > maxBody) {
            res.writeHead(413).end();
            return;
        }
        const chunks = [];
        let received = 0;
        for await (const chunk of req) {
            received += chunk.length;
            if (received > maxBody) {
                res.writeHead(413).end();
                req.destroy();
                return;
            }
            chunks.push(chunk);
        }
        const body = Buffer.concat(chunks).toString("utf8");
        const ts = header(req, "x-standin-timestamp");
        const sig = header(req, "x-standin-signature");
        if (!verifyBridge(this.cfg.chatSecret, ts, body, sig, this.deps.nowMs?.() ?? Date.now())) {
            res.writeHead(401, { "content-type": "application/json" }).end(JSON.stringify({ error: "unauthorized" }));
            return;
        }
        const parsed = parseInbound(body);
        if (!parsed.ok) {
            res.writeHead(400, { "content-type": "application/json" }).end(JSON.stringify({ error: parsed.error }));
            return;
        }
        const fresh = this.seen.markFirst(`${parsed.message.tenantId}:${parsed.message.conversationId}:${parsed.message.activityId}`);
        res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ ok: true }));
        if (!fresh)
            return;
        this.enqueueTurn(parsed.message);
    }
    enqueueTurn(message) {
        if (this.stopped)
            return;
        const key = `${message.tenantId}:${message.conversationId}`;
        const prev = this.chains.get(key) ?? Promise.resolve();
        const next = prev
            .then(() => (this.stopped ? undefined : this.processAsync(message)))
            .catch(() => undefined);
        this.chains.set(key, next);
        void next.finally(() => {
            if (this.chains.get(key) === next)
                this.chains.delete(key);
        });
    }
    static TURN_TIMEOUT_MS = 5 * 60 * 1000;
    async processAsync(message) {
        const typing = this.postReply(buildReply(message, "", "typing")).catch(() => undefined);
        try {
            const text = await withTimeout(this.deps.respond(message), ManagedChatServer.TURN_TIMEOUT_MS, "agent turn");
            await typing;
            if (text.trim().length > 0) {
                await this.postReply(buildReply(message, text));
            }
            else {
                this.deps.log.warn("msteams managed chat: agent returned an empty answer");
                await this.postReply(buildReply(message, "I couldn't come up with an answer to that — try rephrasing, or ask something else.", "error"));
            }
        }
        catch (err) {
            this.deps.log.error(`msteams managed chat: agent turn failed: ${String(err)}`);
            await this.postReply(buildReply(message, "Something went wrong answering that — please try again.", "error")).catch(() => undefined);
        }
    }
    static REPLY_ATTEMPTS = 3;
    async postReply(reply) {
        if (this.stopped)
            return;
        const body = JSON.stringify(reply);
        const fetchFn = this.deps.fetchFn ?? fetch;
        const attempts = reply.kind === "typing" ? 1 : ManagedChatServer.REPLY_ATTEMPTS;
        for (let attempt = 1; attempt <= attempts; attempt++) {
            if (this.stopped)
                return;
            const { timestamp, signature } = signBridge(this.cfg.chatSecret, body, this.deps.nowMs?.() ?? Date.now());
            try {
                const res = await fetchFn(this.cfg.gatewayReplyUrl, {
                    method: "POST",
                    headers: {
                        "content-type": "application/json",
                        "x-standin-timestamp": timestamp,
                        "x-standin-signature": signature,
                    },
                    body,
                    signal: AbortSignal.timeout(30_000),
                });
                if (res.ok)
                    return;
                this.deps.log.warn(`msteams managed chat: gateway reply -> HTTP ${res.status} (attempt ${attempt}/${attempts})`);
                if (res.status < 500 && res.status !== 429)
                    return;
            }
            catch (err) {
                this.deps.log.warn(`msteams managed chat: gateway reply failed: ${String(err)} (attempt ${attempt}/${attempts})`);
            }
            if (attempt < attempts)
                await new Promise((r) => setTimeout(r, 1000 * 4 ** (attempt - 1)));
        }
    }
}
function withTimeout(promise, ms, what) {
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`${what} timed out after ${ms}ms`)), ms);
        promise.then((v) => { clearTimeout(timer); resolve(v); }, (e) => { clearTimeout(timer); reject(e); });
    });
}
function header(req, name) {
    const v = req.headers[name];
    return Array.isArray(v) ? v[0] : v;
}
export function resolveManagedChatConfig(raw) {
    const c = (raw ?? {});
    const chatSecret = typeof c.chatSecret === "string" ? c.chatSecret : "";
    const explicitlyOff = c.enabled === false;
    return {
        configuredWithoutSecret: c.enabled === true && chatSecret.length === 0,
        enabled: chatSecret.length > 0 && !explicitlyOff,
        transcribeVoiceMessages: c.transcribeVoiceMessages === true,
        port: Number(c.port ?? 9444),
        bindAddress: typeof c.bindAddress === "string" ? c.bindAddress : "127.0.0.1",
        path: typeof c.path === "string" ? c.path : "/msteams/messages",
        chatSecret,
        gatewayReplyUrl: typeof c.gatewayReplyUrl === "string" && c.gatewayReplyUrl.length > 0
            ? c.gatewayReplyUrl
            : "https://teams.standin.komaa.com/api/chat/reply",
    };
}
