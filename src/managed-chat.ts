// StandIn managed chat mode. Wire contract: protocol/chat-schema.yaml (published in this repo).
//
// In managed mode you do NOT register a Teams bot of your own. StandIn runs the bot and speaks the
// normalized chat protocol to your agent, so your agent never holds a Bot Framework credential.
//
// This module is your side of that protocol:
//   1. Serve HTTP at `path`. Requests are InboundMessage, signed with your connection's CHAT key.
//   2. Verify the signature, then answer 200 IMMEDIATELY. Do not wait for the agent - the 200 is an
//      acknowledgement of receipt, and StandIn handles retry and ordering from there.
//   3. Consult the agent asynchronously, then POST the reply to `gatewayReplyUrl`, signed with the
//      SAME key.
//
// The voice WebSocket (msteams-media-stream) is unchanged by managed mode; chat is an added lane.

import { createHmac, timingSafeEqual } from "node:crypto";
import http from "node:http";

/** Accepted clock skew for the bridge HMAC, both directions (chat-schema.yaml REPLAY_WINDOW_MS). */
export const REPLAY_WINDOW_MS = 300_000;

/** Value carried in every message's schemaVersion (chat-schema.yaml SCHEMA_VERSION). */
export const SCHEMA_VERSION = 1;

export interface ManagedChatConfig {
  enabled: boolean;
  /**
   * Transcribe inbound Teams voice messages and fold the text into the agent's turn.
   *
   * Off by default and deliberately so: each clip is an STT call, and a voice note can be minutes
   * long, so this is real per-message cost that an operator should opt into rather than discover.
   */
  transcribeVoiceMessages?: boolean;
  /** enabled:true with no chatSecret - resolved disabled, but the runtime warns loudly. */
  configuredWithoutSecret?: boolean;
  port: number;
  bindAddress?: string;
  path: string;
  /** Your connection's CHAT key. Separate from the voice key: chat and voice are signed independently,
   * so one being exposed does not authorize the other. Both are shown in the StandIn portal. */
  chatSecret: string;
  /** The gateway's reply endpoint, e.g. https://teams.standin.komaa.com/api/chat/reply */
  gatewayReplyUrl: string;
}

/** The inbound fields this agent actually consumes (a SUBSET of chat-schema.yaml InboundMessage —
 * subsets are legal; unknown fields are ignored by contract). */
export interface ManagedInbound {
  tenantId: string;
  /** Id of the StandIn connection (binding) this conversation resolved to. Carried VERBATIM so
   * replies can echo it (see buildReply); old gateways do not send it, so it can be absent. */
  bindingId?: string;
  conversationId: string;
  activityId: string;
  scope: string;
  text: string;
  sender: { aadObjectId?: string; displayName?: string; isGuest?: boolean; isLinkedOwner?: boolean };
  attachments?: Array<{ kind: string; name?: string; url?: string; relayable?: boolean }>;
  locale?: string;
  /** Submit payload of an agent card's Action.Submit (additive v1; text is empty on these). */
  cardAction?: Record<string, unknown>;
}

// ── bridge HMAC. Construction is specified in protocol/chat-schema.yaml and pinned by known-answer
// tests in this repo, so an independent implementation can be checked against the same vectors. ─────

export function signBridge(
  secret: string,
  body: string,
  nowMs = Date.now(),
): { timestamp: string; signature: string } {
  const timestamp = String(nowMs);
  return { timestamp, signature: computeBridgeSignature(secret, timestamp, body) };
}

export function computeBridgeSignature(secret: string, timestamp: string, body: string): string {
  return createHmac("sha256", secret).update(`${timestamp}.${body}`).digest("hex");
}

export function verifyBridge(
  secret: string,
  timestamp: string | undefined,
  body: string,
  signature: string | undefined,
  nowMs = Date.now(),
): boolean {
  if (!secret || !timestamp || !signature) return false;
  const ts = Number(timestamp);
  if (!Number.isFinite(ts)) return false;
  if (Math.abs(nowMs - ts) > REPLAY_WINDOW_MS) return false;
  const expected = Buffer.from(computeBridgeSignature(secret, timestamp, body), "utf8");
  const provided = Buffer.from(signature.toLowerCase(), "utf8");
  return expected.length === provided.length && timingSafeEqual(expected, provided);
}

// ── inbound parsing (tolerant of unknown fields, strict on the routing keys) ──────────────────────

export function parseInbound(body: string): { ok: true; message: ManagedInbound } | { ok: false; error: string } {
  let raw: unknown;
  try {
    raw = JSON.parse(body);
  } catch {
    return { ok: false, error: "malformed json" };
  }
  if (typeof raw !== "object" || raw === null) return { ok: false, error: "body must be an object" };
  const m = raw as Record<string, unknown>;
  for (const key of ["tenantId", "conversationId", "activityId"] as const) {
    if (typeof m[key] !== "string" || (m[key] as string).length === 0) {
      return { ok: false, error: `${key} is required` };
    }
  }
  const sender = (typeof m.sender === "object" && m.sender !== null ? m.sender : {}) as ManagedInbound["sender"];
  return {
    ok: true,
    message: {
      tenantId: m.tenantId as string,
      // Verbatim when present, undefined otherwise: old gateways send nothing here, and that must
      // keep working. Never synthesized - a plugin talks to ONE binding, so this is a copy, not a
      // choice.
      bindingId: typeof m.bindingId === "string" && m.bindingId.length > 0 ? m.bindingId : undefined,
      conversationId: m.conversationId as string,
      activityId: m.activityId as string,
      scope: typeof m.scope === "string" ? m.scope : "personal",
      text: typeof m.text === "string" ? m.text : "",
      sender,
      attachments: Array.isArray(m.attachments) ? (m.attachments as ManagedInbound["attachments"]) : undefined,
      locale: typeof m.locale === "string" ? m.locale : undefined,
      // Additive v1 field: the submit payload of an agent card's
      // Action.Submit button. text is EMPTY on these messages - without carrying the payload through,
      // a button press became an empty agent turn ("I didn't catch that").
      cardAction: typeof m.cardAction === "object" && m.cardAction !== null ? (m.cardAction as Record<string, unknown>) : undefined,
    },
  };
}

/** At-least-once dedupe: the gateway REDELIVERS on retry, and activityId is the idempotency key the
 * schema tells agents to honor. Bounded LRU so the window cannot grow without limit. */
export class SeenActivities {
  private readonly seen = new Map<string, true>();

  constructor(private readonly capacity = 2048) {}

  /** True the FIRST time an activity id is offered; false on a redelivery. */
  markFirst(activityId: string): boolean {
    if (this.seen.has(activityId)) return false;
    this.seen.set(activityId, true);
    if (this.seen.size > this.capacity) {
      const oldest = this.seen.keys().next().value;
      if (oldest !== undefined) this.seen.delete(oldest);
    }
    return true;
  }
}

/** Build the reply the gateway expects. tenantId/conversationId/bindingId echo the inbound EXACTLY -
 * the gateway rejects a tenant mismatch (the cross-tenant guard, the load-bearing check of the
 * relay), and when bindingId is present it verifies the HMAC against THAT binding's key and rejects
 * a reply into a conversation assigned to a different binding (per-binding isolation inside the
 * tenant). Omitted when the inbound carried none, so old gateways see the exact shape they always
 * did. */
export function buildReply(
  inbound: Pick<ManagedInbound, "tenantId" | "conversationId" | "activityId" | "bindingId">,
  text: string,
  kind: "message" | "typing" | "error" = "message",
): Record<string, unknown> {
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

// ── the server ────────────────────────────────────────────────────────────────────────────────────

/** An image fetched from the gateway's signed URL, ready for the agent consult. */
export interface FetchedImage {
  type: "image";
  data: string;
  mimeType: string;
}

/**
 * Fetch RELAYABLE IMAGE attachments from their gateway-signed URLs into consult images (4.7: "the
 * agent fetches within the reference TTL"). Images only - the consult accepts images, and files are
 * still named in the turn text. Size-capped and best-effort per attachment: one bad fetch drops that
 * image, never the turn.
 */
export async function fetchAttachmentImages(
  attachments: ManagedInbound["attachments"],
  opts?: { fetchFn?: typeof fetch; maxBytes?: number; maxImages?: number; gatewayOrigin?: string },
): Promise<FetchedImage[]> {
  const fetchFn = opts?.fetchFn ?? fetch;
  const maxBytes = opts?.maxBytes ?? 4 * 1024 * 1024;
  // A message can name many attachments; each is a fetch and a base64 blob in the consult. Cap the
  // COUNT as well as each size, or one message multiplies into an unbounded amount of work.
  const maxImages = opts?.maxImages ?? 4;
  const images: FetchedImage[] = [];
  for (const a of attachments ?? []) {
    if (images.length >= maxImages) break;
    if (a.kind !== "image" || a.relayable === false || !a.url) continue;
    // Only the configured gateway may be fetched. The URL is gateway-signed, but the signature is
    // checked by the GATEWAY - it tells us nothing here, and the URL arrives inside a message. Pinning
    // the origin is what actually stops this fetch being pointed anywhere.
    if (!originAllowed(a.url, opts?.gatewayOrigin)) continue;
    try {
      // Bounded and redirect-refusing - the URL is gateway-signed and same-host, so a
      // redirect means something is off; following it would re-open the SSRF door the signing closed.
      const res = await fetchFn(a.url, { signal: AbortSignal.timeout(10_000), redirect: "error" });
      if (!res.ok) continue;

      // Refuse anything that is not an image BEFORE reading a byte of it.
      const mime = String(
        (a as { contentType?: string }).contentType ?? res.headers.get("content-type") ?? "",
      ).split(";")[0].trim().toLowerCase();
      if (!mime.startsWith("image/")) continue;

      // A declared length over the cap is refused without transferring the body at all.
      const declared = Number(res.headers.get("content-length"));
      if (Number.isFinite(declared) && declared > maxBytes) continue;

      const buf = await readCapped(res, maxBytes);
      if (!buf || buf.length === 0) continue;
      images.push({ type: "image", data: buf.toString("base64"), mimeType: mime });
    } catch {
      // Best-effort: the turn still runs; the text names the attachment either way.
    }
  }
  return images;
}

/** A voice clip fetched from the gateway, ready to hand to file-based STT. */
export interface FetchedAudio {
  /** Attachment name as Teams reported it, for the placeholder when transcription fails. */
  name?: string;
  bytes: Buffer;
  mime: string;
}

/**
 * Fetch inbound voice-message attachments so they can be transcribed.
 *
 * Same posture as fetchAttachmentImages, and for the same reasons: origin-pinned to the configured
 * gateway (the URL is gateway-SIGNED, but that signature is verified BY the gateway - it proves
 * nothing here, and the URL arrives inside a message), redirect-refusing, size-capped while reading
 * rather than after, and count-capped so one message cannot multiply into unbounded work.
 *
 * Audio gets a larger byte cap than images because a voice note is minutes of audio, and a smaller
 * count cap because each one costs an STT call.
 */
export async function fetchAttachmentAudio(
  attachments: ManagedInbound["attachments"],
  opts?: { fetchFn?: typeof fetch; maxBytes?: number; maxClips?: number; gatewayOrigin?: string },
): Promise<FetchedAudio[]> {
  const fetchFn = opts?.fetchFn ?? fetch;
  const maxBytes = opts?.maxBytes ?? 16 * 1024 * 1024;
  const maxClips = opts?.maxClips ?? 2;
  const clips: FetchedAudio[] = [];
  for (const a of attachments ?? []) {
    if (clips.length >= maxClips) break;
    if (a.kind !== "audio" || a.relayable === false || !a.url) continue;
    if (!originAllowed(a.url, opts?.gatewayOrigin)) continue;
    try {
      const res = await fetchFn(a.url, { signal: AbortSignal.timeout(20_000), redirect: "error" });
      if (!res.ok) continue;
      const mime = String(
        (a as { contentType?: string }).contentType ?? res.headers.get("content-type") ?? "",
      )
        .split(";")[0]
        .trim()
        .toLowerCase();
      // Refuse anything that is not audio BEFORE reading a byte of it.
      if (!mime.startsWith("audio/") && !mime.startsWith("video/")) continue;
      const declared = Number(res.headers.get("content-length"));
      if (Number.isFinite(declared) && declared > maxBytes) continue;
      const buf = await readCapped(res, maxBytes);
      if (!buf || buf.length === 0) continue;
      clips.push({ name: a.name ?? undefined, bytes: buf, mime });
    } catch {
      // Best-effort: the turn still runs, and the text keeps naming the attachment.
    }
  }
  return clips;
}

/** True when the URL is on the gateway we are configured to talk to (or no origin is pinned). */
function originAllowed(url: string, gatewayOrigin?: string): boolean {
  if (!gatewayOrigin) return true;
  try {
    return new URL(url).origin === new URL(gatewayOrigin).origin;
  } catch {
    return false;
  }
}

/**
 * Read a response body, ABORTING once it exceeds the cap.
 *
 * res.arrayBuffer() allocates the whole body first and checks the size after - which means a
 * content-length that lies (or is absent) gets to allocate whatever it likes before we object. The
 * cap has to be enforced while reading, not once reading is done. Returns null when the body runs
 * over, so the caller drops that attachment.
 */
async function readCapped(res: Response, maxBytes: number): Promise<Buffer | null> {
  const body = res.body;
  if (!body) return null;
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => undefined);
        return null;
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock?.();
  }
  return Buffer.concat(chunks.map((c) => Buffer.from(c)), total);
}

/**
 * Post a message into a Teams conversation through the gateway, with no inbound message to reply to.
 *
 * The SAME hop an ordinary chat reply takes - the gateway's /api/chat/reply, signed with this
 * binding's connection secret - just addressed explicitly rather than derived from something that
 * arrived. The agent never holds a Bot Framework credential; the gateway performs the Teams send.
 *
 * It exists because in-call chat had no route on a managed connection. post_meeting_minutes delivers
 * through the HOST's message tool, which needs the customer's own Teams channel - a managed customer
 * has none, so "post that to the chat" during a call could only fail. The plugin already holds both
 * sockets; this uses the one built for this direction.
 *
 * Best-effort: returns false rather than throwing, because a failed post must not break a live call.
 */
export async function postManagedMessage(opts: {
  chatSecret: string;
  gatewayReplyUrl: string;
  tenantId: string;
  /** Echo of an INBOUND bindingId when the post answers something that arrived with one. Optional:
   * an agent-initiated message has no inbound to echo, carries none, and the gateway stamps the
   * binding it resolves the conversation to - existing callers need not change. */
  bindingId?: string;
  conversationId: string;
  text: string;
  idempotencyKey?: string;
  fetchFn?: typeof fetch;
}): Promise<boolean> {
  const body = JSON.stringify({
    // Every message on this wire carries schemaVersion (chat-schema.yaml). buildReply() sets it and
    // this did not - the current gateway defaults it in C# and hid the omission, which is exactly the
    // kind of thing that breaks against a stricter consumer rather than against the one that wrote it.
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
  } catch {
    return false;
  }
}

export interface ManagedChatDeps {
  /** Run one agent turn for an inbound message; returns the reply text. */
  respond: (message: ManagedInbound) => Promise<string>;
  log: { info: (m: string) => void; warn: (m: string) => void; error: (m: string) => void };
  /** Injectable for tests. */
  fetchFn?: typeof fetch;
  nowMs?: () => number;
}

export class ManagedChatServer {
  private server?: http.Server;
  private readonly seen = new SeenActivities();
  /** Per-conversation processing chains: the schema promises per-conversation ORDERING,
   * and independent tasks per message let replies overtake each other. Each conversation's turns run
   * strictly sequentially; different conversations still run concurrently. Entries are cleaned when
   * their chain drains so idle conversations cost nothing. */
  private readonly chains = new Map<string, Promise<void>>();

  constructor(
    private readonly cfg: ManagedChatConfig,
    private readonly deps: ManagedChatDeps,
  ) {}

  async start(): Promise<void> {
    const server = http.createServer((req, res) => {
      // handle() is async and its result was DISCARDED. A client that sends a partial body and
      // disconnects makes the request iterator throw ("aborted") before authentication even runs, and
      // nothing was there to catch it - an unhandled rejection from an unauthenticated peer, which
      // under Node's default policy takes the process down. Catch at the boundary: an aborted upload
      // is routine, not an error worth logging at warn, and the socket is already gone.
      void this.handle(req, res).catch((err) => {
        // Not warn: a client hanging up mid-body is routine and an unauthenticated peer must not be
        // able to fill the operator's log by doing it repeatedly.
        void err;
        try {
          if (!res.headersSent) res.writeHead(400).end();
        } catch {
          // The socket is gone - which is the usual reason we are here.
        }
      });
    });
    this.server = server;
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(this.cfg.port, this.cfg.bindAddress, () => resolve());
    });
    this.deps.log.info(
      `msteams managed chat: listening on ${this.cfg.bindAddress ?? "0.0.0.0"}:${this.cfg.port}${this.cfg.path}`,
    );
  }

  /** Set by stop(). Checked at every point a turn could still reach the agent or the gateway, so a
   * chain that was already running when we stopped cannot speak for a runtime that no longer exists. */
  private stopped = false;

  async stop(): Promise<void> {
    // Mark FIRST: from here no new request is accepted, no queued turn starts, and no in-flight turn
    // posts its reply. Closing the listener alone left all of that running - a turn that began before
    // stop() still posted its final "message" after the runtime was gone, so an OpenClaw reload could
    // produce a late reply from the previous runtime, and tool activity after teardown.
    this.stopped = true;

    const server = this.server;
    this.server = undefined;
    if (server) {
      // server.close() waits for every in-flight request to finish, so a slow or half-sent request
      // could hold a reload open far past the drain budget below - the budget only covered the agent
      // turns, not the listener. Bound the close, then destroy whatever is still attached.
      server.closeIdleConnections?.();
      await Promise.race([
        new Promise<void>((resolve) => server.close(() => resolve())),
        new Promise<void>((resolve) => setTimeout(resolve, ManagedChatServer.CLOSE_MS).unref?.()),
      ]);
      // Anything still holding the listener open at this point is not going to finish in time. It
      // cannot post a reply either way (see the stopped guard), so the socket is all that is left.
      server.closeAllConnections?.();
    }

    // Then give the chains that are already running a BOUNDED chance to finish. They cannot post
    // anymore (the guard above), so this is about letting agent work unwind cleanly rather than
    // abandoning it mid-flight; we never block teardown on it.
    const inflight = [...this.chains.values()];
    if (inflight.length > 0) {
      await Promise.race([
        Promise.allSettled(inflight),
        new Promise<void>((resolve) => setTimeout(resolve, ManagedChatServer.DRAIN_MS).unref?.()),
      ]);
    }
    this.chains.clear();
  }

  /** How long stop() waits for in-flight chains before returning. Bounded because a host reload must
   * not hang on an agent turn, and the reply guard already makes a straggler harmless. */
  private static readonly DRAIN_MS = 5000;

  /** How long stop() waits for the LISTENER to close before destroying connections. Separate from
   * DRAIN_MS: one bounds sockets, the other bounds agent work, and the two used to be conflated. */
  private static readonly CLOSE_MS = 2000;

  private async handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    // The configured path is the ONLY path served - no legacy aliases. If a deployment needs a
    // different one, it sets `path`; nothing silently answers a route this bridge used to have.
    if (req.method !== "POST" || (req.url ?? "").split("?")[0] !== this.cfg.path) {
      res.writeHead(404).end();
      return;
    }
    // Bounded read BEFORE any auth work: an unauthenticated peer must not make us buffer
    // an arbitrary body. 1 MB comfortably fits any relay payload (attachments travel by REFERENCE).
    const maxBody = 1024 * 1024;
    const declared = Number(req.headers["content-length"]);
    if (Number.isFinite(declared) && declared > maxBody) {
      res.writeHead(413).end();
      return;
    }
    const chunks: Buffer[] = [];
    let received = 0;
    for await (const chunk of req) {
      received += (chunk as Buffer).length;
      if (received > maxBody) {
        res.writeHead(413).end();
        req.destroy();
        return;
      }
      chunks.push(chunk as Buffer);
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

    // ACK FIRST (the gateway's relay window is short; agent latency is not) — then process async.
    // A redelivered activity ACKs and does nothing: the first delivery's turn is already running.
    const fresh = this.seen.markFirst(
      `${parsed.message.tenantId}:${parsed.message.conversationId}:${parsed.message.activityId}`);
    res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ ok: true }));
    if (!fresh) return;

    this.enqueueTurn(parsed.message);
  }

  /** Chain the turn behind the conversation's previous one (ordering); see `chains`. */
  private enqueueTurn(message: ManagedInbound): void {
    // Nothing new after stop(): a queued turn starting during teardown would run the agent for a
    // runtime that is going away.
    if (this.stopped) return;
    const key = `${message.tenantId}:${message.conversationId}`;
    const prev = this.chains.get(key) ?? Promise.resolve();
    // Re-check on the way IN, not only when queued: this callback can sit behind another turn and
    // reach the front long after stop() ran, at which point starting an agent turn for a runtime the
    // host has already replaced is exactly what we are trying to avoid.
    const next = prev
      .then(() => (this.stopped ? undefined : this.processAsync(message)))
      .catch(() => undefined);
    this.chains.set(key, next);
    void next.finally(() => {
      if (this.chains.get(key) === next) this.chains.delete(key);
    });
  }

  /** Serialization would make a HUNG turn wedge its whole conversation forever (every later
   * message chains behind it, and the chain entry never drains). Every turn is therefore bounded: a
   * turn that exceeds the budget fails like any other error, the user hears about it, and the chain
   * moves on. Generous, because agent turns legitimately run long. */
  static readonly TURN_TIMEOUT_MS = 5 * 60 * 1000;

  private async processAsync(message: ManagedInbound): Promise<void> {
    // Typing while the agent thinks — best-effort, ephemeral by design. Started, NOT awaited, before
    // the turn: awaiting it put a whole outbound timeout in front of every answer on a slow gateway.
    // It is awaited just before the reply instead, so the indicator still lands first (one that
    // arrives after the answer is worse than a slow one) at no real cost - the turn is always longer.
    const typing = this.postReply(buildReply(message, "", "typing")).catch(() => undefined);
    try {
      const text = await withTimeout(this.deps.respond(message), ManagedChatServer.TURN_TIMEOUT_MS, "agent turn");
      await typing;
      if (text.trim().length > 0) {
        await this.postReply(buildReply(message, text));
      } else {
        // An empty consult answer must not read as the bot ignoring the user - after the
        // typing indicator, silence looks exactly like a hang. Say so, as an error-kind reply.
        this.deps.log.warn("msteams managed chat: agent returned an empty answer");
        await this.postReply(
          buildReply(message, "I couldn't come up with an answer to that — try rephrasing, or ask something else.", "error"),
        );
      }
    } catch (err) {
      this.deps.log.error(`msteams managed chat: agent turn failed: ${String(err)}`);
      await this.postReply(
        buildReply(message, "Something went wrong answering that — please try again.", "error"),
      ).catch(() => undefined);
    }
  }

  /** The reply leg retries a bounded number of times - the idempotencyKey (activityId:kind)
   * makes a duplicate arrival a silent gateway-side drop, so retrying is safe, and without it one
   * transient gateway blip ate a finished agent turn. Typing indicators never retry (ephemeral). */
  static readonly REPLY_ATTEMPTS = 3;

  private async postReply(reply: Record<string, unknown>): Promise<void> {
    // The single choke point for agent -> Teams. A turn already in flight when stop() ran must not
    // deliver: that is what produced a late reply from a runtime the host had already replaced.
    if (this.stopped) return;
    const body = JSON.stringify(reply);
    const fetchFn = this.deps.fetchFn ?? fetch;
    const attempts = reply.kind === "typing" ? 1 : ManagedChatServer.REPLY_ATTEMPTS;
    for (let attempt = 1; attempt <= attempts; attempt++) {
      // Re-checked EVERY attempt, not just on entry. With up to three attempts and backoff between
      // them, this loop can run for ~30 seconds - so a stop() that arrived after the first attempt
      // started would still let a later attempt post, which is the late reply the entry check exists
      // to prevent, only harder to see.
      if (this.stopped) return;
      // Fresh signature per attempt: a retry after backoff must not replay a stale timestamp into
      // the gateway's +/-5min window edge.
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
          // An unbounded reply POST would wedge the conversation chain exactly like a hung turn.
          signal: AbortSignal.timeout(30_000),
        });
        if (res.ok) return;
        // 5xx/429 are retryable; anything else 4xx is OUR bug (rejected card, bad payload) - retrying
        // re-sends the same bytes and cannot succeed.
        this.deps.log.warn(`msteams managed chat: gateway reply -> HTTP ${res.status} (attempt ${attempt}/${attempts})`);
        if (res.status < 500 && res.status !== 429) return;
      } catch (err) {
        this.deps.log.warn(`msteams managed chat: gateway reply failed: ${String(err)} (attempt ${attempt}/${attempts})`);
      }
      if (attempt < attempts) await new Promise((r) => setTimeout(r, 1000 * 4 ** (attempt - 1)));
    }
  }
}

/** Reject after ms; the underlying promise keeps running (we cannot cancel the agent) but the chain
 * stops waiting on it — a wedged conversation beats a cancelled-mid-tool-use agent turn either way. */
function withTimeout<T>(promise: Promise<T>, ms: number, what: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`${what} timed out after ${ms}ms`)), ms);
    promise.then(
      (v) => { clearTimeout(timer); resolve(v); },
      (e) => { clearTimeout(timer); reject(e); },
    );
  });
}

function header(req: http.IncomingMessage, name: string): string | undefined {
  const v = req.headers[name];
  return Array.isArray(v) ? v[0] : v;
}

/**
 * Resolve the managedBot block of the plugin config.
 *
 * ACTIVATION (matched with the Hermes bridge, deliberately): the SECRET is the switch.
 *   - secret present            -> ON. A user who pastes the secret from the StandIn portal is done;
 *                                  requiring a second `enabled: true` meant the natural onboarding
 *                                  flow produced a silently dead chat lane.
 *   - `enabled: false` present  -> OFF, even with a secret. An explicit off must win.
 *   - `enabled: true`, no secret-> OFF (nothing could verify a request anyway) and FLAGGED, so the
 *                                  runtime says so at startup instead of going quiet.
 */
export function resolveManagedChatConfig(raw: unknown): ManagedChatConfig {
  const c = (raw ?? {}) as Record<string, unknown>;
  const chatSecret = typeof c.chatSecret === "string" ? c.chatSecret : "";
  const explicitlyOff = c.enabled === false;
  return {
    configuredWithoutSecret: c.enabled === true && chatSecret.length === 0,
    enabled: chatSecret.length > 0 && !explicitlyOff,
    transcribeVoiceMessages: c.transcribeVoiceMessages === true,
    port: Number(c.port ?? 9444),
    // Default to LOOPBACK, the same default the calling lane has. Leaving this undefined handed it to
    // server.listen(port, undefined), which binds every interface - so a config that named no bind
    // address at all got calling on 127.0.0.1 and messages on the LAN, while the docs said the two
    // lanes share one. The portal's snippet always writes bindAddress explicitly, so this only ever
    // bit people following the README.
    bindAddress: typeof c.bindAddress === "string" ? c.bindAddress : "127.0.0.1",
    path: typeof c.path === "string" ? c.path : "/msteams/messages",
    chatSecret,
    gatewayReplyUrl:
      typeof c.gatewayReplyUrl === "string" && c.gatewayReplyUrl.length > 0
        ? c.gatewayReplyUrl
        : "https://teams.standin.komaa.com/api/chat/reply",
  };
}
