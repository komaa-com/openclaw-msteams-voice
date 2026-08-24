// StandIn managed chat mode: the agent side of the normalized chat relay (protocol/chat-schema.yaml).
// The HMAC KAT is the SAME vector pinned in @standin/bridge-hmac (TS), the gateway's LinkTokensTests
// (C#), and the media-bridge callers — four independent implementations, one set of bytes.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import {
  buildReply,
  fetchAttachmentImages,
  computeBridgeSignature,
  postManagedMessage,
  ManagedChatServer,
  parseInbound,
  REPLAY_WINDOW_MS,
  resolveManagedChatConfig,
  SeenActivities,
  signBridge,
  verifyBridge,
  type ManagedInbound,
} from "./managed-chat.js";

const KAT_SECRET = "test-secret";
const KAT_TS = "1700000000000";
const KAT_BODY = "hello";
const KAT_SIG = "1ea836ba1a9714e5a5824a9026b2b40567ee9e5e2ddd0d1cb598da3b42afce38";
const KAT_NOW = 1700000000000;

describe("bridge HMAC", () => {
  it("matches the cross-repo KAT", () => {
    expect(computeBridgeSignature(KAT_SECRET, KAT_TS, KAT_BODY)).toBe(KAT_SIG);
    const signed = signBridge(KAT_SECRET, KAT_BODY, KAT_NOW);
    expect(signed).toEqual({ timestamp: KAT_TS, signature: KAT_SIG });
  });

  it("verifies inside the replay window and refuses outside it", () => {
    expect(verifyBridge(KAT_SECRET, KAT_TS, KAT_BODY, KAT_SIG, KAT_NOW)).toBe(true);
    expect(verifyBridge(KAT_SECRET, KAT_TS, KAT_BODY, KAT_SIG, KAT_NOW + REPLAY_WINDOW_MS - 1)).toBe(true);
    expect(verifyBridge(KAT_SECRET, KAT_TS, KAT_BODY, KAT_SIG, KAT_NOW + REPLAY_WINDOW_MS + 1)).toBe(false);
    expect(verifyBridge(KAT_SECRET, KAT_TS, KAT_BODY, KAT_SIG, KAT_NOW - REPLAY_WINDOW_MS - 1)).toBe(false);
  });

  it("refuses tampering, wrong keys, and absent headers", () => {
    expect(verifyBridge(KAT_SECRET, KAT_TS, KAT_BODY + "x", KAT_SIG, KAT_NOW)).toBe(false);
    expect(verifyBridge("other-secret", KAT_TS, KAT_BODY, KAT_SIG, KAT_NOW)).toBe(false);
    expect(verifyBridge(KAT_SECRET, undefined, KAT_BODY, KAT_SIG, KAT_NOW)).toBe(false);
    expect(verifyBridge(KAT_SECRET, KAT_TS, KAT_BODY, undefined, KAT_NOW)).toBe(false);
    expect(verifyBridge("", KAT_TS, KAT_BODY, KAT_SIG, KAT_NOW)).toBe(false); // no secret = fail closed
    expect(verifyBridge(KAT_SECRET, "not-a-number", KAT_BODY, KAT_SIG, KAT_NOW)).toBe(false);
  });

  it("accepts an UPPERCASE hex signature (hex case is not part of the contract)", () => {
    expect(verifyBridge(KAT_SECRET, KAT_TS, KAT_BODY, KAT_SIG.toUpperCase(), KAT_NOW)).toBe(true);
  });
});

describe("inbound parsing", () => {
  const valid = JSON.stringify({
    schemaVersion: 1,
    tenantId: "t1",
    bindingId: "b1",
    conversationId: "c1",
    activityId: "a1",
    scope: "personal",
    sender: { displayName: "Alaa", isLinkedOwner: true },
    text: "hello agent",
    someFutureField: { ignored: true },
  });

  it("accepts a valid message and ignores unknown fields (additive evolution)", () => {
    const r = parseInbound(valid);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.message.tenantId).toBe("t1");
      expect(r.message.text).toBe("hello agent");
      expect(r.message.sender.displayName).toBe("Alaa");
    }
  });

  it("carries bindingId VERBATIM when present, undefined when absent or malformed", () => {
    // Verbatim: the reply echoes it, so any normalization here would break the echo.
    const withIt = parseInbound(valid);
    expect(withIt.ok && withIt.message.bindingId).toBe("b1");
    // Old gateways send nothing, and that must keep working.
    for (const bindingId of [undefined, null, "", 42, { id: "b1" }]) {
      const m = JSON.parse(valid) as Record<string, unknown>;
      if (bindingId === undefined) delete m.bindingId;
      else m.bindingId = bindingId;
      const r = parseInbound(JSON.stringify(m));
      expect(r.ok).toBe(true);
      if (r.ok) expect(r.message.bindingId).toBeUndefined();
    }
  });

  it("requires the routing keys and rejects malformed bodies", () => {
    expect(parseInbound("not json").ok).toBe(false);
    expect(parseInbound("[]").ok).toBe(false);
    for (const missing of ["tenantId", "conversationId", "activityId"]) {
      const m = JSON.parse(valid) as Record<string, unknown>;
      delete m[missing];
      const r = parseInbound(JSON.stringify(m));
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.error).toContain(missing);
    }
  });
});

describe("redelivery dedupe", () => {
  it("is first-time-true, redelivery-false, and bounded", () => {
    const seen = new SeenActivities(2);
    expect(seen.markFirst("a")).toBe(true);
    expect(seen.markFirst("a")).toBe(false);
    expect(seen.markFirst("b")).toBe(true);
    expect(seen.markFirst("c")).toBe(true); // evicts "a"
    expect(seen.markFirst("a")).toBe(true); // aged out of the window - acceptable at-least-once behavior
  });
});

describe("reply building", () => {
  const inbound = { tenantId: "t1", conversationId: "c1", activityId: "a1" };

  it("echoes tenant + conversation exactly (the gateway's cross-tenant guard depends on it)", () => {
    const reply = buildReply(inbound, "answer");
    expect(reply.tenantId).toBe("t1");
    expect(reply.conversationId).toBe("c1");
    expect(reply.replyToId).toBe("a1");
    expect(reply.kind).toBe("message");
    expect(reply.text).toBe("answer");
    expect(reply.idempotencyKey).toBe("a1:message");
  });

  it("typing carries no text and its own idempotency key", () => {
    const typing = buildReply(inbound, "ignored", "typing");
    expect(typing.kind).toBe("typing");
    expect("text" in typing).toBe(false);
    expect(typing.idempotencyKey).toBe("a1:typing");
  });

  it("echoes the inbound bindingId when present (per-binding isolation inside the tenant)", () => {
    const reply = buildReply({ ...inbound, bindingId: "b1" }, "answer");
    expect(reply.bindingId).toBe("b1");
  });

  it("omits bindingId when the inbound carried none (old-gateway shape unchanged)", () => {
    const reply = buildReply(inbound, "answer");
    expect("bindingId" in reply).toBe(false);
  });
});

describe("plugin config path (managedBot lands where the runtime reads it)", () => {
  it("`secret` is the ONLY key, and it fills both lanes", async () => {
    const { resolvePluginConfig } = await import("./plugin-config.js");
    const one = resolvePluginConfig({ secret: "ONE" });
    expect(one.media.sharedSecret).toBe("ONE");
    expect(one.managedChat.enabled).toBe(true);
    expect(one.managedChat.chatSecret).toBe("ONE");

    // The former per-lane overrides are GONE. They are the reason the published docs taught
    // `sharedSecret` and left the messages lane silently off for everyone who followed them, so a
    // config still carrying them must not quietly half-work - it must resolve to nothing.
    const legacy = resolvePluginConfig({ sharedSecret: "V" });
    expect(legacy.media.sharedSecret).toBe("");
    expect(legacy.managedChat.enabled).toBe(false);

    const legacyMsgs = resolvePluginConfig({ secret: "ONE", messagesSecret: "OVR" });
    expect(legacyMsgs.managedChat.chatSecret).toBe("ONE");
  });

  it("resolves the messages lane from flat keys, managedBot as compatibility, and one secret for both", async () => {
    const { resolvePluginConfig } = await import("./plugin-config.js");

    // The compatibility block still works.
    const viaBlock = resolvePluginConfig({ managedBot: { chatSecret: "k" } });
    expect(viaBlock.managedChat.enabled).toBe(true);
    expect(viaBlock.managedChat.chatSecret).toBe("k");

    // `secret` wins over the compatibility block, and the flat lane keys still apply.
    const flat = resolvePluginConfig({
      secret: "S",
      messagesPort: 9555,
      messagesPath: "/msteams/messages",
      managedBot: { chatSecret: "block" },
    });
    expect(flat.managedChat.chatSecret).toBe("S");
    expect(flat.managedChat.port).toBe(9555);

    // ONE secret fills BOTH lanes - the whole point of `secret`.
    const one = resolvePluginConfig({ secret: "S" });
    expect(one.media.sharedSecret).toBe("S");
    expect(one.managedChat.chatSecret).toBe("S");
    expect(one.managedChat.enabled).toBe(true);

    // The removed `managedChat` alias no longer resolves. It is gone from the manifest schema too,
    // which sets additionalProperties:false - so such a config fails validation before reaching here.
    const removed = resolvePluginConfig({ managedChat: { chatSecret: "k" } });
    expect(removed.managedChat.enabled).toBe(false);

    // Unset = off.
    expect(resolvePluginConfig({}).managedChat.enabled).toBe(false);
  });
});

describe("config resolution", () => {
  it("fails closed without a string chatSecret, exactly like the voice sharedSecret", () => {
    expect(resolveManagedChatConfig({ enabled: true, chatSecret: "k" }).enabled).toBe(true);
    expect(resolveManagedChatConfig({ enabled: true }).enabled).toBe(false);
    expect(resolveManagedChatConfig({ enabled: true, chatSecret: { env: "UNSET" } }).enabled).toBe(false);
    expect(resolveManagedChatConfig(undefined).enabled).toBe(false);
  });

  it("treats the SECRET as the switch, and an explicit enabled:false as the override", () => {
    // Matches the Hermes bridge. Requiring `enabled: true` on top of the secret meant a user who
    // followed the portal (which hands out a secret, not a flag) got a silently dead chat lane.
    expect(resolveManagedChatConfig({ chatSecret: "k" }).enabled).toBe(true);
    expect(resolveManagedChatConfig({ chatSecret: "k", enabled: false }).enabled).toBe(false);
    // enabled:true with no secret stays OFF but is FLAGGED so the runtime can warn.
    const bad = resolveManagedChatConfig({ enabled: true });
    expect(bad.enabled).toBe(false);
    expect(bad.configuredWithoutSecret).toBe(true);
  });

  it("carries sane defaults", () => {
    const cfg = resolveManagedChatConfig({ enabled: true, chatSecret: "k" });
    expect(cfg.port).toBe(9444);
    expect(cfg.path).toBe("/msteams/messages");
    expect(cfg.gatewayReplyUrl).toContain("/api/chat/reply");
  });
});

describe("schema drift (protocol/chat-schema.yaml is the source of truth)", () => {
  const here = dirname(fileURLToPath(import.meta.url));
  const schema = readFileSync(join(here, "..", "protocol", "chat-schema.yaml"), "utf8");

  it("every wire name this module reads or writes exists in the schema copy", () => {
    // A SUBSET is legal (unknown fields are ignored by contract); a name the schema does not know is
    // a typo that silently drops data. Line-based on purpose - no YAML dependency.
    const consumed = [
      "schemaVersion", "tenantId", "bindingId", "conversationId", "activityId", "scope", "sender",
      "text", "attachments", "locale", "replyToId", "kind", "idempotencyKey",
      "aadObjectId", "displayName", "isGuest", "isLinkedOwner", "name", "url", "relayable",
    ];
    for (const field of consumed) {
      expect(schema, `field '${field}' is not in chat-schema.yaml`).toMatch(
        new RegExp(`name: ${field}$`, "m"),
      );
    }
  });

  it("the schema constants this module hardcodes match the schema copy", () => {
    expect(schema).toContain("name: SCHEMA_VERSION\n    value: 1");
    expect(schema).toContain(`value: ${REPLAY_WINDOW_MS}`);
  });
});

describe("attachment image fetch (4.7 agent-side leg)", () => {
  const img = (over: Record<string, unknown> = {}) => ({
    kind: "image", name: "shot.png", url: "https://gw.test/api/chat/attachment/a1?e=1&s=x",
    contentType: "image/png", relayable: true, ...over,
  });
  const fakeFetch = (bytes: number, status = 200) =>
    (async () => new Response(new Uint8Array(bytes), { status, headers: { "content-type": "image/png" } })) as unknown as typeof fetch;

  it("fetches relayable images into base64 consult images", async () => {
    const images = await fetchAttachmentImages([img()], { fetchFn: fakeFetch(16) });
    expect(images).toHaveLength(1);
    expect(images[0].mimeType).toBe("image/png");
    expect(Buffer.from(images[0].data, "base64")).toHaveLength(16);
  });

  it("posts an in-call message over the messages lane, signed with the connection secret", async () => {
    // In-call chat had no route on a managed connection: post_meeting_minutes delivers through the
    // HOST's message tool, which needs the customer's own Teams channel - a managed customer has
    // none. This is the same hop a chat REPLY takes, just addressed explicitly.
    const sent: Array<{ url: string; body: Record<string, unknown>; headers: Record<string, string> }> = [];
    const fetchFn = (async (url: string | URL | Request, init?: RequestInit) => {
      sent.push({
        url: String(url),
        body: JSON.parse(String(init?.body)) as Record<string, unknown>,
        headers: init?.headers as Record<string, string>,
      });
      return new Response("{}", { status: 200 });
    }) as unknown as typeof fetch;

    const ok = await postManagedMessage({
      chatSecret: KAT_SECRET,
      gatewayReplyUrl: "https://gateway.test/api/chat/reply",
      tenantId: "t1",
      conversationId: "c1",
      text: "the link you asked for",
      idempotencyKey: "call-1-abc",
      fetchFn,
    });

    expect(ok).toBe(true);
    expect(sent).toHaveLength(1);
    expect(sent[0].url).toBe("https://gateway.test/api/chat/reply");
    expect(sent[0].body).toMatchObject({
      tenantId: "t1",
      conversationId: "c1",
      text: "the link you asked for",
      kind: "message",
      idempotencyKey: "call-1-abc",
    });
    // Signed with the binding's secret over the exact bytes sent - the gateway verifies per binding.
    const expected = computeBridgeSignature(KAT_SECRET, sent[0].headers["x-standin-timestamp"], JSON.stringify(sent[0].body));
    expect(sent[0].headers["x-standin-signature"]).toBe(expected);
    // No bindingId was given (agent-initiated post): none goes on the wire; the gateway stamps the
    // binding it resolves the conversation to.
    expect("bindingId" in sent[0].body).toBe(false);
  });

  it("includes bindingId on the wire when the caller provides one", async () => {
    const sent: Array<Record<string, unknown>> = [];
    const fetchFn = (async (_url: string | URL | Request, init?: RequestInit) => {
      sent.push(JSON.parse(String(init?.body)) as Record<string, unknown>);
      return new Response("{}", { status: 200 });
    }) as unknown as typeof fetch;
    const ok = await postManagedMessage({
      chatSecret: KAT_SECRET,
      gatewayReplyUrl: "https://gateway.test/api/chat/reply",
      tenantId: "t1",
      bindingId: "b1",
      conversationId: "c1",
      text: "x",
      fetchFn,
    });
    expect(ok).toBe(true);
    expect(sent[0].bindingId).toBe("b1");
  });

  it("reports a failed in-call post instead of throwing into the call", async () => {
    const failing = (async () => new Response("nope", { status: 500 })) as unknown as typeof fetch;
    expect(
      await postManagedMessage({
        chatSecret: KAT_SECRET,
        gatewayReplyUrl: "https://gateway.test/api/chat/reply",
        tenantId: "t1",
        conversationId: "c1",
        text: "x",
        fetchFn: failing,
      }),
    ).toBe(false);
  });

  it("aborts an oversize body WHILE reading, not after allocating it", async () => {
    // The cap used to be checked after res.arrayBuffer(), which allocates the whole body first - so a
    // response that lies about (or omits) content-length got to allocate whatever it liked before we
    // objected. Here the body is 64 bytes with NO content-length, so only a streamed cap can catch it.
    const noLength = (async () =>
      new Response(new Uint8Array(64), { status: 200, headers: { "content-type": "image/png" } })) as unknown as typeof fetch;
    expect(await fetchAttachmentImages([img()], { fetchFn: noLength, maxBytes: 32 })).toHaveLength(0);
    // ...and the same body under the cap still comes through.
    expect(await fetchAttachmentImages([img()], { fetchFn: noLength, maxBytes: 128 })).toHaveLength(1);
  });

  it("refuses a non-image content type without reading the body", async () => {
    const html = (async () =>
      new Response(new Uint8Array(16), { status: 200, headers: { "content-type": "text/html" } })) as unknown as typeof fetch;
    expect(await fetchAttachmentImages([img({ contentType: undefined })], { fetchFn: html })).toHaveLength(0);
  });

  it("fetches only from the configured gateway origin", async () => {
    const ok = fakeFetch(16);
    expect(
      await fetchAttachmentImages([img({ url: "https://evil.example/x.png" })], {
        fetchFn: ok,
        gatewayOrigin: "https://teams.standin.komaa.com",
      }),
    ).toHaveLength(0);
    expect(
      await fetchAttachmentImages([img({ url: "https://teams.standin.komaa.com/x.png" })], {
        fetchFn: ok,
        gatewayOrigin: "https://teams.standin.komaa.com",
      }),
    ).toHaveLength(1);
  });

  it("caps how MANY images one message can pull", async () => {
    const many = Array.from({ length: 10 }, () => img());
    expect(await fetchAttachmentImages(many, { fetchFn: fakeFetch(8), maxImages: 3 })).toHaveLength(3);
  });

  it("skips files, unrelayable, missing urls, failures, and oversize - never throws", async () => {
    expect(await fetchAttachmentImages([img({ kind: "file" })], { fetchFn: fakeFetch(16) })).toHaveLength(0);
    expect(await fetchAttachmentImages([img({ relayable: false })], { fetchFn: fakeFetch(16) })).toHaveLength(0);
    expect(await fetchAttachmentImages([img({ url: undefined })], { fetchFn: fakeFetch(16) })).toHaveLength(0);
    expect(await fetchAttachmentImages([img()], { fetchFn: fakeFetch(16, 404) })).toHaveLength(0);
    expect(await fetchAttachmentImages([img()], { fetchFn: fakeFetch(64, 200), maxBytes: 32 })).toHaveLength(0);
    expect(
      await fetchAttachmentImages([img()], { fetchFn: (async () => { throw new Error("net"); }) as unknown as typeof fetch }),
    ).toHaveLength(0);
    expect(await fetchAttachmentImages(undefined, { fetchFn: fakeFetch(16) })).toHaveLength(0);
  });
});

describe("the server end to end", () => {
  let server: ManagedChatServer | undefined;
  afterEach(async () => {
    await server?.stop();
    server = undefined;
  });

  async function startServer(opts?: { respond?: (m: ManagedInbound) => Promise<string> }) {
    const replies: Array<{ url: string; body: Record<string, unknown>; ts: string; sig: string }> = [];
    let resolveReplyDone: (() => void) | undefined;
    const replyDone = new Promise<void>((r) => { resolveReplyDone = r; });
    const port = 19_444 + Math.floor(Math.random() * 1000);
    const cfg = {
      enabled: true, port, bindAddress: "127.0.0.1", path: "/msteams/messages",
      chatSecret: KAT_SECRET, gatewayReplyUrl: "https://gateway.test/api/chat/reply",
    };
    server = new ManagedChatServer(cfg, {
      respond: opts?.respond ?? (async () => "the answer"),
      log: { info: () => {}, warn: () => {}, error: () => {} },
      fetchFn: (async (url: string | URL | Request, init?: RequestInit) => {
        const headers = init?.headers as Record<string, string>;
        replies.push({
          url: String(url),
          body: JSON.parse(String(init?.body)) as Record<string, unknown>,
          ts: headers["x-standin-timestamp"],
          sig: headers["x-standin-signature"],
        });
        if (replies.length >= 2) resolveReplyDone?.(); // typing + message
        return new Response("{}", { status: 200 });
      }) as typeof fetch,
    });
    await server.start();
    return { port, replies, replyDone };
  }

  it("survives an aborted UNAUTHENTICATED upload (no unhandled rejection)", async () => {
    const { port } = await startServer();
    // Announce a long body, send a fragment, then destroy the socket. The request iterator throws
    // "aborted" BEFORE authentication runs. handle()'s promise used to be discarded with `void`, so
    // nothing caught it - an unauthenticated peer could take the process down under Node's default
    // unhandled-rejection policy. A raw socket is the only way to be precise about this; fetch will
    // not send a deliberately truncated body.
    const rejections: unknown[] = [];
    const onUnhandled = (e: unknown) => rejections.push(e);
    process.on("unhandledRejection", onUnhandled);
    try {
      const net = await import("node:net");
      await new Promise<void>((resolve) => {
        const sock = net.connect(port, "127.0.0.1", () => {
          sock.write(
            "POST /msteams/messages HTTP/1.1\r\n" +
              "Host: 127.0.0.1\r\n" +
              "Content-Type: application/json\r\n" +
              "Content-Length: 999\r\n\r\n" +
              '{"tenantId":"t1","conv',
          );
          setTimeout(() => { sock.destroy(); resolve(); }, 50);
        });
        sock.on("error", () => resolve());
      });
      await new Promise((r) => setTimeout(r, 200));
      expect(rejections).toHaveLength(0);
      // ...and the server is still serving.
      const res = await post(port, JSON.stringify({ ...JSON.parse(inbound), activityId: "a-after-abort" }));
      expect(res.status).toBe(200);
    } finally {
      process.off("unhandledRejection", onUnhandled);
    }
  });

  it("posts NO reply once stop() has run", async () => {
    // A turn already in flight when the host reloads used to deliver its final "message" anyway - a
    // late reply from a runtime that no longer exists.
    let release: (() => void) | undefined;
    const held = new Promise<void>((r) => { release = r; });
    const { port, replies } = await startServer({
      respond: async () => { await held; return "too late"; },
    });
    const res = await post(port, JSON.stringify({ ...JSON.parse(inbound), activityId: "a-late-reply" }));
    expect(res.status).toBe(200);
    await new Promise((r) => setTimeout(r, 50)); // let the turn begin

    const stopping = server!.stop();
    release?.();
    await stopping;
    await new Promise((r) => setTimeout(r, 150));

    expect(replies.some((x) => x.body.kind === "message")).toBe(false);
  });

  function post(port: number, body: string, sign = true, path = "/msteams/messages") {
    const { timestamp, signature } = signBridge(KAT_SECRET, body);
    return fetch(`http://127.0.0.1:${port}${path}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(sign ? { "x-standin-timestamp": timestamp, "x-standin-signature": signature } : {}),
      },
      body,
    });
  }

  const inbound = JSON.stringify({
    tenantId: "t1", bindingId: "bind-e2e", conversationId: "c1", activityId: "a-e2e", scope: "personal",
    sender: { displayName: "Alaa" }, text: "hi",
  });

  it("ACKs a signed message, then posts typing + the reply back with the SAME chat key", async () => {
    const { port, replies, replyDone } = await startServer();
    const res = await post(port, inbound);
    expect(res.status).toBe(200);
    await replyDone;

    expect(replies.map((r) => r.body.kind)).toEqual(["typing", "message"]);
    const reply = replies[1];
    expect(reply.url).toBe("https://gateway.test/api/chat/reply");
    expect(reply.body.tenantId).toBe("t1");
    // The inbound bindingId is echoed verbatim, all the way through the server path.
    expect(reply.body.bindingId).toBe("bind-e2e");
    expect(reply.body.text).toBe("the answer");
    // The reply is signed with the same chat key, verifiable by the gateway's construction.
    expect(verifyBridge(KAT_SECRET, reply.ts, JSON.stringify(reply.body), reply.sig, Number(reply.ts))).toBe(true);
  });

  it("rejects unsigned and mis-signed requests without consulting the agent", async () => {
    let consulted = 0;
    const { port } = await startServer({ respond: async () => { consulted++; return "x"; } });
    expect((await post(port, inbound, false)).status).toBe(401);
    const bad = await fetch(`http://127.0.0.1:${port}/msteams/messages`, {
      method: "POST",
      headers: { "x-standin-timestamp": String(Date.now()), "x-standin-signature": "deadbeef" },
      body: inbound,
    });
    expect(bad.status).toBe(401);
    expect(consulted).toBe(0);
  });

  it("turns in ONE conversation run sequentially; different conversations run concurrently", async () => {
    // The schema promises per-conversation ordering - replies must not overtake each other.
    const events: string[] = [];
    const gates = new Map<string, () => void>();
    const { port } = await startServer({
      respond: async (m) => {
        events.push(`start:${m.activityId}`);
        await new Promise<void>((r) => gates.set(m.activityId, r));
        events.push(`end:${m.activityId}`);
        return "";
      },
    });
    const msg = (conv: string, id: string) =>
      JSON.stringify({ tenantId: "t1", conversationId: conv, activityId: id, scope: "personal", sender: {}, text: "x" });

    await post(port, msg("c1", "a1"));
    await post(port, msg("c1", "a2"));
    await post(port, msg("c2", "b1"));
    await new Promise((r) => setTimeout(r, 80));

    // a2 must NOT have started while a1 holds the gate; b1 (another conversation) runs concurrently.
    expect(events).toContain("start:a1");
    expect(events).toContain("start:b1");
    expect(events).not.toContain("start:a2");

    gates.get("a1")!();
    await new Promise((r) => setTimeout(r, 80));
    expect(events).toContain("end:a1");
    expect(events).toContain("start:a2");
    gates.get("a2")?.();
    gates.get("b1")?.();
    await new Promise((r) => setTimeout(r, 40));
  });

  it("rejects oversized bodies before running any agent turn", async () => {
    let turns = 0;
    const { port } = await startServer({ respond: async () => { turns++; return "x"; } });
    const big = JSON.stringify({ tenantId: "t1", conversationId: "c1", activityId: "big", text: "y".repeat(1_100_000) });
    const res = await post(port, big);
    expect(res.status).toBe(413);
    expect(turns).toBe(0);
  });

  it("a redelivered activity ACKs but does not run a second agent turn", async () => {
    let consulted = 0;
    const { port } = await startServer({ respond: async () => { consulted++; return "x"; } });
    expect((await post(port, inbound)).status).toBe(200);
    expect((await post(port, inbound)).status).toBe(200);
    await new Promise((r) => setTimeout(r, 50));
    expect(consulted).toBe(1);
  });

  it("404s other paths", async () => {
    const { port } = await startServer();
    expect((await post(port, inbound, true, "/other")).status).toBe(404);
  });
});
