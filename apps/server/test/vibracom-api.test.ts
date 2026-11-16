import { afterEach, describe, expect, test } from "bun:test";
import { schema, sql } from "@agenteschat/db";
import { signJwtHs256 } from "@agenteschat/engine";
import { verifyServiceToken } from "../src/vibracom-api";
import { vibracomMaySetPassword, vibracomPasswordRefusal } from "../src/vibracom-sso";
import { browser, createTestServer, ORIGIN, seedOrg, signUp, type TestServer } from "./harness";

const SECRET = "v".repeat(48);
const now = () => Math.floor(Date.now() / 1000);
const act = (agents: string[], over: Record<string, unknown> = {}) =>
  signJwtHs256(
    {
      iss: "vibracom-sistema",
      aud: ORIGIN,
      purpose: "act",
      email: "ana@vibracom.example",
      name: "Ana",
      agents,
      iat: now(),
      exp: now() + 60,
      ...over,
    },
    SECRET,
  );
const admin = () =>
  signJwtHs256({ iss: "vibracom-sistema", aud: ORIGIN, purpose: "admin", iat: now(), exp: now() + 60 }, SECRET);

let t: TestServer | undefined;
afterEach(async () => {
  await t?.close();
  t = undefined;
});

async function setup() {
  t = await createTestServer({ env: { VIBRACOM_SSO_SECRET: SECRET, VIBRACOM_SSO_ORG_ID: "" } });
  const owner = browser(t);
  await signUp(owner, "owner@example.com");
  const seeded = await seedOrg(owner);
  const other = (await (
    await owner(`/api/app/organizations/${seeded.orgId}/agents`, {
      json: { name: "Fin", handle: "fin", model: "claude-sonnet-5-5", credentialId: seeded.credentialId },
    })
  ).json()) as { id: string };
  const server = t;
  const call = (path: string, token: string, init: { json?: unknown; body?: FormData } = {}) =>
    server.app.request(`/api/vibracom/v1${path}`, {
      method: init.json !== undefined || init.body ? "POST" : "GET",
      headers: {
        authorization: `Bearer ${token}`,
        ...(init.json !== undefined ? { "content-type": "application/json" } : {}),
      },
      body: init.json !== undefined ? JSON.stringify(init.json) : init.body,
    });
  return { ...seeded, otherAgentId: other.id, call };
}

describe("vibracom service api", () => {
  test("a person reaches only the agents their token names, and only their own conversations", async () => {
    const { agentId, otherAgentId, call } = await setup();
    expect((await call("/me/agents", "not-a-token")).status).toBe(401);
    expect((await call("/me/agents", admin())).status).toBe(401);

    const listed = (await (await call("/me/agents", act([agentId]))).json()) as { agents: { id: string }[] };
    expect(listed.agents.map((a) => a.id)).toEqual([agentId]);

    expect((await call("/me/conversations", act([agentId]), { json: { agentId: otherAgentId } })).status).toBe(403);
    const opened = await call("/me/conversations", act([agentId]), { json: { agentId } });
    expect(opened.status).toBe(201);
    const { id } = (await opened.json()) as { id: string };

    const sent = await call(`/me/conversations/${id}/messages`, act([agentId]), {
      json: { text: "Oi, preciso de ajuda" },
    });
    expect(sent.status).toBe(201);
    expect(((await sent.json()) as { from: string }).from).toBe("person");

    const form = new FormData();
    form.set("file", new File(["a,b\n1,2"], "planilha.csv", { type: "text/csv" }));
    const up = await call(`/me/conversations/${id}/files`, act([agentId]), { body: form });
    expect(up.status).toBe(201);
    const file = (await up.json()) as { id: string; title: string };
    expect(file.title).toBe("planilha.csv");
    expect(
      (await call(`/me/conversations/${id}/messages`, act([agentId]), { json: { text: "Veja", files: [file.id] } }))
        .status,
    ).toBe(201);
    const down = await call(`/me/files/${file.id}`, act([agentId]));
    expect(down.status).toBe(200);
    expect(await down.text()).toBe("a,b\n1,2");

    const read = (await (await call(`/me/conversations/${id}/messages`, act([agentId]))).json()) as {
      messages: { text: string; files: { id: string }[] }[];
    };
    expect(read.messages.map((m) => m.text)).toEqual(["Oi, preciso de ajuda", "Veja"]);
    expect(read.messages[1]?.files.map((f) => f.id)).toEqual([file.id]);

    // The job lost that agent: its conversation is out of reach.
    expect((await call(`/me/conversations/${id}/messages`, act([otherAgentId]))).status).toBe(404);
    const mine = (await (await call("/me/conversations", act([otherAgentId]))).json()) as { conversations: unknown[] };
    expect(mine.conversations).toEqual([]);

    // Somebody else never sees Ana's conversation.
    const bia = act([agentId], { email: "bia@vibracom.example", name: "Bia" });
    expect((await call(`/me/conversations/${id}/messages`, bia)).status).toBe(404);
    expect(
      ((await (await call("/me/conversations", bia)).json()) as { conversations: unknown[] }).conversations,
    ).toEqual([]);
  });

  test("admin: usage per person and agent, and ending a person's sign-ins", async () => {
    const { orgId, agentId, call } = await setup();
    const server = t as TestServer;
    expect((await call("/admin/usage?from=2020-01-01", act([agentId]))).status).toBe(401);
    const { id } = (await (await call("/me/conversations", act([agentId]), { json: { agentId } })).json()) as {
      id: string;
    };
    const sent = (await (
      await call(`/me/conversations/${id}/messages`, act([agentId]), { json: { text: "Resuma o dia" } })
    ).json()) as { id: string };
    // Posting queued the agent's work: its usage counts for the person who asked.
    const [run] = await server.db
      .select({ id: schema.agentRuns.id })
      .from(schema.agentRuns)
      .where(sql`trigger_message_id = ${sent.id}`);
    expect(run).toBeDefined();
    await server.db.insert(schema.usageRecords).values({
      orgId,
      agentId,
      runId: run?.id,
      provider: "anthropic",
      model: "m",
      requestedModel: "m",
      inputTokens: 10,
      outputTokens: 10,
      costNanoUsd: 250_000_000,
    });
    const usage = (await (await call("/admin/usage?from=2020-01-01", admin())).json()) as {
      totalUsd: number;
      usage: { email: string; agentId: string; costUsd: number; runs: number }[];
    };
    // The workspace's own calls (routing a message, say) count in the total with no person.
    expect(usage.totalUsd).toBeGreaterThanOrEqual(0.25);
    expect(usage.usage.filter((u) => u.email)).toEqual([
      { email: "ana@vibracom.example", agentId, costUsd: 0.25, runs: 1 },
    ]);

    const [ana] = await server.db.select().from(schema.users).where(sql`email = 'ana@vibracom.example'`);
    await server.db.insert(schema.sessions).values({
      id: crypto.randomUUID(),
      userId: ana?.id as string,
      token: "tok-ana-1",
      expiresAt: new Date(Date.now() + 3600_000),
      createdAt: new Date(),
      updatedAt: new Date(),
    } as typeof schema.sessions.$inferInsert);
    const revoked = await call("/admin/revoke", admin(), { json: { email: "Ana@Vibracom.example" } });
    expect(((await revoked.json()) as { revoked: number }).revoked).toBe(1);
  });
});

describe("vibracom service tokens and lockdown", () => {
  const AUD = "https://agentes.example.com";
  test("a token for one purpose never passes as another, nor lives long", () => {
    const n = 1_800_000_000;
    const base = { iss: "vibracom-sistema", aud: AUD, iat: n, exp: n + 60 };
    const { z } = require("zod") as typeof import("zod");
    const Admin = z.object({
      iss: z.literal("vibracom-sistema"),
      aud: z.string(),
      purpose: z.literal("admin"),
      iat: z.number(),
      exp: z.number(),
    });
    expect(
      verifyServiceToken(signJwtHs256({ ...base, purpose: "admin" }, SECRET), SECRET, AUD, Admin, n),
    ).not.toBeNull();
    expect(verifyServiceToken(signJwtHs256({ ...base, purpose: "act" }, SECRET), SECRET, AUD, Admin, n)).toBeNull();
    expect(
      verifyServiceToken(signJwtHs256({ ...base, purpose: "admin", exp: n + 600 }, SECRET), SECRET, AUD, Admin, n),
    ).toBeNull();
    expect(
      verifyServiceToken(signJwtHs256({ ...base, purpose: "admin" }, "x".repeat(48)), SECRET, AUD, Admin, n),
    ).toBeNull();
  });

  test("with the lockdown only the listed accounts use a password", () => {
    const on = { VIBRACOM_LOCKDOWN: "on" as const, VIBRACOM_DIRECT_LOGIN: ["ti@listralize.com"] };
    const off = { VIBRACOM_LOCKDOWN: "off" as const, VIBRACOM_DIRECT_LOGIN: [] };
    expect(vibracomPasswordRefusal(off, "/sign-in/email", "ana@x.com")).toBeNull();
    expect(vibracomPasswordRefusal(on, "/sign-in/email", "ana@x.com")).toContain("sistema vibracom");
    expect(vibracomPasswordRefusal(on, "/request-password-reset", "ana@x.com")).not.toBeNull();
    expect(vibracomPasswordRefusal(on, "/sign-in/email", " TI@listralize.com ")).toBeNull();
    expect(vibracomPasswordRefusal(on, "/get-session", undefined)).toBeNull();
    expect(vibracomMaySetPassword(on, "ana@x.com")).toBe(false);
    expect(vibracomMaySetPassword(on, "ti@listralize.com")).toBe(true);
    expect(vibracomMaySetPassword(off, "ana@x.com")).toBe(true);
  });
});

describe("vibracom lockdown on a server", () => {
  test("the handed-over sign-in lets in only IT, and passwords only the listed account", async () => {
    t = await createTestServer({
      env: { VIBRACOM_SSO_SECRET: SECRET, VIBRACOM_LOCKDOWN: "on", VIBRACOM_DIRECT_LOGIN: "owner@example.com" },
    });
    const owner = browser(t);
    await signUp(owner, "owner@example.com");
    await seedOrg(owner);
    const sso = (over: Record<string, unknown>) =>
      signJwtHs256(
        {
          iss: "vibracom-sistema",
          aud: ORIGIN,
          sub: "u1",
          email: "ana@vibracom.example",
          name: "Ana",
          iat: now(),
          exp: now() + 60,
          jti: crypto.randomUUID().replaceAll("-", ""),
          ...over,
        },
        SECRET,
      );
    const lay = await t.app.request(`/api/auth/vibracom-sso?t=${sso({})}`);
    expect(lay.status).toBe(403);
    const it = await t.app.request(
      `/api/auth/vibracom-sso?t=${sso({ area: "tecnica", email: "ti@vibracom.example" })}`,
    );
    expect(it.status).toBe(302);

    const signIn = (email: string) =>
      browser(t as TestServer)("/api/auth/sign-in/email", { json: { email, password: "senha-muito-boa-123" } });
    expect((await signIn("ana@vibracom.example")).status).toBe(403);
    expect((await signIn("owner@example.com")).status).not.toBe(403);
  });
});
