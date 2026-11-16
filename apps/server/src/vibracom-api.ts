import { createHmac, randomUUID } from "node:crypto";
import { and, type Database, eq, inArray, isNull, rowsOf, schema, sql } from "@agenteschat/db";
import {
  ARTIFACT_LIMITS,
  type ArtifactDeps,
  accountClosed,
  activeRunsIn,
  artifactFile,
  createFileArtifact,
  joinOrganization,
  listDms,
  listMessages,
  type MessageView,
  openDm,
  postPersonMessage,
  safeEqual,
} from "@agenteschat/engine";
import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import { z } from "zod";
import type { AppDeps } from "./routes/app/context";
import { vibracomOrgId } from "./vibracom-sso";

/**
 * Fork vibracom (not upstream): the service API vibracom-sistema uses to give its staff the agents in its own
 * simple page, without this app's screens.
 *
 * Every call carries a JWT (HS256, `VIBRACOM_SSO_SECRET`) minted by vibracom-sistema for that one call, good for
 * at most 120 seconds. `purpose: "act"` names the person (email, name) and the agents their job may use; the
 * person is found or created with no password and joined as a member, and everything runs as them, so an agent's
 * tools (the vibracom MCP among them) keep that person's own permissions. Only direct conversations with the named
 * agents are reachable. `purpose: "admin"` (no person) reads the month's usage and ends a person's sign-ins.
 * Limits, who may use which agent and the audit trail live in vibracom-sistema. Unset secret: the routes don't exist.
 */

const ISSUER = "vibracom-sistema";
const MAX_LIFE_SECONDS = 120;
const CLOCK_SLACK_SECONDS = 30;

const ActClaims = z.object({
  iss: z.literal(ISSUER),
  aud: z.string(),
  purpose: z.literal("act"),
  email: z.email().max(254),
  name: z.string().trim().min(1).max(160),
  agents: z.array(z.uuid()).max(50),
  iat: z.number().int(),
  exp: z.number().int(),
});
const AdminClaims = z.object({
  iss: z.literal(ISSUER),
  aud: z.string(),
  purpose: z.literal("admin"),
  iat: z.number().int(),
  exp: z.number().int(),
});
export type VibracomActClaims = z.infer<typeof ActClaims>;

/** The payload of a vibracom-sistema service token when its signature, audience and short life check out. */
export function verifyServiceToken<T extends z.ZodType<{ aud: string; iat: number; exp: number }>>(
  token: string,
  secret: string,
  audience: string,
  shape: T,
  nowSeconds = Math.floor(Date.now() / 1000),
): z.infer<T> | null {
  const parts = token.split(".");
  if (parts.length !== 3 || token.length > 8192) return null;
  const [head, body, signature] = parts as [string, string, string];
  try {
    const header = JSON.parse(Buffer.from(head, "base64url").toString("utf8"));
    if (header?.alg !== "HS256") return null;
    const expected = createHmac("sha256", secret).update(`${head}.${body}`).digest("base64url");
    if (!safeEqual(expected, signature)) return null;
    const parsed = shape.safeParse(JSON.parse(Buffer.from(body, "base64url").toString("utf8")));
    if (!parsed.success) return null;
    const c = parsed.data;
    if (c.aud !== audience) return null;
    if (c.exp < nowSeconds - CLOCK_SLACK_SECONDS || c.iat > nowSeconds + CLOCK_SLACK_SECONDS) return null;
    if (c.exp - c.iat > MAX_LIFE_SECONDS) return null;
    return c;
  } catch {
    return null;
  }
}

/** The person of an `act` token: found by e-mail, or created with no password, and a member of the workspace. */
export async function vibracomPerson(db: Database, orgId: string, email: string, name: string) {
  const address = email.toLowerCase();
  const find = () =>
    db.select({ id: schema.users.id }).from(schema.users).where(eq(schema.users.email, address)).limit(1);
  let [user] = await find();
  if (!user) {
    await db
      .insert(schema.users)
      .values({ id: randomUUID(), name, email: address, emailVerified: true, locale: "pt-BR" })
      .onConflictDoNothing();
    [user] = await find();
  }
  if (!user) throw new Error("vibracom api: the person could not be created");
  if (await accountClosed(db, user.id)) return null;
  await db.transaction(async (tx) => {
    await tx.execute(sql`select pg_advisory_xact_lock(hashtext(${`vibracom-sso:${user.id}`}))`);
    const [member] = await tx
      .select({ userId: schema.organizationMembers.userId })
      .from(schema.organizationMembers)
      .where(and(eq(schema.organizationMembers.orgId, orgId), eq(schema.organizationMembers.userId, user.id)));
    if (!member) await joinOrganization(tx, orgId, user.id, "member");
  });
  return user.id;
}

/** A message as the simple page shows it: who wrote it, the text, its files and when. */
export function plainMessage(m: MessageView) {
  const files = Array.isArray(m.meta?.artifacts) ? (m.meta.artifacts as { id?: unknown; title?: unknown }[]) : [];
  return {
    id: m.id,
    from: m.author.type === "agent" ? ("agent" as const) : ("person" as const),
    agentId: m.author.type === "agent" ? m.author.id : null,
    runId: m.agentRunId,
    text: m.body,
    files: files.flatMap((f) =>
      typeof f.id === "string" ? [{ id: f.id, title: typeof f.title === "string" ? f.title : "arquivo" }] : [],
    ),
    createdAt: m.createdAt,
  };
}

type Vars = { userId: string; orgId: string; agents: string[] };

export function vibracomApiRoutes(deps: AppDeps) {
  const { db, config, adapters } = deps;
  const app = new Hono<{ Variables: Vars }>();
  const secret = config.VIBRACOM_SSO_SECRET as string;
  const audience = new URL(config.PUBLIC_URL).origin;
  const bearer = (header: string | undefined) => (header?.startsWith("Bearer ") ? header.slice(7) : "");
  const refuse = (status: 401 | 403 | 404, message: string) =>
    new Response(JSON.stringify({ error: message }), { status, headers: { "content-type": "application/json" } });

  app.use("/admin/*", async (c, next) => {
    if (!verifyServiceToken(bearer(c.req.header("authorization")), secret, audience, AdminClaims))
      return refuse(401, "unauthorized");
    const orgId = await vibracomOrgId(db, config);
    if (!orgId) return refuse(404, "workspace not configured");
    c.set("orgId", orgId);
    await next();
  });

  app.use("/me/*", async (c, next) => {
    const claims = verifyServiceToken(bearer(c.req.header("authorization")), secret, audience, ActClaims);
    if (!claims) return refuse(401, "unauthorized");
    const orgId = await vibracomOrgId(db, config);
    if (!orgId) return refuse(404, "workspace not configured");
    const userId = await vibracomPerson(db, orgId, claims.email, claims.name);
    if (!userId) return refuse(403, "blocked");
    c.set("userId", userId);
    c.set("orgId", orgId);
    c.set("agents", claims.agents);
    await next();
  });

  /** The person's conversation with an agent their job may use, or null. */
  const ownDm = async (userId: string, orgId: string, agents: string[], channelId: string) => {
    if (!z.uuid().safeParse(channelId).success) return null;
    const [dm] = await listDms(db, userId, orgId, channelId);
    if (dm?.with.type !== "agent" || !agents.includes(dm.with.id)) return null;
    return dm;
  };

  // The agents this person may use (only those the token names), as the page lists them.
  app.get("/me/agents", async (c) => {
    const ids = c.get("agents");
    if (ids.length === 0) return c.json({ agents: [] });
    const rows = await db
      .select({ id: schema.agents.id, name: schema.agents.name, role: schema.agents.role })
      .from(schema.agents)
      .where(
        and(eq(schema.agents.orgId, c.get("orgId")), inArray(schema.agents.id, ids), isNull(schema.agents.archivedAt)),
      );
    return c.json({ agents: rows });
  });

  // Their own conversations with those agents, newest first.
  app.get("/me/conversations", async (c) => {
    const agents = c.get("agents");
    const dms = await listDms(db, c.get("userId"), c.get("orgId"));
    return c.json({
      conversations: dms
        .filter((d) => d.with.type === "agent" && agents.includes(d.with.id))
        .map((d) => ({
          id: d.channelId,
          agentId: d.with.id,
          agentName: d.with.name,
          lastText: d.lastMessage?.body.slice(0, 200) ?? null,
          lastAt: (d.lastMessage?.createdAt ?? d.openedAt).toISOString(),
        })),
    });
  });

  // Opens (or finds) their conversation with one agent.
  app.post("/me/conversations", async (c) => {
    const parsed = z.object({ agentId: z.uuid() }).safeParse(await c.req.json().catch(() => null));
    if (!parsed.success || !c.get("agents").includes(parsed.data.agentId)) return refuse(403, "agent not allowed");
    const dm = await openDm(
      db,
      c.get("userId"),
      c.get("orgId"),
      { agentId: parsed.data.agentId },
      {
        pubsub: adapters.pubsub,
      },
    );
    return c.json({ id: dm.id }, 201);
  });

  app.get("/me/conversations/:channelId/messages", async (c) => {
    const { userId, orgId } = { userId: c.get("userId"), orgId: c.get("orgId") };
    const channelId = c.req.param("channelId");
    if (!(await ownDm(userId, orgId, c.get("agents"), channelId))) return refuse(404, "not found");
    const list = await listMessages(db, userId, orgId, channelId, { limit: 100, includeReplies: true });
    const flat = list.flatMap((m) => [m, ...(m.replies?.latest ?? [])]);
    flat.sort((a, b) => a.createdAt.localeCompare(b.createdAt));
    const runs = await activeRunsIn(db, orgId, channelId);
    return c.json({
      messages: flat
        .filter((m) => m.body.trim() || (m.meta?.artifacts as unknown[] | undefined)?.length)
        .map(plainMessage),
      working: runs.some((r) => !r.background),
    });
  });

  app.post("/me/conversations/:channelId/messages", async (c) => {
    const { userId, orgId } = { userId: c.get("userId"), orgId: c.get("orgId") };
    const channelId = c.req.param("channelId");
    if (!(await ownDm(userId, orgId, c.get("agents"), channelId))) return refuse(404, "not found");
    const parsed = z
      .object({ text: z.string().trim().min(1).max(20_000), files: z.array(z.uuid()).max(10).optional() })
      .safeParse(await c.req.json().catch(() => null));
    if (!parsed.success) return c.json({ error: "invalid message" }, 400);
    const limit = await adapters.rateLimiter.consume(`post:${userId}`, { limit: 30, windowMs: 10_000 });
    if (!limit.allowed) return c.json({ error: "rate_limited" }, 429);
    const message = await postPersonMessage(
      { db, pubsub: adapters.pubsub, judge: deps.extras?.context?.judge, talker: deps.extras?.talker, gifs: null },
      userId,
      orgId,
      channelId,
      { body: parsed.data.text, attachments: parsed.data.files },
    );
    deps.wakeWorkers?.();
    return c.json(plainMessage(message), 201);
  });

  const artifacts = (): ArtifactDeps => {
    const a = deps.extras?.artifacts;
    if (!a) throw new Error("artifacts are not configured on this server");
    return a;
  };

  app.post(
    "/me/conversations/:channelId/files",
    bodyLimit({ maxSize: ARTIFACT_LIMITS.fileBytes + 64 * 1024, onError: (c) => c.json({ error: "too large" }, 413) }),
    async (c) => {
      const { userId, orgId } = { userId: c.get("userId"), orgId: c.get("orgId") };
      const channelId = c.req.param("channelId");
      if (!(await ownDm(userId, orgId, c.get("agents"), channelId))) return refuse(404, "not found");
      const form = await c.req.formData().catch(() => null);
      const file = form?.get("file");
      if (!(file instanceof File)) return c.json({ error: "send the file in the field file" }, 400);
      if (file.size > ARTIFACT_LIMITS.fileBytes) return c.json({ error: "too large" }, 413);
      const created = await createFileArtifact(artifacts(), { type: "person", userId }, orgId, {
        name: file.name,
        contentType: file.type || null,
        bytes: new Uint8Array(await file.arrayBuffer()),
        title: file.name,
        channelId,
        threadId: null,
      });
      return c.json({ id: created.id, title: created.title }, 201);
    },
  );

  // A file the person can see (theirs, or one an agent made in their conversation), always as a download.
  app.get("/me/files/:artifactId", async (c) => {
    const artifactId = c.req.param("artifactId");
    if (!z.uuid().safeParse(artifactId).success) return refuse(404, "not found");
    const file = await artifactFile(artifacts(), c.get("userId"), c.get("orgId"), artifactId, {});
    return new Response(file.body as ConstructorParameters<typeof Response>[0], {
      headers: {
        "content-type": file.contentType,
        "content-disposition": `attachment; filename*=UTF-8''${encodeURIComponent(file.filename)}`,
        "x-content-type-options": "nosniff",
        "cache-control": "private, no-store",
      },
    });
  });

  // The usage since a moment, per person (who sent the message the work answered) and agent, plus the total.
  app.get("/admin/usage", async (c) => {
    const from = new Date(c.req.query("from") ?? "");
    if (Number.isNaN(from.getTime())) return c.json({ error: "from must be a date" }, 400);
    const orgId = c.get("orgId");
    const rows = rowsOf<{ email: string | null; agent_id: string | null; nano: string | null; runs: string }>(
      await db.execute(sql`
        select u.email, ur.agent_id, sum(ur.cost_nano_usd)::text as nano, count(distinct ur.run_id)::text as runs
        from usage_records ur
        left join agent_runs r on r.id = ur.run_id
        left join messages m on m.id = r.trigger_message_id and m.org_id = r.org_id and m.author_type = 'person'
        left join users u on u.id = m.author_user_id
        where ur.org_id = ${orgId} and ur.created_at >= ${from.toISOString()} and ur.billed_to = 'org'
        group by u.email, ur.agent_id`),
    );
    const usage = rows.map((r) => ({
      email: r.email,
      agentId: r.agent_id,
      costUsd: Number(r.nano ?? 0) / 1e9,
      runs: Number(r.runs),
    }));
    return c.json({ from: from.toISOString(), totalUsd: usage.reduce((s, r) => s + r.costUsd, 0), usage });
  });

  // Ends every sign-in of one person here at once (someone who left the company, or lost access to the agents).
  app.post("/admin/revoke", async (c) => {
    const parsed = z.object({ email: z.email().max(254) }).safeParse(await c.req.json().catch(() => null));
    if (!parsed.success) return c.json({ error: "invalid email" }, 400);
    const [user] = await db
      .select({ id: schema.users.id })
      .from(schema.users)
      .where(eq(schema.users.email, parsed.data.email.toLowerCase()))
      .limit(1);
    if (!user) return c.json({ revoked: 0 });
    const gone = await db
      .delete(schema.sessions)
      .where(eq(schema.sessions.userId, user.id))
      .returning({ id: schema.sessions.id });
    return c.json({ revoked: gone.length });
  });

  return app;
}
