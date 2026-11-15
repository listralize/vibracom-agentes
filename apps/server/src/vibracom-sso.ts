import { createHmac, randomUUID } from "node:crypto";
import type { Config } from "@agenteschat/config";
import { type Database, eq, isNull, schema, sql } from "@agenteschat/db";
import { accountClosed, joinOrganization, safeEqual } from "@agenteschat/engine";
import type { BetterAuthPlugin } from "better-auth";
import { APIError, createAuthEndpoint } from "better-auth/api";
import { setSessionCookie } from "better-auth/cookies";
import { z } from "zod";
import type { Logger } from "./logger";

/**
 * Fork vibracom (not upstream): the sign-in vibracom-sistema hands over to the people it already signed in.
 *
 * vibracom-sistema mints a JWT (HS256, `VIBRACOM_SSO_SECRET`) good for at most 120 seconds and opens
 * `GET /api/auth/vibracom-sso?t=<jwt>` (in its "Agentes" page's frame, or a new tab). Here the token is checked
 * (signature with the algorithm pinned, issuer, audience, expiry, a `jti` used once), the person is found by email
 * or created with no password (they only come in through vibracom-sistema), added to the vibracom workspace as a
 * member, and signed in with a session cookie; then the browser goes to the app.
 *
 * A person blocked or closed here stays out, and nothing in the token can make anyone an owner or admin: roles
 * are given in the workspace by its admins, as for any member.
 */

const ISSUER = "vibracom-sistema";
const MAX_LIFE_SECONDS = 120;
const CLOCK_SLACK_SECONDS = 30;

const Claims = z.object({
  iss: z.literal(ISSUER),
  aud: z.string(),
  sub: z.string().min(1).max(200),
  email: z.email().max(254),
  name: z.string().trim().min(1).max(160),
  iat: z.number().int(),
  exp: z.number().int(),
  jti: z.string().regex(/^[A-Za-z0-9_-]{16,100}$/),
});
export type VibracomSsoClaims = z.infer<typeof Claims>;

/** The claims of a token signed with `secret`, or null when anything about it is off. */
export function verifyVibracomToken(
  token: string,
  secret: string,
  audience: string,
  nowSeconds = Math.floor(Date.now() / 1000),
): VibracomSsoClaims | null {
  const parts = token.split(".");
  if (parts.length !== 3 || token.length > 4096) return null;
  const [head, body, signature] = parts as [string, string, string];
  let header: unknown;
  let payload: unknown;
  try {
    header = JSON.parse(Buffer.from(head, "base64url").toString("utf8"));
    payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
  } catch {
    return null;
  }
  if (!header || typeof header !== "object" || (header as { alg?: unknown }).alg !== "HS256") return null;
  const expected = createHmac("sha256", secret).update(`${head}.${body}`).digest("base64url");
  if (!safeEqual(expected, signature)) return null;
  const parsed = Claims.safeParse(payload);
  if (!parsed.success) return null;
  const claims = parsed.data;
  if (claims.aud !== audience) return null;
  if (claims.exp < nowSeconds - CLOCK_SLACK_SECONDS) return null;
  if (claims.iat > nowSeconds + CLOCK_SLACK_SECONDS) return null;
  if (claims.exp - claims.iat > MAX_LIFE_SECONDS) return null;
  return claims;
}

/** The workspace people join: the configured one, or the only one there is. */
async function vibracomOrgId(db: Database, config: Config): Promise<string | null> {
  if (config.VIBRACOM_SSO_ORG_ID) return config.VIBRACOM_SSO_ORG_ID;
  const rows = await db
    .select({ id: schema.organizations.id })
    .from(schema.organizations)
    .where(isNull(schema.organizations.deletionDueAt))
    .limit(2);
  return rows.length === 1 ? (rows[0]?.id ?? null) : null;
}

export function vibracomSso(deps: { db: Database; config: Config; log: Logger }) {
  const { db, config, log } = deps;
  const publicOrigin = new URL(config.PUBLIC_URL).origin;
  return {
    id: "vibracom-sso",
    endpoints: {
      vibracomSso: createAuthEndpoint(
        "/vibracom-sso",
        { method: "GET", query: z.object({ t: z.string().min(20).max(4096), next: z.string().max(300).optional() }) },
        async (ctx) => {
          const secret = config.VIBRACOM_SSO_SECRET;
          if (!secret) throw new APIError("NOT_FOUND", { message: "Not found" });
          const claims = verifyVibracomToken(ctx.query.t, secret, publicOrigin);
          if (!claims)
            throw new APIError("UNAUTHORIZED", {
              message: "Link de acesso inválido ou expirado. Abra de novo pelo sistema.",
            });
          // Each token signs in once: its jti is kept for as long as the token could still be shown.
          const identifier = `vibracom-sso:${claims.jti}`;
          if (await ctx.context.internalAdapter.findVerificationValue(identifier)) {
            throw new APIError("UNAUTHORIZED", {
              message: "Este link de acesso já foi usado. Abra de novo pelo sistema.",
            });
          }
          await ctx.context.internalAdapter.createVerificationValue({
            identifier,
            value: "used",
            expiresAt: new Date((claims.exp + CLOCK_SLACK_SECONDS) * 1000),
          });
          const orgId = await vibracomOrgId(db, config);
          if (!orgId)
            throw new APIError("INTERNAL_SERVER_ERROR", { message: "Workspace da vibracom não configurado." });

          const email = claims.email.toLowerCase();
          let user = await ctx.context.internalAdapter.findUserByEmail(email).then((found) => found?.user ?? null);
          if (!user) {
            const id = ctx.context.generateId({ model: "user" }) || randomUUID();
            await db
              .insert(schema.users)
              .values({ id, name: claims.name, email, emailVerified: true, locale: "pt-BR" })
              .onConflictDoNothing();
            user = await ctx.context.internalAdapter.findUserByEmail(email).then((found) => found?.user ?? null);
            if (!user) throw new APIError("INTERNAL_SERVER_ERROR", { message: "Não foi possível criar o acesso." });
            log.info("vibracom sso: person created", { userId: user.id });
          }
          if (await accountClosed(db, user.id))
            throw new APIError("FORBIDDEN", { message: "Acesso bloqueado nos Agentes." });
          await db.transaction(async (tx) => {
            await tx.execute(sql`select pg_advisory_xact_lock(hashtext(${`vibracom-sso:${user.id}`}))`);
            const [member] = await tx
              .select({ userId: schema.organizationMembers.userId })
              .from(schema.organizationMembers)
              .where(
                sql`${schema.organizationMembers.orgId} = ${orgId} and ${schema.organizationMembers.userId} = ${user.id}`,
              );
            if (!member) await joinOrganization(tx, orgId, user.id, "member");
          });
          // The workspace this session opens on.
          const session = await ctx.context.internalAdapter.createSession(user.id);
          if (!session) throw new APIError("INTERNAL_SERVER_ERROR", { message: "Não foi possível entrar." });
          await db
            .update(schema.sessions)
            .set({ activeOrganizationId: orgId })
            .where(eq(schema.sessions.id, session.id))
            .catch(() => undefined);
          await setSessionCookie(ctx, { session, user });
          const next = ctx.query.next?.startsWith("/") && !ctx.query.next.startsWith("//") ? ctx.query.next : "/";
          throw ctx.redirect(`${publicOrigin}${next}`);
        },
      ),
    },
  } satisfies BetterAuthPlugin;
}
