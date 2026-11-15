import { describe, expect, test } from "bun:test";
import { signJwtHs256 } from "@agenteschat/engine";
import { appCsp } from "../src/app";
import { verifyVibracomToken } from "../src/vibracom-sso";

const SECRET = "s".repeat(48);
const AUD = "https://agentes.example.com";
const now = 1_800_000_000;
const claims = (over: Record<string, unknown> = {}) => ({
  iss: "vibracom-sistema",
  aud: AUD,
  sub: "u1",
  email: "Pessoa@Vibracom.com.br",
  name: "Pessoa",
  iat: now,
  exp: now + 60,
  jti: "abcdefghijklmnop1234",
  ...over,
});

describe("vibracom sso token", () => {
  test("accepts a fresh token signed with the secret", () => {
    expect(verifyVibracomToken(signJwtHs256(claims(), SECRET), SECRET, AUD, now)?.email).toBe("Pessoa@Vibracom.com.br");
  });
  test("refuses another secret, audience, issuer, an expired or too long-lived token", () => {
    expect(verifyVibracomToken(signJwtHs256(claims(), "x".repeat(48)), SECRET, AUD, now)).toBeNull();
    expect(
      verifyVibracomToken(signJwtHs256(claims({ aud: "https://evil.example" }), SECRET), SECRET, AUD, now),
    ).toBeNull();
    expect(verifyVibracomToken(signJwtHs256(claims({ iss: "other" }), SECRET), SECRET, AUD, now)).toBeNull();
    expect(verifyVibracomToken(signJwtHs256(claims({ exp: now - 100 }), SECRET), SECRET, AUD, now)).toBeNull();
    expect(verifyVibracomToken(signJwtHs256(claims({ exp: now + 3600 }), SECRET), SECRET, AUD, now)).toBeNull();
  });
  test("refuses alg none and a tampered body", () => {
    const [, body] = signJwtHs256(claims(), SECRET).split(".");
    const none = `${Buffer.from(JSON.stringify({ alg: "none" })).toString("base64url")}.${body}.`;
    expect(verifyVibracomToken(none, SECRET, AUD, now)).toBeNull();
    const [h, , sig] = signJwtHs256(claims(), SECRET).split(".");
    const forged = Buffer.from(JSON.stringify(claims({ email: "chefe@vibracom.com.br" }))).toString("base64url");
    expect(verifyVibracomToken(`${h}.${forged}.${sig}`, SECRET, AUD, now)).toBeNull();
  });
});

describe("frame ancestors", () => {
  test("upstream policy when unset, the listed origins when set", () => {
    expect(appCsp(undefined)).toContain("frame-ancestors 'none'");
    expect(appCsp("https://sistema.example.com")).toContain("frame-ancestors 'self' https://sistema.example.com;");
  });
});
