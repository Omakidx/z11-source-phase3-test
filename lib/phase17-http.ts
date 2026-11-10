import { createHmac, timingSafeEqual } from "node:crypto";

/** Same shape as the phase4 fixture's environment record. */
export type FixtureEnvironment = Record<string, string | undefined>;

/**
 * Helpers shared by the fixture's request handlers (login, notes, upload): the
 * test account, the signed login session, and small response builders. The
 * fixture never logs or echoes a credential.
 */

export const LOGIN_COOKIE = "fixture_session";
export const SESSION_SECONDS = 15 * 60;
export const MAX_BODY_BYTES = 4_096;

export type Account = { identifier: string; password: string };

export function account(environment: FixtureEnvironment): Account | undefined {
  const identifier = environment.FIXTURE_LOGIN_IDENTIFIER;
  const password = environment.FIXTURE_LOGIN_PASSWORD;
  return identifier && password ? { identifier, password } : undefined;
}

export function digest(value: string, key: string) {
  return createHmac("sha256", key).update(value).digest();
}

/** Constant-time comparison that also hides the length. */
export function safeEqual(left: string, right: string) {
  return timingSafeEqual(digest(left, "compare"), digest(right, "compare"));
}

export function sign(expires: number, found: Account) {
  return createHmac("sha256", `fixture-session:${found.password}`)
    .update(`${found.identifier}:${expires}`)
    .digest("base64url");
}

export function sessionValid(request: Request, found: Account, nowMs: number) {
  const cookie = request.headers
    .get("cookie")
    ?.split(/;\s*/u)
    .find((part) => part.startsWith(`${LOGIN_COOKIE}=`));
  if (!cookie) return false;
  const [expiresText, signature] = cookie.slice(LOGIN_COOKIE.length + 1).split(".");
  const expires = Number(expiresText);
  if (!Number.isInteger(expires) || expires * 1000 < nowMs || !signature) return false;
  return safeEqual(signature, sign(expires, found));
}

export function html(body: string, status = 200, title = "Z11 fixture sign-in") {
  return new Response(
    `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>${title}</title></head><body><main>${body}</main></body></html>`,
    {
      status,
      headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" },
    },
  );
}

export function redirect(location: string, cookie?: string) {
  const headers = new Headers({ location, "cache-control": "no-store" });
  if (cookie) headers.append("set-cookie", cookie);
  return new Response(null, { status: 303, headers });
}

export function cookieAttributes(request: Request) {
  const secure =
    new URL(request.url).protocol === "https:" ||
    request.headers.get("x-forwarded-proto") === "https";
  return `Path=/; HttpOnly; SameSite=Lax${secure ? "; Secure" : ""}`;
}


export async function readForm(request: Request) {
  const text = await request.text();
  if (text.length > MAX_BODY_BYTES) return undefined;
  return new URLSearchParams(text);
}
