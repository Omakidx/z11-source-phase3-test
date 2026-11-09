import { createHmac, timingSafeEqual } from "node:crypto";

import { createControlledFailureResponse, type FixtureEnvironment } from "./fixture-contract";

/**
 * Login journey fixture for Z11 Phase 6. A framework-free request handler so the
 * Next.js route files and the journey runner tests serve exactly the same
 * behavior.
 *
 *   GET  /login        form (identifier, password, submit)
 *   POST /api/login    sets a session cookie and redirects to /account, or to
 *                      /login?error=invalid
 *   GET  /account      "Welcome" page with a sign-out control; requires the cookie
 *   POST /api/logout   clears the cookie and redirects to /login
 *
 * The test account comes from FIXTURE_LOGIN_IDENTIFIER and
 * FIXTURE_LOGIN_PASSWORD; without both, every route answers 404. The existing
 * FIXTURE_ENABLE_CONTROLLED_FAILURE switch (off by default) makes /login and
 * /api/login answer 503. The fixture never logs or echoes a credential.
 */

export const LOGIN_COOKIE = "fixture_session";
export const SESSION_SECONDS = 15 * 60;
const MAX_BODY_BYTES = 4_096;

type Account = { identifier: string; password: string };

function account(environment: FixtureEnvironment): Account | undefined {
  const identifier = environment.FIXTURE_LOGIN_IDENTIFIER;
  const password = environment.FIXTURE_LOGIN_PASSWORD;
  return identifier && password ? { identifier, password } : undefined;
}

function digest(value: string, key: string) {
  return createHmac("sha256", key).update(value).digest();
}

/** Constant-time comparison that also hides the length. */
function safeEqual(left: string, right: string) {
  return timingSafeEqual(digest(left, "compare"), digest(right, "compare"));
}

function sign(expires: number, found: Account) {
  return createHmac("sha256", `fixture-session:${found.password}`)
    .update(`${found.identifier}:${expires}`)
    .digest("base64url");
}

function sessionValid(request: Request, found: Account, nowMs: number) {
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

function html(body: string, status = 200) {
  return new Response(
    `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Z11 fixture sign-in</title></head><body><main>${body}</main></body></html>`,
    {
      status,
      headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" },
    },
  );
}

function redirect(location: string, cookie?: string) {
  const headers = new Headers({ location, "cache-control": "no-store" });
  if (cookie) headers.append("set-cookie", cookie);
  return new Response(null, { status: 303, headers });
}

function cookieAttributes(request: Request) {
  const secure =
    new URL(request.url).protocol === "https:" ||
    request.headers.get("x-forwarded-proto") === "https";
  return `Path=/; HttpOnly; SameSite=Lax${secure ? "; Secure" : ""}`;
}

function loginPage(error: boolean) {
  return html(
    `<h1>Sign in</h1>${error ? '<p role="alert" id="error">Invalid identifier or password.</p>' : ""}` +
      `<form method="post" action="/api/login">` +
      `<label for="identifier">Identifier</label><input id="identifier" name="identifier" type="text" autocomplete="username">` +
      `<label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password">` +
      `<button id="sign-in" type="submit">Sign in</button></form>`,
  );
}

async function readForm(request: Request) {
  const text = await request.text();
  if (text.length > MAX_BODY_BYTES) return undefined;
  return new URLSearchParams(text);
}

/**
 * Handles a fixture login request; returns `undefined` for paths it does not
 * own, so a host can fall through to its other routes.
 */
export async function handleLoginFixtureRequest(
  request: Request,
  environment: FixtureEnvironment,
  nowMs: number = Date.now(),
): Promise<Response | undefined> {
  const url = new URL(request.url);
  const path = url.pathname;
  if (!["/login", "/api/login", "/account", "/api/logout"].includes(path)) return undefined;
  const found = account(environment);
  if (!found) return new Response("Not found", { status: 404 });
  // Phase 16 staging regression: the sign-in page is unavailable.
  if (path === "/login" || path === "/api/login")
    return new Response("Service unavailable", { status: 503, headers: { "cache-control": "no-store" } });

  if (path === "/login" && request.method === "GET")
    return sessionValid(request, found, nowMs)
      ? redirect("/account")
      : loginPage(url.searchParams.get("error") === "invalid");

  if (path === "/api/login" && request.method === "POST") {
    const form = await readForm(request);
    const valid =
      form !== undefined &&
      safeEqual(form.get("identifier") ?? "", found.identifier) &&
      safeEqual(form.get("password") ?? "", found.password);
    if (!valid) return redirect("/login?error=invalid");
    const expires = Math.floor(nowMs / 1000) + SESSION_SECONDS;
    return redirect(
      "/account",
      `${LOGIN_COOKIE}=${expires}.${sign(expires, found)}; Max-Age=${SESSION_SECONDS}; ${cookieAttributes(request)}`,
    );
  }

  if (path === "/account" && request.method === "GET")
    return sessionValid(request, found, nowMs)
      ? html(
          `<h1>Welcome</h1><p>You are signed in to the Z11 fixture.</p>` +
            `<form method="post" action="/api/logout"><button id="sign-out" type="submit">Sign out</button></form>`,
        )
      : redirect("/login");

  if (path === "/api/logout" && request.method === "POST")
    return redirect("/login", `${LOGIN_COOKIE}=; Max-Age=0; ${cookieAttributes(request)}`);

  return new Response("Method not allowed", { status: 405 });
}
