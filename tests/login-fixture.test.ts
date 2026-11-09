import { describe, expect, test } from "bun:test";

import { handleLoginFixtureRequest } from "../lib/login-fixture";

const env = { FIXTURE_LOGIN_IDENTIFIER: "journey@fixture.test", FIXTURE_LOGIN_PASSWORD: "correct horse" };
const base = "https://app.fixture.test";
const post = (path: string, fields: Record<string, string>, cookie?: string) =>
  new Request(`${base}${path}`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", ...(cookie ? { cookie } : {}) },
    body: new URLSearchParams(fields).toString(),
  });
const handle = (request: Request, environment: Record<string, string | undefined> = env, nowMs?: number) =>
  handleLoginFixtureRequest(request, environment, nowMs);
const sessionCookie = (response: Response) => response.headers.get("set-cookie")!.split(";")[0]!;

describe("login fixture", () => {
  test("is disabled without the test account and ignores other paths", async () => {
    expect((await handle(new Request(`${base}/login`), {}))!.status).toBe(404);
    expect(await handle(new Request(`${base}/api/health`))).toBeUndefined();
  });

  test("serves the form and signs in with the env account", async () => {
    const form = await handle(new Request(`${base}/login`));
    expect(form!.status).toBe(200);
    expect(await form!.text()).toContain('id="password"');
    const signedIn = await handle(post("/api/login", { identifier: env.FIXTURE_LOGIN_IDENTIFIER, password: env.FIXTURE_LOGIN_PASSWORD }));
    expect(signedIn!.status).toBe(303);
    expect(signedIn!.headers.get("location")).toBe("/account");
    expect(signedIn!.headers.get("set-cookie")).toMatch(/HttpOnly.*SameSite=Lax.*Secure/u);
    const account = await handle(new Request(`${base}/account`, { headers: { cookie: sessionCookie(signedIn!) } }));
    const text = await account!.text();
    expect(text).toContain("Welcome");
    expect(text).toContain('id="sign-out"');
  });

  test("rejects a wrong password and a forged or expired session", async () => {
    const wrong = await handle(post("/api/login", { identifier: env.FIXTURE_LOGIN_IDENTIFIER, password: "nope" }));
    expect(wrong!.headers.get("location")).toBe("/login?error=invalid");
    expect(wrong!.headers.get("set-cookie")).toBeNull();
    const forged = await handle(new Request(`${base}/account`, { headers: { cookie: "fixture_session=9999999999.forged" } }));
    expect(forged!.headers.get("location")).toBe("/login");
    const signedIn = await handle(post("/api/login", { identifier: env.FIXTURE_LOGIN_IDENTIFIER, password: env.FIXTURE_LOGIN_PASSWORD }));
    const expired = await handle(new Request(`${base}/account`, { headers: { cookie: sessionCookie(signedIn!) } }), env, Date.now() + 3_600_000);
    expect(expired!.headers.get("location")).toBe("/login");
  });

  test("sign-out clears the cookie", async () => {
    const out = await handle(post("/api/logout", {}));
    expect(out!.headers.get("location")).toBe("/login");
    expect(out!.headers.get("set-cookie")).toContain("Max-Age=0");
  });

  test("the controlled failure switch is off by default and makes login unavailable when on", async () => {
    expect((await handle(new Request(`${base}/login`)))!.status).toBe(200);
    const failing = { ...env, FIXTURE_ENABLE_CONTROLLED_FAILURE: "true" };
    expect((await handle(new Request(`${base}/login`), failing))!.status).toBe(503);
    expect((await handle(post("/api/login", {}), failing))!.status).toBe(503);
  });
});
