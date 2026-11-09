import { handleLoginFixtureRequest } from "../../lib/login-fixture";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  return (await handleLoginFixtureRequest(request, process.env)) ?? new Response("Not found", { status: 404 });
}
