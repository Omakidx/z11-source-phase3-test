import { handleUploadFixtureRequest } from "../../lib/upload-fixture";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  return (await handleUploadFixtureRequest(request)) ?? new Response("Not found", { status: 404 });
}
