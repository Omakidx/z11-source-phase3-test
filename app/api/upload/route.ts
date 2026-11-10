import { handleUploadFixtureRequest } from "../../../lib/upload-fixture";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  return (await handleUploadFixtureRequest(request)) ?? new Response("Not found", { status: 404 });
}
