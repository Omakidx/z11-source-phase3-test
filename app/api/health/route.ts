import { createHealthResponse, fixtureRuntimeLog } from "../../../lib/fixture-contract";

export const dynamic = "force-dynamic";

export function GET() {
  const response = createHealthResponse(process.env);
  console.info(fixtureRuntimeLog("health", response.buildMarker));

  return Response.json(response, {
    headers: { "cache-control": "no-store" },
  });
}
