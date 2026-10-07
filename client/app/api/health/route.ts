export const dynamic = "force-dynamic";

export function GET() {
  return Response.json(
    {
      status: "ok",
      fixture: "z11-source-phase3-test",
      buildMarker: process.env.VERCEL_GIT_COMMIT_SHA ?? "local-unset",
    },
    { headers: { "cache-control": "no-store" } },
  );
}
