import { averageScore, REPRO_INPUT } from "../../../client/lib/z11-repro/score";

export const dynamic = "force-dynamic";

export function GET(): Response {
  const result = averageScore(REPRO_INPUT);
  if (!Number.isFinite(result)) {
    return new Response("z11-repro: invalid score\n", {
      status: 500,
      headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
    });
  }
  return new Response("ok\n", {
    status: 200,
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
  });
}
