import { createHash } from "node:crypto";

import { readFaultMode } from "../../../../lib/z11-p18-fault";
import { buildStatusSummary } from "../../../../lib/z11-p18-status";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(request: Request) {
  const { mode, raw } = await readFaultMode();
  const debug = { "x-z11-fault-mode": raw, "cache-control": "no-store" };

  if (mode === "invalid") {
    return new Response(
      "<html><body>internal error (fixture invalid mode)</body></html>",
      {
        status: 500,
        headers: { ...debug, "content-type": "text/html; charset=utf-8" },
      },
    );
  }
  if (mode === "ratelimit") {
    return new Response("rate limited", {
      status: 429,
      headers: {
        ...debug,
        "retry-after": "120",
        "content-type": "text/plain; charset=utf-8",
      },
    });
  }

  const body = JSON.stringify(
    buildStatusSummary(mode, new Date().toISOString()),
  );
  const etag = `"${createHash("sha256").update(body).digest("hex").slice(0, 32)}"`;
  if (request.headers.get("if-none-match") === etag) {
    return new Response(null, { status: 304, headers: { ...debug, etag } });
  }
  return new Response(body, {
    status: 200,
    headers: {
      ...debug,
      etag,
      "content-type": "application/json; charset=utf-8",
    },
  });
}
