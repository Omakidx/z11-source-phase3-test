import { readFaultMode } from "../../../lib/z11-p18-fault";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET() {
  const { mode, raw } = await readFaultMode();
  const headers = { "cache-control": "no-store", "x-z11-fault-mode": raw };

  if (mode === "outage") {
    return Response.json(
      { ok: false, dependency: "fixture-payments" },
      { status: 503, headers },
    );
  }
  return Response.json({ ok: true }, { headers });
}
