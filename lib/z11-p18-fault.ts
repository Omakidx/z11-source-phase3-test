export type FaultMode = "operational" | "outage" | "invalid" | "ratelimit";

export const DEFAULT_FAULT_RECORD = "_z11-p18-fault.p16.staging.z11.dev";
export const FAULT_CACHE_TTL_MS = 30_000;
export const FAULT_LOOKUP_TIMEOUT_MS = 3_000;

export interface FaultObservation {
  /** Effective mode used for behavior. Unknown values and failures fail safe to operational. */
  mode: FaultMode;
  /** Raw observed value for debugging: the TXT string, "absent", or "lookup-failed". */
  raw: string;
}

type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

interface DohAnswer {
  type?: number;
  data?: string;
}

interface DohBody {
  Status?: number;
  Answer?: DohAnswer[];
}

let cached: { observation: FaultObservation; expiresAt: number } | undefined;

export function resolveFaultRecordName(
  env: Record<string, string | undefined>,
): string {
  const value = env.Z11_P18_FAULT_RECORD?.trim();
  return value && /^[A-Za-z0-9._-]{1,253}$/.test(value)
    ? value
    : DEFAULT_FAULT_RECORD;
}

export function modeFromRaw(raw: string): FaultMode {
  switch (raw.trim().toLowerCase()) {
    case "outage":
      return "outage";
    case "invalid":
      return "invalid";
    case "ratelimit":
      return "ratelimit";
    default:
      return "operational";
  }
}

function stripTxtQuotes(data: string): string {
  // DoH TXT data is quoted; multi-string records appear as "a" "b".
  return data
    .split(/"\s+"/)
    .map((part) => part.replace(/^"|"$/g, ""))
    .join("")
    .trim();
}

export function parseDohResponse(body: unknown): FaultObservation {
  const doh = (body ?? {}) as DohBody;
  const txt = Array.isArray(doh.Answer)
    ? doh.Answer.find((a) => a?.type === 16 && typeof a.data === "string")
    : undefined;
  if (!txt?.data) {
    return { mode: "operational", raw: "absent" };
  }
  const raw = stripTxtQuotes(txt.data).slice(0, 64);
  return { mode: modeFromRaw(raw), raw: raw.replace(/[^\x20-\x7e]/g, "?") };
}

export async function readFaultMode(
  options: {
    env?: Record<string, string | undefined>;
    fetchImpl?: FetchLike;
    now?: number;
  } = {},
): Promise<FaultObservation> {
  const now = options.now ?? Date.now();
  if (cached && cached.expiresAt > now) {
    return cached.observation;
  }

  const name = resolveFaultRecordName(options.env ?? process.env);
  const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=TXT`;
  let observation: FaultObservation;
  try {
    const response = await (options.fetchImpl ?? fetch)(url, {
      headers: { accept: "application/dns-json" },
      signal: AbortSignal.timeout(FAULT_LOOKUP_TIMEOUT_MS),
      cache: "no-store",
    });
    observation = response.ok
      ? parseDohResponse(await response.json())
      : { mode: "operational", raw: "lookup-failed" };
  } catch {
    observation = { mode: "operational", raw: "lookup-failed" };
  }

  cached = { observation, expiresAt: now + FAULT_CACHE_TTL_MS };
  return observation;
}

export function resetFaultCacheForTests(): void {
  cached = undefined;
}
