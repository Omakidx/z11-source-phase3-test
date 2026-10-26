import { createHash, webcrypto } from "node:crypto";

import { SANDBOX_HARD_LIMITS, type SandboxLimits } from "../policy";
import type { SandboxJobEnvelopeV1, SandboxJobV1 } from "./types";

type Code =
  | "INVALID_SANDBOX_JOB"
  | "INVALID_SANDBOX_JOB_ENVELOPE"
  | "INVALID_SANDBOX_JOB_KEY"
  | "INVALID_SANDBOX_JOB_SIGNATURE"
  | "INVALID_SANDBOX_JOB_AUDIENCE"
  | "EXPIRED_SANDBOX_JOB"
  | "NOT_YET_VALID_SANDBOX_JOB";

/** Codes are stable; messages never echo a submitted value or key material. */
export class SandboxJobGrantError extends Error {
  readonly name = "SandboxJobGrantError";
  constructor(readonly code: Code) {
    super(code);
  }
}

function fail(code: Code): never {
  throw new SandboxJobGrantError(code);
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const IMAGE = /^sha256:[0-9a-f]{64}$/;
const COMMIT = /^[0-9a-f]{40}$/;
const GITHUB_ID = /^[1-9][0-9]{0,19}$/;
const OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/;
const REPO = /^[A-Za-z0-9_.-]{1,100}$/;
const EXECUTABLE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const SEGMENT = /^[A-Za-z0-9._-]+$/;
const CONTROL = /[\u0000-\u001f\u007f]/u;
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const MIN_LIMITS: SandboxLimits = {
  cpuMilliCores: 50,
  memoryMiB: 32,
  pids: 1,
  diskMiB: 16,
  wallTimeMs: 1_000,
  outputBytes: 2,
};
const MAX_TTL_MS = 15 * 60_000;
const MAX_ISSUED_SKEW_MS = 30_000;
const MAX_RETENTION_MS = 7 * 24 * 60 * 60_000;
const MAX_SOURCE_BYTES = 16 * 1024 * 1024;
const MAX_ARTIFACT_BYTES = 1024 * 1024;
const MAX_TOTAL_ARTIFACT_BYTES = 4 * MAX_ARTIFACT_BYTES;
/** Separates this signature from every other use of the same Ed25519 key. */
const SIGNATURE_DOMAIN = "z11.sandbox-job.v1\0";

type Data = Record<string, unknown>;

/** Snapshot data descriptors without invoking getters or array iterators. */
function data(value: unknown, keys: readonly string[], code: Code): Data {
  try {
    if (value === null || typeof value !== "object" || Array.isArray(value))
      return fail(code);
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) return fail(code);
    const result: Data = Object.create(null) as Data;
    const allowed = new Set(keys);
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== "string" || !allowed.has(key)) return fail(code);
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !("value" in descriptor)) return fail(code);
      result[key] = descriptor.value;
    }
    for (const key of keys) if (!Object.hasOwn(result, key)) return fail(code);
    return result;
  } catch {
    return fail(code);
  }
}

function array(
  value: unknown,
  minimum: number,
  maximum: number,
  code: Code,
): unknown[] {
  try {
    if (
      !Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Array.prototype
    )
      return fail(code);
    const length = Object.getOwnPropertyDescriptor(value, "length")?.value;
    if (!Number.isSafeInteger(length) || length < minimum || length > maximum)
      return fail(code);
    const result: unknown[] = [];
    for (const key of Reflect.ownKeys(value)) {
      if (key === "length") continue;
      if (
        typeof key !== "string" ||
        !/^(0|[1-9][0-9]*)$/.test(key) ||
        Number(key) >= length
      )
        return fail(code);
    }
    for (let i = 0; i < length; i++) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(i));
      if (!descriptor || !("value" in descriptor)) return fail(code);
      result.push(descriptor.value);
    }
    return result;
  } catch {
    return fail(code);
  }
}

function text(value: unknown, pattern: RegExp, code: Code): string {
  if (typeof value !== "string" || !pattern.test(value)) return fail(code);
  return value;
}

function integer(
  value: unknown,
  minimum: number,
  maximum: number,
  code: Code,
): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < minimum ||
    value > maximum
  )
    return fail(code);
  return value;
}

function timestamp(value: unknown, code: Code): { text: string; ms: number } {
  if (typeof value !== "string" || !ISO.test(value)) return fail(code);
  const ms = Date.parse(value);
  if (!Number.isFinite(ms) || new Date(ms).toISOString() !== value)
    return fail(code);
  return { text: value, ms };
}

function path(
  value: unknown,
  allowRoot: boolean,
  forbidGit: boolean,
  code: Code,
): string {
  if (allowRoot && value === ".") return ".";
  if (typeof value !== "string" || Buffer.byteLength(value, "utf8") > 256)
    return fail(code);
  const segments = value.split("/");
  if (
    segments.length < 1 ||
    segments.length > 16 ||
    segments.some(
      (part) =>
        !SEGMENT.test(part) ||
        part === "." ||
        part === ".." ||
        (forbidGit && part.toLowerCase() === ".git"),
    )
  )
    return fail(code);
  return value;
}

function command(value: unknown, code: Code): SandboxJobV1["command"] {
  const input = data(value, ["argv", "cwd"], code);
  const values = array(input.argv, 1, 64, code);
  const argv: string[] = [];
  let total = 0;
  for (const value of values) {
    if (typeof value !== "string" || value.length === 0 || CONTROL.test(value))
      return fail(code);
    const size = Buffer.byteLength(value, "utf8");
    total += size;
    if (size > 4_096 || total > 16_384) return fail(code);
    argv.push(value);
  }
  text(argv[0], EXECUTABLE, code);
  return Object.freeze({
    argv: Object.freeze(argv),
    cwd: path(input.cwd, true, true, code),
  });
}

function limits(value: unknown, code: Code): SandboxLimits {
  const keys = Object.keys(SANDBOX_HARD_LIMITS) as (keyof SandboxLimits)[];
  const input = data(value, keys, code);
  const result = {} as Record<keyof SandboxLimits, number>;
  for (const key of keys)
    result[key] = integer(
      input[key],
      MIN_LIMITS[key],
      SANDBOX_HARD_LIMITS[key],
      code,
    );
  return Object.freeze(result);
}

function artifacts(
  value: unknown,
  expiresMs: number,
  code: Code,
): SandboxJobV1["artifacts"] {
  const input = data(
    value,
    [
      "paths",
      "maxFiles",
      "maxFileBytes",
      "maxTotalBytes",
      "maxCaptureMs",
      "retentionUntil",
    ],
    code,
  );
  const maxFiles = integer(input.maxFiles, 0, 32, code);
  const maxFileBytes = integer(input.maxFileBytes, 1, MAX_ARTIFACT_BYTES, code);
  const maxTotalBytes = integer(
    input.maxTotalBytes,
    1,
    MAX_TOTAL_ARTIFACT_BYTES,
    code,
  );
  const maxCaptureMs = integer(input.maxCaptureMs, 1, 5_000, code);
  const paths = array(input.paths, 0, maxFiles, code).map((item) =>
    path(item, false, true, code),
  );
  if (new Set(paths.map((item) => item.toLowerCase())).size !== paths.length)
    return fail(code);
  const retention = timestamp(input.retentionUntil, code);
  if (retention.ms < expiresMs || retention.ms - expiresMs > MAX_RETENTION_MS)
    return fail(code);
  return Object.freeze({
    paths: Object.freeze(paths),
    maxFiles,
    maxFileBytes,
    maxTotalBytes,
    maxCaptureMs,
    retentionUntil: retention.text,
  });
}

function job(value: unknown): SandboxJobV1 {
  const code = "INVALID_SANDBOX_JOB";
  const input = data(
    value,
    [
      "version",
      "jobId",
      "nonce",
      "hostId",
      "scope",
      "repository",
      "imageDigest",
      "command",
      "limits",
      "network",
      "source",
      "artifacts",
      "issuedAt",
      "expiresAt",
      "policySha256",
    ],
    code,
  );
  if (input.version !== 1 || input.network !== "none") return fail(code);
  const scope = data(
    input.scope,
    ["organizationId", "applicationId", "environmentId"],
    code,
  );
  const repository = data(
    input.repository,
    [
      "repositoryId",
      "sourceConnectionId",
      "sourceRevisionId",
      "provider",
      "providerRepositoryId",
      "fullName",
      "commitSha",
    ],
    code,
  );
  if (repository.provider !== "github") return fail(code);
  const fullName = text(repository.fullName, /^[^/]+\/[^/]+$/, code);
  const [owner, repo] = fullName.split("/");
  text(owner, OWNER, code);
  text(repo, REPO, code);
  const source = data(input.source, ["format", "sha256", "byteLength"], code);
  if (source.format !== "git-bundle-v2") return fail(code);
  const issued = timestamp(input.issuedAt, code);
  const expires = timestamp(input.expiresAt, code);
  if (expires.ms <= issued.ms || expires.ms - issued.ms > MAX_TTL_MS)
    return fail(code);
  return Object.freeze({
    version: 1,
    jobId: text(input.jobId, UUID, code),
    nonce: text(input.nonce, UUID, code),
    hostId: text(input.hostId, UUID, code),
    scope: Object.freeze({
      organizationId: text(scope.organizationId, UUID, code),
      applicationId: text(scope.applicationId, UUID, code),
      environmentId: text(scope.environmentId, UUID, code),
    }),
    repository: Object.freeze({
      repositoryId: text(repository.repositoryId, UUID, code),
      sourceConnectionId: text(repository.sourceConnectionId, UUID, code),
      sourceRevisionId: text(repository.sourceRevisionId, UUID, code),
      provider: "github",
      providerRepositoryId: text(
        repository.providerRepositoryId,
        GITHUB_ID,
        code,
      ),
      fullName,
      commitSha: text(repository.commitSha, COMMIT, code),
    }),
    imageDigest: text(input.imageDigest, IMAGE, code),
    command: command(input.command, code),
    limits: limits(input.limits, code),
    network: "none",
    source: Object.freeze({
      format: "git-bundle-v2",
      sha256: text(source.sha256, SHA256, code),
      byteLength: integer(source.byteLength, 1, MAX_SOURCE_BYTES, code),
    }),
    artifacts: artifacts(input.artifacts, expires.ms, code),
    issuedAt: issued.text,
    expiresAt: expires.text,
    policySha256: text(input.policySha256, SHA256, code),
  });
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object")
    return `{${Object.entries(value)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`)
      .join(",")}}`;
  return JSON.stringify(value);
}

function key(value: CryptoKey, operation: "sign" | "verify"): void {
  try {
    if (
      value === null ||
      typeof value !== "object" ||
      value.type !== (operation === "sign" ? "private" : "public") ||
      value.algorithm.name !== "Ed25519" ||
      !value.usages.includes(operation)
    )
      return fail("INVALID_SANDBOX_JOB_KEY");
  } catch {
    return fail("INVALID_SANDBOX_JOB_KEY");
  }
}

function signedBytes(value: SandboxJobV1): Uint8Array {
  return new TextEncoder().encode(SIGNATURE_DOMAIN + canonical(value));
}

/** Stable domain-separated identity for the exact validated signed claims. */
export function sandboxJobSha256(input: unknown): string {
  return createHash("sha256")
    .update(signedBytes(job(input)))
    .digest("hex");
}

/**
 * Signs validated, copied data only. Callers must authorize scope and source
 * first. The issuer must bind hostId to a trusted host record and its pinned
 * verification key; the host must durably admit each nonce at most once.
 */
export async function signSandboxJobV1(
  jobInput: unknown,
  privateKey: CryptoKey,
): Promise<SandboxJobEnvelopeV1> {
  const validated = job(jobInput);
  key(privateKey, "sign");
  let signature: ArrayBuffer;
  try {
    signature = await webcrypto.subtle.sign(
      "Ed25519",
      privateKey,
      signedBytes(validated),
    );
  } catch {
    return fail("INVALID_SANDBOX_JOB_KEY");
  }
  return Object.freeze({
    job: validated,
    signature: Buffer.from(signature).toString("base64url"),
  });
}

/** Cryptographic and audience verification; durable replay admission belongs to the host. */
export async function verifySandboxJobV1(
  envelopeInput: unknown,
  publicKey: CryptoKey,
  options: Readonly<{ nowMs: number; hostId: string }>,
): Promise<SandboxJobV1> {
  const envelope = data(
    envelopeInput,
    ["job", "signature"],
    "INVALID_SANDBOX_JOB_ENVELOPE",
  );
  const validated = job(envelope.job);
  const signature = envelope.signature;
  if (typeof signature !== "string" || !/^[A-Za-z0-9_-]{86}$/.test(signature))
    return fail("INVALID_SANDBOX_JOB_SIGNATURE");
  const decoded = Buffer.from(signature, "base64url");
  if (decoded.length !== 64 || decoded.toString("base64url") !== signature)
    return fail("INVALID_SANDBOX_JOB_SIGNATURE");
  key(publicKey, "verify");
  let valid: boolean;
  try {
    valid = await webcrypto.subtle.verify(
      "Ed25519",
      publicKey,
      decoded,
      signedBytes(validated),
    );
  } catch {
    return fail("INVALID_SANDBOX_JOB_KEY");
  }
  if (!valid) return fail("INVALID_SANDBOX_JOB_SIGNATURE");
  let nowMs: number;
  let hostId: unknown;
  try {
    nowMs = options.nowMs;
    hostId = options.hostId;
  } catch {
    return fail("INVALID_SANDBOX_JOB");
  }
  if (!Number.isSafeInteger(nowMs)) return fail("INVALID_SANDBOX_JOB");
  if (
    typeof hostId !== "string" ||
    !UUID.test(hostId) ||
    hostId !== validated.hostId
  )
    return fail("INVALID_SANDBOX_JOB_AUDIENCE");
  if (Date.parse(validated.issuedAt) > nowMs + MAX_ISSUED_SKEW_MS)
    return fail("NOT_YET_VALID_SANDBOX_JOB");
  if (nowMs >= Date.parse(validated.expiresAt))
    return fail("EXPIRED_SANDBOX_JOB");
  return validated;
}
