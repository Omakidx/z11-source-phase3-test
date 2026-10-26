/** Foundation hard maxima; an isolated runtime must enforce accepted limits. */
export const SANDBOX_HARD_LIMITS = Object.freeze({
  cpuMilliCores: 2_000,
  memoryMiB: 2_048,
  pids: 128,
  diskMiB: 4_096,
  wallTimeMs: 300_000,
  outputBytes: 1_048_576,
});

const MIN_LIMITS = Object.freeze({
  cpuMilliCores: 50,
  memoryMiB: 32,
  pids: 1,
  diskMiB: 16,
  wallTimeMs: 1_000,
  outputBytes: 2,
});
const ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
const SHA = /^[0-9a-f]{40}$/;
const IMAGE = /^sha256:[0-9a-f]{64}$/;
const EXECUTABLE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const CWD_SEGMENT = /^[A-Za-z0-9._-]+$/;
const CONTROL = /[\u0000-\u001f\u007f]/u;

type ValidationCode =
  | "INVALID_SANDBOX_REQUEST"
  | "INVALID_SANDBOX_GRANT"
  | "INVALID_OUTPUT_LIMIT"
  | "INVALID_OUTPUT_CHUNK";

/** Deliberately never includes submitted values or credentials in its message. */
export class SandboxValidationError extends Error {
  readonly name = "SandboxValidationError";
  constructor(readonly code: ValidationCode) {
    super(code);
  }
}

function invalid(code: ValidationCode): never {
  throw new SandboxValidationError(code);
}

type Data = Record<string, unknown>;

/** Read array data descriptors without invoking caller-defined methods or iterators. */
function dataArray(
  value: unknown,
  minimum: number,
  maximum: number,
  code: ValidationCode,
): unknown[] {
  try {
    if (
      !Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Array.prototype
    )
      return invalid(code);
    const length = Object.getOwnPropertyDescriptor(value, "length")?.value;
    if (!Number.isSafeInteger(length) || length < minimum || length > maximum)
      return invalid(code);
    const result: unknown[] = [];
    for (const key of Reflect.ownKeys(value)) {
      if (key === "length") continue;
      if (
        typeof key !== "string" ||
        !/^(0|[1-9][0-9]*)$/.test(key) ||
        Number(key) >= length
      )
        return invalid(code);
    }
    for (let index = 0; index < length; index++) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !("value" in descriptor)) return invalid(code);
      result.push(descriptor.value);
    }
    return result;
  } catch {
    return invalid(code);
  }
}

/** Snapshot own data properties; reject prototypes, accessors and unknown fields. */
function data(
  value: unknown,
  required: readonly string[],
  optional: readonly string[],
  code: ValidationCode,
): Data {
  try {
    if (value === null || typeof value !== "object" || Array.isArray(value))
      return invalid(code);
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null)
      return invalid(code);
    const result: Data = Object.create(null) as Data;
    const allowed = new Set([...required, ...optional]);
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== "string" || !allowed.has(key)) return invalid(code);
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !("value" in descriptor)) return invalid(code);
      result[key] = descriptor.value;
    }
    for (const key of required)
      if (!Object.hasOwn(result, key)) return invalid(code);
    return result;
  } catch {
    return invalid(code);
  }
}

function id(value: unknown, code: ValidationCode): string {
  if (typeof value !== "string" || !ID.test(value)) return invalid(code);
  return value;
}

function scope(value: unknown, code: ValidationCode) {
  const input = data(
    value,
    ["organizationId", "applicationId", "environmentId"],
    [],
    code,
  );
  return {
    organizationId: id(input.organizationId, code),
    applicationId: id(input.applicationId, code),
    environmentId: id(input.environmentId, code),
  };
}

function repository(value: unknown, code: ValidationCode) {
  const input = data(value, ["repositoryId", "commitSha"], [], code);
  const commitSha = input.commitSha;
  if (typeof commitSha !== "string" || !SHA.test(commitSha))
    return invalid(code);
  return { repositoryId: id(input.repositoryId, code), commitSha };
}

export type SandboxLimits = Readonly<{
  cpuMilliCores: number;
  memoryMiB: number;
  pids: number;
  diskMiB: number;
  wallTimeMs: number;
  outputBytes: number;
}>;

function limits(value: unknown, code: ValidationCode): SandboxLimits {
  const keys = Object.keys(SANDBOX_HARD_LIMITS) as (keyof SandboxLimits)[];
  const input = data(value, keys, [], code);
  const result = {} as Record<keyof SandboxLimits, number>;
  for (const key of keys) {
    const candidate = input[key];
    if (
      typeof candidate !== "number" ||
      !Number.isSafeInteger(candidate) ||
      candidate < MIN_LIMITS[key] ||
      candidate > SANDBOX_HARD_LIMITS[key]
    )
      return invalid(code);
    result[key] = candidate;
  }
  return result;
}

function runtimeImage(
  value: unknown,
  code: ValidationCode,
): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || !IMAGE.test(value)) return invalid(code);
  return value;
}

function executable(value: unknown, code: ValidationCode): string {
  if (typeof value !== "string" || !EXECUTABLE.test(value))
    return invalid(code);
  return value;
}

function allowedExecutables(value: unknown, code: ValidationCode): string[] {
  const names = dataArray(value, 1, 32, code).map((item) =>
    executable(item, code),
  );
  if (new Set(names).size !== names.length) return invalid(code);
  return names;
}

function cwd(value: unknown, code: ValidationCode): string {
  if (value === ".") return ".";
  if (typeof value !== "string" || Buffer.byteLength(value, "utf8") > 256)
    return invalid(code);
  const segments = value.split("/");
  if (
    segments.length < 1 ||
    segments.length > 16 ||
    segments.some(
      (segment) =>
        !CWD_SEGMENT.test(segment) || segment === "." || segment === "..",
    )
  )
    return invalid(code);
  return value;
}

function command(value: unknown, code: ValidationCode) {
  const input = data(value, ["argv", "cwd"], [], code);
  const values = dataArray(input.argv, 1, 64, code);
  const argv: string[] = [];
  let bytes = 0;
  for (const item of values) {
    if (typeof item !== "string" || item.length === 0 || CONTROL.test(item))
      return invalid(code);
    const size = Buffer.byteLength(item, "utf8");
    bytes += size;
    if (size > 4_096 || bytes > 16_384) return invalid(code);
    argv.push(item);
  }
  executable(argv[0], code);
  return { argv, cwd: cwd(input.cwd, code) };
}

export type SandboxGrant = Readonly<{
  scope: Readonly<{
    organizationId: string;
    applicationId: string;
    environmentId: string;
  }>;
  repository: Readonly<{ repositoryId: string; commitSha: string }>;
  allowedExecutables: readonly string[];
  limits: SandboxLimits;
  network: "none";
  runtimeImage?: string;
}>;

export type SandboxRequest = Readonly<{
  scope: SandboxGrant["scope"];
  repository: SandboxGrant["repository"];
  command: Readonly<{ argv: readonly string[]; cwd: string }>;
  limits: SandboxLimits;
  network: "none";
  runtimeImage?: string;
}>;

export type CompiledSandboxRequest = SandboxRequest &
  Readonly<{ allowedExecutables: readonly string[] }>;

/**
 * Pure policy compilation. A trusted control plane must issue the grant and a
 * future isolated adapter must enforce the compiled limits before execution.
 */
export function compileSandboxRequest(
  input: unknown,
  grant: SandboxGrant,
): CompiledSandboxRequest {
  const trusted = data(
    grant,
    ["scope", "repository", "allowedExecutables", "limits", "network"],
    ["runtimeImage"],
    "INVALID_SANDBOX_GRANT",
  );
  const grantScope = scope(trusted.scope, "INVALID_SANDBOX_GRANT");
  const grantRepository = repository(
    trusted.repository,
    "INVALID_SANDBOX_GRANT",
  );
  const grantLimits = limits(trusted.limits, "INVALID_SANDBOX_GRANT");
  const grantExecutables = allowedExecutables(
    trusted.allowedExecutables,
    "INVALID_SANDBOX_GRANT",
  );
  if (trusted.network !== "none") return invalid("INVALID_SANDBOX_GRANT");
  const grantImage = runtimeImage(
    trusted.runtimeImage,
    "INVALID_SANDBOX_GRANT",
  );

  const candidate = data(
    input,
    ["scope", "repository", "command", "limits", "network"],
    ["runtimeImage"],
    "INVALID_SANDBOX_REQUEST",
  );
  const requestScope = scope(candidate.scope, "INVALID_SANDBOX_REQUEST");
  const requestRepository = repository(
    candidate.repository,
    "INVALID_SANDBOX_REQUEST",
  );
  const requestCommand = command(candidate.command, "INVALID_SANDBOX_REQUEST");
  const requestLimits = limits(candidate.limits, "INVALID_SANDBOX_REQUEST");
  const requestImage = runtimeImage(
    candidate.runtimeImage,
    "INVALID_SANDBOX_REQUEST",
  );
  if (
    candidate.network !== "none" ||
    requestScope.organizationId !== grantScope.organizationId ||
    requestScope.applicationId !== grantScope.applicationId ||
    requestScope.environmentId !== grantScope.environmentId ||
    requestRepository.repositoryId !== grantRepository.repositoryId ||
    requestRepository.commitSha !== grantRepository.commitSha ||
    !grantExecutables.includes(requestCommand.argv[0]!) ||
    (requestImage !== undefined && requestImage !== grantImage) ||
    (Object.keys(SANDBOX_HARD_LIMITS) as (keyof SandboxLimits)[]).some(
      (key) => requestLimits[key] > grantLimits[key],
    )
  )
    return invalid("INVALID_SANDBOX_REQUEST");

  return Object.freeze({
    scope: Object.freeze(requestScope),
    repository: Object.freeze(requestRepository),
    command: Object.freeze({
      argv: Object.freeze(requestCommand.argv),
      cwd: requestCommand.cwd,
    }),
    limits: Object.freeze(requestLimits),
    network: "none" as const,
    allowedExecutables: Object.freeze(grantExecutables),
    ...(grantImage === undefined ? {} : { runtimeImage: grantImage }),
  });
}
