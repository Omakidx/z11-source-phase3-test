import { createHash } from "node:crypto";

import { verifySandboxJobV1 } from "./grant";
import type { SandboxJobEnvelopeV1, SandboxJobV1 } from "./types";

type Code =
  | "INVALID_SANDBOX_JOB_INPUT"
  | "INVALID_SANDBOX_JOB_OUTPUT"
  | "INCOMPLETE_SANDBOX_JOB_OUTPUT";

/** Fixed errors never echo guest bytes, source contents, or signed claims. */
export class SandboxJobProtocolError extends Error {
  readonly name = "SandboxJobProtocolError";
  constructor(readonly code: Code) {
    super(code);
  }
}

function fail(code: Code): never {
  throw new SandboxJobProtocolError(code);
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const BASENAME = /^[A-Za-z0-9._-]+$/;
const CHUNK = 65_536;
const OUTPUT_WIRE_MAX = 6 * 1024 * 1024;
const OUTPUT_FRAME_MAX = 256;
const INPUT_FRAME_MAX = 258;
const SOURCE_MAX = 16 * 1024 * 1024;
const MAX_ARTIFACT_BYTES = 1024 * 1024;
const MAX_TOTAL_ARTIFACT_BYTES = 4 * MAX_ARTIFACT_BYTES;
const typedArrayByteLength = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  "byteLength",
)!.get!;
const typedArrayBuffer = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  "buffer",
)!.get!;
const typedArrayByteOffset = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  "byteOffset",
)!.get!;
const utf8 = new TextEncoder();
const strictUtf8 = new TextDecoder("utf-8", { fatal: true });

type Data = Record<string, unknown>;

function data(value: unknown, keys: readonly string[], code: Code): Data {
  try {
    if (value === null || typeof value !== "object" || Array.isArray(value))
      return fail(code);
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) return fail(code);
    const output: Data = Object.create(null) as Data;
    const allowed = new Set(keys);
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== "string" || !allowed.has(key)) return fail(code);
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !("value" in descriptor)) return fail(code);
      output[key] = descriptor.value;
    }
    for (const key of keys) if (!Object.hasOwn(output, key)) return fail(code);
    return output;
  } catch {
    return fail(code);
  }
}

function array(value: unknown, maximum: number, code: Code): unknown[] {
  try {
    if (
      !Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Array.prototype
    )
      return fail(code);
    const length = Object.getOwnPropertyDescriptor(value, "length")?.value;
    if (!Number.isSafeInteger(length) || length > maximum) return fail(code);
    const output: unknown[] = [];
    for (const key of Reflect.ownKeys(value)) {
      if (key === "length") continue;
      if (
        typeof key !== "string" ||
        !/^(0|[1-9][0-9]*)$/.test(key) ||
        Number(key) >= length
      )
        return fail(code);
    }
    for (let index = 0; index < length; index++) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !("value" in descriptor)) return fail(code);
      output.push(descriptor.value);
    }
    return output;
  } catch {
    return fail(code);
  }
}

function bytesLength(value: unknown, code: Code): number {
  try {
    if (!(value instanceof Uint8Array)) return fail(code);
    return typedArrayByteLength.call(value) as number;
  } catch {
    return fail(code);
  }
}

function flatPaths(job: SandboxJobV1, code: Code): readonly string[] {
  try {
    const artifacts = data(
      job.artifacts,
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
    if (
      !Number.isSafeInteger(artifacts.maxFiles) ||
      (artifacts.maxFiles as number) < 0 ||
      (artifacts.maxFiles as number) > 32 ||
      !Number.isSafeInteger(artifacts.maxFileBytes) ||
      (artifacts.maxFileBytes as number) < 1 ||
      (artifacts.maxFileBytes as number) > MAX_ARTIFACT_BYTES ||
      !Number.isSafeInteger(artifacts.maxTotalBytes) ||
      (artifacts.maxTotalBytes as number) < 1 ||
      (artifacts.maxTotalBytes as number) > MAX_TOTAL_ARTIFACT_BYTES
    )
      return fail(code);
    const values = array(artifacts.paths, artifacts.maxFiles as number, code);
    const paths: string[] = [];
    for (const value of values) {
      if (
        typeof value !== "string" ||
        value.length > 256 ||
        !BASENAME.test(value) ||
        value === "." ||
        value === ".." ||
        value.toLowerCase() === ".git"
      )
        return fail(code);
      paths.push(value);
    }
    if (new Set(paths.map((path) => path.toLowerCase())).size !== paths.length)
      return fail(code);
    return Object.freeze(paths);
  } catch {
    return fail(code);
  }
}

function frame(
  target: Uint8Array,
  offset: number,
  type: number,
  payload: Uint8Array,
): number {
  const view = new DataView(target.buffer, target.byteOffset + offset, 8);
  view.setUint8(0, type);
  view.setUint8(1, 0);
  view.setUint16(2, 0, false);
  view.setUint32(4, payload.byteLength, false);
  target.set(payload, offset + 8);
  return offset + 8 + payload.byteLength;
}

/**
 * Verify the signed grant and source before creating host-to-guest bytes.
 * Authorization, pinned image/policy approval and durable nonce admission are
 * separate control-plane gates. The deadline must also narrow the host runtime
 * deadline, which this pure encoder cannot observe.
 */
export async function encodeSandboxJobInput(
  input: Readonly<{
    envelope: unknown;
    sandboxId: string;
    deadlineMs: number;
    sourceBytes: Uint8Array;
  }>,
  publicKey: CryptoKey,
  options: Readonly<{ nowMs: number; hostId: string }>,
): Promise<Uint8Array> {
  const candidate = data(
    input,
    ["envelope", "sandboxId", "deadlineMs", "sourceBytes"],
    "INVALID_SANDBOX_JOB_INPUT",
  );
  const envelope = data(
    candidate.envelope,
    ["job", "signature"],
    "INVALID_SANDBOX_JOB_INPUT",
  );
  if (
    typeof envelope.signature !== "string" ||
    typeof candidate.sandboxId !== "string" ||
    !UUID.test(candidate.sandboxId) ||
    !Number.isSafeInteger(candidate.deadlineMs)
  )
    return fail("INVALID_SANDBOX_JOB_INPUT");
  let job: SandboxJobV1;
  try {
    job = await verifySandboxJobV1(envelope, publicKey, options);
  } catch {
    return fail("INVALID_SANDBOX_JOB_INPUT");
  }
  flatPaths(job, "INVALID_SANDBOX_JOB_INPUT");
  let nowMs: number;
  try {
    nowMs = options.nowMs;
  } catch {
    return fail("INVALID_SANDBOX_JOB_INPUT");
  }
  if (
    (candidate.deadlineMs as number) <= nowMs ||
    (candidate.deadlineMs as number) > Date.parse(job.expiresAt)
  )
    return fail("INVALID_SANDBOX_JOB_INPUT");
  const byteLength = bytesLength(
    candidate.sourceBytes,
    "INVALID_SANDBOX_JOB_INPUT",
  );
  if (byteLength !== job.source.byteLength || byteLength > SOURCE_MAX)
    return fail("INVALID_SANDBOX_JOB_INPUT");
  let source: Uint8Array;
  try {
    source = new Uint8Array(byteLength);
    Uint8Array.prototype.set.call(source, candidate.sourceBytes as Uint8Array);
  } catch {
    return fail("INVALID_SANDBOX_JOB_INPUT");
  }
  if (createHash("sha256").update(source).digest("hex") !== job.source.sha256)
    return fail("INVALID_SANDBOX_JOB_INPUT");
  const header = utf8.encode(
    JSON.stringify({
      envelope: {
        job,
        signature: envelope.signature,
      } satisfies SandboxJobEnvelopeV1,
      sandboxId: candidate.sandboxId,
      deadlineMs: candidate.deadlineMs,
    }),
  );
  if (header.byteLength > CHUNK) return fail("INVALID_SANDBOX_JOB_INPUT");
  const chunks = Math.ceil(byteLength / CHUNK);
  const frameCount = chunks + 2;
  if (frameCount > INPUT_FRAME_MAX) return fail("INVALID_SANDBOX_JOB_INPUT");
  const output = new Uint8Array(
    8 + 8 + header.byteLength + chunks * 8 + byteLength + 8,
  );
  output.set([0x5a, 0x31, 0x31, 0x49, 0, 1, 0, 0]);
  let offset = frame(output, 8, 0x01, header);
  for (let sourceOffset = 0; sourceOffset < byteLength; sourceOffset += CHUNK)
    offset = frame(
      output,
      offset,
      0x02,
      source.subarray(sourceOffset, sourceOffset + CHUNK),
    );
  frame(output, offset, 0x03, new Uint8Array(0));
  return output;
}

/** Parse only a flat bounded JSON object, rejecting duplicate decoded keys. */
function flatJson(payload: Uint8Array, keys: readonly string[]): Data {
  let source: string;
  try {
    source = strictUtf8.decode(payload);
  } catch {
    return fail("INVALID_SANDBOX_JOB_OUTPUT");
  }
  let index = 0;
  const skip = () => {
    while (/[\x20\t\r\n]/.test(source[index] ?? "")) index++;
  };
  const stringToken = (): string => {
    if (source[index] !== '"') return fail("INVALID_SANDBOX_JOB_OUTPUT");
    const start = index++;
    while (index < source.length) {
      if (source[index] === "\\") {
        index += 2;
        continue;
      }
      if (source[index++] === '"') {
        try {
          return JSON.parse(source.slice(start, index)) as string;
        } catch {
          return fail("INVALID_SANDBOX_JOB_OUTPUT");
        }
      }
    }
    return fail("INVALID_SANDBOX_JOB_OUTPUT");
  };
  skip();
  if (source[index++] !== "{") return fail("INVALID_SANDBOX_JOB_OUTPUT");
  const result: Data = Object.create(null) as Data;
  const allowed = new Set(keys);
  skip();
  if (source[index] !== "}") {
    while (true) {
      skip();
      const key = stringToken();
      if (!allowed.has(key) || Object.hasOwn(result, key))
        return fail("INVALID_SANDBOX_JOB_OUTPUT");
      skip();
      if (source[index++] !== ":") return fail("INVALID_SANDBOX_JOB_OUTPUT");
      skip();
      let value: unknown;
      if (source[index] === '"') value = stringToken();
      else {
        const match =
          /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(
            source.slice(index),
          );
        if (!match) return fail("INVALID_SANDBOX_JOB_OUTPUT");
        try {
          value = JSON.parse(match[0]) as unknown;
        } catch {
          return fail("INVALID_SANDBOX_JOB_OUTPUT");
        }
        index += match[0].length;
      }
      result[key] = value;
      skip();
      if (source[index] === "}") break;
      if (source[index++] !== ",") return fail("INVALID_SANDBOX_JOB_OUTPUT");
    }
  }
  index++;
  skip();
  if (index !== source.length || Object.keys(result).length !== keys.length)
    return fail("INVALID_SANDBOX_JOB_OUTPUT");
  return result;
}

function integer(value: unknown, minimum: number, maximum: number): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < minimum ||
    value > maximum
  )
    return fail("INVALID_SANDBOX_JOB_OUTPUT");
  return value;
}

export type SandboxJobOutputV1 = Readonly<{
  receipt: Readonly<{
    jobId: string;
    nonce: string;
    sandboxId: string;
    policySha256: string;
  }>;
  logs: Readonly<{
    stdout: Uint8Array;
    stderr: Uint8Array;
    stdoutBytes: number;
    stderrBytes: number;
    stdoutTruncated: boolean;
    stderrTruncated: boolean;
  }>;
  artifacts: readonly Readonly<{
    path: string;
    bytes: Uint8Array;
    sha256: string;
  }>[];
  terminal: Readonly<{
    jobId: string;
    status: "completed" | "failed" | "source_failed" | "artifact_failed";
    reportedCommandExitCode: number | null;
    artifactsComplete: boolean;
    peerStopObservation: "no_live_peers_observed" | "unconfirmed";
  }>;
  /** Structural precondition only; host cleanup must separately authorize publication. */
  publishable: boolean;
}>;

export type SandboxJobOutputDecoder = Readonly<{
  push(chunk: Uint8Array): void;
  finish(): SandboxJobOutputV1;
}>;

/** Trusted, already verified job is required; this decoder never grants guest authority. */
export function createSandboxJobOutputDecoder(
  job: SandboxJobV1,
  sandboxId: string,
): SandboxJobOutputDecoder {
  const code = "INVALID_SANDBOX_JOB_OUTPUT";
  let jobId: string, nonce: string, policySha256: string, outputLimit: number;
  let maxFiles: number, maxFileBytes: number, maxTotalBytes: number;
  try {
    jobId = job.jobId;
    nonce = job.nonce;
    policySha256 = job.policySha256;
    outputLimit = job.limits.outputBytes;
    maxFiles = job.artifacts.maxFiles;
    maxFileBytes = job.artifacts.maxFileBytes;
    maxTotalBytes = job.artifacts.maxTotalBytes;
  } catch {
    return fail(code);
  }
  if (
    typeof sandboxId !== "string" ||
    !UUID.test(sandboxId) ||
    typeof jobId !== "string" ||
    !UUID.test(jobId) ||
    typeof nonce !== "string" ||
    !UUID.test(nonce) ||
    typeof policySha256 !== "string" ||
    !SHA256.test(policySha256) ||
    !Number.isSafeInteger(outputLimit) ||
    outputLimit < 2 ||
    outputLimit > 1_048_576
  )
    return fail(code);
  const paths = flatPaths(job, code);
  const fixed = new Uint8Array(CHUNK);
  let pending = 0,
    required = 8,
    wireBytes = 0,
    frames = 0;
  let phase: "preamble" | "header" | "payload" | "done" = "preamble";
  let failed = false;
  let type = 0,
    payloadLength = 0;
  let stage:
    | "receipt"
    | "metadata"
    | "stdout"
    | "stderr"
    | "artifacts"
    | "artifactData"
    | "artifactDigest"
    | "terminal" = "receipt";
  let receipt: SandboxJobOutputV1["receipt"] | undefined;
  let metadata:
    Omit<SandboxJobOutputV1["logs"], "stdout" | "stderr"> | undefined;
  let stdout = new Uint8Array(0),
    stderr = new Uint8Array(0);
  let stdoutReceived = 0,
    stderrReceived = 0;
  let artifactTotal = 0,
    lastIndex = -1;
  const artifacts: { path: string; bytes: Uint8Array; sha256: string }[] = [];
  let active:
    | { index: number; size: number; bytes: Uint8Array; received: number }
    | undefined;
  let terminal: SandboxJobOutputV1["terminal"] | undefined;

  function expected(type: number, length: number): void {
    if (
      stage === "stdout" &&
      metadata &&
      stdoutReceived === metadata.stdoutBytes
    )
      stage = "stderr";
    if (
      stage === "stderr" &&
      metadata &&
      stderrReceived === metadata.stderrBytes
    )
      stage = "artifacts";
    if (stage === "artifactData" && active && active.received === active.size)
      stage = "artifactDigest";
    if (stage === "receipt") {
      if (type !== 0x10 || length > 1024) fail(code);
    } else if (stage === "metadata") {
      if (type !== 0x13 || length > 1024) fail(code);
    } else if (stage === "stdout") {
      if (
        type !== 0x11 ||
        !metadata ||
        length !== Math.min(CHUNK, metadata.stdoutBytes - stdoutReceived)
      )
        fail(code);
    } else if (stage === "stderr") {
      if (
        type !== 0x12 ||
        !metadata ||
        length !== Math.min(CHUNK, metadata.stderrBytes - stderrReceived)
      )
        fail(code);
    } else if (stage === "artifacts") {
      if ((type !== 0x20 || length !== 6) && (type !== 0x7f || length > 2048))
        fail(code);
      if (type === 0x7f) stage = "terminal";
    } else if (stage === "artifactData") {
      if (
        type !== 0x21 ||
        !active ||
        length !== Math.min(CHUNK, active.size - active.received)
      )
        fail(code);
    } else if (stage === "artifactDigest") {
      if (type !== 0x22 || length !== 32) fail(code);
    } else if (stage === "terminal") {
      if (type !== 0x7f || length > 2048) fail(code);
    } else fail(code);
  }

  function consume(type: number, payload: Uint8Array): void {
    if (type === 0x10) {
      const item = flatJson(payload, [
        "jobId",
        "nonce",
        "sandboxId",
        "policySha256",
      ]);
      if (
        item.jobId !== jobId ||
        item.nonce !== nonce ||
        item.sandboxId !== sandboxId ||
        item.policySha256 !== policySha256
      )
        fail(code);
      receipt = Object.freeze({ jobId, nonce, sandboxId, policySha256 });
      stage = "metadata";
    } else if (type === 0x13) {
      const item = flatJson(payload, [
        "stdoutBytes",
        "stderrBytes",
        "stdoutTruncated",
        "stderrTruncated",
      ]);
      const stdoutBytes = integer(item.stdoutBytes, 0, outputLimit);
      const stderrBytes = integer(
        item.stderrBytes,
        0,
        outputLimit - stdoutBytes,
      );
      if (
        typeof item.stdoutTruncated !== "boolean" ||
        typeof item.stderrTruncated !== "boolean"
      )
        fail(code);
      metadata = Object.freeze({
        stdoutBytes,
        stderrBytes,
        stdoutTruncated: item.stdoutTruncated,
        stderrTruncated: item.stderrTruncated,
      });
      stdout = new Uint8Array(stdoutBytes);
      stderr = new Uint8Array(stderrBytes);
      stage = "stdout";
    } else if (type === 0x11) {
      stdout.set(payload, stdoutReceived);
      stdoutReceived += payload.byteLength;
    } else if (type === 0x12) {
      stderr.set(payload, stderrReceived);
      stderrReceived += payload.byteLength;
    } else if (type === 0x20) {
      const view = new DataView(payload.buffer, payload.byteOffset, 6);
      const index = view.getUint16(0, false),
        size = view.getUint32(2, false);
      if (
        index <= lastIndex ||
        index >= paths.length ||
        artifacts.length >= maxFiles ||
        size > maxFileBytes ||
        artifactTotal + size > maxTotalBytes
      )
        fail(code);
      artifactTotal += size;
      lastIndex = index;
      active = { index, size, bytes: new Uint8Array(size), received: 0 };
      stage = size === 0 ? "artifactDigest" : "artifactData";
    } else if (type === 0x21) {
      if (!active) fail(code);
      active.bytes.set(payload, active.received);
      active.received += payload.byteLength;
    } else if (type === 0x22) {
      if (!active) fail(code);
      const digest = createHash("sha256").update(active.bytes).digest();
      if (!digest.equals(Buffer.from(payload))) fail(code);
      artifacts.push({
        path: paths[active.index]!,
        bytes: active.bytes,
        sha256: digest.toString("hex"),
      });
      active = undefined;
      stage = "artifacts";
    } else if (type === 0x7f) {
      const item = flatJson(payload, [
        "jobId",
        "status",
        "reportedCommandExitCode",
        "artifactsComplete",
        "peerStopObservation",
      ]);
      if (
        item.jobId !== jobId ||
        (item.status !== "completed" &&
          item.status !== "failed" &&
          item.status !== "source_failed" &&
          item.status !== "artifact_failed") ||
        (item.reportedCommandExitCode !== null &&
          (typeof item.reportedCommandExitCode !== "number" ||
            !Number.isSafeInteger(item.reportedCommandExitCode) ||
            item.reportedCommandExitCode < 0 ||
            item.reportedCommandExitCode > 255)) ||
        typeof item.artifactsComplete !== "boolean" ||
        (item.peerStopObservation !== "no_live_peers_observed" &&
          item.peerStopObservation !== "unconfirmed")
      )
        fail(code);
      if (item.artifactsComplete && artifacts.length !== paths.length)
        fail(code);
      terminal = Object.freeze({
        jobId,
        status: item.status,
        reportedCommandExitCode: item.reportedCommandExitCode,
        artifactsComplete: item.artifactsComplete,
        peerStopObservation: item.peerStopObservation,
      });
      stage = "terminal";
    }
  }

  function push(chunk: Uint8Array): void {
    try {
      if (failed) fail(code);
      const length = bytesLength(chunk, code);
      if (
        length > OUTPUT_WIRE_MAX - wireBytes ||
        (phase === "done" && length > 0)
      )
        fail(code);
      wireBytes += length;
      const buffer = typedArrayBuffer.call(chunk) as ArrayBufferLike;
      const byteOffset = typedArrayByteOffset.call(chunk) as number;
      let offset = 0;
      while (offset < length) {
        const count = Math.min(required - pending, length - offset);
        fixed.set(new Uint8Array(buffer, byteOffset + offset, count), pending);
        pending += count;
        offset += count;
        if (pending !== required) continue;
        if (phase === "preamble") {
          if (
            fixed[0] !== 0x5a ||
            fixed[1] !== 0x31 ||
            fixed[2] !== 0x31 ||
            fixed[3] !== 0x4f ||
            fixed[4] !== 0 ||
            fixed[5] !== 1 ||
            fixed[6] !== 0 ||
            fixed[7] !== 0
          )
            fail(code);
          phase = "header";
          required = 8;
        } else if (phase === "header") {
          const view = new DataView(fixed.buffer, 0, 8);
          type = view.getUint8(0);
          payloadLength = view.getUint32(4, false);
          if (
            view.getUint8(1) !== 0 ||
            view.getUint16(2, false) !== 0 ||
            payloadLength > CHUNK ||
            ++frames > OUTPUT_FRAME_MAX
          )
            fail(code);
          expected(type, payloadLength);
          phase = "payload";
          required = payloadLength;
          if (required === 0) {
            consume(type, fixed.subarray(0, 0));
            phase = type === 0x7f ? "done" : "header";
            required = 8;
          }
        } else if (phase === "payload") {
          consume(type, fixed.subarray(0, payloadLength));
          phase = type === 0x7f ? "done" : "header";
          required = 8;
        } else fail(code);
        pending = 0;
      }
    } catch (error) {
      failed = true;
      if (error instanceof SandboxJobProtocolError) throw error;
      return fail(code);
    }
  }

  function finish(): SandboxJobOutputV1 {
    if (
      failed ||
      phase !== "done" ||
      pending !== 0 ||
      !receipt ||
      !metadata ||
      !terminal
    ) {
      failed = true;
      return fail("INCOMPLETE_SANDBOX_JOB_OUTPUT");
    }
    const copiedArtifacts = artifacts.map((artifact) =>
      Object.freeze({
        path: artifact.path,
        bytes: artifact.bytes.slice(),
        sha256: artifact.sha256,
      }),
    );
    const publishable =
      terminal.status === "completed" &&
      terminal.artifactsComplete &&
      terminal.peerStopObservation === "no_live_peers_observed" &&
      copiedArtifacts.length === paths.length;
    return Object.freeze({
      receipt,
      logs: Object.freeze({
        ...metadata,
        stdout: stdout.slice(),
        stderr: stderr.slice(),
      }),
      artifacts: Object.freeze(copiedArtifacts),
      terminal,
      publishable,
    });
  }

  return Object.freeze({ push, finish });
}
