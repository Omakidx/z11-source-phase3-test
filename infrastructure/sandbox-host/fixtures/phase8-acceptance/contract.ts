/** Test tooling only. This module neither authorizes nor launches a job. */
import { createHash } from "node:crypto";
import { createSandboxJobOutputDecoder } from "../../../../packages/sandbox/src/job/protocol";
import type { SandboxJobV1 } from "../../../../packages/sandbox/src/job/types";
import type { SandboxCustomerExecutionResult } from "../../../../packages/sandbox/src/runtime/types";

export const MODES = [
  "boundary",
  "network",
  "write-marker",
  "fresh-marker",
  "cpu",
  "memory",
  "pids",
  "fds",
  "tmpfs",
  "inodes",
  "stdout-flood",
  "stderr-flood",
  "mixed-flood",
  "timeout",
  "cancel",
  "peer",
  "normal-error",
] as const;
export type Mode = (typeof MODES)[number];
export const LIMITS = Object.freeze({
  cpuMilliCores: 100,
  memoryMiB: 128,
  pids: 16,
  diskMiB: 64,
  wallTimeMs: 10_000,
  outputBytes: 4096,
});
export const BOUNDS = Object.freeze({
  cpuIterations: 100_000_000,
  cpuMs: 2000,
  memoryMiB: 192,
  childAttempts: 24,
  childMs: 2000,
  fdAttempts: 1100,
  tmpfsMiB: 16,
  inodeAttempts: 256,
  waitMs: 10_000,
  networkTargets: 6,
  connectMs: 500,
  readBytes: 65_536,
});
export const GUEST_PATH =
  "infrastructure/sandbox-host/fixtures/phase8-acceptance/guest.ts";
export const TARGETS = Object.freeze([
  { name: "private4", host: "10.0.0.1", port: 9 },
  { name: "metadata4", host: "169.254.169.254", port: 80 },
  { name: "egress4", host: "192.0.2.1", port: 9 },
  { name: "private6", host: "fd00::1", port: 9 },
  { name: "metadata6", host: "fd00:ec2::254", port: 80 },
  { name: "egress6", host: "2001:db8::1", port: 9 },
]);

export function mode(value: string): Mode {
  if (!(MODES as readonly string[]).includes(value))
    throw new Error("CASE_INVALID");
  return value as Mode;
}

export function parameters(token: string, hostCanaryPid: number) {
  if (
    !/^[0-9a-f]{32}$/.test(token) ||
    !Number.isSafeInteger(hostCanaryPid) ||
    hostCanaryPid < 2 ||
    hostCanaryPid > 2 ** 31 - 1
  )
    throw new Error("CASE_IDENTITY_REQUIRED");
  return {
    token,
    hostCanaryPid,
    hostCanary: `/var/lib/z11-acceptance/canary-${token}`,
    processTag: `z11${token.slice(0, 12)}`,
    marker: `/workspace/acceptance-${token}`,
  };
}

/** Unsigned fields only. Root must supply real source, audience, scope and admission. */
export function jobFields(name: string, token: string, hostCanaryPid: number) {
  const selected = mode(name);
  parameters(token, hostCanaryPid);
  return {
    command: {
      argv: ["bun", GUEST_PATH, selected, token, String(hostCanaryPid)],
      cwd: ".",
    },
    limits: {
      ...LIMITS,
      wallTimeMs:
        selected === "timeout" || selected === "cancel"
          ? 3000
          : LIMITS.wallTimeMs,
    },
    network: "none" as const,
  };
}

export function invocation(argv: readonly string[]) {
  if (argv.length !== 5 || !/^[1-9][0-9]{0,9}$/.test(argv[4]!))
    throw new Error("GUEST_ONLY");
  const selected = mode(argv[2]!);
  const p = parameters(argv[3]!, Number(argv[4]));
  return { selected, ...p };
}

/** Accidental host-invocation guard; never a native isolation attestation. */
export function checkContext(context: {
  platform: string;
  uid: number | undefined;
  gid: number | undefined;
  cwd: string;
  environment: Record<string, string | undefined>;
}) {
  const expected = {
    PATH: "/usr/bin:/bin",
    HOME: "/nonexistent",
    XDG_CONFIG_HOME: "/nonexistent",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_SYSTEM: "/dev/null",
    GIT_TERMINAL_PROMPT: "0",
    GIT_LFS_SKIP_SMUDGE: "1",
    GIT_OPTIONAL_LOCKS: "0",
    GIT_ALLOW_PROTOCOL: "file",
    GIT_PROTOCOL_FROM_USER: "0",
    LC_ALL: "C",
    TZ: "UTC",
  };
  if (
    context.platform !== "linux" ||
    context.uid !== 10001 ||
    context.gid !== 10001 ||
    context.cwd !== "/workspace/repo" ||
    Object.keys(context.environment).sort().join() !==
      Object.keys(expected).sort().join() ||
    Object.entries(expected).some(
      ([key, value]) => context.environment[key] !== value,
    )
  )
    throw new Error("GUEST_ONLY");
}

/** Parse retained bytes using the existing production Z11O decoder, not a new protocol. */
export function outputSummary(
  job: SandboxJobV1,
  sandboxId: string,
  wire: Uint8Array,
) {
  const decoder = createSandboxJobOutputDecoder(job, sandboxId);
  decoder.push(wire);
  const value = decoder.finish();
  return {
    terminal: value.terminal,
    publishable: value.publishable,
    stdoutBytes: value.logs.stdoutBytes,
    stderrBytes: value.logs.stderrBytes,
    stdoutTruncated: value.logs.stdoutTruncated,
    stderrTruncated: value.logs.stderrTruncated,
    stdoutSha256: createHash("sha256").update(value.logs.stdout).digest("hex"),
    stderrSha256: createHash("sha256").update(value.logs.stderr).digest("hex"),
  };
}

/** Cleanup is independently host-authored; a guest terminal is insufficient. */
export function checkCleanup(
  job: SandboxJobV1,
  sandboxId: string,
  jobSha256: string,
  report: SandboxCustomerExecutionResult["report"],
) {
  const receipt = report.cleanup;
  const sameScope = (scope: SandboxJobV1["scope"] | undefined) =>
    scope &&
    Object.keys(job.scope).every(
      (key) =>
        scope[key as keyof typeof scope] ===
        job.scope[key as keyof typeof job.scope],
    );
  if (
    report.sourceMode !== "customer_bundle" ||
    report.jobId !== job.jobId ||
    report.jobSha256 !== jobSha256 ||
    report.hostId !== job.hostId ||
    report.sandboxId !== sandboxId ||
    !sameScope(report.scope) ||
    !/^[0-9a-f]{64}$/.test(report.containerId) ||
    report.runtime === "cleanup_unconfirmed" ||
    !receipt ||
    receipt.status !== "confirmed" ||
    receipt.jobId !== job.jobId ||
    receipt.jobSha256 !== jobSha256 ||
    receipt.hostId !== job.hostId ||
    receipt.sandboxId !== sandboxId ||
    receipt.containerId !== report.containerId ||
    !sameScope(receipt.scope) ||
    receipt.ownershipChecked !== true ||
    receipt.removalConfirmed !== true ||
    receipt.absenceConfirmed !== true
  )
    throw new Error("HOST_CLEANUP_UNPROVEN");
  return { cleanup: "confirmed" as const, nativeIsolationAccepted: false };
}
