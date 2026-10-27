/**
 * Guest-visible contract. Imports nothing from the repository on purpose: this file,
 * guest.ts and probe.ts are the whole customer-guest source closure, so the fixture
 * commit never has to carry job, policy or protocol code. Test tooling only.
 */
export const MODES = [
  "boundary",
  "network",
  "dns-rebinding",
  "http-redirect",
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
  rebindAttempts: 6,
  redirectHops: 3,
  resolveMs: 500,
  redirectServeMs: 1000,
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

/** DNS-rebinding plan: two lookups of one reserved name, then each address an attacker would rebind to. */
export const REBIND_CONNECTS = Object.freeze([
  { name: "reboundPrivate4", host: "10.0.0.1", port: 80 },
  { name: "reboundMetadata4", host: "169.254.169.254", port: 80 },
  { name: "reboundPrivate6", host: "fd00::1", port: 80 },
  { name: "reboundMetadata6", host: "fd00:ec2::254", port: 80 },
]);
/** Each redirect is issued by an in-guest loopback server; following it is a bare connect only. */
export const REDIRECT_CHAIN = Object.freeze([
  {
    name: "redirectMetadata4",
    location: "http://169.254.169.254/latest/meta-data/",
    host: "169.254.169.254",
    port: 80,
  },
  {
    name: "redirectPrivate4",
    location: "http://10.0.0.1/",
    host: "10.0.0.1",
    port: 80,
  },
  {
    name: "redirectMetadata6",
    location: "http://[fd00:ec2::254]/",
    host: "fd00:ec2::254",
    port: 80,
  },
]);

export function mode(value: string): Mode {
  if (!(MODES as readonly string[]).includes(value))
    throw new Error("CASE_INVALID");
  return value as Mode;
}

/**
 * Contract v2: every guest argv is fixed per mode, so each mode has exactly one policy
 * hash. Nothing per-run (token, host canary pid, nonce) is ever placed in argv; the guest
 * generates its own nonce and root keeps the token/pid as operation scope and positive-
 * control bookends only.
 */
export const HOST_CANARY_PATH = "/var/lib/z11-acceptance/canary";
/** Fixed process comm of the root-side canary process; at most 15 characters. */
export const PROCESS_TAG = "z11-accept-cnry";
export const MARKER_PATH = "/workspace/acceptance-marker";
export const MARKER_PREFIX = "acceptance-";
export const WORKSPACE_DIR = "/workspace";
export const PROC_DIR = "/proc";
/** Upper bounds for the guest /proc scan; exceeding either is inconclusive. */
export const PROC_ENTRY_CAP = 4096;
export const COMM_READ_BYTES = 64;
export const inodePath = (index: number) => `/tmp/acceptance-${index}`;

/** Guest-side argv check: exactly [runtime, script, mode]. Nothing per-run is accepted. */
export function invocation(argv: readonly string[]) {
  if (argv.length !== 3) throw new Error("GUEST_ONLY");
  return { selected: mode(argv[2]!) };
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
