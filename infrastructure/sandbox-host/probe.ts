// Controlled, credential-free guest probe. The trusted adapter invokes one
// fixed mode with /usr/bin/timeout and bounded stdout/stderr collection.
// Never run this on the management host outside its pinned sandbox image.
import { readdir, stat, unlink } from "node:fs/promises";
import { createConnection } from "node:net";

export const NETWORK_TARGETS = Object.freeze(
  [
    { name: "privateDenied", host: "10.0.0.1", port: 9 },
    { name: "metadataDenied", host: "169.254.169.254", port: 80 },
    // Documentation addresses avoid involving an unrelated public service.
    { name: "ipv4EgressDenied", host: "192.0.2.1", port: 9 },
    { name: "ipv6EgressDenied", host: "2001:db8::1", port: 9 },
  ].map((target) => Object.freeze(target)),
);

export type ConnectionOutcome = "denied" | "reachable" | "inconclusive";

export const OUTPUT_FLOOD_BYTES_PER_STREAM = 1_100_000;
const OUTPUT_FLOOD_CHUNK_BYTES = 16 * 1024;
const OUTPUT_FLOOD_CHUNK = new Uint8Array(OUTPUT_FLOOD_CHUNK_BYTES).fill(0x78);

export type OutputFloodMode = "stdout-flood" | "stderr-flood" | "mixed-flood";
export type ProbeOutputStream = "stdout" | "stderr";

/** Generate bounded, deterministic output while retaining only one fixed chunk. */
export async function emitOutputFlood(
  mode: OutputFloodMode,
  write: (stream: ProbeOutputStream, chunk: Uint8Array) => Promise<void>,
): Promise<{ stdoutBytes: number; stderrBytes: number }> {
  const targets =
    mode === "stdout-flood"
      ? { stdout: OUTPUT_FLOOD_BYTES_PER_STREAM, stderr: 0 }
      : mode === "stderr-flood"
        ? { stdout: 0, stderr: OUTPUT_FLOOD_BYTES_PER_STREAM }
        : { stdout: 600_000, stderr: 600_000 };
  const emitted = { stdoutBytes: 0, stderrBytes: 0 };

  const remaining = { ...targets };
  while (remaining.stdout > 0 || remaining.stderr > 0) {
    for (const stream of ["stdout", "stderr"] as const) {
      if (remaining[stream] === 0) continue;
      const chunk = OUTPUT_FLOOD_CHUNK.subarray(
        0,
        Math.min(remaining[stream], OUTPUT_FLOOD_CHUNK_BYTES),
      );
      await write(stream, chunk);
      emitted[`${stream}Bytes`] += chunk.byteLength;
      remaining[stream] -= chunk.byteLength;
    }
  }

  return emitted;
}

/** A timeout, DNS failure or closed endpoint does not prove isolation. */
export function connectionOutcome(code: unknown): ConnectionOutcome {
  return ["ENETUNREACH", "EHOSTUNREACH", "EACCES", "EPERM"].includes(
    typeof code === "string" ? code : "",
  )
    ? "denied"
    : "inconclusive";
}

export async function readOnlyRootProbe(
  write: () => Promise<void>,
): Promise<Record<string, boolean | string>> {
  try {
    await write();
    return { rootReadOnly: false, rootWriteOutcome: "writable" };
  } catch (error) {
    const readOnly = (error as NodeJS.ErrnoException | null)?.code === "EROFS";
    return {
      rootReadOnly: readOnly,
      rootWriteOutcome: readOnly ? "read-only" : "inconclusive",
    };
  }
}

function connect(
  target: (typeof NETWORK_TARGETS)[number],
): Promise<ConnectionOutcome> {
  return new Promise((resolve) => {
    let settled = false;
    const socket = createConnection({ host: target.host, port: target.port });
    const finish = (outcome: ConnectionOutcome) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolve(outcome);
    };
    const timer = setTimeout(() => finish("inconclusive"), 1500);
    socket.once("connect", () => finish("reachable"));
    socket.once("error", (error: NodeJS.ErrnoException) =>
      finish(connectionOutcome(error.code)),
    );
    socket.once("close", () => finish("inconclusive"));
  });
}

/** Injected dependencies let CI test verdicts without opening any socket. */
export async function networkProbe(dependencies: {
  interfaces(): Promise<string[]>;
  connect(target: (typeof NETWORK_TARGETS)[number]): Promise<ConnectionOutcome>;
}): Promise<Record<string, boolean | string>> {
  const interfaces = await dependencies.interfaces();
  const result: Record<string, boolean | string> = {
    onlyLoopback: interfaces.length === 1 && interfaces[0] === "lo",
  };
  for (const target of NETWORK_TARGETS) {
    const outcome = await dependencies.connect(target);
    result[target.name] = outcome === "denied";
    result[`${target.name}Outcome`] = outcome;
  }
  return result;
}

async function main(): Promise<void> {
  const mode = Bun.argv[2];
  // No default execution, and refuse an ordinary root/operator environment.
  // This is an accidental-invocation guard, not an attestation of isolation.
  if (
    Bun.argv.length !== 3 ||
    typeof mode !== "string" ||
    ![
      "smoke",
      "filesystem",
      "network",
      "environment",
      "output-cap",
      "stdout-flood",
      "stderr-flood",
      "mixed-flood",
    ].includes(mode ?? "") ||
    process.platform !== "linux" ||
    process.getuid?.() !== 10001 ||
    process.getgid?.() !== 10001 ||
    process.cwd() !== "/workspace" ||
    Object.keys(process.env).sort().join(",") !== "HOME,PATH,TMPDIR" ||
    process.env.HOME !== "/workspace" ||
    process.env.PATH !== "/usr/local/bin:/usr/bin:/bin" ||
    process.env.TMPDIR !== "/tmp"
  )
    throw new Error("SANDBOX_PROBE_INVOCATION_DENIED");
  if (!(await stat("/workspace")).isDirectory())
    throw new Error("SANDBOX_PROBE_INVOCATION_DENIED");
  const result: Record<string, boolean | string> = { mode };

  if (mode === "smoke") {
    result.runtime = typeof Bun.version === "string";
    result.workspace = await stat("/workspace")
      .then((entry) => entry.isDirectory())
      .catch(() => false);
    result.nonRoot = process.getuid?.() === 10001;
  } else if (mode === "filesystem") {
    const marker = `/workspace/probe-${process.pid}`;
    await Bun.write(marker, "ok");
    result.tmpfsWritable = (await Bun.file(marker).text()) === "ok";
    await unlink(marker);
    // This directory is guest-owned in the fixture image. EACCES on /etc
    // would merely prove Unix permissions, not a read-only root mount.
    const rootMarker = "/opt/z11-fixture-writable/root-write-probe";
    Object.assign(
      result,
      await readOnlyRootProbe(async () => {
        await Bun.write(rootMarker, "x");
      }),
    );
    if (result.rootWriteOutcome === "writable") await unlink(rootMarker);
  } else if (mode === "network") {
    Object.assign(
      result,
      await networkProbe({
        interfaces: () => readdir("/sys/class/net"),
        connect,
      }),
    );
  } else if (mode === "environment") {
    result.onlyApprovedEnvironment =
      Object.keys(process.env).sort().join(",") === "HOME,PATH,TMPDIR" &&
      process.env.HOME === "/workspace" &&
      process.env.PATH === "/usr/local/bin:/usr/bin:/bin" &&
      process.env.TMPDIR === "/tmp";
  } else if (
    mode === "output-cap" ||
    mode === "stdout-flood" ||
    mode === "stderr-flood" ||
    mode === "mixed-flood"
  ) {
    // The host collector owns the measured/truncated byte counts. The guest
    // emits a fixed payload and never logs or persists the payload itself.
    const floodMode: OutputFloodMode =
      mode === "output-cap" ? "stdout-flood" : mode;
    await emitOutputFlood(
      floodMode,
      (stream, chunk) =>
        new Promise<void>((resolve, reject) => {
          const output = stream === "stdout" ? process.stdout : process.stderr;
          output.write(chunk, (error) => (error ? reject(error) : resolve()));
        }),
    );
    return;
  } else {
    process.exit(2);
  }

  if (Object.values(result).some((value) => value === false))
    throw new Error("SANDBOX_PROBE_FAILED");
  console.log(JSON.stringify(result));
}

// Imports are safe for verdict tests: they never execute a guest probe.
if (import.meta.main) {
  main().catch(() => {
    process.stderr.write("SANDBOX_PROBE_FAILED\n");
    process.exitCode = 1;
  });
}
