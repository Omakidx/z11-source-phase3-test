/** Future guest entrypoint only. Imports perform no probe actions. */
import { constants } from "node:fs";
import { lstat, open, unlink, writeFile } from "node:fs/promises";
import { createConnection } from "node:net";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { connectionOutcome, emitOutputFlood } from "../../probe";
import {
  BOUNDS,
  TARGETS,
  checkContext,
  invocation,
  mode,
  parameters,
  type Mode,
} from "./contract";

type Child = { stop(): void; closed: Promise<void> };
export type Ops = {
  exists(path: string): Promise<boolean>;
  read(path: string, cap: number): Promise<Uint8Array>;
  write(path: string, bytes: Uint8Array): Promise<void>;
  remove(path: string): Promise<void>;
  burn(iterations: number, milliseconds: number): number;
  allocateMiB(): Uint8Array;
  child(milliseconds: number, outliveCommand: boolean): Promise<Child>;
  openNull(): Promise<{ close(): Promise<void> }>;
  connect(host: string, port: number, milliseconds: number): Promise<string>;
  wait(milliseconds: number): Promise<void>;
  output(stream: "stdout" | "stderr", bytes: Uint8Array): Promise<void>;
};
const code = (error: unknown) => (error as { code?: string })?.code;
const text = (bytes: Uint8Array) =>
  new TextDecoder("utf-8", { fatal: true }).decode(bytes);
const expectedAbsent = async (ops: Ops, path: string) => {
  try {
    return !(await ops.exists(path));
  } catch {
    return "inconclusive";
  }
};

/** Injected operations permit offline tests without host reads, sockets or children. */
export async function runCase(
  selected: Mode,
  token: string,
  hostPid: number,
  ops: Ops,
) {
  mode(selected);
  const p = parameters(token, hostPid);
  const observed: Record<string, boolean | number | string> = {};
  let exitCode = 0;
  if (selected === "boundary") {
    observed.hostCanaryAbsent = await expectedAbsent(ops, p.hostCanary);
    for (const [name, path] of [
      ["dockerSocketAbsent", "/var/run/docker.sock"],
      ["containerdSocketAbsent", "/run/containerd/containerd.sock"],
      ["hostConfigAbsent", "/etc/z11-sandbox"],
    ])
      observed[name!] = await expectedAbsent(ops, path!);
    try {
      observed.hostProcessTagAbsent =
        text(await ops.read(`/proc/${hostPid}/comm`, 64)).trim() !==
        p.processTag;
    } catch (error) {
      observed.hostProcessTagAbsent =
        code(error) === "ENOENT" ? true : "inconclusive";
    }
    try {
      const mounts = text(
        await ops.read("/proc/self/mountinfo", BOUNDS.readBytes),
      );
      observed.hostCanaryMountAbsent =
        !mounts.includes("/var/lib/z11-acceptance") &&
        !mounts.includes("/etc/z11-sandbox") &&
        !mounts.includes("docker.sock");
      observed.mountInfoSha256 = createHash("sha256")
        .update(mounts)
        .digest("hex");
    } catch {
      observed.hostCanaryMountAbsent = "inconclusive";
    }
  } else if (selected === "network") {
    for (const target of TARGETS) {
      const result = await ops.connect(
        target.host,
        target.port,
        BOUNDS.connectMs,
      );
      observed[target.name] =
        result === "reachable" ? "reachable" : connectionOutcome(result);
    }
    // No secret, canary contents, DNS name, HTTP request or packet payload is sent.
  } else if (selected === "write-marker") {
    await ops.write(p.marker, new TextEncoder().encode(token));
    observed.markerWritten = text(await ops.read(p.marker, 64)) === token;
  } else if (selected === "fresh-marker") {
    observed.previousMarkerAbsent = await expectedAbsent(ops, p.marker);
  } else if (selected === "cpu") {
    observed.iterations = ops.burn(BOUNDS.cpuIterations, BOUNDS.cpuMs);
  } else if (selected === "memory") {
    const held: Uint8Array[] = [];
    for (let i = 0; i < BOUNDS.memoryMiB; i++) held.push(ops.allocateMiB());
    observed.allocatedMiB = held.length;
    // Survival is an observation, never proof that the memory cap worked.
  } else if (selected === "pids" || selected === "peer") {
    const children: Child[] = [];
    try {
      const count = selected === "peer" ? 1 : BOUNDS.childAttempts;
      for (let i = 0; i < count; i++) {
        try {
          children.push(await ops.child(BOUNDS.childMs, selected === "peer"));
        } catch (error) {
          observed.refusal =
            code(error) === "EAGAIN" ? "EAGAIN" : "inconclusive";
          break;
        }
      }
      observed.childrenStarted = children.length;
    } finally {
      if (selected !== "peer") {
        for (const child of children) child.stop();
        await Promise.all(children.map((child) => child.closed));
      }
      // peer intentionally outlives this command, with its own two-second cap.
    }
  } else if (selected === "fds") {
    const handles: Awaited<ReturnType<Ops["openNull"]>>[] = [];
    try {
      for (let i = 0; i < BOUNDS.fdAttempts; i++) {
        try {
          handles.push(await ops.openNull());
        } catch (error) {
          observed.refusal =
            code(error) === "EMFILE" ? "EMFILE" : "inconclusive";
          break;
        }
      }
      observed.opened = handles.length;
    } finally {
      await Promise.all(handles.map((handle) => handle.close()));
    }
  } else if (selected === "tmpfs" || selected === "inodes") {
    const paths: string[] = [];
    const count = selected === "tmpfs" ? BOUNDS.tmpfsMiB : BOUNDS.inodeAttempts;
    const chunk = new Uint8Array(selected === "tmpfs" ? 1_048_576 : 1).fill(
      0x61,
    );
    try {
      for (let i = 0; i < count; i++) {
        const path = `/tmp/acceptance-${token}-${i}`;
        paths.push(path); // Also remove a partially written ENOSPC leaf.
        try {
          await ops.write(path, chunk);
        } catch (error) {
          // O_EXCL found an older leaf: it was never ours to remove.
          if (code(error) === "EEXIST") paths.pop();
          observed.refusal =
            code(error) === "ENOSPC" ? "ENOSPC" : "inconclusive";
          break;
        }
      }
      observed.attemptedFiles = paths.length;
    } finally {
      for (const path of paths) await ops.remove(path);
    }
  } else if (selected.endsWith("-flood")) {
    await emitOutputFlood(
      selected as "stdout-flood" | "stderr-flood" | "mixed-flood",
      ops.output,
    );
    return { exitCode: 0, observed: null };
  } else if (selected === "timeout" || selected === "cancel") {
    await ops.wait(BOUNDS.waitMs);
    observed.waitCompleted = true;
  } else if (selected === "normal-error") {
    observed.deliberateExit = 23;
    exitCode = 23;
  }
  if (
    Object.values(observed).some(
      (value) =>
        value === false || value === "inconclusive" || value === "reachable",
    )
  )
    exitCode = 2;
  return { exitCode, observed };
}

/** Fixed child vector; offline tests inject just the spawn leaf. No default launcher. */
export function boundedSleeper(
  outliveCommand: boolean,
  launch: typeof spawn,
): Promise<Child> {
  return new Promise((resolve, reject) => {
    const child = launch("/bin/sleep", ["2"], {
      stdio: "ignore",
      env: { PATH: "/usr/bin:/bin" },
      detached: false,
    });
    const timer = setTimeout(() => child.kill("SIGKILL"), BOUNDS.childMs);
    if (outliveCommand) {
      child.unref();
      timer.unref();
    }
    const closed = new Promise<void>((done) => {
      child.once("close", () => {
        clearTimeout(timer);
        done();
      });
    });
    child.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once("spawn", () =>
      resolve({
        stop: () => {
          child.kill("SIGKILL");
        },
        closed,
      }),
    );
  });
}

/** These functions are only called after the guest-only main guard. */
function nativeOps(): Ops {
  return {
    async exists(path) {
      try {
        await lstat(path);
        return true;
      } catch (error) {
        if (code(error) === "ENOENT") return false;
        throw error;
      }
    },
    async read(path, cap) {
      const file = await open(
        path,
        constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
      );
      try {
        const buffer = Buffer.alloc(cap + 1);
        let used = 0;
        while (used < buffer.length) {
          const result = await file.read(
            buffer,
            used,
            buffer.length - used,
            null,
          );
          if (!result.bytesRead) break;
          used += result.bytesRead;
        }
        if (used > cap) throw new Error("READ_BOUND");
        return buffer.subarray(0, used);
      } finally {
        await file.close();
      }
    },
    async write(path, bytes) {
      await writeFile(path, bytes, { flag: "wx", mode: 0o600 });
    },
    async remove(path) {
      try {
        await unlink(path);
      } catch (error) {
        if (code(error) !== "ENOENT") throw error;
      }
    },
    burn(iterations, milliseconds) {
      const end = performance.now() + milliseconds;
      let i = 0,
        accumulator = 0;
      for (; i < iterations; i++) {
        accumulator = (accumulator + i) | 0;
        if ((i & 16383) === 0 && performance.now() >= end) break;
      }
      // Keep the computation observable without logging its intermediate data.
      if (!Number.isInteger(accumulator)) throw new Error("CPU_BOUND");
      return i;
    },
    allocateMiB: () => new Uint8Array(1_048_576).fill(0xa5),
    child(milliseconds, outliveCommand) {
      if (milliseconds !== BOUNDS.childMs) throw new Error("CHILD_BOUND");
      return boundedSleeper(outliveCommand, spawn);
    },
    openNull: () => open("/dev/null", constants.O_RDONLY),
    connect(host, port, milliseconds) {
      return new Promise((resolve) => {
        let settled = false;
        const socket = createConnection({ host, port });
        const finish = (value: string) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          socket.destroy();
          resolve(value);
        };
        const timer = setTimeout(() => finish("ETIMEDOUT"), milliseconds);
        socket.once("connect", () => finish("reachable"));
        socket.once("error", (error) => finish(code(error) ?? "unknown"));
        socket.once("close", () => finish("closed"));
      });
    },
    wait: (milliseconds) =>
      new Promise((resolve) => setTimeout(resolve, milliseconds)),
    output: (stream, bytes) =>
      new Promise((resolve, reject) => {
        process[stream].write(bytes, (error) =>
          error ? reject(error) : resolve(),
        );
      }),
  };
}

if (import.meta.main) {
  try {
    // Do not even construct native operations before all invocation checks pass.
    const args = invocation(Bun.argv);
    checkContext({
      platform: process.platform,
      uid: process.getuid?.(),
      gid: process.getgid?.(),
      cwd: process.cwd(),
      environment: process.env,
    });
    const result = await runCase(
      args.selected,
      args.token,
      args.hostCanaryPid,
      nativeOps(),
    );
    if (result.observed)
      process.stdout.write(
        JSON.stringify({
          version: 1,
          mode: args.selected,
          evidenceClass: "guest-self-report",
          observed: result.observed,
        }) + "\n",
      );
    process.exitCode = result.exitCode;
  } catch {
    process.stderr.write("ACCEPTANCE_CASE_UNCONFIRMED\n");
    process.exitCode = 2;
  }
}
