/** Future guest entrypoint only. Imports perform no probe actions. */
import { constants } from "node:fs";
import { lstat, open, unlink, writeFile } from "node:fs/promises";
import { createConnection } from "node:net";
import { lookup } from "node:dns/promises";
import { createServer, request as httpRequest } from "node:http";
import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { opendir } from "node:fs/promises";
import { hostname as osHostname } from "node:os";
import {
  REBIND_NAME,
  connectionOutcome,
  emitOutputFlood,
  nameResolutionOutcome,
  redirectHop,
} from "../../probe";
import {
  BOUNDS,
  COMM_READ_BYTES,
  HOST_CANARY_PATH,
  MARKER_PATH,
  MARKER_PREFIX,
  PROCESS_TAG,
  PROC_DIR,
  PROC_ENTRY_CAP,
  REBIND_CONNECTS,
  REDIRECT_CHAIN,
  TARGETS,
  checkContext,
  inodePath,
  invocation,
  mode,
  WORKSPACE_DIR,
  type Mode,
} from "./guest-contract";

type Child = { stop(): void; closed: Promise<void> };
export type Ops = {
  exists(path: string): Promise<boolean>;
  read(path: string, cap: number): Promise<Uint8Array>;
  /** Names in a directory, stopping after `cap + 1` so a caller can detect overflow. */
  listDir(path: string, cap: number): Promise<string[]>;
  /** Lowercase hex of `bytes` fresh random bytes. */
  randomHex(bytes: number): string;
  /** The guest's own pid, the positive control for the /proc scan. */
  selfPid(): number;
  /** Advisory only: a guest can say anything about its own name. */
  hostname(): string;
  write(path: string, bytes: Uint8Array): Promise<void>;
  remove(path: string): Promise<void>;
  burn(iterations: number, milliseconds: number): number;
  allocateMiB(): Uint8Array;
  child(milliseconds: number, outliveCommand: boolean): Promise<Child>;
  openNull(): Promise<{ close(): Promise<void> }>;
  connect(host: string, port: number, milliseconds: number): Promise<string>;
  /** "resolved" if any address came back, else the error code. Never connects. */
  resolve(name: string, milliseconds: number): Promise<string>;
  /** Serve one 302 from loopback inside the guest and report what a client saw. */
  redirectOnce(
    location: string,
    milliseconds: number,
  ): Promise<{ status: number; location: string | null }>;
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

const connectVerdict = (result: string) =>
  result === "reachable" ? "reachable" : connectionOutcome(result);

/** Deterministic, ordered attempted-target record; never contains payload bytes. */
function recordAttempts(
  observed: Record<string, boolean | number | string>,
  attempts: readonly string[],
) {
  observed.attemptCount = attempts.length;
  observed.attempted = attempts.join(" ");
  observed.attemptedSha256 = createHash("sha256")
    .update(attempts.join("\n"))
    .digest("hex");
}

/** Injected operations permit offline tests without host reads, sockets or children. */
export async function runCase(selected: Mode, ops: Ops) {
  mode(selected);
  const nonce = ops.randomHex(16);
  const hostname = ops.hostname();
  if (!/^[0-9a-f]{32}$/.test(nonce)) throw new Error("NONCE_INVALID");
  const observed: Record<string, boolean | number | string> = {};
  let exitCode = 0;
  if (selected === "boundary") {
    observed.hostCanaryAbsent = await expectedAbsent(ops, HOST_CANARY_PATH);
    if (observed.hostCanaryAbsent === false) {
      // Report only whether the leaf is readable and a digest; never the bytes.
      try {
        observed.hostCanaryReadSha256 = createHash("sha256")
          .update(await ops.read(HOST_CANARY_PATH, 4096))
          .digest("hex");
      } catch {
        observed.hostCanaryReadSha256 = "unreadable";
      }
    }
    for (const [name, path] of [
      ["dockerSocketAbsent", "/var/run/docker.sock"],
      ["containerdSocketAbsent", "/run/containerd/containerd.sock"],
      ["hostConfigAbsent", "/etc/z11-sandbox"],
    ])
      observed[name!] = await expectedAbsent(ops, path!);
    try {
      const entries = await ops.listDir(PROC_DIR, PROC_ENTRY_CAP);
      const pids = entries.filter((name) => /^[1-9][0-9]*$/.test(name));
      observed.procEntryCount = pids.length;
      let tagSeen = false;
      let unreadable = false;
      let selfRead = false;
      const self = String(ops.selfPid());
      // listDir stops at cap + 1 names, so more than `cap` means the listing was cut off.
      if (entries.length > PROC_ENTRY_CAP) unreadable = true;
      else
        for (const pid of pids) {
          try {
            const comm = text(
              await ops.read(`${PROC_DIR}/${pid}/comm`, COMM_READ_BYTES),
            ).trim();
            if (comm === PROCESS_TAG) tagSeen = true;
            if (pid === self) selfRead = true;
          } catch (error) {
            // A process that exited between listing and reading is not an error.
            if (code(error) !== "ENOENT" && code(error) !== "ESRCH")
              unreadable = true;
          }
        }
      // Positive control: an empty or filtered /proc proves nothing. The scan counts only
      // if it listed at least one entry, listed this process and read its own comm.
      const selfObserved = pids.length >= 1 && pids.includes(self) && selfRead;
      observed.procSelfObserved = selfObserved;
      observed.hostProcessTagAbsent = tagSeen
        ? false
        : unreadable || !selfObserved
          ? "inconclusive"
          : true;
    } catch {
      observed.procEntryCount = 0;
      observed.procSelfObserved = false;
      observed.hostProcessTagAbsent = "inconclusive";
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
  } else if (selected === "dns-rebinding") {
    const attempts: string[] = [];
    // A rebinding attack needs a name answer first; with network=none there must be none.
    for (const name of ["rebindFirst", "rebindSecond"]) {
      attempts.push(`dns:${REBIND_NAME}`);
      const result = await ops.resolve(REBIND_NAME, BOUNDS.resolveMs);
      observed[name] = nameResolutionOutcome(result);
      observed[`${name}Code`] = result;
    }
    // The addresses a rebinder would substitute are still literal-only socket attempts.
    for (const target of REBIND_CONNECTS) {
      attempts.push(`tcp:${target.host}:${target.port}`);
      const result = await ops.connect(
        target.host,
        target.port,
        BOUNDS.connectMs,
      );
      observed[target.name] = connectVerdict(result);
      observed[`${target.name}Code`] = result;
    }
    recordAttempts(observed, attempts);
  } else if (selected === "http-redirect") {
    const attempts: string[] = [];
    for (const hop of REDIRECT_CHAIN) {
      attempts.push(`http-loopback-302:${hop.location}`);
      let issued: { status: number; location: string | null } | null = null;
      try {
        issued = await ops.redirectOnce(hop.location, BOUNDS.redirectServeMs);
      } catch {
        /* Harness failure stays inconclusive below. */
      }
      observed[`${hop.name}Issued`] = issued?.status === 302;
      // Never follow automatically: only the parsed literal Location is dialed, with no HTTP bytes.
      const next = redirectHop(issued?.location ?? null);
      const bound =
        next !== null && next.host === hop.host && next.port === hop.port;
      if (!bound) {
        observed[hop.name] = "inconclusive";
        continue;
      }
      attempts.push(`tcp:${next.host}:${next.port}`);
      const result = await ops.connect(next.host, next.port, BOUNDS.connectMs);
      observed[hop.name] = connectVerdict(result);
      observed[`${hop.name}Code`] = result;
    }
    recordAttempts(observed, attempts);
  } else if (selected === "write-marker") {
    await ops.write(MARKER_PATH, new TextEncoder().encode(nonce));
    observed.markerWritten = text(await ops.read(MARKER_PATH, 64)) === nonce;
  } else if (selected === "fresh-marker") {
    observed.previousMarkerAbsent = await expectedAbsent(ops, MARKER_PATH);
    try {
      const names = await ops.listDir(WORKSPACE_DIR, PROC_ENTRY_CAP);
      observed.noAcceptanceLeaf =
        names.length > PROC_ENTRY_CAP
          ? "inconclusive"
          : !names.some((name) => name.startsWith(MARKER_PREFIX));
    } catch {
      observed.noAcceptanceLeaf = "inconclusive";
    }
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
        const path = inodePath(i);
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
    return { exitCode: 0, observed: null, nonce, hostname };
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
        value === false ||
        value === "inconclusive" ||
        value === "reachable" ||
        value === "resolved",
    )
  )
    exitCode = 2;
  return { exitCode, observed, nonce, hostname };
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
    async listDir(path, cap) {
      const names: string[] = [];
      const directory = await opendir(path);
      try {
        for await (const entry of directory) {
          names.push(entry.name);
          if (names.length > cap) break;
        }
      } finally {
        await directory.close().catch(() => undefined);
      }
      return names;
    },
    randomHex: (bytes) => randomBytes(bytes).toString("hex"),
    hostname: () => osHostname(),
    selfPid: () => process.pid,
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
    resolve(name, milliseconds) {
      return new Promise((resolve) => {
        const timer = setTimeout(() => resolve("ETIMEDOUT"), milliseconds);
        lookup(name, { all: true }).then(
          (answers) => {
            clearTimeout(timer);
            resolve(answers.length > 0 ? "resolved" : "ENOTFOUND");
          },
          (error) => {
            clearTimeout(timer);
            resolve(code(error) ?? "unknown");
          },
        );
      });
    },
    redirectOnce(location, milliseconds) {
      return new Promise((resolve, reject) => {
        const server = createServer((_request, response) => {
          response.writeHead(302, { location, connection: "close" });
          response.end();
        });
        const finish = (error: Error | null, value?: never) => {
          clearTimeout(timer);
          server.close();
          if (error) reject(error);
          else resolve(value as never);
        };
        const timer = setTimeout(
          () => finish(new Error("REDIRECT_TIMEOUT")),
          milliseconds,
        );
        server.once("error", (error) => finish(error));
        server.listen(0, "127.0.0.1", () => {
          const { port } = server.address() as { port: number };
          const client = httpRequest(
            { host: "127.0.0.1", port, method: "GET", path: "/" },
            (response) => {
              response.resume();
              const header = response.headers.location;
              finish(null, {
                status: response.statusCode ?? 0,
                location: typeof header === "string" ? header : null,
              } as never);
            },
          );
          client.once("error", (error) => finish(error));
          client.end();
        });
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
    const result = await runCase(args.selected, nativeOps());
    if (result.observed)
      process.stdout.write(
        JSON.stringify({
          version: 2,
          mode: args.selected,
          evidenceClass: "guest-self-report",
          nonce: result.nonce,
          hostname: result.hostname,
          observed: result.observed,
        }) + "\n",
      );
    process.exitCode = result.exitCode;
  } catch {
    process.stderr.write("ACCEPTANCE_CASE_UNCONFIRMED\n");
    process.exitCode = 2;
  }
}
