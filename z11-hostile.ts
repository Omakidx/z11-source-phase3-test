/**
 * Phase 12 condition C2: the hostile guest for the host-teardown measurement.
 *
 * It exists to make the host's teardown as slow as a guest can: it saturates the pids ceiling with busy
 * processes that ignore SIGTERM, fills every writable tmpfs to ENOSPC (/workspace, /tmp, /dev/shm) so up
 * to 1 GiB of the cgroup's memory is tmpfs pages, adds anonymous memory pressure below the limit, and runs
 * past the wall time so the host has to kill it at the deadline with everything still alive. It prints one
 * short line per second (never a flood: an output-limit kill would end the job before the deadline and
 * measure the wrong thing).
 *
 * It is only meant to run through the pinned `bun-script.v1` profile (`bun run z11:reproduce`) in the Phase 8
 * sandbox. Running it anywhere else is a fork bomb with a disk filler; the local smoke test below uses tiny
 * numbers and a private directory.
 *
 *   in the guest (defaults):          bun run z11:reproduce
 *   local smoke test, harmless:       bun hostile.ts --pids 6 --mb 16 --rss-mb 8 --seconds 4 --fill-dirs ./fill-test
 *
 * Defaults: pids 126 (it keeps trying until the cgroup refuses, so the real count is the ceiling), 1024 MiB of
 * target writes across the three tmpfs, 256 MiB of anonymous memory, runs 600 s (the host kills it at 120 s).
 */
import { closeSync, mkdirSync, openSync, rmSync, writeSync } from "node:fs";

function num(flag: string, fallback: number): number {
  const index = process.argv.indexOf(flag);
  if (index < 0) return fallback;
  const value = Number(process.argv[index + 1]);
  if (!Number.isFinite(value) || value < 0) throw new Error(`bad ${flag}`);
  return value;
}
function text(flag: string, fallback: string): string {
  const index = process.argv.indexOf(flag);
  return index < 0 ? fallback : String(process.argv[index + 1]);
}

const PIDS = num("--pids", 126);
const WRITE_MB = num("--mb", 1024);
const RSS_MB = num("--rss-mb", 256);
const SECONDS = num("--seconds", 600);
const FILL_DIRS = text("--fill-dirs", "/workspace,/tmp,/dev/shm").split(",");
const LOCAL = process.argv.includes("--fill-dirs"); // only the smoke test overrides the directories
const started = Date.now();

process.on("SIGTERM", () => undefined);
process.on("SIGINT", () => undefined);

// 1. Busy children that ignore SIGTERM. Each is one light `sh` process (no fork per iteration). The loop is bounded
//    by an iteration count (POSIX arithmetic only: no $SECONDS, no date), long enough to outlast the 120 s wall
//    time by a wide margin, so a crashed smoke test cannot leave an endless process behind.
const children: ReturnType<typeof Bun.spawn>[] = [];
const ITERATIONS = 4_000_000_000;
let spawnFailures = 0;
function spawnBusy(): boolean {
  try {
    children.push(
      Bun.spawn(["sh", "-c", `trap '' TERM INT; i=0; while [ "$i" -lt ${ITERATIONS} ]; do i=$((i+1)); done`], {
        stdin: "ignore",
        stdout: "ignore",
        stderr: "ignore",
      }),
    );
    return true;
  } catch {
    spawnFailures++;
    return false;
  }
}
for (let i = 0; i < PIDS; i++) if (!spawnBusy() && spawnFailures >= 3) break;

// 2. Fill each tmpfs to ENOSPC (or to the target), 1 MiB at a time, with incompressible-looking data.
const chunk = Buffer.alloc(1 << 20, 0x5a);
let writtenMiB = 0;
const created: string[] = [];
for (const dir of FILL_DIRS) {
  if (LOCAL) mkdirSync(dir, { recursive: true });
  let index = 0;
  while (writtenMiB < WRITE_MB) {
    const path = `${dir}/z11-fill-${index++}`;
    try {
      const fd = openSync(path, "w");
      created.push(path);
      try {
        for (let part = 0; part < 64 && writtenMiB < WRITE_MB; part++) {
          writeSync(fd, chunk);
          writtenMiB++;
        }
      } finally {
        closeSync(fd);
      }
    } catch {
      break; // ENOSPC or EDQUOT: this directory is full
    }
  }
}

// 3. Anonymous memory pressure, kept below the cgroup limit by the caller's choice of RSS_MB.
const ballast: Buffer[] = [];
try {
  for (let i = 0; i < RSS_MB; i++) ballast.push(Buffer.alloc(1 << 20, i & 0xff));
} catch {
  /* out of memory: the host's view of the job is then OOM, which is also a valid measurement */
}

// 4. Hold everything until the host kills the guest.
const timer = setInterval(() => {
  const alive = children.filter((child) => child.exitCode === null).length;
  console.log(`hostile t=${Math.round((Date.now() - started) / 1000)}s pids=${alive} wroteMiB=${writtenMiB} rssMiB=${ballast.length}`);
  if (Date.now() - started >= SECONDS * 1000) {
    clearInterval(timer);
    for (const child of children) child.kill(9);
    if (LOCAL) for (const path of created) rmSync(path, { force: true });
    if (LOCAL) for (const dir of FILL_DIRS) rmSync(dir, { recursive: true, force: true });
    process.exit(3);
  }
}, 1000);
