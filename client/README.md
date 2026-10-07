# Rally

A responsive ping-pong landing page with a playable solo rally game, built with Next.js, TypeScript, and Bun.

## Run locally

```sh
bun install
bun run dev
```

Open http://localhost:3000. Move the paddle with your mouse, touch, or arrow keys.

## Validate and run production

```sh
bun run build
bun run typecheck
bun run start
```

All Next.js commands use Bun as the runtime. Dependencies are pinned by `bun.lock`.
