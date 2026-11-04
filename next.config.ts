import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  outputFileTracingRoot: __dirname,
  reactStrictMode: true,
  // Keep the controlled fixture's build inside its one-CPU sandbox profile.
  experimental: { cpus: 1 },
};

export default nextConfig;
