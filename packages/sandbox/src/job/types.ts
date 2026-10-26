import type { SandboxLimits } from "../policy";

/** A single, immutable execution intent. Issuance requires authorization elsewhere. */
export type SandboxJobV1 = Readonly<{
  version: 1;
  jobId: string;
  nonce: string;
  /** Exact host audience; host identities must not be reused for replacements. */
  hostId: string;
  scope: Readonly<{
    organizationId: string;
    applicationId: string;
    environmentId: string;
  }>;
  repository: Readonly<{
    repositoryId: string;
    sourceConnectionId: string;
    sourceRevisionId: string;
    provider: "github";
    providerRepositoryId: string;
    fullName: string;
    commitSha: string;
  }>;
  imageDigest: string;
  command: Readonly<{ argv: readonly string[]; cwd: string }>;
  limits: SandboxLimits;
  network: "none";
  source: Readonly<{
    format: "git-bundle-v2";
    sha256: string;
    byteLength: number;
  }>;
  artifacts: Readonly<{
    paths: readonly string[];
    maxFiles: number;
    maxFileBytes: number;
    maxTotalBytes: number;
    maxCaptureMs: number;
    retentionUntil: string;
  }>;
  issuedAt: string;
  expiresAt: string;
  policySha256: string;
}>;

export type SandboxJobEnvelopeV1 = Readonly<{
  job: SandboxJobV1;
  /** Ed25519 over `z11.sandbox-job.v1\0` plus canonical job JSON, in base64url. */
  signature: string;
}>;
