const MAX_BUILD_MARKER_LENGTH = 96;
const SAFE_BUILD_MARKER = /^[A-Za-z0-9._:-]+$/;

export const FIXTURE_ID = "z11-phase4-vercel-nextjs";
export const FIXTURE_VERSION = "1";

export type FixtureEnvironment = Record<string, string | undefined>;

export function getFixtureBuildMarker(environment: FixtureEnvironment): string {
  const candidate =
    environment.NEXT_PUBLIC_FIXTURE_BUILD_MARKER ?? environment.VERCEL_GIT_COMMIT_SHA;

  if (!candidate || candidate.length > MAX_BUILD_MARKER_LENGTH || !SAFE_BUILD_MARKER.test(candidate)) {
    return "local-unset";
  }

  return candidate;
}

export function createHealthResponse(environment: FixtureEnvironment) {
  return {
    status: "ok" as const,
    fixture: FIXTURE_ID,
    fixtureVersion: FIXTURE_VERSION,
    buildMarker: getFixtureBuildMarker(environment),
  };
}

export function createControlledFailureResponse(environment: FixtureEnvironment): {
  status: 404 | 503;
  body: {
    status: "disabled" | "unavailable";
    fixture: typeof FIXTURE_ID;
    fixtureVersion: typeof FIXTURE_VERSION;
    buildMarker: string;
  };
} {
  const buildMarker = getFixtureBuildMarker(environment);

  if (environment.FIXTURE_ENABLE_CONTROLLED_FAILURE !== "true") {
    return {
      status: 404,
      body: {
        status: "disabled",
        fixture: FIXTURE_ID,
        fixtureVersion: FIXTURE_VERSION,
        buildMarker,
      },
    };
  }

  return {
    status: 503,
    body: {
      status: "unavailable",
      fixture: FIXTURE_ID,
      fixtureVersion: FIXTURE_VERSION,
      buildMarker,
    },
  };
}

export function fixtureRuntimeLog(event: "health" | "controlled-failure", buildMarker: string): string {
  return `${FIXTURE_ID} event=${event} marker=${buildMarker.slice(0, 48)}`;
}
