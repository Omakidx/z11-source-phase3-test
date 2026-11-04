import { getFixtureBuildMarker } from "../lib/fixture-contract";

const buildMarker = getFixtureBuildMarker(process.env);

export default function FixturePage() {
  return (
    <main>
      <p className="eyebrow">Z11 Phase 4 validation fixture</p>
      <h1>Vercel + Next.js</h1>
      <p>This disposable application proves deployed revision and runtime evidence collection.</p>
      <dl>
        <dt>Build marker</dt>
        <dd data-testid="build-marker">{buildMarker}</dd>
        <dt>Health endpoint</dt>
        <dd>
          <code>/api/health</code>
        </dd>
      </dl>
    </main>
  );
}
