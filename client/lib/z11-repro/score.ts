// Z11 Phase 12 controlled incident: DELIBERATE BUG. Do not fix outside the planned revert.
export const REPRO_INPUT: readonly number[] = [3, 5, 7];

/** Intended: arithmetic mean of the values. */
export function averageScore(values: readonly number[]): number {
  if (values.length === 0) {
    return 0;
  }
  const total = values.reduce((sum, value) => sum + value, 0);
  return total / values.length;
}
