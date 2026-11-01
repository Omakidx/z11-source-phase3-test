// Z11 Phase 12 controlled incident: DELIBERATE BUG. Do not fix outside the planned revert.
export const REPRO_INPUT: readonly number[] = [3, 5, 7];

/** Intended: arithmetic mean of the values. */
export function averageScore(values: readonly number[]): number {
  let total = 0;
  // Deliberate off-by-one: reads one element past the end, yielding NaN.
  for (let index = 0; index <= values.length; index += 1) {
    total += values[index] as number;
  }
  return total / values.length;
}
