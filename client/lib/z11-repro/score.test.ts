// @ts-nocheck -- bun:test types are not installed in the Next.js build; this file runs only under `bun test`.
import { expect, test } from "bun:test";
import { averageScore } from "./score";

test("averageScore returns the arithmetic mean", () => {
  expect(averageScore([3, 5, 7])).toBe(5);
});
