import { test } from "node:test";
import assert from "node:assert/strict";

import { paramsSubset } from "./subset.ts";

// CLC-v1 §6.2 (v1.1): an array grant is the set of allowed values, not a bound.
// Regression guard for the 2026-09-11 alignment (see go/params_enum_test.go).
const cases: [string, unknown, unknown, boolean][] = [
  ["scalar-not-member", 2, [3], false],
  ["scalar-member", 3, [3], true],
  ["array-all-members", [1, 3], [1, 3], true],
  ["array-one-non-member", [1, 2], [1, 3], false],
  ["empty-set-denies-class", 1, [], false],
  ["scalar-number-keeps-bound", 50, 100, true],
  ["scalar-number-exceeds-bound", 150, 100, false],
];

for (const [name, agent, grant, want] of cases) {
  test(`params array-enum: ${name}`, () => {
    assert.equal(paramsSubset(agent, grant), want);
  });
}
