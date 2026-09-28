import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

test("React entrypoint declares a visible result", () => {
  assert.match(readFileSync("src/App.tsx", "utf8"), /Sofa quality pilot/);
});
