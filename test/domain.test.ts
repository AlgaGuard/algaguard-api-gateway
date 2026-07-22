import test from "node:test";
import assert from "node:assert/strict";
import { TokenBucket } from "../src/domain.js";
test("rate limit is bounded by subject and window", () => {
  const bucket = new TokenBucket(2, 1000);
  assert.equal(bucket.take("user", 0), true);
  assert.equal(bucket.take("user", 1), true);
  assert.equal(bucket.take("user", 2), false);
  assert.equal(bucket.take("user", 1000), true);
});
