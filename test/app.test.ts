import test from "node:test";
import assert from "node:assert/strict";
import request from "supertest";
import { buildApp } from "../src/app.js";
import { copySafeUpstreamHeaders } from "../src/routes.js";
test("liveness and correlation middleware are available", async () => {
  const response = await request(buildApp())
    .get("/health/live")
    .set("x-correlation-id", "test-correlation");
  assert.equal(response.status, 200);
  assert.equal(response.body.service, "algaguard-api-gateway");
  assert.equal(response.headers["x-correlation-id"], "test-correlation");
});
test("unknown routes use problem details", async () => {
  const response = await request(buildApp()).get("/missing");
  assert.equal(response.status, 404);
  assert.match(
    response.headers["content-type"] ?? "",
    /application\/problem\+json/,
  );
});

test("proxied no-store response header is preserved", () => {
  const headers = new Headers({
    "cache-control": "no-store",
    "content-type": "application/json",
    "set-cookie": "session=secret",
  });
  const copied = new Map<string, string>();
  const response = {
    type(value: string) {
      copied.set("content-type", value);
      return this;
    },
    setHeader(name: string, value: string) {
      copied.set(name.toLowerCase(), value);
      return this;
    },
  };

  copySafeUpstreamHeaders(headers, response);

  assert.equal(copied.get("content-type"), "application/json");
  assert.equal(copied.get("cache-control"), "no-store");
  assert.equal(copied.has("set-cookie"), false);
});
