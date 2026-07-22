import { Router } from "express";
import { TokenBucket, routes, validateKeycloakToken } from "./domain.js";
export const router = Router();
const limiter = new TokenBucket(60, 60_000);
router.get("/routes", (_request, response) => response.json(routes));
router.post("/auth/check", async (request, response) => {
  const key = request.ip ?? "unknown";
  if (!limiter.take(key))
    return response
      .status(429)
      .json({ title: "Rate limit exceeded", status: 429 });
  const token = request.header("authorization")?.replace(/^Bearer /, "");
  if (!token)
    return response
      .status(401)
      .json({ title: "Bearer token required", status: 401 });
  try {
    const result = await validateKeycloakToken(
      token,
      process.env.KEYCLOAK_ISSUER ?? "http://keycloak:8080/realms/algaguard",
      process.env.KEYCLOAK_AUDIENCE ?? "algaguard-api",
    );
    return response.json({ subject: result.payload.sub, valid: true });
  } catch {
    return response.status(401).json({ title: "Invalid token", status: 401 });
  }
});
router.use("/services/:service", async (request, response) => {
  const service = request.params.service as keyof typeof routes;
  const target = routes[service];
  if (!target)
    return response.status(404).json({ title: "Unknown service", status: 404 });
  const authorization = request.header("authorization");
  if (!authorization)
    return response
      .status(401)
      .json({ title: "Bearer token required", status: 401 });
  try {
    await validateKeycloakToken(
      authorization.replace(/^Bearer /, ""),
      process.env.KEYCLOAK_ISSUER ?? "http://keycloak:8080/realms/algaguard",
      process.env.KEYCLOAK_AUDIENCE ?? "algaguard-api",
    );
  } catch {
    return response.status(401).json({ title: "Invalid token", status: 401 });
  }
  const upstream = await fetch(`${target}/v1${request.url}`, {
    method: request.method,
    headers: {
      "content-type": request.header("content-type") ?? "application/json",
      authorization,
      "x-correlation-id":
        response.getHeader("x-correlation-id")?.toString() ?? "",
    },
    ...(request.method === "GET" || request.method === "HEAD"
      ? {}
      : { body: JSON.stringify(request.body) }),
  });
  response.status(upstream.status);
  response.type(upstream.headers.get("content-type") ?? "application/json");
  return response.send(Buffer.from(await upstream.arrayBuffer()));
});
