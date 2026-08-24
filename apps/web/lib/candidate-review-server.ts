import { createHash } from "node:crypto";

// @ts-ignore Focused Node tests require the explicit source extension.
import { buildCandidateReviewRequest, readCandidateReview, type CandidateReviewRequestInput } from "./candidate-review-client.ts";
// @ts-ignore Focused Node tests require the explicit source extension.
import { buildCandidateReviewPostRequest, postCandidateReview } from "./candidate-review-post-client.ts";
import type { CandidateReviewView } from "./candidate-review";

const MAX_JSON_BYTES = 262_144;
const MAX_ACTION_BYTES = 64;
const API_ORIGIN = "https://review.synthetic.example";
const DEV_ENVIRONMENTS = new Set(["development", "dev", "local", "test"]);
const TOKEN_PATTERN = /^[A-Za-z0-9._:-]{32,256}$/;
const MATERIAL_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const FORBIDDEN_PROOF_VALUES = new Set([
  "changeme",
  "change-me",
  "default",
  "dev",
  "local",
  "password",
  "placeholder",
  "replace-me",
  "secret",
  "synthetic",
  "test",
  "token",
]);

type CachedResponse = Readonly<{ status: number; body: unknown }>;
type ReviewAction = "approve" | "reject";
type ParsedAction = Readonly<{ ordinal: number; action: ReviewAction }>;
type ServerConfig = Readonly<{
  apiBase: string;
  reviewerProof: string;
  reviewerSession: string;
  reviewerCsrf: string;
  browserOrigin: string;
  browserHost: string;
}>;

export type CandidateReviewActionResult =
  | "success"
  | "conflict"
  | "unavailable";

function canonicalMaterial(value: unknown): value is string {
  if (typeof value !== "string" || !MATERIAL_PATTERN.test(value)) return false;
  try {
    const decoded = Buffer.from(value, "base64url");
    return (
      decoded.length === 32 &&
      new Set(decoded).size >= 4 &&
      decoded.toString("base64url") === value
    );
  } catch {
    return false;
  }
}

function validProof(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value === value.trim() &&
    TOKEN_PATTERN.test(value) &&
    !FORBIDDEN_PROOF_VALUES.has(value.toLowerCase()) &&
    new Set(value).size >= 4
  );
}

function serverConfig(): ServerConfig | null {
  try {
    const environment = process.env.ENVIRONMENT;
    const apiBase = process.env.WORKFLOW_REVIEW_API_BASE_URL;
    const reviewerProof = process.env.WORKFLOW_DEV_REVIEWER_PROOF;
    const reviewerSession = process.env.WORKFLOW_DEV_REVIEWER_SESSION;
    const reviewerCsrf = process.env.WORKFLOW_DEV_REVIEWER_CSRF;
    const browserOrigin = process.env.WORKFLOW_REVIEW_BROWSER_ORIGIN;
    const browserHost = process.env.WORKFLOW_REVIEW_BROWSER_HOST;
    if (
      typeof environment !== "string" ||
      !DEV_ENVIRONMENTS.has(environment) ||
      typeof apiBase !== "string" ||
      typeof browserOrigin !== "string" ||
      typeof browserHost !== "string" ||
      !validProof(reviewerProof) ||
      !canonicalMaterial(reviewerSession) ||
      !canonicalMaterial(reviewerCsrf) ||
      new Set([reviewerProof, reviewerSession, reviewerCsrf]).size !== 3
    ) {
      return null;
    }
    const api = new URL(apiBase);
    const browser = new URL(browserOrigin);
    if (
      apiBase !== api.origin ||
      api.protocol !== "http:" ||
      !["api", "localhost", "127.0.0.1"].includes(api.hostname) ||
      api.port.length === 0 ||
      browserOrigin !== browser.origin ||
      browser.protocol !== "http:" ||
      !["localhost", "127.0.0.1"].includes(browser.hostname) ||
      browser.port.length === 0 ||
      browser.host !== browserHost
    ) {
      return null;
    }
    return Object.freeze({
      apiBase,
      reviewerProof,
      reviewerSession,
      reviewerCsrf,
      browserOrigin,
      browserHost,
    });
  } catch {
    return null;
  }
}

function apiHeaders(config: ServerConfig, csrf = false): Headers {
  const headers = new Headers({
    accept: "application/json",
    cookie: `workflow_session=${config.reviewerSession}`,
    origin: API_ORIGIN,
    "x-workflow-dev-reviewer-proof": config.reviewerProof,
  });
  if (csrf) headers.set("x-csrf-token", config.reviewerCsrf);
  return headers;
}

async function boundedJsonFetch(
  fetcher: typeof fetch,
  url: string,
  init: RequestInit,
): Promise<CachedResponse | null> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5_000);
  try {
    const response = await fetcher(url, {
      ...init,
      cache: "no-store",
      credentials: "omit",
      redirect: "error",
      signal: controller.signal,
    });
    if (
      response.redirected ||
      (response.url !== "" && response.url !== url) ||
      response.headers.get("content-type") !== "application/json"
    ) {
      return null;
    }
    const declared = response.headers.get("content-length");
    if (declared !== null) {
      const value = Number(declared);
      if (
        !Number.isSafeInteger(value) ||
        value < 0 ||
        value > MAX_JSON_BYTES ||
        String(value) !== declared
      ) {
        return null;
      }
    }
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes.byteLength > MAX_JSON_BYTES) return null;
    return Object.freeze({
      status: response.status,
      body: JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)),
    });
  } catch {
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

function listInput(correlationId: string): CandidateReviewRequestInput {
  return Object.freeze({ correlation_id: correlationId, limit: 100 });
}

async function cachedList(
  config: ServerConfig,
  correlationId: string,
  fetcher: typeof fetch,
): Promise<{ cached: CachedResponse; view: CandidateReviewView } | null> {
  const input = listInput(correlationId);
  const descriptor = buildCandidateReviewRequest(input);
  if (descriptor === null) return null;
  const query = new URLSearchParams({
    correlation_id: descriptor.correlation_id,
    limit: String(descriptor.limit),
  });
  const cached = await boundedJsonFetch(
    fetcher,
    `${config.apiBase}${descriptor.path}?${query.toString()}`,
    { method: "GET", headers: apiHeaders(config) },
  );
  if (cached === null) return null;
  const view = readCandidateReview(() => cached, input);
  return { cached, view };
}

/** Return only the existing redacted queue union to the server component. */
export async function loadCandidateReviewQueue(
  fetcher: typeof fetch = fetch,
): Promise<CandidateReviewView> {
  const config = serverConfig();
  if (config === null) return { status: "unavailable" };
  const listed = await cachedList(config, "web-candidate-review", fetcher);
  return listed?.view ?? { status: "unavailable" };
}

function rawItem(value: unknown, ordinal: number): Record<string, unknown> | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  const items = (value as Record<string, unknown>).items;
  if (!Array.isArray(items) || ordinal < 1 || ordinal > items.length) return null;
  const item = items[ordinal - 1];
  return item !== null && typeof item === "object" && !Array.isArray(item)
    ? item as Record<string, unknown>
    : null;
}

/** Re-fetch, bind one ordinal server-side, and return no raw identifier. */
export async function submitCandidateReviewAction(
  ordinal: number,
  action: ReviewAction,
  fetcher: typeof fetch = fetch,
): Promise<CandidateReviewActionResult> {
  const config = serverConfig();
  if (
    config === null ||
    !Number.isSafeInteger(ordinal) ||
    ordinal < 1 ||
    ordinal > 100 ||
    !["approve", "reject"].includes(action)
  ) {
    return "unavailable";
  }
  const listed = await cachedList(config, "web-candidate-action", fetcher);
  if (listed === null || listed.view.status !== "populated") return "unavailable";
  const item = rawItem(listed.cached.body, ordinal);
  if (item === null) return "unavailable";
  const publicationKey = item.publication_key;
  const reviewTarget = item.review_target_id;
  if (typeof publicationKey !== "string" || typeof reviewTarget !== "string") {
    return "unavailable";
  }
  const status = action === "approve" ? "approved" : "rejected";
  const identity = createHash("sha256")
    .update(`workflow-helper\0dev-review\0${publicationKey}\0${status}`)
    .digest("hex");
  const request = Object.freeze({
    review_target_id: reviewTarget,
    correlation_id: "web-candidate-action",
    idempotency_key: `web-dev-${identity}`,
    status,
  });
  const descriptor = buildCandidateReviewPostRequest(publicationKey, request);
  if (descriptor === null) return "unavailable";
  const headers = apiHeaders(config, true);
  headers.set("content-type", "application/json");
  const cached = await boundedJsonFetch(
    fetcher,
    `${config.apiBase}${descriptor.path}`,
    {
      method: descriptor.method,
      headers,
      body: JSON.stringify(descriptor.body),
    },
  );
  if (cached === null) return "unavailable";
  return postCandidateReview(
    () => cached,
    publicationKey,
    request,
  ).status;
}

async function boundedActionBody(request: Request, expected: number): Promise<string | null> {
  if (request.body === null || expected < 1 || expected > MAX_ACTION_BYTES) return null;
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      total += next.value.byteLength;
      if (total > expected || total > MAX_ACTION_BYTES) {
        await reader.cancel();
        return null;
      }
      chunks.push(next.value);
    }
  } catch {
    return null;
  }
  if (total !== expected) return null;
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

/** Validate the same-origin two-field browser form without accepting authority. */
export async function parseCandidateReviewActionRequest(
  request: Request,
): Promise<ParsedAction | null> {
  const config = serverConfig();
  if (config === null) return null;
  const url = new URL(request.url);
  const contentLength = request.headers.get("content-length");
  if (
    request.method !== "POST" ||
    url.pathname !== "/candidate-review/action" ||
    url.search !== "" ||
    url.host !== config.browserHost ||
    request.headers.get("host") !== config.browserHost ||
    request.headers.get("origin") !== config.browserOrigin ||
    request.headers.get("content-type") !== "application/x-www-form-urlencoded" ||
    request.headers.has("cookie") ||
    request.headers.has("authorization") ||
    request.headers.has("x-workflow-dev-proof") ||
    request.headers.has("x-workflow-dev-reviewer-proof") ||
    request.headers.has("x-csrf-token") ||
    contentLength === null ||
    !/^[1-9][0-9]?$/.test(contentLength)
  ) {
    return null;
  }
  const length = Number(contentLength);
  const body = await boundedActionBody(request, length);
  if (body === null || body.includes("candidate-publication") || body.includes("candidate-skill")) {
    return null;
  }
  const match = /^ordinal=((?:[1-9][0-9]?|100))&action=(approve|reject)$/.exec(body);
  if (match === null) return null;
  const ordinal = Number(match[1]);
  if (ordinal > 100) return null;
  return Object.freeze({ ordinal, action: match[2] as ReviewAction });
}

export function candidateReviewRedirect(): Response {
  return new Response(null, {
    status: 303,
    headers: {
      "cache-control": "no-store",
      location: "/candidate-review",
      "referrer-policy": "no-referrer",
    },
  });
}
