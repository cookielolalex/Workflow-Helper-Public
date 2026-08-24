// @ts-expect-error TS5097 -- focused Node strip-types tests require the explicit source extension.
import { toCandidateReviewOutcomesView, toCandidateReviewView, type CandidateReviewOutcomesView, type CandidateReviewView } from "./candidate-review.ts";

export const CANDIDATE_REVIEW_QUEUE_PATH =
  "/v1/control/candidate-publications/review-queue" as const;
export const CANDIDATE_REVIEW_OUTCOMES_PATH =
  "/v1/control/candidate-publications/review-outcomes" as const;
export const MIN_CANDIDATE_REVIEW_LIMIT = 1 as const;
export const MAX_CANDIDATE_REVIEW_LIMIT = 100 as const;
export const MAX_CANDIDATE_REVIEW_CORRELATION_ID_LENGTH = 128 as const;
export const MAX_CANDIDATE_REVIEW_CURSOR_LENGTH = 4096 as const;

export type CandidateReviewRequest = {
  readonly path: typeof CANDIDATE_REVIEW_QUEUE_PATH;
  readonly method: "GET";
  readonly correlation_id: string;
  readonly limit: number;
  readonly cursor?: string;
};

export type CandidateReviewTransportResult = {
  readonly status: number;
  readonly body: unknown;
};

export type CandidateReviewTransport = (
  request: CandidateReviewRequest,
) => CandidateReviewTransportResult;

export type CandidateReviewRequestInput = {
  readonly correlation_id: string;
  readonly limit?: number;
  readonly cursor?: string;
};

export type CandidateReviewOutcomesRequest = {
  readonly path: typeof CANDIDATE_REVIEW_OUTCOMES_PATH;
  readonly method: "GET";
};

const RESPONSE_KEYS = ["status", "body"] as const;
const unavailable = (): CandidateReviewView => ({ status: "unavailable" });

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  try {
    return Object.getPrototypeOf(value) === Object.prototype;
  } catch {
    return false;
  }
}

function hasExactKeys<T extends readonly string[]>(
  value: Record<string, unknown>,
  expected: T,
): boolean {
  let ownKeys: (string | symbol)[];
  try {
    ownKeys = Reflect.ownKeys(value);
  } catch {
    return false;
  }
  if (ownKeys.length !== expected.length) return false;
  for (const key of ownKeys) {
    if (typeof key !== "string" || !expected.includes(key)) return false;
  }
  return expected.every((key) =>
    Object.prototype.propertyIsEnumerable.call(value, key)
  );
}

function validCorrelationId(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length >= 1 &&
    value.length <= MAX_CANDIDATE_REVIEW_CORRELATION_ID_LENGTH &&
    /^[A-Za-z0-9._:-]+$/.test(value)
  );
}

function validLimit(value: unknown): value is number {
  return (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= MIN_CANDIDATE_REVIEW_LIMIT &&
    value <= MAX_CANDIDATE_REVIEW_LIMIT
  );
}

function validCursor(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length >= 1 &&
    value.length <= MAX_CANDIDATE_REVIEW_CURSOR_LENGTH
  );
}

function requestInput(
  value: unknown,
  limitOverride?: unknown,
  cursorOverride?: unknown,
): CandidateReviewRequestInput | null {
  if (typeof value === "string") {
    return {
      correlation_id: value,
      limit: limitOverride === undefined
        ? MAX_CANDIDATE_REVIEW_LIMIT
        : limitOverride as number,
      ...(cursorOverride === undefined || cursorOverride === null
        ? {}
        : { cursor: cursorOverride as string }),
    };
  }
  if (!isPlainRecord(value)) return null;
  return {
    correlation_id: value.correlation_id as string,
    limit: value.limit === undefined
      ? MAX_CANDIDATE_REVIEW_LIMIT
      : value.limit as number,
    ...(value.cursor === undefined || value.cursor === null
      ? {}
      : { cursor: value.cursor as string }),
  };
}

function validRequestInput(
  value: CandidateReviewRequestInput | null,
): value is CandidateReviewRequestInput {
  return (
    value !== null &&
    validCorrelationId(value.correlation_id) &&
    validLimit(value.limit) &&
    (value.cursor === undefined || validCursor(value.cursor))
  );
}

/** Build the only fixed-route descriptor accepted by the synthetic transport. */
export function buildCandidateReviewRequest(
  input: CandidateReviewRequestInput | string,
  limit?: number,
  cursor?: string,
): CandidateReviewRequest | null {
  try {
    const normalized = requestInput(input, limit, cursor);
    if (!validRequestInput(normalized)) return null;
    return Object.freeze({
      path: CANDIDATE_REVIEW_QUEUE_PATH,
      method: "GET",
      correlation_id: normalized.correlation_id,
      limit: normalized.limit!,
      ...(normalized.cursor === undefined
        ? {}
        : { cursor: normalized.cursor }),
    });
  } catch {
    return null;
  }
}

export const createCandidateReviewRequest = buildCandidateReviewRequest;
export const makeCandidateReviewRequest = buildCandidateReviewRequest;

function transportResult(value: unknown): CandidateReviewView {
  try {
    if (
      !isPlainRecord(value) ||
      !hasExactKeys(value, RESPONSE_KEYS) ||
      value.status !== 200
    ) {
      return unavailable();
    }
    return toCandidateReviewView({
      status: "available",
      authenticated: true,
      response: value.body,
    });
  } catch {
    return unavailable();
  }
}

/** Resolve a synchronous fixed-route response into the closed redacted view. */
export function readCandidateReview(
  first: CandidateReviewTransport | CandidateReviewRequestInput | string,
  second: CandidateReviewTransport | CandidateReviewRequestInput | string,
  third?: number,
  fourth?: string,
): CandidateReviewView {
  try {
    const transport = typeof first === "function"
      ? first as CandidateReviewTransport
      : typeof second === "function"
        ? second as CandidateReviewTransport
        : null;
    const input = typeof first === "function" ? second : first;
    const request = buildCandidateReviewRequest(
      input as CandidateReviewRequestInput | string,
      typeof input === "string" ? third : undefined,
      typeof input === "string" ? fourth : undefined,
    );
    if (transport === null || request === null) return unavailable();
    return transportResult(transport(request));
  } catch {
    return unavailable();
  }
}

export const loadCandidateReview = readCandidateReview;
export const getCandidateReview = readCandidateReview;
export const listCandidatePublications = readCandidateReview;
export const requestCandidateReview = readCandidateReview;

/** Build the only terminal-outcome route descriptor accepted by the server boundary. */
export function buildCandidateReviewOutcomesRequest(): CandidateReviewOutcomesRequest {
  return Object.freeze({ path: CANDIDATE_REVIEW_OUTCOMES_PATH, method: "GET" });
}

/** Resolve one synchronous fixed outcome response into its redacted view. */
export function readCandidateReviewOutcomes(
  transport: (request: CandidateReviewOutcomesRequest) => CandidateReviewTransportResult,
): CandidateReviewOutcomesView {
  try {
    const value = transport(buildCandidateReviewOutcomesRequest());
    if (
      !isPlainRecord(value) ||
      !hasExactKeys(value, RESPONSE_KEYS) ||
      value.status !== 200
    ) {
      return { status: "unavailable" };
    }
    return toCandidateReviewOutcomesView({
      status: "available",
      authenticated: true,
      response: value.body,
    });
  } catch {
    return { status: "unavailable" };
  }
}

export type { CandidateReviewOutcomesView, CandidateReviewView } from "./candidate-review.ts";
