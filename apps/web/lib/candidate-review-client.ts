// @ts-ignore The focused Node loader requires the explicit source extension.
import { toCandidateReviewView, type CandidateReviewView } from "./candidate-review.ts";

export const CANDIDATE_PUBLICATIONS_PATH =
  "/v1/control/candidate-publications" as const;
export const MIN_CANDIDATE_REVIEW_LIMIT = 1 as const;
export const MAX_CANDIDATE_REVIEW_LIMIT = 100 as const;
export const MAX_CANDIDATE_REVIEW_CORRELATION_ID_LENGTH = 128 as const;
export const MAX_CANDIDATE_REVIEW_CURSOR_LENGTH = 4096 as const;

export type CandidateReviewRequest = {
  readonly path: typeof CANDIDATE_PUBLICATIONS_PATH;
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
  for (const key of expected) {
    if (!Object.prototype.propertyIsEnumerable.call(value, key)) return false;
  }
  return true;
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
      limit: limitOverride === undefined ? MAX_CANDIDATE_REVIEW_LIMIT : limitOverride as number,
      ...(cursorOverride === undefined || cursorOverride === null
        ? {}
        : { cursor: cursorOverride as string }),
    };
  }

  if (!isPlainRecord(value)) return null;
  const correlationId = value.correlation_id;
  const limit = value.limit === undefined
    ? MAX_CANDIDATE_REVIEW_LIMIT
    : value.limit;
  const cursor = value.cursor;
  return {
    correlation_id: correlationId as string,
    limit: limit as number,
    ...(cursor === undefined || cursor === null ? {} : { cursor: cursor as string }),
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

/** Build the only descriptor accepted by the injected transport. */
export function buildCandidateReviewRequest(
  input: CandidateReviewRequestInput | string,
  limit?: number,
  cursor?: string,
): CandidateReviewRequest | null {
  try {
    const normalized = requestInput(input, limit, cursor);
    if (!validRequestInput(normalized)) return null;

    return normalized.cursor === undefined
      ? {
          path: CANDIDATE_PUBLICATIONS_PATH,
          method: "GET",
          correlation_id: normalized.correlation_id,
          limit: normalized.limit!,
        }
      : {
          path: CANDIDATE_PUBLICATIONS_PATH,
          method: "GET",
          correlation_id: normalized.correlation_id,
          limit: normalized.limit!,
          cursor: normalized.cursor,
        };
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

function invocation(
  first: unknown,
  second: unknown,
  third: unknown,
  fourth: unknown,
): { transport: CandidateReviewTransport; request: CandidateReviewRequest } | null {
  let transport: unknown;
  let input: unknown;
  let limit: unknown;
  let cursor: unknown;

  if (typeof first === "function") {
    transport = first;
    input = second;
    limit = typeof second === "string" ? third : undefined;
    cursor = typeof second === "string" ? fourth : undefined;
  } else if (typeof second === "function") {
    transport = second;
    input = first;
    limit = typeof first === "string" ? third : undefined;
    cursor = typeof first === "string" ? fourth : undefined;
  } else {
    return null;
  }

  if (typeof transport !== "function") return null;
  const request = buildCandidateReviewRequest(
    input as CandidateReviewRequestInput | string,
    limit as number | undefined,
    cursor as string | undefined,
  );
  return request === null
    ? null
    : { transport: transport as CandidateReviewTransport, request };
}

/**
 * Resolve one synthetic transport result into the existing closed view union.
 * The injected transport and this resolver are synchronous and side-effect free.
 */
export function readCandidateReview(
  first: CandidateReviewTransport | CandidateReviewRequestInput | string,
  second: CandidateReviewTransport | CandidateReviewRequestInput | string,
  third?: number,
  fourth?: string,
): CandidateReviewView {
  try {
    const call = invocation(first, second, third, fourth);
    if (call === null) return unavailable();

    const supplied = call.transport(call.request);
    return transportResult(supplied);
  } catch {
    return unavailable();
  }
}

export const loadCandidateReview = readCandidateReview;
export const getCandidateReview = readCandidateReview;
export const listCandidatePublications = readCandidateReview;
export const requestCandidateReview = readCandidateReview;

export type { CandidateReviewView } from "./candidate-review.ts";
