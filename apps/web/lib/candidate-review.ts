/**
 * A deliberately small, pure seam for a future candidate-review surface.
 *
 * The input is an explicitly wrapped synthetic response.  The wrapper keeps
 * loading and authority failures distinct from a valid route response.  The
 * route payload is checked before any view fields are selected.
 */

export const MAX_CANDIDATE_REVIEW_ITEMS = 100;
export const MAX_CANDIDATE_REVIEW_BYTES = 262_144;

export type CandidateReviewRow = {
  readonly ordinal: number;
  readonly schema_version: "1.0";
  readonly byte_length: number;
  readonly finalized_at: string;
};

export type CandidateReviewView =
  | { readonly status: "loading" }
  | { readonly status: "unavailable" }
  | { readonly status: "empty" }
  | {
      readonly status: "populated";
      readonly rows: readonly CandidateReviewRow[];
    };

const ROUTE_RESPONSE_KEYS = ["items", "count", "next_cursor"] as const;
const ROUTE_ITEM_KEYS = [
  "publication_key",
  "schema_version",
  "job_id",
  "session_id",
  "source_result_sha256",
  "derivation_evidence_sha256",
  "review_target_id",
  "content_sha256",
  "full_sha256",
  "publication_identity",
  "byte_length",
  "state",
  "finalized_at_us",
] as const;
const LOADING_KEYS = ["status"] as const;
const UNAVAILABLE_KEYS = ["status"] as const;
const AVAILABLE_KEYS = ["status", "authenticated", "response"] as const;

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

function boundedText(value: unknown, maximum = 4096): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= maximum
  );
}

function boundedByteLength(value: unknown): value is number {
  return (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= 1 &&
    value <= MAX_CANDIDATE_REVIEW_BYTES
  );
}

function finalizedTimestamp(value: unknown): string | null {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value <= 0
  ) {
    return null;
  }
  const timestamp = new Date(Math.trunc(value / 1000));
  if (Number.isNaN(timestamp.getTime())) return null;
  return timestamp.toISOString();
}

function parseRouteResponse(value: unknown): CandidateReviewView {
  if (!isPlainRecord(value) || !hasExactKeys(value, ROUTE_RESPONSE_KEYS)) {
    return unavailable();
  }

  const items = value.items;
  const count = value.count;
  const cursor = value.next_cursor;
  if (
    !Array.isArray(items) ||
    typeof count !== "number" ||
    !Number.isSafeInteger(count) ||
    count < 0 ||
    count > MAX_CANDIDATE_REVIEW_ITEMS ||
    count !== items.length ||
    !(cursor === null || boundedText(cursor, 4096)) ||
    (items.length === 0 && cursor !== null) ||
    items.length > MAX_CANDIDATE_REVIEW_ITEMS
  ) {
    return unavailable();
  }

  const rows: CandidateReviewRow[] = [];
  for (let index = 0; index < items.length; index += 1) {
    const item = items[index];
    if (!isPlainRecord(item) || !hasExactKeys(item, ROUTE_ITEM_KEYS)) {
      return unavailable();
    }

    if (
      !boundedText(item.publication_key) ||
      item.schema_version !== "1.0" ||
      !boundedText(item.job_id) ||
      !boundedText(item.session_id) ||
      !boundedText(item.source_result_sha256, 256) ||
      !boundedText(item.derivation_evidence_sha256, 256) ||
      !boundedText(item.review_target_id) ||
      !boundedText(item.content_sha256, 256) ||
      !boundedText(item.full_sha256, 256) ||
      !boundedText(item.publication_identity, 256) ||
      !boundedByteLength(item.byte_length) ||
      item.state !== "finalized"
    ) {
      return unavailable();
    }

    const finalizedAt = finalizedTimestamp(item.finalized_at_us);
    if (finalizedAt === null) return unavailable();

    rows.push({
      ordinal: index + 1,
      schema_version: "1.0",
      byte_length: item.byte_length,
      finalized_at: finalizedAt,
    });
  }

  if (rows.length === 0) return { status: "empty" };
  return { status: "populated", rows };
}

/**
 * Convert one synthetic fixture into the closed view union.
 *
 * No value is treated as an empty queue unless the wrapper explicitly says
 * that the response is available and authenticated and the strict route
 * payload validates with zero items.
 */
export function toCandidateReviewView(input: unknown): CandidateReviewView {
  try {
    if (!isPlainRecord(input)) return unavailable();

    if (hasExactKeys(input, LOADING_KEYS) && input.status === "loading") {
      return { status: "loading" };
    }
    if (hasExactKeys(input, UNAVAILABLE_KEYS) && input.status === "unavailable") {
      return unavailable();
    }
    if (!hasExactKeys(input, AVAILABLE_KEYS)) return unavailable();
    if (input.status !== "available" || input.authenticated !== true) {
      return unavailable();
    }
    return parseRouteResponse(input.response);
  } catch {
    return unavailable();
  }
}

export const adaptCandidateReview = toCandidateReviewView;
export const parseCandidateReview = toCandidateReviewView;
export const redactCandidateReviewResponse = toCandidateReviewView;
