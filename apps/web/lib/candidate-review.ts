/**
 * The deliberately small, pure projection used by the guarded synthetic
 * candidate-review surface.
 *
 * The input is an explicitly wrapped synthetic response.  The wrapper keeps
 * loading and authority failures distinct from a valid route response.  The
 * route payload is checked before any view fields are selected.
 */

export const MAX_CANDIDATE_REVIEW_ITEMS = 100;
export const MAX_CANDIDATE_REVIEW_BYTES = 262_144;
export const MAX_CANDIDATE_REVIEW_COMMANDS = 64;

export type CandidateReviewRow = {
  readonly ordinal: number;
  readonly command_sequence: readonly string[];
  readonly occurrence_count: number;
  readonly provenance: "observed";
  readonly review_status: "unreviewed" | "pending";
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

export type CandidateReviewOutcomeRow = {
  readonly ordinal: number;
  readonly command_sequence: readonly string[];
  readonly occurrence_count: number;
  readonly provenance: "observed";
  readonly review_status: "approved" | "rejected" | "needs_changes";
  readonly decided_at: string;
};

export type CandidateReviewOutcomesView =
  | { readonly status: "unavailable" }
  | { readonly status: "empty" }
  | { readonly status: "populated"; readonly rows: readonly CandidateReviewOutcomeRow[] };

const ROUTE_RESPONSE_KEYS = ["items", "count"] as const;
const ROUTE_ITEM_KEYS = [
  "publication_key",
  "review_target_id",
  "command_sequence",
  "occurrence_count",
  "provenance",
  "review_status",
  "finalized_at_us",
] as const;
const OUTCOME_ITEM_KEYS = [
  "command_sequence",
  "occurrence_count",
  "provenance",
  "review_status",
  "decided_at_us",
] as const;
const LOADING_KEYS = ["status"] as const;
const UNAVAILABLE_KEYS = ["status"] as const;
const AVAILABLE_KEYS = ["status", "authenticated", "response"] as const;

const unavailable = (): CandidateReviewView => ({ status: "unavailable" });
const outcomeUnavailable = (): CandidateReviewOutcomesView => ({ status: "unavailable" });

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

function boundedText(value: unknown, maximum: number): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= maximum &&
    value === value.trim()
  );
}

function validCommand(value: unknown): value is string {
  return (
    boundedText(value, 128) &&
    !Array.from(value).some((character) => {
      const point = character.codePointAt(0) ?? 0;
      return point < 32 || point === 127;
    })
  );
}

const PUBLICATION_KEY_PATTERN =
  /^candidate-publication:1\.0:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const REVIEW_TARGET_PATTERN =
  /^candidate-skill:1\.0:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}:sha256:[a-f0-9]{64}$/;

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

function parseOutcomeResponse(value: unknown): CandidateReviewOutcomesView {
  if (!isPlainRecord(value) || !hasExactKeys(value, ROUTE_RESPONSE_KEYS)) {
    return outcomeUnavailable();
  }
  if (
    !Array.isArray(value.items) ||
    typeof value.count !== "number" ||
    !Number.isSafeInteger(value.count) ||
    value.count < 0 ||
    value.count > MAX_CANDIDATE_REVIEW_ITEMS ||
    value.count !== value.items.length
  ) {
    return outcomeUnavailable();
  }
  const rows: CandidateReviewOutcomeRow[] = [];
  for (let index = 0; index < value.items.length; index += 1) {
    const item = value.items[index];
    if (
      !isPlainRecord(item) ||
      !hasExactKeys(item, OUTCOME_ITEM_KEYS) ||
      !Array.isArray(item.command_sequence) ||
      item.command_sequence.length < 2 ||
      item.command_sequence.length > MAX_CANDIDATE_REVIEW_COMMANDS ||
      !item.command_sequence.every(validCommand) ||
      typeof item.occurrence_count !== "number" ||
      !Number.isSafeInteger(item.occurrence_count) ||
      item.occurrence_count !== item.command_sequence.length ||
      item.provenance !== "observed" ||
      !["approved", "rejected", "needs_changes"].includes(
        item.review_status as string,
      )
    ) {
      return outcomeUnavailable();
    }
    const decidedAt = finalizedTimestamp(item.decided_at_us);
    if (decidedAt === null) return outcomeUnavailable();
    rows.push({
      ordinal: index + 1,
      command_sequence: [...item.command_sequence],
      occurrence_count: item.occurrence_count,
      provenance: "observed",
      review_status: item.review_status as CandidateReviewOutcomeRow["review_status"],
      decided_at: decidedAt,
    });
  }
  return rows.length === 0 ? { status: "empty" } : { status: "populated", rows };
}

function parseRouteResponse(value: unknown): CandidateReviewView {
  if (!isPlainRecord(value) || !hasExactKeys(value, ROUTE_RESPONSE_KEYS)) {
    return unavailable();
  }

  const items = value.items;
  const count = value.count;
  if (
    !Array.isArray(items) ||
    typeof count !== "number" ||
    !Number.isSafeInteger(count) ||
    count < 0 ||
    count > MAX_CANDIDATE_REVIEW_ITEMS ||
    count !== items.length ||
    items.length > MAX_CANDIDATE_REVIEW_ITEMS
  ) {
    return unavailable();
  }

  const rows: CandidateReviewRow[] = [];
  const publicationKeys = new Set<string>();
  const reviewTargets = new Set<string>();
  for (let index = 0; index < items.length; index += 1) {
    const item = items[index];
    if (!isPlainRecord(item) || !hasExactKeys(item, ROUTE_ITEM_KEYS)) {
      return unavailable();
    }

    if (
      typeof item.publication_key !== "string" ||
      !PUBLICATION_KEY_PATTERN.test(item.publication_key) ||
      typeof item.review_target_id !== "string" ||
      !REVIEW_TARGET_PATTERN.test(item.review_target_id) ||
      publicationKeys.has(item.publication_key) ||
      reviewTargets.has(item.review_target_id) ||
      !Array.isArray(item.command_sequence) ||
      item.command_sequence.length < 2 ||
      item.command_sequence.length > MAX_CANDIDATE_REVIEW_COMMANDS ||
      !item.command_sequence.every(validCommand) ||
      typeof item.occurrence_count !== "number" ||
      !Number.isSafeInteger(item.occurrence_count) ||
      item.occurrence_count !== item.command_sequence.length ||
      item.provenance !== "observed" ||
      (item.review_status !== "unreviewed" && item.review_status !== "pending")
    ) {
      return unavailable();
    }

    const finalizedAt = finalizedTimestamp(item.finalized_at_us);
    if (finalizedAt === null) return unavailable();
    publicationKeys.add(item.publication_key);
    reviewTargets.add(item.review_target_id);

    rows.push({
      ordinal: index + 1,
      command_sequence: [...item.command_sequence],
      occurrence_count: item.occurrence_count,
      provenance: "observed",
      review_status: item.review_status,
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

/** Strictly redact the identifier-free terminal outcome route response. */
export function toCandidateReviewOutcomesView(input: unknown): CandidateReviewOutcomesView {
  try {
    if (
      !isPlainRecord(input) ||
      !hasExactKeys(input, AVAILABLE_KEYS) ||
      input.status !== "available" ||
      input.authenticated !== true
    ) {
      return outcomeUnavailable();
    }
    return parseOutcomeResponse(input.response);
  } catch {
    return outcomeUnavailable();
  }
}
