/**
 * A dormant, synchronous seam for one synthetic candidate-review POST.
 *
 * The caller supplies both the public identifiers and the transport.  This
 * module never creates a network client, awaits a result, or exposes a server
 * response body.  Every object crossing the seam is checked as a bounded,
 * exact plain-object shape before it is used.
 */

const PUBLICATION_KEY_PATTERN =
  /^candidate-publication:1\.0:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const REVIEW_TARGET_PATTERN =
  /^candidate-skill:1\.0:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}:sha256:[a-f0-9]{64}$/;
const IDENTIFIER_PATTERN = /^[A-Za-z0-9._:-]+$/;

const REQUEST_REQUIRED_KEYS = [
  "review_target_id",
  "correlation_id",
  "idempotency_key",
  "status",
] as const;
const REQUEST_OPTIONAL_KEYS = ["reason", "evidence"] as const;
const REQUEST_ALLOWED_KEYS = [
  ...REQUEST_REQUIRED_KEYS,
  ...REQUEST_OPTIONAL_KEYS,
] as const;
const ENVELOPE_KEYS = ["status", "body"] as const;
const SUCCESS_BODY_KEYS = ["status"] as const;

export type CandidateReviewStatus =
  | "pending"
  | "approved"
  | "rejected"
  | "needs_changes";

export type CandidateReviewEvidenceValue =
  | string
  | number
  | boolean
  | null;

export type CandidateReviewEvidence = Readonly<
  Record<string, CandidateReviewEvidenceValue>
>;

export type CandidateReviewRequest = {
  readonly review_target_id: string;
  readonly correlation_id: string;
  readonly idempotency_key: string;
  readonly status: CandidateReviewStatus;
  readonly reason?: string | null;
  readonly evidence?: CandidateReviewEvidence | null;
};

export type CandidateReviewPostRequest = {
  readonly path: string;
  readonly method: "POST";
  readonly body: CandidateReviewRequest;
};

export type CandidateReviewPostTransport = (
  request: CandidateReviewPostRequest,
) => unknown;

export type CandidateReviewPostResult =
  | { readonly status: "success" }
  | { readonly status: "conflict" }
  | { readonly status: "unavailable" };

type DataDescriptor = PropertyDescriptor & { readonly value: unknown };

const SUCCESS: CandidateReviewPostResult = Object.freeze({
  status: "success",
});
const CONFLICT: CandidateReviewPostResult = Object.freeze({
  status: "conflict",
});
const UNAVAILABLE: CandidateReviewPostResult = Object.freeze({
  status: "unavailable",
});

function isFiniteNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

function isReviewStatus(value: unknown): value is CandidateReviewStatus {
  return (
    value === "pending" ||
    value === "approved" ||
    value === "rejected" ||
    value === "needs_changes"
  );
}

function isThenableShape(value: object): boolean {
  try {
    let current: object | null = value;
    while (current !== null) {
      const descriptor = Object.getOwnPropertyDescriptor(current, "then");
      if (descriptor !== undefined) {
        if (
          Object.prototype.hasOwnProperty.call(descriptor, "get") ||
          Object.prototype.hasOwnProperty.call(descriptor, "set")
        ) {
          return true;
        }
        return typeof descriptor.value === "function";
      }
      current = Object.getPrototypeOf(current);
    }
    return false;
  } catch {
    // A revoked proxy or hostile descriptor is unavailable, never callable.
    return true;
  }
}

function cloneProbe(value: object): boolean {
  try {
    // structuredClone rejects transparent and revoked proxies without
    // invoking a thenable.  It is deliberately used only after all accessors
    // have been rejected by descriptor inspection below.
    if (typeof structuredClone !== "function") return false;
    structuredClone(value);
    return true;
  } catch {
    return false;
  }
}

/**
 * Read an object's own enumerable data descriptors without invoking getters.
 * `allowed === null` means any string key is allowed; symbols are never.
 */
function ownDataRecord(
  value: unknown,
  allowed: readonly string[] | null,
  required: readonly string[],
  maxKeys?: number,
): Map<string, DataDescriptor> | null {
  if (value === null || typeof value !== "object") return null;

  try {
    if (
      Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype ||
      isThenableShape(value)
    ) {
      return null;
    }

    const ownKeys = Reflect.ownKeys(value);
    if (ownKeys.length < required.length) return null;
    if (maxKeys !== undefined && ownKeys.length > maxKeys) return null;
    if (allowed !== null && ownKeys.length > allowed.length) return null;

    const descriptors = new Map<string, DataDescriptor>();
    for (const key of ownKeys) {
      if (
        typeof key !== "string" ||
        (allowed !== null && !allowed.includes(key))
      ) {
        return null;
      }

      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (
        descriptor === undefined ||
        descriptor.enumerable !== true ||
        !Object.prototype.hasOwnProperty.call(descriptor, "value") ||
        Object.prototype.hasOwnProperty.call(descriptor, "get") ||
        Object.prototype.hasOwnProperty.call(descriptor, "set")
      ) {
        return null;
      }
      descriptors.set(key, descriptor as DataDescriptor);
    }

    for (const key of required) {
      if (!descriptors.has(key)) return null;
    }
    return descriptors;
  } catch {
    return null;
  }
}

/**
 * Check an opaque response body recursively without reading accessors.  The
 * conflict body is never returned, but hostile objects still fail closed.
 */
function safeOpaqueValue(
  value: unknown,
  seen = new WeakSet<object>(),
): boolean {
  if (value === null) return true;
  if (typeof value === "string" || typeof value === "boolean") return true;
  if (isFiniteNumber(value)) return true;
  if (typeof value !== "object") return false;

  try {
    if (seen.has(value)) return true;
    seen.add(value);
    const descriptors = ownDataRecord(value, null, []);
    if (descriptors === null) return false;
    for (const descriptor of descriptors.values()) {
      if (!safeOpaqueValue(descriptor.value, seen)) return false;
    }
    return cloneProbe(value);
  } catch {
    return false;
  }
}

function validBoundedIdentifier(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length >= 1 &&
    value.length <= 128 &&
    IDENTIFIER_PATTERN.test(value)
  );
}

function validPublicationKey(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length >= 1 &&
    value.length <= 128 &&
    PUBLICATION_KEY_PATTERN.test(value)
  );
}

function validReviewTarget(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length >= 1 &&
    value.length <= 256 &&
    REVIEW_TARGET_PATTERN.test(value)
  );
}

function validReason(value: unknown): value is string | null {
  return value === null || (typeof value === "string" && value.length <= 512);
}

function validEvidenceValue(value: unknown): value is CandidateReviewEvidenceValue {
  return (
    value === null ||
    typeof value === "boolean" ||
    isFiniteNumber(value) ||
    (typeof value === "string" && value.length <= 512)
  );
}

function copyEvidence(
  descriptors: Map<string, DataDescriptor>,
): CandidateReviewEvidence | null {
  const copy: Record<string, CandidateReviewEvidenceValue> = {};
  try {
    for (const [key, descriptor] of descriptors) {
      Object.defineProperty(copy, key, {
        configurable: true,
        enumerable: true,
        value: descriptor.value as CandidateReviewEvidenceValue,
        writable: true,
      });
    }
    return Object.freeze(copy);
  } catch {
    return null;
  }
}

type ValidatedRequest = {
  readonly review_target_id: string;
  readonly correlation_id: string;
  readonly idempotency_key: string;
  readonly status: CandidateReviewStatus;
  readonly hasReason: boolean;
  readonly reason?: string | null;
  readonly hasEvidence: boolean;
  readonly evidence?: CandidateReviewEvidence | null;
};

function validateRequest(value: unknown): ValidatedRequest | null {
  const descriptors = ownDataRecord(
    value,
    REQUEST_ALLOWED_KEYS,
    REQUEST_REQUIRED_KEYS,
  );
  if (descriptors === null) return null;

  try {
    const reviewTarget = descriptors.get("review_target_id")!.value;
    const correlationId = descriptors.get("correlation_id")!.value;
    const idempotencyKey = descriptors.get("idempotency_key")!.value;
    const status = descriptors.get("status")!.value;
    if (
      !validReviewTarget(reviewTarget) ||
      !validBoundedIdentifier(correlationId) ||
      !validBoundedIdentifier(idempotencyKey) ||
      !isReviewStatus(status)
    ) {
      return null;
    }

    const reasonDescriptor = descriptors.get("reason");
    const hasReason = reasonDescriptor !== undefined;
    const reason = reasonDescriptor?.value;
    if (hasReason && !validReason(reason)) return null;

    const evidenceDescriptor = descriptors.get("evidence");
    const hasEvidence = evidenceDescriptor !== undefined;
    const evidenceValue = evidenceDescriptor?.value;
    let evidence: CandidateReviewEvidence | null | undefined;
    if (hasEvidence) {
      if (evidenceValue === null) {
        evidence = null;
      } else {
        const evidenceDescriptors = ownDataRecord(
          evidenceValue,
          null,
          [],
          20,
        );
        if (evidenceDescriptors === null) return null;
        for (const [key, descriptor] of evidenceDescriptors) {
          if (
            key.length < 1 ||
            key.length > 128 ||
            !IDENTIFIER_PATTERN.test(key) ||
            !validEvidenceValue(descriptor.value)
          ) {
            return null;
          }
        }
        evidence = copyEvidence(evidenceDescriptors);
        if (evidence === null) return null;
      }
    }

    // Reject a transparent proxy after descriptor validation, and reject
    // nested proxies/accessors before the clone probe can inspect them.
    if (!cloneProbe(value as object)) return null;
    if (hasEvidence && evidenceValue !== null) {
      if (!safeOpaqueValue(evidenceValue)) return null;
    }

    return {
      review_target_id: reviewTarget,
      correlation_id: correlationId,
      idempotency_key: idempotencyKey,
      status,
      hasReason,
      ...(hasReason ? { reason: reason as string | null } : {}),
      hasEvidence,
      ...(hasEvidence ? { evidence } : {}),
    };
  } catch {
    return null;
  }
}

/** Build the exact descriptor accepted by the injected POST transport. */
export function buildCandidateReviewPostRequest(
  publicationKey: unknown,
  request: unknown,
): CandidateReviewPostRequest | null {
  try {
    if (!validPublicationKey(publicationKey)) return null;
    const validated = validateRequest(request);
    if (validated === null) return null;

    const body: Record<string, unknown> = {
      review_target_id: validated.review_target_id,
      correlation_id: validated.correlation_id,
      idempotency_key: validated.idempotency_key,
      status: validated.status,
    };
    if (validated.hasReason) body.reason = validated.reason;
    if (validated.hasEvidence) body.evidence = validated.evidence;

    return Object.freeze({
      path: `/v1/control/candidate-publications/${encodeURIComponent(publicationKey)}/review`,
      method: "POST" as const,
      body: Object.freeze(body) as CandidateReviewRequest,
    });
  } catch {
    return null;
  }
}

function parseTransportResult(
  value: unknown,
  submittedStatus: CandidateReviewStatus,
): CandidateReviewPostResult {
  const descriptors = ownDataRecord(value, ENVELOPE_KEYS, ENVELOPE_KEYS);
  if (descriptors === null) return UNAVAILABLE;

  try {
    // This graph check rejects proxies, accessors, undefined values, arrays,
    // promises, thenables, and unsupported values without exposing details.
    if (!safeOpaqueValue(value)) return UNAVAILABLE;

    const status = descriptors.get("status")!.value;
    if (status === 409) return CONFLICT;
    if (status !== 200) return UNAVAILABLE;

    const body = descriptors.get("body")!.value;
    const successBody = ownDataRecord(
      body,
      SUCCESS_BODY_KEYS,
      SUCCESS_BODY_KEYS,
    );
    if (successBody === null || !cloneProbe(body as object)) {
      return UNAVAILABLE;
    }
    const returnedStatus = successBody.get("status")!.value;
    return returnedStatus === submittedStatus ? SUCCESS : UNAVAILABLE;
  } catch {
    return UNAVAILABLE;
  }
}

/** Submit exactly one synchronous request and return only its generic result. */
export function submitCandidateReview(
  transport: CandidateReviewPostTransport,
  publicationKey: unknown,
  request: unknown,
): CandidateReviewPostResult {
  if (typeof transport !== "function") return UNAVAILABLE;
  const descriptor = buildCandidateReviewPostRequest(publicationKey, request);
  if (descriptor === null) return UNAVAILABLE;

  try {
    const response = transport(descriptor);
    return parseTransportResult(response, descriptor.body.status);
  } catch {
    return UNAVAILABLE;
  }
}

export const postCandidateReview = submitCandidateReview;
