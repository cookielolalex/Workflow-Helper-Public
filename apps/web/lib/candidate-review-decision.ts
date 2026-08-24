/**
 * A deliberately small, synchronous seam for the synthetic candidate-review
 * decision preview.
 *
 * This module knows only generated ordinals and the three review actions.  A
 * caller supplies the transport; no browser or server transport is created
 * here.  Every value crossing that seam is checked as an exact, bounded plain
 * object before it can affect the state machine.
 */

export const CANDIDATE_REVIEW_ACTIONS = [
  "approved",
  "rejected",
  "needs_changes",
] as const;

export type CandidateReviewAction = (typeof CANDIDATE_REVIEW_ACTIONS)[number];

export const CANDIDATE_REVIEW_DECISION_STATUSES = [
  "ready",
  "pending",
  "success",
  "conflict",
  "unavailable",
] as const;

export type CandidateReviewDecisionStatus =
  (typeof CANDIDATE_REVIEW_DECISION_STATUSES)[number];

export const MAX_CANDIDATE_REVIEW_ORDINAL = 100 as const;

export type CandidateReviewDecisionRequest = {
  readonly candidate_ordinal: number;
  readonly action: CandidateReviewAction;
};

export type CandidateReviewDecisionResponse = {
  readonly status: Exclude<CandidateReviewDecisionStatus, "ready" | "pending">;
  readonly action: CandidateReviewAction;
};

export type CandidateReviewDecisionTransport = (
  request: CandidateReviewDecisionRequest,
) => unknown;

export type CandidateReviewDecisionState =
  | {
      readonly ordinal: number;
      readonly status: "ready" | "pending";
    }
  | {
      readonly ordinal: number;
      readonly status: "success";
      readonly action: CandidateReviewAction;
    }
  | {
      readonly ordinal: number;
      readonly status: "conflict" | "unavailable";
    };

export type CandidateReviewDecisionController = {
  readonly getState: (candidateOrdinal: unknown) => CandidateReviewDecisionState;
  readonly getStates: () => readonly CandidateReviewDecisionState[];
  readonly dispatch: (
    candidateOrdinal: unknown,
    action: unknown,
  ) => CandidateReviewDecisionState;
};

export type CandidateReviewDecisionControllerOptions = {
  readonly transport: CandidateReviewDecisionTransport;
  readonly candidateOrdinals?: readonly number[];
};

const REQUEST_KEYS = ["candidate_ordinal", "action"] as const;
const RESPONSE_KEYS = ["status", "action"] as const;
const TERMINAL_STATUSES = ["success", "conflict", "unavailable"] as const;

type TerminalStatus = (typeof TERMINAL_STATUSES)[number];

const FALLBACK_ORDINAL = 0;

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object") return false;
  try {
    if (Array.isArray(value)) return false;
    return Object.getPrototypeOf(value) === Object.prototype;
  } catch {
    return false;
  }
}

function hasExactKeys<T extends readonly string[]>(
  value: Record<string, unknown>,
  expected: T,
): boolean {
  try {
    const ownKeys = Reflect.ownKeys(value);
    if (ownKeys.length !== expected.length) return false;
    for (const key of ownKeys) {
      if (typeof key !== "string" || !expected.includes(key)) return false;
    }
    for (const key of expected) {
      if (!Object.prototype.propertyIsEnumerable.call(value, key)) return false;
    }
    return true;
  } catch {
    return false;
  }
}

function isCandidateOrdinal(value: unknown): value is number {
  return (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= 1 &&
    value <= MAX_CANDIDATE_REVIEW_ORDINAL
  );
}

function isCandidateReviewAction(value: unknown): value is CandidateReviewAction {
  return (
    typeof value === "string" &&
    (value === "approved" ||
      value === "rejected" ||
      value === "needs_changes")
  );
}

function isTerminalStatus(value: unknown): value is TerminalStatus {
  return (
    value === "success" || value === "conflict" || value === "unavailable"
  );
}

function state(
  ordinal: number,
  status: "ready" | "pending" | "conflict" | "unavailable",
): CandidateReviewDecisionState {
  return Object.freeze({ ordinal, status });
}

function successState(
  ordinal: number,
  action: CandidateReviewAction,
): CandidateReviewDecisionState {
  return Object.freeze({ ordinal, status: "success" as const, action });
}

function unavailableState(ordinal: number): CandidateReviewDecisionState {
  return state(ordinal, "unavailable");
}

function isThenable(value: unknown): boolean {
  if (
    value === null ||
    (typeof value !== "object" && typeof value !== "function")
  ) {
    return false;
  }
  try {
    return typeof (value as { then?: unknown }).then === "function";
  } catch {
    // A hostile then getter is indistinguishable from an unavailable
    // asynchronous result and must never be invoked.
    return true;
  }
}

function makeRequest(
  candidateOrdinal: unknown,
  action: unknown,
): CandidateReviewDecisionRequest | null {
  if (!isCandidateOrdinal(candidateOrdinal) || !isCandidateReviewAction(action)) {
    return null;
  }

  // The request is created here, rather than accepting caller-owned data, so
  // it always has the one bounded shape allowed at the transport boundary.
  return Object.freeze({
    candidate_ordinal: candidateOrdinal,
    action,
  });
}

function validRequest(value: unknown): value is CandidateReviewDecisionRequest {
  try {
    return (
      isPlainRecord(value) &&
      hasExactKeys(value, REQUEST_KEYS) &&
      isCandidateOrdinal(value.candidate_ordinal) &&
      isCandidateReviewAction(value.action)
    );
  } catch {
    return false;
  }
}

function parseResponse(
  value: unknown,
  requestedAction: CandidateReviewAction,
): CandidateReviewDecisionResponse | null {
  try {
    if (isThenable(value) || !isPlainRecord(value)) return null;
    if (!hasExactKeys(value, RESPONSE_KEYS)) return null;

    const responseStatus = value.status;
    const responseAction = value.action;
    if (
      !isTerminalStatus(responseStatus) ||
      !isCandidateReviewAction(responseAction) ||
      responseAction !== requestedAction
    ) {
      return null;
    }

    return Object.freeze({
      status: responseStatus,
      action: responseAction,
    });
  } catch {
    return null;
  }
}

function normalizedOrdinals(value: unknown): number[] {
  if (value === undefined) return [1];
  if (!Array.isArray(value) || value.length < 1 || value.length > MAX_CANDIDATE_REVIEW_ORDINAL) {
    return [];
  }

  const result: number[] = [];
  const seen = new Set<number>();
  for (const ordinal of value) {
    if (!isCandidateOrdinal(ordinal) || seen.has(ordinal)) return [];
    seen.add(ordinal);
    result.push(ordinal);
  }
  return result;
}

function optionParts(
  optionsOrTransport:
    | CandidateReviewDecisionControllerOptions
    | CandidateReviewDecisionTransport,
  fallbackOrdinals: unknown,
): {
  readonly transport: CandidateReviewDecisionTransport | null;
  readonly ordinals: number[];
} {
  if (typeof optionsOrTransport === "function") {
    return {
      transport: optionsOrTransport,
      ordinals: normalizedOrdinals(fallbackOrdinals),
    };
  }

  if (!isPlainRecord(optionsOrTransport)) {
    return { transport: null, ordinals: [] };
  }

  try {
    const transport = optionsOrTransport.transport;
    const ordinals = optionsOrTransport.candidateOrdinals;
    return {
      transport: typeof transport === "function" ? transport : null,
      ordinals: normalizedOrdinals(ordinals),
    };
  } catch {
    return { transport: null, ordinals: [] };
  }
}

/**
 * Create a per-candidate decision controller.
 *
 * The controller records `pending` before invoking the injected transport.
 * That ordering makes a synchronous re-entrant call observe the pending
 * state, so it cannot dispatch a duplicate decision for the same candidate.
 */
export function createCandidateReviewDecisionController(
  optionsOrTransport:
    | CandidateReviewDecisionControllerOptions
    | CandidateReviewDecisionTransport,
  candidateOrdinals?: readonly number[],
): CandidateReviewDecisionController {
  const parts = optionParts(optionsOrTransport, candidateOrdinals);
  const transport = parts.transport;
  const states = new Map<number, CandidateReviewDecisionState>();
  for (const ordinal of parts.ordinals) {
    states.set(ordinal, state(ordinal, "ready"));
  }

  const unavailableForUnknown = (): CandidateReviewDecisionState =>
    unavailableState(FALLBACK_ORDINAL);

  const getState = (candidateOrdinal: unknown): CandidateReviewDecisionState => {
    try {
      if (!isCandidateOrdinal(candidateOrdinal)) return unavailableForUnknown();
      return states.get(candidateOrdinal) ?? unavailableForUnknown();
    } catch {
      return unavailableForUnknown();
    }
  };

  const getStates = (): readonly CandidateReviewDecisionState[] => {
    try {
      return Object.freeze([...states.values()]);
    } catch {
      return Object.freeze([]);
    }
  };

  const dispatch = (
    candidateOrdinal: unknown,
    action: unknown,
  ): CandidateReviewDecisionState => {
    let ordinal = FALLBACK_ORDINAL;
    try {
      if (!isCandidateOrdinal(candidateOrdinal)) return unavailableForUnknown();
      ordinal = candidateOrdinal;
      const current = states.get(ordinal);
      if (current === undefined) return unavailableForUnknown();

      // Invalid input and every terminal state are fail-closed and terminal.
      // In particular, this also makes conflict/unavailable non-retryable.
      if (current.status !== "ready") return current;
      const request = makeRequest(ordinal, action);
      if (request === null || transport === null) {
        const terminal = unavailableState(ordinal);
        states.set(ordinal, terminal);
        return terminal;
      }

      // Mark pending before the call.  A transport may synchronously re-enter
      // this controller; that call then sees pending and cannot duplicate it.
      const pending = state(ordinal, "pending");
      states.set(ordinal, pending);

      let rawResponse: unknown;
      try {
        if (!validRequest(request)) throw new Error("invalid request");
        rawResponse = transport(request);
      } catch {
        const terminal = unavailableState(ordinal);
        states.set(ordinal, terminal);
        return terminal;
      }

      const response = parseResponse(rawResponse, request.action);
      if (response === null) {
        const terminal = unavailableState(ordinal);
        states.set(ordinal, terminal);
        return terminal;
      }

      if (response.status === "success") {
        const terminal = successState(ordinal, response.action);
        states.set(ordinal, terminal);
        return terminal;
      }

      const terminal = state(ordinal, response.status);
      states.set(ordinal, terminal);
      return terminal;
    } catch {
      // No thrown transport, getter, proxy, or malformed value crosses the
      // seam.  If an ordinal was already pending, make it terminal generic.
      if (typeof ordinal === "number" && isCandidateOrdinal(ordinal)) {
        const terminal = unavailableState(ordinal);
        states.set(ordinal, terminal);
        return terminal;
      }
      return unavailableForUnknown();
    }
  };

  return Object.freeze({ getState, getStates, dispatch });
}

/** Alias with a shorter name for callers that treat the controller as a seam. */
export const createCandidateReviewDecision =
  createCandidateReviewDecisionController;

/** Alias retained for a reducer-like call site. */
export const createCandidateReviewDecisionSeam =
  createCandidateReviewDecisionController;

/**
 * Run one isolated decision through the same guarded state machine.
 *
 * This convenience function is synchronous and returns the terminal state;
 * callers that need to observe `pending` during a transport call should keep
 * the controller returned by `createCandidateReviewDecisionController`.
 */
export function dispatchCandidateReviewDecision(
  transport: CandidateReviewDecisionTransport,
  candidateOrdinal: unknown,
  action: unknown,
): CandidateReviewDecisionState {
  const controller = createCandidateReviewDecisionController(transport, [
    candidateOrdinal as number,
  ]);
  return controller.dispatch(candidateOrdinal, action);
}

export const decideCandidateReview = dispatchCandidateReviewDecision;
export const submitCandidateReviewDecision = dispatchCandidateReviewDecision;
