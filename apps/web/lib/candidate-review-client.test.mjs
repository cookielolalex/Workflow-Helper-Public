import assert from "node:assert/strict";
import test from "node:test";

import {
  CANDIDATE_REVIEW_QUEUE_PATH,
  MAX_CANDIDATE_REVIEW_CORRELATION_ID_LENGTH,
  MAX_CANDIDATE_REVIEW_CURSOR_LENGTH,
  buildCandidateReviewRequest,
  readCandidateReview,
} from "./candidate-review-client.ts";

const PUBLICATION_KEY =
  "candidate-publication:1.0:01234567-89ab-4def-8123-456789abcdef";
const REVIEW_TARGET =
  "candidate-skill:1.0:fedcba98-7654-4321-8765-ba9876543210:sha256:" +
  "a".repeat(64);

function item(overrides = {}) {
  return {
    publication_key: PUBLICATION_KEY,
    review_target_id: REVIEW_TARGET,
    command_sequence: ["LINE", "TRIM", "LINE", "TRIM"],
    occurrence_count: 4,
    provenance: "observed",
    approval_status: "unreviewed",
    finalized_at_us: 1_000_000_000,
    ...overrides,
  };
}

function routeResponse(items = [item()], count = items.length) {
  return { items, count };
}

function response(status, body) {
  return { status, body };
}

function readWith(body, status = 200) {
  return readCandidateReview(
    (request) => {
      assert.equal(request.path, CANDIDATE_REVIEW_QUEUE_PATH);
      assert.equal(request.method, "GET");
      return response(status, body);
    },
    { correlation_id: "corr-client", limit: 100 },
  );
}

test("descriptor uses only the fixed review-queue route", () => {
  assert.deepEqual(buildCandidateReviewRequest("corr-client", 100), {
    path: CANDIDATE_REVIEW_QUEUE_PATH,
    method: "GET",
    correlation_id: "corr-client",
    limit: 100,
  });
  assert.deepEqual(
    buildCandidateReviewRequest({
      correlation_id: "corr-client",
      limit: 1,
      cursor: "opaque-server-cursor",
    }),
    {
      path: CANDIDATE_REVIEW_QUEUE_PATH,
      method: "GET",
      correlation_id: "corr-client",
      limit: 1,
      cursor: "opaque-server-cursor",
    },
  );
});

test("invalid request bounds do not invoke transport", () => {
  let calls = 0;
  const transport = () => {
    calls += 1;
    return response(200, routeResponse([]));
  };
  for (const input of [
    { correlation_id: "", limit: 1 },
    { correlation_id: "x".repeat(MAX_CANDIDATE_REVIEW_CORRELATION_ID_LENGTH + 1), limit: 1 },
    { correlation_id: "corr", limit: 0 },
    { correlation_id: "corr", limit: 101 },
    { correlation_id: "corr", limit: 1.5 },
    { correlation_id: "corr", limit: 1, cursor: "" },
    { correlation_id: "corr", limit: 1, cursor: "x".repeat(MAX_CANDIDATE_REVIEW_CURSOR_LENGTH + 1) },
  ]) {
    assert.deepEqual(readCandidateReview(transport, input), {
      status: "unavailable",
    });
  }
  assert.equal(calls, 0);
});

test("strict 200 response becomes the redacted informed view", () => {
  const view = readWith(routeResponse());
  assert.deepEqual(view, {
    status: "populated",
    rows: [
      {
        ordinal: 1,
        command_sequence: ["LINE", "TRIM", "LINE", "TRIM"],
        occurrence_count: 4,
        provenance: "observed",
        approval_status: "unreviewed",
        finalized_at: "1970-01-01T00:16:40.000Z",
      },
    ],
  });
  const serialized = JSON.stringify(view);
  assert.equal(serialized.includes(PUBLICATION_KEY), false);
  assert.equal(serialized.includes(REVIEW_TARGET), false);
});

test("empty is distinct from malformed and non-200 responses", () => {
  assert.deepEqual(readWith(routeResponse([])), { status: "empty" });
  for (const body of [
    null,
    {},
    { items: [], count: 0, extra: "private" },
    routeResponse([item({ approval_status: "approved" })]),
    routeResponse([item()], 0),
  ]) {
    assert.deepEqual(readWith(body), { status: "unavailable" });
  }
  for (const status of [401, 403, 404, 422, 500, 503]) {
    assert.deepEqual(readWith({ detail: "private" }, status), {
      status: "unavailable",
    });
  }
});

test("transport failures and asynchronous envelopes fail closed", () => {
  assert.deepEqual(
    readCandidateReview(
      () => {
        throw new Error("private transport detail");
      },
      { correlation_id: "corr", limit: 1 },
    ),
    { status: "unavailable" },
  );
  assert.deepEqual(
    readCandidateReview(
      () => Promise.resolve(response(200, routeResponse())),
      { correlation_id: "corr", limit: 1 },
    ),
    { status: "unavailable" },
  );
});
