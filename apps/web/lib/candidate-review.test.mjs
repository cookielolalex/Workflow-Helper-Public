import assert from "node:assert/strict";
import test from "node:test";

import {
  MAX_CANDIDATE_REVIEW_BYTES,
  MAX_CANDIDATE_REVIEW_ITEMS,
  toCandidateReviewView,
} from "./candidate-review.ts";

function item(overrides = {}) {
  const value = {
    publication_key: "candidate-publication:synthetic",
    schema_version: "1.0",
    job_id: "job-synthetic",
    session_id: "session-synthetic",
    source_result_sha256: "source-sentinel",
    derivation_evidence_sha256: "evidence-sentinel",
    review_target_id: "review-target-sentinel",
    content_sha256: "content-digest-sentinel",
    full_sha256: "full-digest-sentinel",
    publication_identity: "identity-sentinel",
    byte_length: 123,
    state: "finalized",
    finalized_at_us: 1_000_000_000,
  };
  for (const [key, replacement] of Object.entries(overrides)) {
    value[key] = replacement;
  }
  return value;
}

function routeResponse(items = [item()], count = items.length, next_cursor = null) {
  return { items, count, next_cursor };
}

function available(response, authenticated = true) {
  return { status: "available", authenticated, response };
}

test("closed view union covers loading, unavailable, empty, and populated", () => {
  assert.deepEqual(toCandidateReviewView({ status: "loading" }), {
    status: "loading",
  });
  assert.deepEqual(toCandidateReviewView({ status: "unavailable" }), {
    status: "unavailable",
  });
  assert.deepEqual(toCandidateReviewView(available(routeResponse([]))), {
    status: "empty",
  });

  const view = toCandidateReviewView(available(routeResponse([item()])));
  assert.deepEqual(view, {
    status: "populated",
    rows: [
      {
        ordinal: 1,
        schema_version: "1.0",
        byte_length: 123,
        finalized_at: "1970-01-01T00:16:40.000Z",
      },
    ],
  });
});

test("strict root and item validation fails closed", () => {
  const malformed = [
    null,
    [],
    {},
    { status: "available", authenticated: true },
    available(null),
    available({ items: "not-an-array", count: 0, next_cursor: null }),
    available({ items: [null], count: 1, next_cursor: null }),
  ];

  for (const fixture of malformed) {
    assert.deepEqual(toCandidateReviewView(fixture), { status: "unavailable" });
  }

  const extraRoot = routeResponse([]);
  extraRoot.private_detail = "should not cross the boundary";
  assert.deepEqual(toCandidateReviewView(available(extraRoot)), {
    status: "unavailable",
  });

  const extraItem = item();
  extraItem.raw = "should not cross the boundary";
  assert.deepEqual(
    toCandidateReviewView(available(routeResponse([extraItem]))),
    { status: "unavailable" },
  );
});

test("wrong types, authority failure, non-finalized state, and count mismatch stay unavailable", () => {
  const wrongTypes = [
    available(routeResponse([item({ schema_version: 1 })])),
    available(routeResponse([item({ byte_length: "123" })])),
    available(routeResponse([item({ finalized_at_us: "1000000" })])),
    available(routeResponse([item({ state: "pending" })])),
    available(routeResponse([item()]), false),
    { status: "available", authenticated: "yes", response: routeResponse([]) },
    { status: "available", authenticated: true, response: routeResponse([item()], 0) },
    { status: "available", authenticated: true, response: routeResponse([], 0, 17) },
  ];

  for (const fixture of wrongTypes) {
    assert.deepEqual(toCandidateReviewView(fixture), { status: "unavailable" });
  }
});

test("the item bound is inclusive at 100 and rejects 101", () => {
  const items = [];
  for (let index = 0; index < MAX_CANDIDATE_REVIEW_ITEMS; index += 1) {
    items.push(item({ publication_key: `candidate-${index}` }));
  }
  const accepted = toCandidateReviewView(available(routeResponse(items)));
  assert.equal(accepted.status, "populated");
  if (accepted.status === "populated") {
    assert.equal(accepted.rows.length, MAX_CANDIDATE_REVIEW_ITEMS);
    assert.equal(accepted.rows[0].ordinal, 1);
    assert.equal(accepted.rows.at(-1).ordinal, MAX_CANDIDATE_REVIEW_ITEMS);
  }

  items.push(item({ publication_key: "candidate-over-bound" }));
  assert.deepEqual(toCandidateReviewView(available(routeResponse(items))), {
    status: "unavailable",
  });
});

test("cursor is validated and then dropped from the safe view", () => {
  const view = toCandidateReviewView(
    available(routeResponse([item()], 1, "opaque-cursor-sentinel")),
  );
  assert.equal(view.status, "populated");
  assert.equal(JSON.stringify(view).includes("opaque-cursor-sentinel"), false);
  assert.equal(JSON.stringify(view).includes("next_cursor"), false);
});

test("bounded bytes, generated ordinals, and forbidden source sentinels never cross", () => {
  const view = toCandidateReviewView(
    available(routeResponse([
      item({ byte_length: MAX_CANDIDATE_REVIEW_BYTES }),
      item({ publication_key: "second-sentinel", finalized_at_us: 2_000_000_000 }),
    ])),
  );
  assert.deepEqual(view, {
    status: "populated",
    rows: [
      {
        ordinal: 1,
        schema_version: "1.0",
        byte_length: MAX_CANDIDATE_REVIEW_BYTES,
        finalized_at: "1970-01-01T00:16:40.000Z",
      },
      {
        ordinal: 2,
        schema_version: "1.0",
        byte_length: 123,
        finalized_at: "1970-01-01T00:33:20.000Z",
      },
    ],
  });

  const serialized = JSON.stringify(view);
  for (const sentinel of [
    "candidate-publication:synthetic",
    "source-sentinel",
    "evidence-sentinel",
    "review-target-sentinel",
    "content-digest-sentinel",
    "full-digest-sentinel",
    "identity-sentinel",
    "job-synthetic",
    "session-synthetic",
  ]) {
    assert.equal(serialized.includes(sentinel), false, sentinel);
  }
  assert.equal(serialized.includes('"state":"finalized"'), false);
  assert.deepEqual(Object.keys(view.rows[0]).sort(), [
    "byte_length",
    "finalized_at",
    "ordinal",
    "schema_version",
  ]);
});

test("invalid input never becomes empty and raw errors remain generic", () => {
  const invalid = [
    { status: "available", authenticated: false, response: routeResponse([]) },
    { status: "available", authenticated: true, response: routeResponse([item({ state: "reserved" })]) },
    { status: "available", authenticated: true, response: routeResponse([item({ byte_length: 0 })]) },
    { status: "available", authenticated: true, response: routeResponse([item({ byte_length: MAX_CANDIDATE_REVIEW_BYTES + 1 })]) },
    { status: "available", authenticated: true, response: routeResponse([], 1) },
  ];
  for (const fixture of invalid) {
    assert.notEqual(toCandidateReviewView(fixture).status, "empty");
  }

  const throwing = {};
  Object.defineProperty(throwing, "status", { value: "available", enumerable: true });
  Object.defineProperty(throwing, "authenticated", { value: true, enumerable: true });
  Object.defineProperty(throwing, "response", {
    enumerable: true,
    get() {
      throw new Error("private raw detail");
    },
  });
  const generic = toCandidateReviewView(throwing);
  assert.deepEqual(generic, { status: "unavailable" });
  assert.equal(JSON.stringify(generic).includes("private raw detail"), false);
});
