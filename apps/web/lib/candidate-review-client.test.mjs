import assert from "node:assert/strict";
import test from "node:test";

import {
  CANDIDATE_PUBLICATIONS_PATH,
  MAX_CANDIDATE_REVIEW_CORRELATION_ID_LENGTH,
  MAX_CANDIDATE_REVIEW_CURSOR_LENGTH,
  MAX_CANDIDATE_REVIEW_LIMIT,
  MIN_CANDIDATE_REVIEW_LIMIT,
  buildCandidateReviewRequest,
  readCandidateReview,
} from "./candidate-review-client.ts";

function item(overrides = {}) {
  return {
    publication_key: "candidate-publication:client-sentinel",
    schema_version: "1.0",
    job_id: "job-client-sentinel",
    session_id: "session-client-sentinel",
    source_result_sha256: "source-client-sentinel",
    derivation_evidence_sha256: "evidence-client-sentinel",
    review_target_id: "review-client-sentinel",
    content_sha256: "content-client-sentinel",
    full_sha256: "full-client-sentinel",
    publication_identity: "identity-client-sentinel",
    byte_length: 123,
    state: "finalized",
    finalized_at_us: 1_000_000_000,
    ...overrides,
  };
}

function routeResponse(items = [item()], count = items.length, next_cursor = null) {
  return { items, count, next_cursor };
}

function response(status, body) {
  return { status, body };
}

function strictAvailable(body) {
  return { status: "available", authenticated: true, response: body };
}

function readWith(body, status = 200, input = { correlation_id: "corr-client", limit: 1 }) {
  return readCandidateReview(
    (request) => {
      assert.equal(request.path, CANDIDATE_PUBLICATIONS_PATH);
      assert.equal(request.method, "GET");
      return response(status, body);
    },
    input,
  );
}

test("request descriptor is fixed, bounded, and omits an absent cursor", () => {
  const seen = [];
  const transport = (request) => {
    seen.push(request);
    return response(401, { private: "sentinel" });
  };

  assert.deepEqual(
    readCandidateReview(transport, {
      correlation_id: "corr-client",
      limit: MIN_CANDIDATE_REVIEW_LIMIT,
    }),
    { status: "unavailable" },
  );
  assert.deepEqual(
    readCandidateReview(transport, {
      correlation_id: "corr-client",
      limit: MAX_CANDIDATE_REVIEW_LIMIT,
    }),
    { status: "unavailable" },
  );

  assert.deepEqual(seen, [
    {
      path: CANDIDATE_PUBLICATIONS_PATH,
      method: "GET",
      correlation_id: "corr-client",
      limit: MIN_CANDIDATE_REVIEW_LIMIT,
    },
    {
      path: CANDIDATE_PUBLICATIONS_PATH,
      method: "GET",
      correlation_id: "corr-client",
      limit: MAX_CANDIDATE_REVIEW_LIMIT,
    },
  ]);
  for (const request of seen) {
    assert.deepEqual(Object.keys(request), [
      "path",
      "method",
      "correlation_id",
      "limit",
    ]);
    assert.equal("body" in request, false);
    assert.equal("headers" in request, false);
    assert.equal("url" in request, false);
  }
});

test("invalid correlation, limit, and cursor bounds do not invoke the transport", () => {
  let calls = 0;
  const transport = () => {
    calls += 1;
    return response(200, routeResponse([]));
  };

  const invalidInputs = [
    { correlation_id: "", limit: 1 },
    {
      correlation_id: "x".repeat(MAX_CANDIDATE_REVIEW_CORRELATION_ID_LENGTH + 1),
      limit: 1,
    },
    { correlation_id: "corr-client", limit: 0 },
    { correlation_id: "corr-client", limit: 101 },
    { correlation_id: "corr-client", limit: 1.5 },
    { correlation_id: "corr-client", limit: Number.NaN },
    { correlation_id: "corr-client", limit: 1, cursor: "" },
    {
      correlation_id: "corr-client",
      limit: 1,
      cursor: "x".repeat(MAX_CANDIDATE_REVIEW_CURSOR_LENGTH + 1),
    },
  ];

  for (const input of invalidInputs) {
    assert.deepEqual(readCandidateReview(transport, input), {
      status: "unavailable",
    });
  }
  assert.equal(calls, 0);

  assert.equal(buildCandidateReviewRequest("corr-client", 1)?.method, "GET");
  assert.equal(buildCandidateReviewRequest("corr-client", 101), null);
});

test("opaque cursor is forwarded only in the fixed descriptor and never in the view", () => {
  const cursor = "opaque-cursor-client-sentinel";
  let seen;
  const view = readCandidateReview(
    (request) => {
      seen = request;
      return response(200, routeResponse([item()]));
    },
    { correlation_id: "corr-client", limit: 1, cursor },
  );

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
  assert.deepEqual(seen, {
    path: CANDIDATE_PUBLICATIONS_PATH,
    method: "GET",
    correlation_id: "corr-client",
    limit: 1,
    cursor,
  });
  assert.equal(JSON.stringify(view).includes(cursor), false);
  assert.equal(JSON.stringify(view).includes("next_cursor"), false);
});

test("thrown transport failures and every non-200 status are exactly unavailable", () => {
  const throwing = readCandidateReview(
    () => {
      throw new Error("private exception sentinel");
    },
    { correlation_id: "corr-client", limit: 1 },
  );
  assert.deepEqual(throwing, { status: "unavailable" });
  assert.equal(JSON.stringify(throwing), '{"status":"unavailable"}');

  for (const status of [401, 403, 404, 422, 500, 503, 599]) {
    assert.deepEqual(
      readWith({ detail: "private status sentinel" }, status),
      { status: "unavailable" },
    );
  }
});

test("only strict authenticated 200 bodies preserve empty or populated", () => {
  assert.deepEqual(readWith(routeResponse([])), { status: "empty" });
  assert.deepEqual(readWith(routeResponse([item()])), {
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

  for (const body of [
    null,
    {},
    { items: [], count: 0, next_cursor: null, extra: "sentinel" },
    routeResponse([item({ state: "reserved" })]),
    routeResponse([item({ byte_length: 0 })]),
    routeResponse([item()], 0),
    { items: "not-an-array", count: 0, next_cursor: null },
  ]) {
    const view = readWith(body);
    assert.deepEqual(view, { status: "unavailable" });
    assert.notEqual(view.status, "empty");
  }
});

test("malformed 200 envelopes and adapter failures stay generic", () => {
  for (const malformed of [
    null,
    {},
    { status: "200", body: routeResponse([]) },
    { status: 200 },
    { status: 200, body: routeResponse([]), private_detail: "sentinel" },
  ]) {
    assert.deepEqual(
      readCandidateReview(
        () => malformed,
        { correlation_id: "corr-client", limit: 1 },
      ),
      { status: "unavailable" },
    );
  }

  const throwingBody = {};
  Object.defineProperty(throwingBody, "items", {
    enumerable: true,
    get() {
      throw new Error("private body detail sentinel");
    },
  });
  assert.deepEqual(readWith(throwingBody), { status: "unavailable" });
});

test("safe view never carries source, review, or storage sentinels", () => {
  const view = readWith(
    strictAvailable(routeResponse([
      item({ byte_length: 321 }),
    ])),
  );
  assert.deepEqual(view, { status: "unavailable" });

  const populated = readWith(routeResponse([item({ byte_length: 321 })]));
  assert.equal(populated.status, "populated");
  const serialized = JSON.stringify(populated);
  for (const sentinel of [
    "candidate-publication:client-sentinel",
    "job-client-sentinel",
    "session-client-sentinel",
    "source-client-sentinel",
    "evidence-client-sentinel",
    "review-client-sentinel",
    "content-client-sentinel",
    "full-client-sentinel",
    "identity-client-sentinel",
    '"state":"finalized"',
    '"state":"reserved"',
    "opaque-cursor-client-sentinel",
  ]) {
    assert.equal(serialized.includes(sentinel), false, sentinel);
  }
  assert.deepEqual(Object.keys(populated.rows[0]).sort(), [
    "byte_length",
    "finalized_at",
    "ordinal",
    "schema_version",
  ]);
});

test("non-synchronous or hidden thenable results fail closed immediately", () => {
  const nativePromise = Promise.resolve(
    response(200, routeResponse([item()])),
  );
  assert.deepEqual(
    readCandidateReview(
      () => nativePromise,
      { correlation_id: "corr-client", limit: 1 },
    ),
    { status: "unavailable" },
  );

  let inheritedResolution;
  const inherited = Object.create({
    status: 200,
    body: routeResponse([item()]),
    then(resolve) {
      inheritedResolution = resolve;
    },
  });
  assert.deepEqual(
    readCandidateReview(
      () => inherited,
      { correlation_id: "corr-client", limit: 1 },
    ),
    { status: "unavailable" },
  );
  assert.equal(inheritedResolution, undefined);

  let hiddenResolution;
  const hidden = new Proxy(
    {
      then(resolve) {
        hiddenResolution = resolve;
      },
    },
    {
      get(target, key, receiver) {
        if (key === "status") return 200;
        if (key === "body") return routeResponse([item()]);
        return Reflect.get(target, key, receiver);
      },
    },
  );
  assert.deepEqual(
    readCandidateReview(
      () => hidden,
      { correlation_id: "corr-client", limit: 1 },
    ),
    { status: "unavailable" },
  );
  assert.equal(hiddenResolution, undefined);
});

test("a status/body thenable envelope cannot bypass strict status handling", () => {
  let resolution;
  const forged = {
    status: 401,
    body: { detail: "private thenable sentinel" },
    then(resolve) {
      resolution = resolve;
    },
  };
  const result = readCandidateReview(
    () => forged,
    { correlation_id: "corr-client", limit: 1 },
  );

  assert.deepEqual(result, { status: "unavailable" });
  assert.equal(resolution, undefined);

  let nullPrototypeResolution;
  const nullPrototype = Object.create(null);
  nullPrototype.status = 401;
  nullPrototype.body = { detail: "private null-prototype sentinel" };
  nullPrototype.then = (resolve) => {
    nullPrototypeResolution = resolve;
  };

  let functionResolution;
  function functionEnvelope() {}
  functionEnvelope.status = 401;
  functionEnvelope.body = { detail: "private function sentinel" };
  functionEnvelope.then = (resolve) => {
    functionResolution = resolve;
  };

  for (const [envelope, resolutionSlot] of [
    [nullPrototype, () => nullPrototypeResolution],
    [functionEnvelope, () => functionResolution],
  ]) {
    const nested = readCandidateReview(
      () => envelope,
      { correlation_id: "corr-client", limit: 1 },
    );
    assert.deepEqual(nested, { status: "unavailable" });
    assert.equal(resolutionSlot(), undefined);
  }
});
