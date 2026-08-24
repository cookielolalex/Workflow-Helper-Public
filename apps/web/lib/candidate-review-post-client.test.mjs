import assert from "node:assert/strict";
import test from "node:test";

import {
  buildCandidateReviewPostRequest,
  postCandidateReview,
  submitCandidateReview,
} from "./candidate-review-post-client.ts";

const PUBLICATION_KEY =
  "candidate-publication:1.0:01234567-89ab-cdef-0123-456789abcdef";
const REVIEW_TARGET =
  "candidate-skill:1.0:fedcba98-7654-3210-fedc-ba9876543210:sha256:" +
  "a".repeat(64);
const EXPECTED_PATH =
  "/v1/control/candidate-publications/candidate-publication%3A1.0%3A01234567-89ab-cdef-0123-456789abcdef/review";

function request(overrides = {}) {
  return {
    review_target_id: REVIEW_TARGET,
    correlation_id: "corr-195",
    idempotency_key: "idem-195",
    status: "approved",
    ...overrides,
  };
}

function envelope(status, body) {
  return {
    status,
    body: arguments.length < 2 ? { status: "approved" } : body,
  };
}

function submit(response, input = request()) {
  return submitCandidateReview(() => response, PUBLICATION_KEY, input);
}

function assertUnavailableWithoutCall(input, publicationKey = PUBLICATION_KEY) {
  let calls = 0;
  assert.deepEqual(
    submitCandidateReview(
      () => {
        calls += 1;
        return envelope(200);
      },
      publicationKey,
      input,
    ),
    { status: "unavailable" },
  );
  assert.equal(calls, 0);
}

test("builds the exact encoded POST descriptor and invokes one transport", () => {
  const input = request();
  const descriptor = buildCandidateReviewPostRequest(PUBLICATION_KEY, input);
  assert.deepEqual(descriptor, {
    path: EXPECTED_PATH,
    method: "POST",
    body: input,
  });
  assert.deepEqual(Object.keys(descriptor), ["path", "method", "body"]);
  assert.deepEqual(Object.keys(descriptor.body), [
    "review_target_id",
    "correlation_id",
    "idempotency_key",
    "status",
  ]);
  assert.equal(Object.isFrozen(descriptor), true);
  assert.equal(Object.isFrozen(descriptor.body), true);

  let calls = 0;
  let seen;
  const result = postCandidateReview(
    (requestDescriptor) => {
      calls += 1;
      seen = requestDescriptor;
      return envelope(200);
    },
    PUBLICATION_KEY,
    input,
  );
  assert.deepEqual(result, { status: "success" });
  assert.equal(calls, 1);
  assert.deepEqual(seen, descriptor);
  assert.equal("headers" in seen, false);
  assert.equal("url" in seen, false);
  assert.equal("credentials" in seen, false);
});

test("preserves omitted versus explicit null optional fields", () => {
  const omitted = buildCandidateReviewPostRequest(PUBLICATION_KEY, request());
  assert.equal("reason" in omitted.body, false);
  assert.equal("evidence" in omitted.body, false);

  const explicitNull = buildCandidateReviewPostRequest(
    PUBLICATION_KEY,
    request({ reason: null, evidence: null }),
  );
  assert.equal("reason" in explicitNull.body, true);
  assert.equal(explicitNull.body.reason, null);
  assert.equal("evidence" in explicitNull.body, true);
  assert.equal(explicitNull.body.evidence, null);

  const evidence = { text: "kept", count: 2, enabled: true, missing: null };
  const withEvidence = buildCandidateReviewPostRequest(
    PUBLICATION_KEY,
    request({ reason: "human note", evidence }),
  );
  assert.deepEqual(withEvidence.body.evidence, evidence);
  assert.notEqual(withEvidence.body.evidence, evidence);
  assert.equal(withEvidence.body.reason, "human note");
});

test("accepts every API status and finite evidence value", () => {
  for (const status of ["pending", "approved", "rejected", "needs_changes"]) {
    const built = buildCandidateReviewPostRequest(
      PUBLICATION_KEY,
      request({ status, evidence: { s: "x", n: 1.5, b: false, z: null } }),
    );
    assert.equal(built.body.status, status);
  }
  const twenty = Object.fromEntries(
    Array.from({ length: 20 }, (_, index) => [`k${index}`, index]),
  );
  assert.ok(buildCandidateReviewPostRequest(PUBLICATION_KEY, request({ evidence: twenty })));
});

test("rejects publication key bounds and exact UUID-shaped pattern", () => {
  for (const publicationKey of [
    "",
    "candidate-publication:1.0:01234567-89ab-cdef-0123-456789abcde",
    "candidate-publication:1.0:01234567-89ab-cdef-0123-456789abcdef0",
    "candidate-publication:1.1:01234567-89ab-cdef-0123-456789abcdef",
    "Candidate-publication:1.0:01234567-89ab-cdef-0123-456789abcdef",
    "candidate-publication:1.0:01234567-89ab-cdef-0123-456789ABCDEf",
    "candidate-publication:1.0:01234567_89ab_cdef_0123_456789abcdef",
    null,
    1,
    [],
    new String(PUBLICATION_KEY),
  ]) {
    assert.equal(buildCandidateReviewPostRequest(publicationKey, request()), null);
  }
  assert.equal(
    buildCandidateReviewPostRequest(PUBLICATION_KEY, request()).path,
    EXPECTED_PATH,
  );
});

test("rejects review target bounds and exact candidate-skill/SHA pattern", () => {
  const invalidTargets = [
    "",
    "candidate-skill:1.0:01234567-89ab-cdef-0123-456789abcdef:sha256:" + "a".repeat(63),
    "candidate-skill:1.0:01234567-89ab-cdef-0123-456789abcdef:sha256:" + "a".repeat(65),
    REVIEW_TARGET.replace("candidate-skill:1.0", "candidate-skill:1.1"),
    REVIEW_TARGET.replace("sha256", "SHA256"),
    REVIEW_TARGET.replace("a".repeat(64), "A".repeat(64)),
    REVIEW_TARGET.replace("fedcba98", "fedcba9g"),
    REVIEW_TARGET + "x",
    null,
    {},
  ];
  for (const reviewTarget of invalidTargets) {
    assertUnavailableWithoutCall(request({ review_target_id: reviewTarget }));
  }
});

test("rejects required identifier bounds, patterns, and status values", () => {
  const invalidIdentifiers = [
    "",
    "x".repeat(129),
    "has space",
    "has/slash",
    "has?query",
    "has%percent",
    "é",
    undefined,
    null,
    1,
  ];
  for (const value of invalidIdentifiers) {
    assertUnavailableWithoutCall(request({ correlation_id: value }));
    assertUnavailableWithoutCall(request({ idempotency_key: value }));
  }
  for (const status of ["", "pending ", "success", "approved\0", null, 200, undefined]) {
    assertUnavailableWithoutCall(request({ status }));
  }
  assertUnavailableWithoutCall(request({ correlation_id: "x".repeat(129) }));
  assertUnavailableWithoutCall(request({ idempotency_key: "x".repeat(129) }));
});

test("enforces reason and evidence bounds, key pattern, and value types", () => {
  assertUnavailableWithoutCall(request({ reason: "x".repeat(513) }));
  assertUnavailableWithoutCall(request({ reason: 1 }));
  assertUnavailableWithoutCall(request({ reason: undefined }));

  const invalidEvidence = [
    undefined,
    [],
    Object.create(null),
    Promise.resolve({}),
    { "": "bad" },
    { "has space": "bad" },
    { ["x".repeat(129)]: "bad" },
    { x: undefined },
    { x: Number.NaN },
    { x: Number.POSITIVE_INFINITY },
    { x: 1n },
    { x: {} },
    { x: [] },
    { x: "x".repeat(513) },
  ];
  for (const evidence of invalidEvidence) {
    assertUnavailableWithoutCall(request({ evidence }));
  }
  const tooMany = Object.fromEntries(
    Array.from({ length: 21 }, (_, index) => [`k${index}`, true]),
  );
  assertUnavailableWithoutCall(request({ evidence: tooMany }));
  assertUnavailableWithoutCall(request({ evidence: { [Symbol("extra")]: true } }));
});

test("rejects extra, symbol, inherited, accessor, undefined, array, and null-prototype requests", () => {
  assertUnavailableWithoutCall({ ...request(), extra: "no" });
  assertUnavailableWithoutCall({ ...request(), [Symbol("extra")]: "no" });

  const inherited = Object.create(request());
  assertUnavailableWithoutCall(inherited);

  let getterCalls = 0;
  const accessor = request();
  Object.defineProperty(accessor, "reason", {
    enumerable: true,
    configurable: true,
    get() {
      getterCalls += 1;
      throw new Error("private accessor");
    },
  });
  assertUnavailableWithoutCall(accessor);
  assert.equal(getterCalls, 0);

  let evidenceGetterCalls = 0;
  const evidenceAccessor = request();
  Object.defineProperty(evidenceAccessor, "evidence", {
    enumerable: true,
    configurable: true,
    get() {
      evidenceGetterCalls += 1;
      throw new Error("private evidence accessor");
    },
  });
  assertUnavailableWithoutCall(evidenceAccessor);
  assert.equal(evidenceGetterCalls, 0);

  for (const invalid of [
    { ...request(), correlation_id: undefined },
    [],
    null,
    Object.create(null),
    Promise.resolve(request()),
  ]) {
    assertUnavailableWithoutCall(invalid);
  }
});

test("rejects request proxies, revoked proxies, and thenables without invoking them", () => {
  let thenCalls = 0;
  const thenable = {
    ...request(),
    then() {
      thenCalls += 1;
    },
  };
  assertUnavailableWithoutCall(thenable);
  assert.equal(thenCalls, 0);

  let proxyGetCalls = 0;
  const proxy = new Proxy(request(), {
    get() {
      proxyGetCalls += 1;
      throw new Error("proxy getter");
    },
  });
  assertUnavailableWithoutCall(proxy);
  assert.equal(proxyGetCalls, 0);

  const revocable = Proxy.revocable(request(), {});
  revocable.revoke();
  assertUnavailableWithoutCall(revocable.proxy);
});

test("maps a valid matching 200 to success and mismatch to unavailable", () => {
  for (const status of ["pending", "approved", "rejected", "needs_changes"]) {
    assert.deepEqual(
      submitCandidateReview(
        () => envelope(200, { status }),
        PUBLICATION_KEY,
        request({ status }),
      ),
      { status: "success" },
    );
    assert.deepEqual(
      submitCandidateReview(
        () => envelope(200, { status: status === "pending" ? "approved" : "pending" }),
        PUBLICATION_KEY,
        request({ status }),
      ),
      { status: "unavailable" },
    );
  }
});

test("maps 409 to generic conflict without exposing server details", () => {
  const result = submit(
    envelope(409, { detail: "private conflict detail", error: "secret" }),
  );
  assert.deepEqual(result, { status: "conflict" });
  assert.equal(JSON.stringify(result).includes("private"), false);
  assert.equal(JSON.stringify(result).includes("detail"), false);
  assert.equal(JSON.stringify(result).includes("secret"), false);
});

test("maps authentication, validation, server, and unknown statuses to unavailable", () => {
  for (const status of [401, 403, 422, 503, 201, 204, 404, 500, 599, 0, "409", null]) {
    assert.deepEqual(submit(envelope(status, { detail: "private" })), {
      status: "unavailable",
    });
  }
});

test("transport throws are generic, synchronous, and never retried", () => {
  let calls = 0;
  const result = submitCandidateReview(
    () => {
      calls += 1;
      throw new Error("private transport failure");
    },
    PUBLICATION_KEY,
    request(),
  );
  assert.deepEqual(result, { status: "unavailable" });
  assert.equal(calls, 1);
  assert.equal(JSON.stringify(result).includes("private"), false);
});

test("rejects malformed response envelopes without reading accessors or thenables", () => {
  for (const malformed of [
    null,
    undefined,
    {},
    { status: 200 },
    { body: { status: "approved" } },
    { status: 200, body: { status: "approved" }, extra: true },
    { status: 200, body: { status: "approved" }, [Symbol("extra")]: true },
    [],
    Object.create(null),
    Promise.resolve(envelope(200)),
    { status: 200, body: { status: "approved" }, then() {} },
    { status: 200, body: undefined },
    { status: undefined, body: { status: "approved" } },
  ]) {
    assert.deepEqual(submit(malformed), { status: "unavailable" });
  }

  let statusGetterCalls = 0;
  const accessor = { body: { status: "approved" } };
  Object.defineProperty(accessor, "status", {
    enumerable: true,
    get() {
      statusGetterCalls += 1;
      throw new Error("private response accessor");
    },
  });
  assert.deepEqual(submit(accessor), { status: "unavailable" });
  assert.equal(statusGetterCalls, 0);

  let bodyGetterCalls = 0;
  const bodyAccessorEnvelope = { status: 200 };
  Object.defineProperty(bodyAccessorEnvelope, "body", {
    enumerable: true,
    get() {
      bodyGetterCalls += 1;
      throw new Error("private response body accessor");
    },
  });
  assert.deepEqual(submit(bodyAccessorEnvelope), { status: "unavailable" });
  assert.equal(bodyGetterCalls, 0);

  const proxy = new Proxy(envelope(200), {
    get() {
      throw new Error("private response proxy getter");
    },
  });
  assert.deepEqual(submit(proxy), { status: "unavailable" });

  const revoked = Proxy.revocable(envelope(200), {});
  revoked.revoke();
  assert.deepEqual(submit(revoked.proxy), { status: "unavailable" });
});

test("rejects malformed success bodies without reading accessors or invoking thenables", () => {
  for (const [index, body] of [
    null,
    undefined,
    {},
    { status: "pending", extra: true },
    { status: "success" },
    { status: 200 },
    [],
    Object.create(null),
    Promise.resolve({ status: "approved" }),
    { status: "approved", then() {} },
    { status: undefined },
    { status: null },
  ].entries()) {
    assert.deepEqual(submit(envelope(200, body)), { status: "unavailable" }, `body ${index}`);
  }

  let bodyGetterCalls = 0;
  const accessorBody = {};
  Object.defineProperty(accessorBody, "status", {
    enumerable: true,
    get() {
      bodyGetterCalls += 1;
      throw new Error("private success body accessor");
    },
  });
  assert.deepEqual(submit(envelope(200, accessorBody)), {
    status: "unavailable",
  });
  assert.equal(bodyGetterCalls, 0);

  const proxyBody = new Proxy({ status: "approved" }, {
    get() {
      throw new Error("private success body proxy getter");
    },
  });
  assert.deepEqual(submit(envelope(200, proxyBody)), {
    status: "unavailable",
  });

  const revokedBody = Proxy.revocable({ status: "approved" }, {});
  revokedBody.revoke();
  assert.deepEqual(submit(envelope(200, revokedBody.proxy)), {
    status: "unavailable",
  });
});

test("rejects response proxies and thenables without invoking their then methods", () => {
  let envelopeThenCalls = 0;
  const envelopeThenable = {
    status: 200,
    body: { status: "approved" },
    then() {
      envelopeThenCalls += 1;
    },
  };
  assert.deepEqual(submit(envelopeThenable), { status: "unavailable" });
  assert.equal(envelopeThenCalls, 0);

  let bodyThenCalls = 0;
  const bodyThenable = {
    status: "approved",
    then() {
      bodyThenCalls += 1;
    },
  };
  assert.deepEqual(submit(envelope(200, bodyThenable)), {
    status: "unavailable",
  });
  assert.equal(bodyThenCalls, 0);
});

test("does not mutate caller input, including evidence", () => {
  const input = request({
    reason: null,
    evidence: { note: "original", count: 3 },
  });
  const before = structuredClone(input);
  const result = submitCandidateReview(
    (descriptor) => {
      assert.notEqual(descriptor.body.evidence, input.evidence);
      try {
        descriptor.body.evidence.note = "transport mutation";
      } catch {
        // The production descriptor is frozen; either way the input is safe.
      }
      return envelope(200);
    },
    PUBLICATION_KEY,
    input,
  );
  assert.deepEqual(result, { status: "success" });
  assert.deepEqual(input, before);
});

test("invalid input never invokes a retry or default transport", () => {
  let calls = 0;
  const invalid = request({ evidence: { bad: undefined } });
  const result = submitCandidateReview(
    () => {
      calls += 1;
      return envelope(200);
    },
    PUBLICATION_KEY,
    invalid,
  );
  assert.deepEqual(result, { status: "unavailable" });
  assert.equal(calls, 0);
});
