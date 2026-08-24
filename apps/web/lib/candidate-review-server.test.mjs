import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  candidateReviewRedirect,
  getSyntheticSessionRoute,
  loadCandidateReviewOutcomes,
  loadCandidateReviewQueue,
  parseCandidateReviewActionRequest,
  submitCandidateReviewAction,
} from "./candidate-review-server.ts";

const ORIGINAL_ENV = { ...process.env };
const PUBLICATION_KEY =
  "candidate-publication:1.0:01234567-89ab-4def-8123-456789abcdef";
const REVIEW_TARGET =
  "candidate-skill:1.0:fedcba98-7654-4321-8765-ba9876543210:sha256:" +
  "a".repeat(64);
const REVIEWER_PROOF = "reviewer-p3b-proof-abcdefghijklmnopqrstuvwxyz0123456789";
const REVIEWER_SESSION = Buffer.from(
  Array.from({ length: 32 }, (_, index) => index + 1),
).toString("base64url");
const REVIEWER_CSRF = Buffer.from(
  Array.from({ length: 32 }, (_, index) => index + 33),
).toString("base64url");
const SESSION_ID = "d6d9e5b7-c9bc-4eb1-ae4a-1a14ed5b1350";

test.afterEach(() => {
  process.env = { ...ORIGINAL_ENV };
});

function configure() {
  process.env.ENVIRONMENT = "development";
  process.env.WORKFLOW_REVIEW_API_BASE_URL = "http://api:8000";
  process.env.WORKFLOW_DEV_REVIEWER_PROOF = REVIEWER_PROOF;
  process.env.WORKFLOW_DEV_REVIEWER_SESSION = REVIEWER_SESSION;
  process.env.WORKFLOW_DEV_REVIEWER_CSRF = REVIEWER_CSRF;
  process.env.WORKFLOW_REVIEW_BROWSER_ORIGIN = "http://127.0.0.1:3000";
  process.env.WORKFLOW_REVIEW_BROWSER_HOST = "127.0.0.1:3000";
  process.env.NEXT_PUBLIC_API_BASE_URL = "https://must-not-be-used.invalid";
}

function item(reviewStatus = "unreviewed") {
  return {
    publication_key: PUBLICATION_KEY,
    review_target_id: REVIEW_TARGET,
    command_sequence: ["LINE", "TRIM", "LINE", "TRIM"],
    occurrence_count: 4,
    provenance: "observed",
    review_status: reviewStatus,
    finalized_at_us: 1_000_000,
  };
}

function jsonResponse(status, body, extraHeaders = {}) {
  const encoded = JSON.stringify(body);
  return new Response(encoded, {
    status,
    headers: {
      "content-length": String(Buffer.byteLength(encoded)),
      "content-type": "application/json",
      ...extraHeaders,
    },
  });
}

test("executes only fixed authenticated synthetic session GET descriptors", async () => {
  configure();
  const calls = [];
  const fetcher = async (url, init) => {
    calls.push({ url, init });
    return jsonResponse(200, { marker: calls.length });
  };

  assert.deepEqual(
    await getSyntheticSessionRoute({ route: "list" }, fetcher),
    { status: 200, body: { marker: 1 } },
  );
  assert.deepEqual(
    await getSyntheticSessionRoute(
      { route: "detail", session_id: SESSION_ID },
      fetcher,
    ),
    { status: 200, body: { marker: 2 } },
  );
  assert.deepEqual(
    await getSyntheticSessionRoute(
      { route: "timeline", session_id: SESSION_ID },
      fetcher,
    ),
    { status: 200, body: { marker: 3 } },
  );

  assert.deepEqual(
    calls.map(({ url }) => url),
    [
      "http://api:8000/v1/sessions",
      `http://api:8000/v1/sessions/${SESSION_ID}`,
      `http://api:8000/v1/sessions/${SESSION_ID}/timeline`,
    ],
  );
  for (const { init } of calls) {
    assert.equal(init.method, "GET");
    assert.equal(init.cache, "no-store");
    assert.equal(init.redirect, "error");
    assert.equal(init.credentials, "omit");
    assert.equal(init.headers.get("cookie"), `workflow_session=${REVIEWER_SESSION}`);
    assert.equal(init.headers.get("origin"), "https://review.synthetic.example");
    assert.equal(init.headers.get("x-workflow-dev-reviewer-proof"), REVIEWER_PROOF);
    assert.equal(init.headers.has("x-csrf-token"), false);
  }
});

test("session GET rejects arbitrary paths, malformed identities, and authority gaps", async () => {
  configure();
  let calls = 0;
  const fetcher = async () => {
    calls += 1;
    return jsonResponse(200, {});
  };
  const invalid = [
    { route: "arbitrary", path: "/v1/control" },
    { route: "list", session_id: SESSION_ID },
    { route: "detail" },
    { route: "detail", session_id: SESSION_ID.toUpperCase() },
    { route: "detail", session_id: "session-1" },
    { route: "timeline", session_id: `${SESSION_ID}?private=1` },
    Object.create({ route: "list" }),
  ];
  for (const descriptor of invalid) {
    assert.equal(await getSyntheticSessionRoute(descriptor, fetcher), null);
  }
  process.env.ENVIRONMENT = "production";
  assert.equal(
    await getSyntheticSessionRoute({ route: "list" }, fetcher),
    null,
  );
  assert.equal(calls, 0);
});

test("loads one redacted row through the existing synchronous GET validator", async () => {
  configure();
  const calls = [];
  const fetcher = async (url, init) => {
    calls.push({ url, init });
    return jsonResponse(200, { items: [item()], count: 1 });
  };

  const view = await loadCandidateReviewQueue(fetcher);

  assert.deepEqual(view, {
    status: "populated",
    rows: [
      {
        ordinal: 1,
        command_sequence: ["LINE", "TRIM", "LINE", "TRIM"],
        occurrence_count: 4,
        provenance: "observed",
        review_status: "unreviewed",
        finalized_at: "1970-01-01T00:00:01.000Z",
      },
    ],
  });
  assert.equal(calls.length, 1);
  assert.equal(
    calls[0].url,
    "http://api:8000/v1/control/candidate-publications/review-queue?correlation_id=web-candidate-review&limit=100",
  );
  assert.equal(calls[0].init.method, "GET");
  assert.equal(calls[0].init.redirect, "error");
  assert.equal(calls[0].init.cache, "no-store");
  assert.equal(calls[0].init.credentials, "omit");
  assert.equal(calls[0].init.headers.get("cookie"), `workflow_session=${REVIEWER_SESSION}`);
  assert.equal(calls[0].init.headers.get("x-workflow-dev-reviewer-proof"), REVIEWER_PROOF);
  assert.equal(JSON.stringify(view).includes(PUBLICATION_KEY), false);
  assert.equal(JSON.stringify(view).includes(REVIEW_TARGET), false);
  assert.equal(JSON.stringify(view).includes(REVIEWER_PROOF), false);
});

test("loads terminal outcomes through only the fixed authenticated server route", async () => {
  configure();
  const calls = [];
  const fetcher = async (url, init) => {
    calls.push({ url, init });
    return jsonResponse(200, {
      items: [{
        command_sequence: ["LINE", "TRIM", "LINE", "TRIM"],
        occurrence_count: 4,
        provenance: "observed",
        review_status: "needs_changes",
        decided_at_us: 2_000_000,
      }],
      count: 1,
    });
  };
  const view = await loadCandidateReviewOutcomes(fetcher);
  assert.equal(view.status, "populated");
  assert.equal(calls.length, 1);
  assert.equal(
    calls[0].url,
    "http://api:8000/v1/control/candidate-publications/review-outcomes",
  );
  assert.equal(calls[0].init.method, "GET");
  assert.equal(calls[0].init.headers.get("cookie"), `workflow_session=${REVIEWER_SESSION}`);
  assert.equal(calls[0].init.headers.get("x-workflow-dev-reviewer-proof"), REVIEWER_PROOF);
  const serialized = JSON.stringify(view);
  assert.equal(serialized.includes(PUBLICATION_KEY), false);
  assert.equal(serialized.includes(REVIEW_TARGET), false);
  assert.equal(serialized.includes(REVIEWER_PROOF), false);
});

test("each legal effective-state action re-fetches and posts exactly once", async () => {
  configure();
  for (const [reviewStatus, action, destination] of [
    ["unreviewed", "approve", "approved"],
    ["unreviewed", "start_review", "pending"],
    ["pending", "approve", "approved"],
    ["pending", "reject", "rejected"],
    ["pending", "needs_changes", "needs_changes"],
  ]) {
    const calls = [];
    const fetcher = async (url, init) => {
      calls.push({ url, init });
      return calls.length === 1
        ? jsonResponse(200, { items: [item(reviewStatus)], count: 1 })
        : jsonResponse(200, { status: destination });
    };
    assert.equal(await submitCandidateReviewAction(1, action, fetcher), "success");
    assert.equal(calls.length, 2);
    assert.equal(calls[1].init.method, "POST");
    assert.equal(calls[1].init.redirect, "error");
    assert.match(calls[1].url, /candidate-publication%3A1\.0%3A/);
    const body = JSON.parse(calls[1].init.body);
    assert.equal(body.review_target_id, REVIEW_TARGET);
    assert.equal(body.status, destination);
    assert.equal(body.correlation_id, "web-candidate-action");
    assert.match(body.idempotency_key, /^web-dev-[a-f0-9]{64}$/);
    assert.equal(calls[1].init.headers.get("origin"), "https://review.synthetic.example");
    assert.equal(calls[1].init.headers.get("x-csrf-token"), REVIEWER_CSRF);
  }
});

test("illegal effective-state transitions fail before the review POST", async () => {
  configure();
  for (const [reviewStatus, action] of [
    ["unreviewed", "reject"],
    ["unreviewed", "needs_changes"],
    ["pending", "start_review"],
  ]) {
    let calls = 0;
    const fetcher = async () => {
      calls += 1;
      return jsonResponse(200, { items: [item(reviewStatus)], count: 1 });
    };
    assert.equal(await submitCandidateReviewAction(1, action, fetcher), "unavailable");
    assert.equal(calls, 1);
  }
});

test("a control-store race remains a generic conflict after one POST", async () => {
  configure();
  let calls = 0;
  const fetcher = async () => {
    calls += 1;
    return calls === 1
      ? jsonResponse(200, { items: [item("pending")], count: 1 })
      : jsonResponse(409, { detail: "request conflicts with current state" });
  };

  assert.equal(await submitCandidateReviewAction(1, "reject", fetcher), "conflict");
  assert.equal(calls, 2);
});

test("malformed cached GET or POST responses fail closed without leaking details", async () => {
  configure();
  let calls = 0;
  const invalidList = async () => {
    calls += 1;
    return jsonResponse(200, {
      items: [{ ...item(), unexpected: "private" }],
      count: 1,
    });
  };
  assert.equal(await submitCandidateReviewAction(1, "approve", invalidList), "unavailable");
  assert.equal(calls, 1);

  calls = 0;
  const mismatchedPost = async () => {
    calls += 1;
    return calls === 1
      ? jsonResponse(200, { items: [item()], count: 1 })
      : jsonResponse(200, { status: "rejected", detail: "private" });
  };
  assert.equal(await submitCandidateReviewAction(1, "approve", mismatchedPost), "unavailable");
  assert.equal(calls, 2);
});

test("environment, API base, credentials, redirects, and byte bounds fail closed", async () => {
  configure();
  let calls = 0;
  const fetcher = async () => {
    calls += 1;
    return jsonResponse(200, { items: [], count: 0 });
  };
  for (const mutate of [
    () => { process.env.ENVIRONMENT = "production"; },
    () => { process.env.WORKFLOW_REVIEW_API_BASE_URL = "http://evil.example:8000"; },
    () => { process.env.WORKFLOW_DEV_REVIEWER_PROOF = "test"; },
    () => { process.env.WORKFLOW_DEV_REVIEWER_SESSION = "A".repeat(43); },
    () => { process.env.WORKFLOW_REVIEW_BROWSER_HOST = "localhost:3000"; },
  ]) {
    configure();
    mutate();
    assert.deepEqual(await loadCandidateReviewQueue(fetcher), { status: "unavailable" });
  }
  assert.equal(calls, 0);

  configure();
  const redirected = async () => {
    const response = jsonResponse(200, { items: [], count: 0 });
    Object.defineProperty(response, "redirected", { value: true });
    return response;
  };
  assert.deepEqual(await loadCandidateReviewQueue(redirected), { status: "unavailable" });

  const oversized = async () => jsonResponse(
    200,
    { items: [], count: 0 },
    { "content-length": "262145" },
  );
  assert.deepEqual(await loadCandidateReviewQueue(oversized), { status: "unavailable" });
});

function actionRequest(
  body,
  headers = {},
  url = "http://127.0.0.1:3000/candidate-review/action",
  method = "POST",
) {
  return new Request(url, {
    method,
    headers: {
      host: "127.0.0.1:3000",
      origin: "http://127.0.0.1:3000",
      "content-type": "application/x-www-form-urlencoded",
      "content-length": String(Buffer.byteLength(body)),
      ...headers,
    },
    ...(method === "GET" || method === "HEAD" ? {} : { body }),
  });
}

test("accepts only the exact same-origin two-field ordinal/action form", async () => {
  configure();
  assert.deepEqual(
    await parseCandidateReviewActionRequest(actionRequest("ordinal=1&action=approve")),
    { ordinal: 1, action: "approve" },
  );
  for (const action of ["start_review", "reject", "needs_changes"]) {
    assert.deepEqual(
      await parseCandidateReviewActionRequest(actionRequest(`ordinal=1&action=${action}`)),
      { ordinal: 1, action },
    );
  }
  assert.deepEqual(
    await parseCandidateReviewActionRequest(actionRequest("ordinal=100&action=approve")),
    { ordinal: 100, action: "approve" },
  );
  assert.deepEqual(
    await parseCandidateReviewActionRequest(
      actionRequest(
        "ordinal=1&action=approve",
        {},
        "http://web:3000/candidate-review/action",
      ),
    ),
    { ordinal: 1, action: "approve" },
  );

  for (const request of [
    actionRequest(
      "ordinal=1&action=approve",
      {},
      "http://web:3000/candidate-review",
    ),
    actionRequest(
      "ordinal=1&action=approve",
      {},
      "http://web:3000/candidate-review/action?next=private",
    ),
    actionRequest(
      "ordinal=1&action=approve",
      {},
      "http://web:3000/candidate-review/action",
      "GET",
    ),
    actionRequest("action=approve&ordinal=1"),
    actionRequest("ordinal=01&action=approve"),
    actionRequest("ordinal=1&action=approved"),
    actionRequest("ordinal=1&action=pending"),
    actionRequest("ordinal=1&action=approve&extra=x"),
    actionRequest("ordinal=candidate-publication%3A1.0%3Araw&action=approve"),
    actionRequest("ordinal=1&action=approve", { "content-type": "application/json" }),
    actionRequest("ordinal=1&action=approve", { cookie: "private=1" }),
    actionRequest("ordinal=1&action=approve", { authorization: "Bearer private" }),
    actionRequest("ordinal=1&action=approve", { origin: "http://localhost:3000" }),
    actionRequest("ordinal=1&action=approve", { host: "localhost:3000" }),
    actionRequest("ordinal=1&action=approve", { "x-workflow-dev-proof": "private" }),
    actionRequest("ordinal=1&action=approve", {
      "x-workflow-dev-reviewer-proof": "private",
    }),
    actionRequest("ordinal=1&action=approve", { "x-csrf-token": "private" }),
  ]) {
    assert.equal(await parseCandidateReviewActionRequest(request), null);
  }
});

test("live review page exposes actions only for their effective state", () => {
  const source = readFileSync(
    new URL("../app/candidate-review/page.tsx", import.meta.url),
    "utf-8",
  );
  assert.match(source, /name="action" value="approve"/);
  assert.match(source, /name="action" value="start_review"/);
  assert.match(source, /name="action" value="reject"/);
  assert.match(source, /name="action" value="needs_changes"/);
  assert.match(source, /row\.review_status === "unreviewed"/);
});

test("returns one fixed generic bodyless 303", async () => {
  const response = candidateReviewRedirect();
  assert.equal(response.status, 303);
  assert.equal(response.headers.get("location"), "/candidate-review");
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(response.headers.get("referrer-policy"), "no-referrer");
  assert.equal(await response.text(), "");
});
