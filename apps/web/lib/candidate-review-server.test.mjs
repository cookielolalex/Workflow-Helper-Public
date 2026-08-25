import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  candidateReviewRedirect,
  downloadApprovedWorkflow,
  getSyntheticSessionRoute,
  loadApprovedWorkflows,
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

function outcome(reviewStatus = "approved", overrides = {}) {
  return {
    command_sequence: ["LINE", "TRIM", "LINE", "TRIM"],
    occurrence_count: 4,
    provenance: "observed",
    review_status: reviewStatus,
    reason_code:
      reviewStatus === "approved"
        ? null
        : reviewStatus === "needs_changes"
          ? "evidence"
          : "sequence",
    decided_at_us: 2_000_000,
    ...overrides,
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
        reason_code: "evidence",
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

test("approved catalog strictly filters validated terminal outcomes", async () => {
  configure();
  const calls = [];
  const fetcher = async (url, init) => {
    calls.push({ url, init });
    return jsonResponse(200, {
      items: [outcome("rejected"), outcome("approved"), outcome("needs_changes")],
      count: 3,
    });
  };

  assert.deepEqual(await loadApprovedWorkflows(fetcher), {
    status: "populated",
    rows: [{
      ordinal: 1,
      command_sequence: ["LINE", "TRIM", "LINE", "TRIM"],
      occurrence_count: 4,
      provenance: "observed",
      approval_status: "approved",
      decided_at: "1970-01-01T00:00:02.000Z",
    }],
  });
  assert.equal(calls.length, 1);
  assert.equal(
    calls[0].url,
    "http://api:8000/v1/control/candidate-publications/review-outcomes",
  );
  assert.equal(JSON.stringify(await loadApprovedWorkflows(async () =>
    jsonResponse(200, { items: [outcome("rejected")], count: 1 })
  )).includes("rejected"), false);
});

test("approved catalog fails closed on corrupt or unavailable outcomes", async () => {
  configure();
  for (const fetcher of [
    async () => jsonResponse(200, {
      items: [outcome("approved", { publication_key: PUBLICATION_KEY })],
      count: 1,
    }),
    async () => jsonResponse(200, {
      items: [outcome("approved", { occurrence_count: 3 })],
      count: 1,
    }),
    async () => jsonResponse(200, { items: [outcome("unreviewed")], count: 1 }),
    async () => jsonResponse(503, { private: REVIEW_TARGET }),
    async () => { throw new Error("private transport failure"); },
  ]) {
    assert.deepEqual(await loadApprovedWorkflows(fetcher), { status: "unavailable" });
  }
  assert.deepEqual(
    await loadApprovedWorkflows(async () => jsonResponse(200, { items: [], count: 0 })),
    { status: "empty" },
  );
});

function approvedDownloadRequest(
  query = "?ordinal=1",
  headers = {},
  path = "/approved-workflows/download",
  method = "GET",
) {
  return new Request(`http://web:3000${path}${query}`, {
    method,
    headers: { host: "127.0.0.1:3000", ...headers },
    ...(method === "GET" || method === "HEAD" ? {} : { body: "private" }),
  });
}

async function assertHardenedDownloadNotFound(response) {
  assert.equal(response.status, 404);
  assert.equal(await response.text(), "");
  assert.deepEqual(Object.fromEntries(response.headers), {
    "cache-control": "no-store",
    "content-length": "0",
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff",
  });
  assert.equal(response.headers.has("content-type"), false);
  assert.equal(response.headers.has("content-disposition"), false);
}

test("approved download re-fetches ordinal and emits deterministic bounded safe bytes", async () => {
  configure();
  const calls = [];
  const fetcher = async (url, init) => {
    calls.push({ url, init });
    return jsonResponse(200, {
      items: [outcome("rejected"), outcome("approved")],
      count: 2,
    });
  };
  const response = await downloadApprovedWorkflow(approvedDownloadRequest(), fetcher);
  const expected = `${JSON.stringify({
    schema: "workflow-helper.approved-workflow",
    version: "1.0",
    command_sequence: ["LINE", "TRIM", "LINE", "TRIM"],
    occurrence_count: 4,
    provenance: "observed",
    approval_status: "approved",
    decided_at: "1970-01-01T00:00:02.000Z",
  })}\n`;

  assert.equal(response.status, 200);
  assert.equal(await response.text(), expected);
  assert.equal(response.headers.get("content-length"), String(Buffer.byteLength(expected)));
  assert.equal(response.headers.get("content-type"), "application/json; charset=utf-8");
  assert.equal(
    response.headers.get("content-disposition"),
    'attachment; filename="approved-workflow.json"',
  );
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
  assert.equal(response.headers.get("referrer-policy"), "no-referrer");
  assert.equal(calls.length, 1);
  for (const forbidden of [
    PUBLICATION_KEY,
    REVIEW_TARGET,
    REVIEWER_PROOF,
    REVIEWER_SESSION,
    REVIEWER_CSRF,
    "reason",
    "evidence",
    "sha256",
    "artifact",
  ]) {
    assert.equal(expected.includes(forbidden), false);
  }
});

test("approved download request and ordinal binding fail closed as bodyless 404", async () => {
  configure();
  let calls = 0;
  const fetcher = async () => {
    calls += 1;
    return jsonResponse(200, { items: [outcome("approved")], count: 1 });
  };
  for (const request of [
    approvedDownloadRequest(""),
    approvedDownloadRequest("?ordinal=0"),
    approvedDownloadRequest("?ordinal=101"),
    approvedDownloadRequest("?ordinal=01"),
    approvedDownloadRequest("?ordinal=%31"),
    approvedDownloadRequest("?ordinal=1&ordinal=1"),
    approvedDownloadRequest("?ordinal=1&extra=x"),
    approvedDownloadRequest("?extra=x&ordinal=1"),
    approvedDownloadRequest("?ordinal=1", {}, "/approved-workflows"),
    approvedDownloadRequest("?ordinal=1", {}, "/approved-workflows/download", "POST"),
    approvedDownloadRequest("?ordinal=1", { host: "localhost:3000" }),
    approvedDownloadRequest("?ordinal=1", { cookie: "private=1" }),
    approvedDownloadRequest("?ordinal=1", { authorization: "Bearer private" }),
    approvedDownloadRequest("?ordinal=1", { "content-type": "application/json" }),
    approvedDownloadRequest("?ordinal=1", { "content-length": "0" }),
    approvedDownloadRequest("?ordinal=1", { "x-workflow-dev-proof": "private" }),
    approvedDownloadRequest("?ordinal=1", { "x-workflow-dev-reviewer-proof": "private" }),
    approvedDownloadRequest("?ordinal=1", { "x-csrf-token": "private" }),
  ]) {
    const before = calls;
    const response = await downloadApprovedWorkflow(request, fetcher);
    await assertHardenedDownloadNotFound(response);
    assert.equal(calls, before);
  }
  for (const query of ["?ordinal=2", "?ordinal=100"]) {
    const response = await downloadApprovedWorkflow(approvedDownloadRequest(query), fetcher);
    await assertHardenedDownloadNotFound(response);
  }
  assert.equal(calls, 2);

  for (const unavailable of [
    async () => jsonResponse(503, { private: REVIEW_TARGET }),
    async () => jsonResponse(200, {
      items: [outcome("approved", { occurrence_count: 3 })],
      count: 1,
    }),
    async () => { throw new Error("private download failure"); },
  ]) {
    const response = await downloadApprovedWorkflow(approvedDownloadRequest(), unavailable);
    await assertHardenedDownloadNotFound(response);
  }
});

test("approved download stays below the fixed export cap at upstream maxima", async () => {
  configure();
  const commands = Array.from({ length: 64 }, () => "X".repeat(128));
  const response = await downloadApprovedWorkflow(
    approvedDownloadRequest(),
    async () => jsonResponse(200, {
      items: [outcome("approved", {
        command_sequence: commands,
        occurrence_count: commands.length,
      })],
      count: 1,
    }),
  );
  const bytes = new Uint8Array(await response.arrayBuffer());
  assert.equal(response.status, 200);
  assert.ok(bytes.byteLength <= 65_536);
  assert.equal(response.headers.get("content-length"), String(bytes.byteLength));
});

test("oversized serialization and thrown export paths return the hardened 404", async () => {
  configure();
  const original = globalThis.TextEncoder;
  try {
    globalThis.TextEncoder = class {
      encode() {
        return new Uint8Array(65_537);
      }
    };
    await assertHardenedDownloadNotFound(
      await downloadApprovedWorkflow(
        approvedDownloadRequest(),
        async () => jsonResponse(200, { items: [outcome("approved")], count: 1 }),
      ),
    );

    globalThis.TextEncoder = class {
      encode() {
        throw new Error("private serialization failure");
      }
    };
    await assertHardenedDownloadNotFound(
      await downloadApprovedWorkflow(
        approvedDownloadRequest(),
        async () => jsonResponse(200, { items: [outcome("approved")], count: 1 }),
      ),
    );
  } finally {
    globalThis.TextEncoder = original;
  }
});

test("approved page and route keep authority and raw bindings server-side", () => {
  const page = readFileSync(
    new URL("../app/approved-workflows/page.tsx", import.meta.url),
    "utf-8",
  );
  const route = readFileSync(
    new URL("../app/approved-workflows/download/route.ts", import.meta.url),
    "utf-8",
  );
  assert.match(page, /loadApprovedWorkflows/);
  assert.match(page, /approved-workflows\/download\?ordinal=/);
  assert.match(route, /downloadApprovedWorkflow\(request\)/);
  for (const source of [page, route]) {
    assert.equal(source.includes(PUBLICATION_KEY), false);
    assert.equal(source.includes(REVIEW_TARGET), false);
    assert.equal(source.includes(REVIEWER_PROOF), false);
    assert.doesNotMatch(source, /NEXT_PUBLIC|WORKFLOW_DEV_REVIEWER|publication_key|review_target_id/);
  }
});

test("dashboard lifecycle counts use independent server snapshots", () => {
  const page = readFileSync(
    new URL("../app/page.tsx", import.meta.url),
    "utf-8",
  );
  assert.match(page, /loadCandidateReviewQueue/);
  assert.match(page, /loadCandidateReviewOutcomes/);
  assert.match(page, /Promise\.all/);
  assert.match(page, /reviewQueue\.status === "unavailable"/);
  assert.match(page, /reviewQueue\.status === "empty"/);
  assert.match(page, /reviewQueue\.rows\.filter\(\(row\) => row\.review_status === "unreviewed"\)/);
  assert.match(page, /reviewQueue\.rows\.filter\(\(row\) => row\.review_status === "pending"\)/);
  assert.match(page, /reviewOutcomes\.status === "unavailable"/);
  assert.match(page, /reviewOutcomes\.status === "empty"/);
  assert.match(page, /reviewOutcomes\.rows\.length/);
  assert.match(page, /row\.review_status === "approved"/);
  assert.doesNotMatch(page, /loadApprovedWorkflows/);
  for (const forbidden of [
    "NEXT_PUBLIC",
    "WORKFLOW_DEV_REVIEWER",
    "WORKFLOW_REVIEW_API_BASE_URL",
    "publication_key",
    "review_target_id",
    "reason_code",
    "sha256",
    "credentials",
    "cookie",
  ]) {
    assert.equal(page.includes(forbidden), false, `dashboard leaked ${forbidden}`);
  }
});

test("dashboard normalizes empty approved outcomes before rendering", () => {
  const page = readFileSync(
    new URL("../app/page.tsx", import.meta.url),
    "utf-8",
  );
  assert.match(
    page,
    /const approvedCount =\s*reviewOutcomes\.status === "populated"\s*\?\s*reviewOutcomes\.rows\.filter\(\(row\) => row\.review_status === "approved"\)\.length\s*:\s*0;/s,
  );
  assert.match(page, /value: approvedCount,/);
  assert.match(page, /detail:\s*\n\s*approvedCount === 0\s*\?/);
  assert.match(page, /tone: approvedCount \? \("good" as const\) : \("neutral" as const\)/);
  assert.doesNotMatch(page, /value: approvedCount \?\? 0/);
  assert.doesNotMatch(page, /approvedCount === null/);
});

test("dashboard lifecycle counts use bounded queue status filters", () => {
  const page = readFileSync(
    new URL("../app/page.tsx", import.meta.url),
    "utf-8",
  );
  assert.match(
    page,
    /const unreviewedCount =\s*reviewQueue\.status === "populated"\s*\?\s*reviewQueue\.rows\.filter\(\(row\) => row\.review_status === "unreviewed"\)\.length\s*:\s*0;/s,
  );
  assert.match(
    page,
    /const pendingCount =\s*reviewQueue\.status === "populated"\s*\?\s*reviewQueue\.rows\.filter\(\(row\) => row\.review_status === "pending"\)\.length\s*:\s*0;/s,
  );
  assert.match(page, /value: "0\/0"/);
  assert.match(page, /Bounded snapshot \(maximum 100\): 0 unreviewed · 0 pending/);
  assert.match(page, /Bounded snapshot \(maximum 100\): \$\{unreviewedCount\} unreviewed · \$\{pendingCount\} pending/);
  assert.match(page, /reviewQueue\.status === "loading"/);
  assert.doesNotMatch(page, /pendingReview/);
});

test("each legal effective-state action re-fetches and posts exactly once", async () => {
  configure();
  for (const [reviewStatus, action, destination, reasonCode] of [
    ["unreviewed", "approve", "approved", undefined],
    ["unreviewed", "start_review", "pending", undefined],
    ["pending", "approve", "approved", undefined],
    ["pending", "reject", "rejected", "sequence"],
    ["pending", "needs_changes", "needs_changes", "evidence"],
  ]) {
    const calls = [];
    const fetcher = async (url, init) => {
      calls.push({ url, init });
      return calls.length === 1
        ? jsonResponse(200, { items: [item(reviewStatus)], count: 1 })
        : jsonResponse(200, { status: destination });
    };
    assert.equal(await submitCandidateReviewAction(1, action, reasonCode, fetcher), "success");
    assert.equal(calls.length, 2);
    assert.equal(calls[1].init.method, "POST");
    assert.equal(calls[1].init.redirect, "error");
    assert.match(calls[1].url, /candidate-publication%3A1\.0%3A/);
    const body = JSON.parse(calls[1].init.body);
    assert.equal(body.review_target_id, REVIEW_TARGET);
    assert.equal(body.status, destination);
    assert.equal(body.correlation_id, "web-candidate-action");
    assert.match(body.idempotency_key, /^web-dev-[a-f0-9]{64}$/);
    assert.deepEqual(
      reasonCode === undefined
        ? { reason: body.reason, evidence: body.evidence }
        : { reason: body.reason, evidence: body.evidence },
      reasonCode === undefined
        ? { reason: undefined, evidence: undefined }
        : {
            reason: reasonCode === "sequence"
              ? "Synthetic command sequence requires correction."
              : "Synthetic observed evidence is insufficient.",
            evidence: { reason_code: reasonCode },
          },
    );
    assert.equal(calls[1].init.headers.get("origin"), "https://review.synthetic.example");
    assert.equal(calls[1].init.headers.get("x-csrf-token"), REVIEWER_CSRF);
  }
});

test("fixed reason codes produce stable retry identity and distinct decisions", async () => {
  configure();
  async function submitted(reasonCode) {
    const bodies = [];
    const fetcher = async (_url, init) => {
      if (init.method === "POST") bodies.push(JSON.parse(init.body));
      return init.method === "POST"
        ? jsonResponse(200, { status: "needs_changes" })
        : jsonResponse(200, { items: [item("pending")], count: 1 });
    };
    assert.equal(
      await submitCandidateReviewAction(1, "needs_changes", reasonCode, fetcher),
      "success",
    );
    return bodies[0];
  }
  const first = await submitted("sequence");
  const replay = await submitted("sequence");
  const changed = await submitted("evidence");
  assert.equal(first.idempotency_key, replay.idempotency_key);
  assert.notEqual(first.idempotency_key, changed.idempotency_key);
  assert.deepEqual(first.evidence, { reason_code: "sequence" });
  assert.deepEqual(changed.evidence, { reason_code: "evidence" });
});

test("illegal effective-state transitions fail before the review POST", async () => {
  configure();
  for (const [reviewStatus, action, reasonCode] of [
    ["unreviewed", "reject", "sequence"],
    ["unreviewed", "needs_changes", "evidence"],
    ["pending", "start_review", undefined],
  ]) {
    let calls = 0;
    const fetcher = async () => {
      calls += 1;
      return jsonResponse(200, { items: [item(reviewStatus)], count: 1 });
    };
    assert.equal(await submitCandidateReviewAction(1, action, reasonCode, fetcher), "unavailable");
    assert.equal(calls, 1);
  }
});

test("reason and action combinations fail before any fetch", async () => {
  configure();
  let calls = 0;
  const fetcher = async () => {
    calls += 1;
    return jsonResponse(200, { items: [item("pending")], count: 1 });
  };
  for (const [action, code] of [
    ["approve", "sequence"],
    ["start_review", "evidence"],
    ["reject", undefined],
    ["needs_changes", undefined],
    ["reject", "unknown"],
  ]) {
    assert.equal(
      await submitCandidateReviewAction(1, action, code, fetcher),
      "unavailable",
    );
  }
  assert.equal(calls, 0);
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

  assert.equal(await submitCandidateReviewAction(1, "reject", "sequence", fetcher), "conflict");
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
  assert.equal(await submitCandidateReviewAction(1, "approve", undefined, invalidList), "unavailable");
  assert.equal(calls, 1);

  calls = 0;
  const mismatchedPost = async () => {
    calls += 1;
    return calls === 1
      ? jsonResponse(200, { items: [item()], count: 1 })
      : jsonResponse(200, { status: "rejected", detail: "private" });
  };
  assert.equal(await submitCandidateReviewAction(1, "approve", undefined, mismatchedPost), "unavailable");
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

test("accepts only exact same-origin action and fixed-reason forms", async () => {
  configure();
  assert.deepEqual(
    await parseCandidateReviewActionRequest(actionRequest("ordinal=1&action=approve")),
    { ordinal: 1, action: "approve" },
  );
  for (const action of ["start_review"]) {
    assert.deepEqual(
      await parseCandidateReviewActionRequest(actionRequest(`ordinal=1&action=${action}`)),
      { ordinal: 1, action },
    );
  }
  for (const action of ["reject", "needs_changes"]) {
    for (const reason_code of ["sequence", "evidence"]) {
      assert.deepEqual(
        await parseCandidateReviewActionRequest(
          actionRequest(`ordinal=1&reason_code=${reason_code}&action=${action}`),
        ),
        { ordinal: 1, action, reason_code },
      );
    }
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
    actionRequest("ordinal=1&action=approve&reason_code=sequence"),
    actionRequest("ordinal=1&action=start_review&reason_code=evidence"),
    actionRequest("ordinal=1&action=reject"),
    actionRequest("ordinal=1&action=needs_changes"),
    actionRequest("ordinal=1&reason_code=unknown&action=reject"),
    actionRequest("ordinal=1&reason_code=sequence&reason_code=evidence&action=reject"),
    actionRequest("ordinal=1&reason_code=%73equence&action=reject"),
    actionRequest("ordinal=1&reason_code=sequence&action=reject&extra=x"),
    actionRequest("ordinal=1&action=reject&reason_code=sequence"),
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
  assert.match(source, /name="reason_code"/);
  assert.match(source, /Sequence mismatch/);
  assert.match(source, /Insufficient evidence/);
  assert.match(source, /No reason code/);
  assert.doesNotMatch(source, /\{row\.reason_code\}/);
  assert.doesNotMatch(source, /textarea|type="text"/);
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
