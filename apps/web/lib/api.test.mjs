import assert from "node:assert/strict";
import test from "node:test";

import {
  getProcessedTimeline,
  getSession,
  getSessions,
  selectSessionPresentationState,
} from "./api.ts";

const ORIGINAL_ENV = { ...process.env };
const ORIGINAL_FETCH = globalThis.fetch;
const SESSION_ID = "d6d9e5b7-c9bc-4eb1-ae4a-1a14ed5b1350";
const OTHER_SESSION_ID = "11111111-1111-4111-8111-111111111111";
const EVENT_IDS = [
  "f74d30dd-9945-4291-8ae9-95658379b335",
  "1e6e2db8-c50a-4cd2-b122-381e3f20640f",
];
const REVIEWER_PROOF = "reviewer-dashboard-proof-abcdefghijklmnopqrstuvwxyz0123456789";
const REVIEWER_SESSION = Buffer.from(
  Array.from({ length: 32 }, (_, index) => index + 1),
).toString("base64url");
const REVIEWER_CSRF = Buffer.from(
  Array.from({ length: 32 }, (_, index) => index + 33),
).toString("base64url");

test.afterEach(() => {
  process.env = { ...ORIGINAL_ENV };
  globalThis.fetch = ORIGINAL_FETCH;
});

function configure() {
  process.env.ENVIRONMENT = "development";
  process.env.WORKFLOW_REVIEW_API_BASE_URL = "http://api:8000";
  process.env.WORKFLOW_DEV_REVIEWER_PROOF = REVIEWER_PROOF;
  process.env.WORKFLOW_DEV_REVIEWER_SESSION = REVIEWER_SESSION;
  process.env.WORKFLOW_DEV_REVIEWER_CSRF = REVIEWER_CSRF;
  process.env.WORKFLOW_REVIEW_BROWSER_ORIGIN = "http://127.0.0.1:3000";
  process.env.WORKFLOW_REVIEW_BROWSER_HOST = "127.0.0.1:3000";
  process.env.API_BASE_URL = "https://must-not-be-used.invalid";
  process.env.NEXT_PUBLIC_API_BASE_URL = "https://must-not-be-used.invalid";
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

function mockResponse(status, body) {
  const calls = [];
  globalThis.fetch = async (url, init) => {
    calls.push({ url, init });
    return jsonResponse(status, body);
  };
  return calls;
}

function timeline(overrides = {}) {
  return {
    schema_version: "2.0",
    session_id: SESSION_ID,
    event_count: 2,
    meaningful_event_count: 2,
    timeline: [
      {
        offset_seconds: 0,
        event_type: "session_started",
        summary: "Approved CAD session started",
        source_event_id: EVENT_IDS[0],
      },
      {
        offset_seconds: 5,
        event_type: "drawing_opened",
        summary: "Drawing opened",
        source_event_id: EVENT_IDS[1],
      },
    ],
    operation_segments: [],
    keyframes: [],
    warnings: [],
    ...overrides,
  };
}

function session(overrides = {}) {
  return {
    schema_version: "1.0",
    session_id: SESSION_ID,
    machine_id: "synthetic-pilot-machine",
    project_id: null,
    started_at: "2026-08-17T00:00:00Z",
    ended_at: "2026-08-17T00:01:00Z",
    active_duration_seconds: 60,
    approved_process: "acad",
    package_sha256: "a".repeat(64),
    package_size_bytes: 4096,
    processing_status: "processed",
    review_status: "pending",
    raw_object_key: `sessions/${SESSION_ID}/packages/${"a".repeat(64)}.zip`,
    processed_prefix: `sessions/${SESSION_ID}/timeline-v2.json`,
    processing_output: timeline(),
    processing_completion_id: "completion-synthetic",
    processing_completed_at: "2026-08-17T00:02:00Z",
    raw_expires_at: "2026-08-31T00:00:00Z",
    created_at: "2026-08-17T00:00:00Z",
    updated_at: "2026-08-17T00:02:00Z",
    ...overrides,
  };
}

test("session list uses fixed authenticated route and projects exact safe fields", async () => {
  configure();
  const calls = mockResponse(200, { items: [session()], count: 1 });
  const result = await getSessions();
  assert.equal(result.status, "available");
  assert.equal(result.sessions.count, 1);
  assert.equal(result.sessions.items[0].session_id, SESSION_ID);
  assert.equal("package_sha256" in result.sessions.items[0], false);
  assert.equal("processing_output" in result.sessions.items[0], false);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "http://api:8000/v1/sessions");
  assert.equal(calls[0].init.method, "GET");
  assert.equal(calls[0].init.headers.get("cookie"), `workflow_session=${REVIEWER_SESSION}`);
  assert.equal(calls[0].init.headers.get("origin"), "https://review.synthetic.example");
  assert.equal(calls[0].init.headers.get("x-workflow-dev-reviewer-proof"), REVIEWER_PROOF);
});

test("list rejects count, duplicate identity, unknown keys, and malformed records", async () => {
  configure();
  for (const body of [
    { items: [session()], count: 0 },
    { items: [session(), session()], count: 2 },
    { items: [session()], count: 1, extra: true },
    { items: [{ ...session(), extra: true }], count: 1 },
    { items: [session({ session_id: "SESSION-PRIVATE" })], count: 1 },
    { items: [session({ active_duration_seconds: Number.NaN })], count: 1 },
    { items: [session({ started_at: "not-a-date" })], count: 1 },
  ]) {
    mockResponse(200, body);
    assert.deepEqual(await getSessions(), { status: "unavailable" });
  }
});

test("detail enforces canonical request and response identity", async () => {
  configure();
  let calls = 0;
  globalThis.fetch = async () => {
    calls += 1;
    return jsonResponse(200, session());
  };
  const result = await getSession(SESSION_ID);
  assert.equal(result.status, "available");
  assert.equal(result.session.session_id, SESSION_ID);
  assert.equal("package_sha256" in result.session, false);
  assert.equal(calls, 1);
  assert.deepEqual(await getSession("SESSION-1"), { status: "unavailable" });
  assert.equal(calls, 1);
  mockResponse(200, session({ session_id: OTHER_SESSION_ID }));
  assert.deepEqual(await getSession(SESSION_ID), { status: "unavailable" });
});

test("detail distinguishes exact 404 while all other failures are unavailable", async () => {
  configure();
  mockResponse(404, { detail: "missing" });
  assert.deepEqual(await getSession(SESSION_ID), { status: "not_found" });
  mockResponse(503, { detail: "private" });
  assert.deepEqual(await getSession(SESSION_ID), { status: "unavailable" });
  globalThis.fetch = async () => { throw new Error("private endpoint"); };
  assert.deepEqual(await getSession(SESSION_ID), { status: "unavailable" });
});

test("v2 timeline preserves valid ordered segments and evidence", async () => {
  configure();
  const raw = timeline({
    operation_segments: [
      {
        sequence: 1,
        start_offset_seconds: 0,
        end_offset_seconds: 0,
        command_names: ["LINE"],
        drawing_ref: "synthetic-drawing-001",
        summary: "AutoCAD command: LINE",
        source_event_ids: [EVENT_IDS[0]],
      },
      {
        sequence: 2,
        start_offset_seconds: 5,
        end_offset_seconds: 5,
        command_names: ["TRIM"],
        drawing_ref: "synthetic-drawing-001",
        summary: "AutoCAD command: TRIM",
        source_event_ids: [EVENT_IDS[1]],
      },
    ],
  });
  const calls = mockResponse(200, raw);
  const result = await getProcessedTimeline(SESSION_ID);
  assert.deepEqual(result, { status: "available", timeline: raw });
  assert.equal(calls[0].url, `http://api:8000/v1/sessions/${SESSION_ID}/timeline`);
});

test("timeline rejects unknown keys, identity/count drift, and non-finite data", async () => {
  configure();
  for (const body of [
    { ...timeline(), extra: true },
    timeline({ session_id: OTHER_SESSION_ID }),
    timeline({ meaningful_event_count: 1 }),
    timeline({ event_count: 1 }),
    timeline({ timeline: [{ ...timeline().timeline[0], offset_seconds: Number.NaN }] }),
    timeline({ timeline: [{ ...timeline().timeline[0], event_type: "unknown" }] }),
    timeline({ timeline: [{ ...timeline().timeline[0], extra: true }] }),
  ]) {
    mockResponse(200, body);
    assert.deepEqual(await getProcessedTimeline(SESSION_ID), { status: "unavailable" });
  }
});

test("timeline rejects malformed segment ordering, identity, bounds, and arrays", async () => {
  configure();
  const validSegment = {
    sequence: 1,
    start_offset_seconds: 0,
    end_offset_seconds: 0,
    command_names: ["LINE"],
    drawing_ref: "synthetic-drawing-001",
    summary: "AutoCAD command: LINE",
    source_event_ids: [EVENT_IDS[0]],
  };
  for (const segment of [
    { ...validSegment, sequence: 2 },
    { ...validSegment, start_offset_seconds: 1 },
    { ...validSegment, command_names: ["LINE", "LINE"] },
    { ...validSegment, source_event_ids: [OTHER_SESSION_ID] },
    { ...validSegment, source_event_ids: [EVENT_IDS[0], EVENT_IDS[0]] },
    { ...validSegment, extra: true },
  ]) {
    mockResponse(200, timeline({ operation_segments: [segment] }));
    assert.deepEqual(await getProcessedTimeline(SESSION_ID), { status: "unavailable" });
  }
});

test("successful v1 timeline remains available without v2 fields", async () => {
  configure();
  const { operation_segments: _removed, ...v1 } = timeline({ schema_version: "1.0" });
  mockResponse(200, v1);
  const result = await getProcessedTimeline(SESSION_ID);
  assert.equal(result.status, "available");
  assert.equal(result.timeline.schema_version, "1.0");
  assert.equal("operation_segments" in result.timeline, false);
});

test("unknown timeline versions and completion-only fields fail closed", async () => {
  configure();
  mockResponse(200, timeline({ schema_version: "3.0" }));
  assert.deepEqual(await getProcessedTimeline(SESSION_ID), { status: "unavailable" });
  mockResponse(200, {
    ...timeline(),
    output_object_key: `sessions/${SESSION_ID}/timeline-v2.json`,
  });
  assert.deepEqual(await getProcessedTimeline(SESSION_ID), { status: "unavailable" });
});

test("processed_prefix never infers completion or bypasses timeline readback", () => {
  const raw = session({
    processing_status: "uploaded",
    processing_output: null,
    processing_completion_id: null,
    processing_completed_at: null,
  });
  const projected = {
    schema_version: "1.0",
    session_id: raw.session_id,
    machine_id: raw.machine_id,
    project_id: raw.project_id,
    started_at: raw.started_at,
    ended_at: raw.ended_at,
    active_duration_seconds: raw.active_duration_seconds,
    approved_process: raw.approved_process,
    processing_status: raw.processing_status,
    review_status: raw.review_status,
    raw_expires_at: raw.raw_expires_at,
    raw_object_key: raw.raw_object_key,
    processed_prefix: "private/processing-result-v2",
  };
  assert.deepEqual(
    selectSessionPresentationState({ status: "available", session: projected }, null),
    { status: "available", session: projected, timeline: null },
  );
});

test("presentation state selection preserves public result unions", () => {
  const projected = {
    schema_version: "1.0",
    session_id: SESSION_ID,
    machine_id: "synthetic-pilot-machine",
    project_id: null,
    started_at: "2026-08-17T00:00:00Z",
    ended_at: "2026-08-17T00:01:00Z",
    active_duration_seconds: 60,
    approved_process: "acad",
    processing_status: "processed",
    review_status: "pending",
    raw_expires_at: "2026-08-31T00:00:00Z",
    raw_object_key: null,
    processed_prefix: null,
  };
  const availableTimeline = { status: "available", timeline: timeline() };
  assert.deepEqual(selectSessionPresentationState({ status: "not_found" }, null), {
    status: "not_found",
  });
  assert.deepEqual(selectSessionPresentationState({ status: "unavailable" }, null), {
    status: "unavailable",
  });
  assert.deepEqual(
    selectSessionPresentationState({ status: "available", session: projected }, null),
    { status: "unavailable" },
  );
  assert.deepEqual(
    selectSessionPresentationState(
      { status: "available", session: projected },
      availableTimeline,
    ),
    { status: "available", session: projected, timeline: availableTimeline.timeline },
  );
  assert.deepEqual(
    selectSessionPresentationState(
      { status: "available", session: { ...projected, processing_status: "uploaded" } },
      null,
    ),
    {
      status: "available",
      session: { ...projected, processing_status: "uploaded" },
      timeline: null,
    },
  );
});
