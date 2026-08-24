import assert from "node:assert/strict";
import test from "node:test";

import {
  getProcessedTimeline,
  getSession,
  selectSessionPresentationState,
} from "./api.ts";

const originalFetch = globalThis.fetch;

test.afterEach(() => {
  globalThis.fetch = originalFetch;
});

function response(status, body) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  };
}

function mockFetch(status, body) {
  globalThis.fetch = async () => response(status, body);
}

function session(overrides = {}) {
  return {
    schema_version: "1.0",
    session_id: "session-1",
    machine_id: "machine-1",
    project_id: null,
    started_at: "2026-01-01T00:00:00Z",
    ended_at: "2026-01-01T00:01:00Z",
    active_duration_seconds: 60,
    approved_process: "synthetic",
    processing_status: "processed",
    review_status: "pending",
    raw_expires_at: "2026-01-02T00:00:00Z",
    raw_object_key: null,
    processed_prefix: null,
    ...overrides,
  };
}

function timeline(overrides = {}) {
  return {
    schema_version: "1.0",
    session_id: "session-1",
    event_count: 0,
    meaningful_event_count: 0,
    timeline: [],
    keyframes: [],
    warnings: [],
    ...overrides,
  };
}

test("successful v1 empty timeline is explicitly available", async () => {
  mockFetch(200, timeline());
  const result = await getProcessedTimeline("session-1");
  assert.equal(result.status, "available");
  assert.deepEqual(result.timeline.timeline, []);
  assert.equal("operation_segments" in result.timeline, false);
});

test("successful v2 empty timeline is explicitly available", async () => {
  mockFetch(200, timeline({ schema_version: "2.0", operation_segments: [] }));
  const result = await getProcessedTimeline("session-1");
  assert.equal(result.status, "available");
  assert.deepEqual(result.timeline.timeline, []);
});

test("successful v2 empty segments are preserved explicitly", async () => {
  mockFetch(200, timeline({ schema_version: "2.0", operation_segments: [] }));
  const result = await getProcessedTimeline("session-1");
  assert.equal(result.status, "available");
  assert.deepEqual(result.timeline.operation_segments, []);
});

test("populated v2 preserves supplied segment and evidence order", async () => {
  const segments = [
    {
      sequence: 2,
      start_offset_seconds: 5,
      end_offset_seconds: 8,
      command_names: ["TRIM", "LINE"],
      drawing_ref: "drawing-b",
      summary: "Second supplied segment",
      source_event_ids: ["event-z", "event-a"],
    },
    {
      sequence: 1,
      start_offset_seconds: 1,
      end_offset_seconds: 2,
      command_names: ["MOVE"],
      drawing_ref: "drawing-a",
      summary: "First-numbered but second-supplied segment",
      source_event_ids: ["event-b"],
    },
  ];
  mockFetch(200, timeline({ schema_version: "2.0", operation_segments: segments }));
  const result = await getProcessedTimeline("session-1");
  assert.equal(result.status, "available");
  assert.deepEqual(result.timeline.operation_segments, segments);
});

test("timeline network and non-2xx failures are unavailable", async (t) => {
  await t.test("network failure", async () => {
    globalThis.fetch = async () => {
      throw new Error("private endpoint and exception detail");
    };
    assert.deepEqual(await getProcessedTimeline("session-1"), { status: "unavailable" });
  });
  await t.test("non-2xx response", async () => {
    mockFetch(503, { detail: "private infrastructure detail" });
    assert.deepEqual(await getProcessedTimeline("session-1"), { status: "unavailable" });
  });
  await t.test("processed timeline 404", async () => {
    mockFetch(404, { detail: "missing" });
    assert.deepEqual(await getProcessedTimeline("session-1"), { status: "unavailable" });
  });
});

test("session 404 is not_found while session 503 is unavailable", async () => {
  mockFetch(404, { detail: "missing" });
  assert.deepEqual(await getSession("session-1"), { status: "not_found" });
  mockFetch(503, { detail: "private infrastructure detail" });
  assert.deepEqual(await getSession("session-1"), { status: "unavailable" });
});

test("session fetch remains v1 and network failures are unavailable", async () => {
  mockFetch(200, session({ schema_version: "2.0" }));
  assert.deepEqual(await getSession("session-1"), { status: "unavailable" });

  globalThis.fetch = async () => {
    throw new Error("private endpoint and exception detail");
  };
  assert.deepEqual(await getSession("session-1"), { status: "unavailable" });
});

test("presentation state selection covers every fetch state", () => {
  const processed = session();
  const uploaded = session({ processing_status: "uploaded" });
  const availableTimeline = { status: "available", timeline: timeline() };

  assert.deepEqual(selectSessionPresentationState({ status: "not_found" }, null), {
    status: "not_found",
  });
  assert.deepEqual(selectSessionPresentationState({ status: "unavailable" }, null), {
    status: "unavailable",
  });
  assert.deepEqual(
    selectSessionPresentationState({ status: "available", session: processed }, null),
    { status: "unavailable" },
  );
  assert.deepEqual(
    selectSessionPresentationState(
      { status: "available", session: processed },
      { status: "unavailable" },
    ),
    { status: "unavailable" },
  );
  assert.deepEqual(
    selectSessionPresentationState(
      { status: "available", session: processed },
      availableTimeline,
    ),
    { status: "available", session: processed, timeline: availableTimeline.timeline },
  );
  assert.deepEqual(
    selectSessionPresentationState({ status: "available", session: uploaded }, null),
    { status: "available", session: uploaded, timeline: null },
  );
});

test("processed_prefix never infers a timeline version or processing completion", () => {
  const uploaded = session({
    processing_status: "uploaded",
    processed_prefix: "private/processing-result-v2",
  });
  assert.deepEqual(
    selectSessionPresentationState({ status: "available", session: uploaded }, null),
    { status: "available", session: uploaded, timeline: null },
  );
});

test("unknown schema versions are unavailable and completion-only output key is not exposed", async () => {
  mockFetch(200, timeline({ schema_version: "3.0", processed_prefix: "v2" }));
  assert.deepEqual(await getProcessedTimeline("session-1"), { status: "unavailable" });

  mockFetch(200, timeline({ output_object_key: "private/result.json" }));
  const result = await getProcessedTimeline("session-1");
  assert.equal(result.status, "available");
  assert.equal("output_object_key" in result.timeline, false);
});
