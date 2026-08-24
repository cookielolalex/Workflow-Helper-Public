import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  MAX_CANDIDATE_REVIEW_COMMANDS,
  MAX_CANDIDATE_REVIEW_ITEMS,
  toCandidateReviewOutcomesView,
  toCandidateReviewView,
} from "./candidate-review.ts";

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
    review_status: "unreviewed",
    finalized_at_us: 1_000_000_000,
    ...overrides,
  };
}

function routeResponse(items = [item()], count = items.length) {
  return { items, count };
}

function available(response, authenticated = true) {
  return { status: "available", authenticated, response };
}

test("closed view exposes exact informed evidence and no server binding", () => {
  assert.deepEqual(toCandidateReviewView({ status: "loading" }), {
    status: "loading",
  });
  assert.deepEqual(toCandidateReviewView({ status: "unavailable" }), {
    status: "unavailable",
  });
  assert.deepEqual(toCandidateReviewView(available(routeResponse([]))), {
    status: "empty",
  });

  const view = toCandidateReviewView(available(routeResponse()));
  assert.deepEqual(view, {
    status: "populated",
    rows: [
      {
        ordinal: 1,
        command_sequence: ["LINE", "TRIM", "LINE", "TRIM"],
        occurrence_count: 4,
        provenance: "observed",
        review_status: "unreviewed",
        finalized_at: "1970-01-01T00:16:40.000Z",
      },
    ],
  });
  const serialized = JSON.stringify(view);
  assert.equal(serialized.includes(PUBLICATION_KEY), false);
  assert.equal(serialized.includes(REVIEW_TARGET), false);
  assert.deepEqual(Object.keys(view.rows[0]).sort(), [
    "command_sequence",
    "finalized_at",
    "occurrence_count",
    "ordinal",
    "provenance",
    "review_status",
  ]);
  const pending = toCandidateReviewView(
    available(routeResponse([item({ review_status: "pending" })])),
  );
  assert.equal(pending.status, "populated");
  if (pending.status === "populated") {
    assert.equal(pending.rows[0].review_status, "pending");
  }
});

test("terminal outcome projection is exact, bounded, and identifier free", () => {
  const response = {
    items: [{
      command_sequence: ["LINE", "TRIM", "LINE", "TRIM"],
      occurrence_count: 4,
      provenance: "observed",
      review_status: "needs_changes",
      decided_at_us: 2_000_000,
    }],
    count: 1,
  };
  const view = toCandidateReviewOutcomesView(available(response));
  assert.equal(view.status, "populated");
  assert.deepEqual(view.status === "populated" ? view.rows[0] : null, {
    ordinal: 1,
    command_sequence: ["LINE", "TRIM", "LINE", "TRIM"],
    occurrence_count: 4,
    provenance: "observed",
    review_status: "needs_changes",
    decided_at: "1970-01-01T00:00:02.000Z",
  });
  for (const malformed of [
    { ...response, extra: true },
    { items: [{ ...response.items[0], publication_key: PUBLICATION_KEY }], count: 1 },
    { items: [{ ...response.items[0], review_status: "pending" }], count: 1 },
    { items: [{ ...response.items[0], occurrence_count: 3 }], count: 1 },
    { items: [{ ...response.items[0], decided_at_us: "2" }], count: 1 },
  ]) {
    assert.deepEqual(toCandidateReviewOutcomesView(available(malformed)), {
      status: "unavailable",
    });
  }
});

test("strict roots, items, counts, identities, and evidence fail closed", () => {
  const malformed = [
    null,
    [],
    {},
    { status: "available", authenticated: true },
    available(null),
    available({ items: "not-an-array", count: 0 }),
    available({ items: [], count: 0, next_cursor: null }),
    available({ items: [null], count: 1 }),
    available(routeResponse([item({ extra: "private" })])),
    available(routeResponse([item({ publication_key: "candidate-publication:raw" })])),
    available(routeResponse([item({ review_target_id: "candidate-skill:raw" })])),
    available(routeResponse([item({ command_sequence: ["LINE"] })])),
    available(routeResponse([item({ occurrence_count: 3 })])),
    available(routeResponse([item({ provenance: "inferred" })])),
    available(routeResponse([item({ review_status: "approved" })])),
    available(routeResponse([item({ finalized_at_us: "1000" })])),
    available(routeResponse([item()], 0)),
    available(routeResponse([]), false),
  ];
  for (const value of malformed) {
    assert.deepEqual(toCandidateReviewView(value), { status: "unavailable" });
  }
});

test("item and occurrence bounds plus duplicate bindings are rejected", () => {
  const bounded = Array.from({ length: MAX_CANDIDATE_REVIEW_ITEMS }, (_, index) => {
    const digit = index.toString(16).padStart(32, "0");
    const uuid = `${digit.slice(0, 8)}-${digit.slice(8, 12)}-4${digit.slice(13, 16)}-8${digit.slice(17, 20)}-${digit.slice(20)}`;
    return item({
      publication_key: `candidate-publication:1.0:${uuid}`,
      review_target_id: `candidate-skill:1.0:${uuid}:sha256:${index.toString(16).padStart(64, "0")}`,
    });
  });
  assert.equal(toCandidateReviewView(available(routeResponse(bounded))).status, "populated");
  assert.deepEqual(
    toCandidateReviewView(available(routeResponse([...bounded, item()]))),
    { status: "unavailable" },
  );
  assert.deepEqual(
    toCandidateReviewView(available(routeResponse([item(), item()]))),
    { status: "unavailable" },
  );
  const commands = Array.from({ length: MAX_CANDIDATE_REVIEW_COMMANDS }, () => "LINE");
  assert.equal(
    toCandidateReviewView(available(routeResponse([
      item({ command_sequence: commands, occurrence_count: commands.length }),
    ]))).status,
    "populated",
  );
  assert.deepEqual(
    toCandidateReviewView(available(routeResponse([
      item({ command_sequence: [...commands, "TRIM"], occurrence_count: commands.length + 1 }),
    ]))),
    { status: "unavailable" },
  );
});

test("command text remains data and the React component uses escaped JSX text", () => {
  const command = '<img src=x onerror="private-sentinel">';
  const view = toCandidateReviewView(available(routeResponse([
    item({ command_sequence: [command, "TRIM"], occurrence_count: 2 }),
  ])));
  assert.equal(view.status, "populated");
  if (view.status === "populated") {
    assert.deepEqual(view.rows[0].command_sequence, [command, "TRIM"]);
  }
  const component = readFileSync(
    new URL("../components/CandidateReviewQueue.tsx", import.meta.url),
    "utf-8",
  );
  assert.match(component, /\{row\.command_sequence\.join\(" → "\)\}/);
  assert.doesNotMatch(component, /dangerouslySetInnerHTML/);
});

test("throwing accessors and private details remain generic", () => {
  const throwing = {};
  Object.defineProperty(throwing, "status", {
    enumerable: true,
    get() {
      throw new Error("private raw detail");
    },
  });
  assert.deepEqual(toCandidateReviewView(throwing), { status: "unavailable" });
});
