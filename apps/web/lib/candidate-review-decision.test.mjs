import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  CANDIDATE_REVIEW_ACTIONS,
  MAX_CANDIDATE_REVIEW_ORDINAL,
  createCandidateReviewDecisionController,
  dispatchCandidateReviewDecision,
} from "./candidate-review-decision.ts";

function success(action) {
  return { status: "success", action };
}
function conflict(action) {
  return { status: "conflict", action };
}

function unavailable(action) {
  return { status: "unavailable", action };
}

function controllerFor(transport, candidateOrdinals = [1]) {
  return createCandidateReviewDecisionController({
    transport,
    candidateOrdinals,
  });
}

test("all three actions use one bounded request and reach action-specific success", () => {
  const seen = [];
  const controller = controllerFor((request) => {
    seen.push(request);
    return success(request.action);
  }, [1, 2, 3]);

  for (const [ordinal, action] of CANDIDATE_REVIEW_ACTIONS.entries()) {
    assert.deepEqual(controller.dispatch(ordinal + 1, action), {
      ordinal: ordinal + 1,
      status: "success",
      action,
    });
  }

  assert.deepEqual(seen, [
    { candidate_ordinal: 1, action: "approved" },
    { candidate_ordinal: 2, action: "rejected" },
    { candidate_ordinal: 3, action: "needs_changes" },
  ]);
  for (const request of seen) {
    assert.deepEqual(Object.keys(request), ["candidate_ordinal", "action"]);
    assert.equal(Object.isFrozen(request), true);
  }
});

test("ready becomes pending before transport and re-entry cannot duplicate", () => {
  let controller;
  let calls = 0;
  let pendingSeen;
  let reentrantResult;
  controller = controllerFor((request) => {
    calls += 1;
    pendingSeen = controller.getState(request.candidate_ordinal);
    reentrantResult = controller.dispatch(request.candidate_ordinal, "rejected");
    return success(request.action);
  });

  assert.deepEqual(controller.getState(1), { ordinal: 1, status: "ready" });
  assert.deepEqual(controller.dispatch(1, "approved"), {
    ordinal: 1,
    status: "success",
    action: "approved",
  });
  assert.deepEqual(pendingSeen, { ordinal: 1, status: "pending" });
  assert.deepEqual(reentrantResult, { ordinal: 1, status: "pending" });
  assert.equal(calls, 1);
  assert.deepEqual(controller.dispatch(1, "approved"), {
    ordinal: 1,
    status: "success",
    action: "approved",
  });
  assert.equal(calls, 1);
});

test("conflict is generic, not optimistic, and terminal without retry", () => {
  let calls = 0;
  const controller = controllerFor((request) => {
    calls += 1;
    return conflict(request.action);
  });

  assert.deepEqual(controller.dispatch(1, "rejected"), {
    ordinal: 1,
    status: "conflict",
  });
  assert.deepEqual(controller.dispatch(1, "approved"), {
    ordinal: 1,
    status: "conflict",
  });
  assert.equal(calls, 1);
});

test("unavailable is generic, says no action was recorded, and is terminal", () => {
  let calls = 0;
  const controller = controllerFor((request) => {
    calls += 1;
    return unavailable(request.action);
  });

  assert.deepEqual(controller.dispatch(1, "needs_changes"), {
    ordinal: 1,
    status: "unavailable",
  });
  assert.deepEqual(controller.dispatch(1, "approved"), {
    ordinal: 1,
    status: "unavailable",
  });
  assert.equal(calls, 1);
});

test("throws, promises, thenables, and malformed responses fail closed", () => {
  const cases = [
    () => {
      throw new Error("private transport detail");
    },
    () => Promise.resolve(success("approved")),
    () => ({ then(resolve) { resolve(success("approved")); } }),
    () => ({ status: "success", action: "approved", extra: "private" }),
    () => ({ status: "success" }),
    () => ({ status: "later", action: "approved" }),
    () => ({ status: "success", action: "rejected" }),
    () => ({ status: "success", action: "not-an-action" }),
    () => null,
    () => [],
    () => Object.create(null),
  ];

  for (const transport of cases) {
    const controller = controllerFor(transport);
    assert.deepEqual(controller.dispatch(1, "approved"), {
      ordinal: 1,
      status: "unavailable",
    });
  }
});

test("invalid actions and ordinals fail closed without invoking transport", () => {
  let calls = 0;
  const controller = controllerFor(() => {
    calls += 1;
    return success("approved");
  });

  assert.deepEqual(controller.dispatch(1, "approve"), {
    ordinal: 1,
    status: "unavailable",
  });
  assert.equal(calls, 0);

  for (const value of [0, -1, 1.5, Number.NaN, MAX_CANDIDATE_REVIEW_ORDINAL + 1, "1", null]) {
    const isolated = controllerFor(() => {
      calls += 1;
      return success("approved");
    });
    assert.deepEqual(isolated.dispatch(value, "approved"), {
      ordinal: 0,
      status: "unavailable",
    });
  }
  assert.equal(calls, 0);
});

test("proxy and getter hazards do not leak or invoke a thenable", () => {
  const revoked = Proxy.revocable({}, {});
  revoked.revoke();
  assert.deepEqual(
    controllerFor(() => revoked.proxy).dispatch(1, "approved"),
    { ordinal: 1, status: "unavailable" },
  );

  const throwingStatus = {};
  Object.defineProperty(throwingStatus, "status", {
    enumerable: true,
    get() {
      throw new Error("private response detail");
    },
  });
  Object.defineProperty(throwingStatus, "action", {
    enumerable: true,
    value: "approved",
  });
  assert.deepEqual(
    controllerFor(() => throwingStatus).dispatch(1, "approved"),
    { ordinal: 1, status: "unavailable" },
  );

  let thenCalls = 0;
  const thenable = {
    then() {
      thenCalls += 1;
    },
  };
  assert.deepEqual(
    controllerFor(() => thenable).dispatch(1, "approved"),
    { ordinal: 1, status: "unavailable" },
  );
  assert.equal(thenCalls, 0);

  const proxy = new Proxy(
    { status: "success", action: "approved" },
    {
      ownKeys() {
        throw new Error("private proxy detail");
      },
    },
  );
  assert.deepEqual(
    controllerFor(() => proxy).dispatch(1, "approved"),
    { ordinal: 1, status: "unavailable" },
  );
});

test("safe state contains only generated ordinal and display-safe action", () => {
  const privateToken = "private-fixture-token-sentinel";
  const state = dispatchCandidateReviewDecision(
    (request) => {
      assert.equal("candidate_token" in request, false);
      assert.equal(JSON.stringify(request).includes(privateToken), false);
      return success(request.action);
    },
    1,
    "approved",
  );

  assert.deepEqual(state, { ordinal: 1, status: "success", action: "approved" });
  const serialized = JSON.stringify(state);
  assert.equal(serialized.includes(privateToken), false);
  assert.deepEqual(Object.keys(state).sort(), ["action", "ordinal", "status"]);
});

test("preview source contains the required accessible decision semantics", () => {
  const component = readFileSync(
    new URL("../components/CandidateReviewDecision.tsx", import.meta.url),
    "utf8",
  );
  const page = readFileSync(
    new URL("../app/synthetic/candidate-review-decision/page.tsx", import.meta.url),
    "utf8",
  );

  assert.match(component, /<fieldset/);
  assert.match(component, /<legend>/);
  assert.match(component, /type="button"/);
  assert.match(component, /aria-label=\{`\$\{ACTION_LABELS\[action\]\} candidate \$\{ordinal\}`\}/);
  assert.match(component, /aria-busy=\{busy\}/);
  assert.match(component, /role=\{feedbackRole\(candidateState\)\}/);
  assert.match(component, /No review recorded/);
  assert.match(component, /No action recorded/);
  assert.match(page, /SYNTHETIC PREVIEW/);
  assert.match(page, /No review is recorded/);
  assert.match(page, /no live or customer data/i);
  assert.match(page, /fixture_token/);
  assert.equal(page.includes("{syntheticFixture.fixture_token}"), false);
});
