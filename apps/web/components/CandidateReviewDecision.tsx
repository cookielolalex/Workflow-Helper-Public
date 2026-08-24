"use client";

import { useMemo, useState } from "react";

import {
  CANDIDATE_REVIEW_ACTIONS,
  createCandidateReviewDecisionController,
  type CandidateReviewAction,
  type CandidateReviewDecisionState,
  type CandidateReviewDecisionTransport,
} from "@/lib/candidate-review-decision";

type CandidateReviewDecisionProps = Readonly<{
  readonly transport: CandidateReviewDecisionTransport;
  /** Generated ordinals are the only candidate identity exposed to this UI. */
  readonly candidateOrdinals?: readonly number[];
  readonly reviewStatus?: "pending";
}>;

const DEFAULT_CANDIDATE_ORDINALS = [1] as const;

const ACTION_LABELS: Readonly<Record<CandidateReviewAction, string>> = {
  approved: "Approve",
  rejected: "Reject",
  needs_changes: "Needs changes",
};

function actionSuccessLabel(action: CandidateReviewAction): string {
  return `${ACTION_LABELS[action]} selected.`;
}
function stateMessage(state: CandidateReviewDecisionState): string {
  switch (state.status) {
    case "ready":
      return "Ready to record a decision.";
    case "pending":
      return "Decision pending. Actions are disabled.";
    case "success":
      return `${actionSuccessLabel(state.action)} No review recorded.`;
    case "conflict":
      return "Decision could not be recorded because the candidate changed. No review recorded.";
    case "unavailable":
      return "Decision unavailable. No action recorded.";
  }
}

function stateLabel(state: CandidateReviewDecisionState): string {
  switch (state.status) {
    case "ready":
      return "Ready";
    case "pending":
      return "Pending";
    case "success":
      return "Complete";
    case "conflict":
      return "Conflict";
    case "unavailable":
      return "Unavailable";
  }
}

function feedbackRole(state: CandidateReviewDecisionState): "status" | "alert" {
  return state.status === "conflict" || state.status === "unavailable"
    ? "alert"
    : "status";
}

export function CandidateReviewDecision({
  transport,
  candidateOrdinals = DEFAULT_CANDIDATE_ORDINALS,
  reviewStatus = "pending",
}: CandidateReviewDecisionProps) {
  const controller = useMemo(
    () =>
      createCandidateReviewDecisionController({
        transport,
        candidateOrdinals,
      }),
    [transport, candidateOrdinals],
  );
  const [states, setStates] = useState<
    readonly CandidateReviewDecisionState[]
  >(() => controller.getStates());

  const dispatch = (ordinal: number, action: CandidateReviewAction) => {
    controller.dispatch(ordinal, action);
    setStates(controller.getStates());
  };

  return (
    <section className="panel" aria-labelledby="candidate-review-decision-heading">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">CANDIDATE REVIEW DECISION</p>
          <h2 id="candidate-review-decision-heading">Review candidate</h2>
        </div>
        <span className="muted">Synthetic only</span>
      </div>
      <div className="decision-list">
        {states.map((candidateState) => {
          const ordinal = candidateState.ordinal;
          const busy = candidateState.status === "pending";
          const messageId = `candidate-review-decision-message-${ordinal}`;

          return (
            <fieldset
              className="decision-card"
              key={ordinal}
              disabled={candidateState.status !== "ready"}
              aria-busy={busy}
              aria-describedby={messageId}
            >
              <legend>Candidate {ordinal} review decision</legend>
              <p className="muted">
                Review status: <strong>{reviewStatus}</strong>
              </p>
              <p className="decision-state" aria-label={`Candidate ${ordinal} state`}>
                State: <strong>{stateLabel(candidateState)}</strong>
              </p>
              <div className="decision-actions" aria-label={`Actions for candidate ${ordinal}`}>
                {CANDIDATE_REVIEW_ACTIONS.map((action) => (
                  <button
                    key={action}
                    type="button"
                    disabled={candidateState.status !== "ready"}
                    aria-label={`${ACTION_LABELS[action]} candidate ${ordinal}`}
                    onClick={() => dispatch(ordinal, action)}
                  >
                    {ACTION_LABELS[action]}
                  </button>
                ))}
              </div>
              <p
                id={messageId}
                className="decision-message"
                role={feedbackRole(candidateState)}
                aria-live={busy ? "polite" : "assertive"}
              >
                {stateMessage(candidateState)}
              </p>
            </fieldset>
          );
        })}
      </div>
      <p className="muted decision-disclaimer">
        This synthetic preview records no review and uses no live or customer data.
      </p>
    </section>
  );
}
