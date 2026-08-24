"use client";

import { CandidateReviewDecision } from "@/components/CandidateReviewDecision";
import type { CandidateReviewDecisionTransport } from "@/lib/candidate-review-decision";

// This fixture is intentionally private to this page and its local transport.
// Only the generated ordinal and the bounded pending label reach the UI.
const syntheticFixture = {
  fixture_token: "synthetic-private-candidate-fixture",
  ordinal: 1,
  status: "pending",
} as const;

const syntheticTransport: CandidateReviewDecisionTransport = (request) => {
  if (
    request.candidate_ordinal !== syntheticFixture.ordinal ||
    syntheticFixture.status !== "pending" ||
    syntheticFixture.fixture_token.length === 0
  ) {
    return { status: "unavailable", action: request.action };
  }

  return { status: "success", action: request.action };
};

export default function CandidateReviewDecisionPreviewPage() {
  return (
    <div className="page-shell">
      <section className="hero">
        <div>
          <p className="eyebrow">SYNTHETIC PREVIEW</p>
          <h1>Candidate review decisions</h1>
          <p>
            No review is recorded. This preview uses no live or customer data.
          </p>
        </div>
      </section>
      <CandidateReviewDecision
        transport={syntheticTransport}
        candidateOrdinals={[syntheticFixture.ordinal]}
        reviewStatus={syntheticFixture.status}
      />
    </div>
  );
}
