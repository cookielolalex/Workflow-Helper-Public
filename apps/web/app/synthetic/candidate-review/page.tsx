import { CandidateReviewQueue } from "@/components/CandidateReviewQueue";
import {
  readCandidateReview,
  type CandidateReviewTransport,
} from "@/lib/candidate-review-client";

const syntheticTransport: CandidateReviewTransport = () => ({
  status: 200,
  body: { items: [], count: 0, next_cursor: null },
});

export default function CandidateReviewPreviewPage() {
  const view = readCandidateReview(syntheticTransport, {
    correlation_id: "synthetic-preview",
    limit: 1,
  });

  return (
    <div className="page-shell">
      <section className="hero">
        <div>
          <p className="eyebrow">SYNTHETIC PREVIEW</p>
          <h1>Candidate review queue</h1>
          <p>This page contains no live or customer data.</p>
        </div>
      </section>
      <CandidateReviewQueue view={view} />
    </div>
  );
}
