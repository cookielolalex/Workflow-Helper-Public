import type { CandidateReviewView } from "@/lib/candidate-review";

type CandidateReviewQueueProps = Readonly<{
  view: CandidateReviewView;
}>;

export function CandidateReviewQueue({ view }: CandidateReviewQueueProps) {
  switch (view.status) {
    case "loading":
      return (
        <div className="empty-state" role="status" aria-live="polite" aria-busy="true">
          Loading candidate queue.
        </div>
      );
    case "unavailable":
      return (
        <div className="empty-state" role="alert">
          Candidate queue unavailable. Try again later.
        </div>
      );
    case "empty":
      return (
        <div className="empty-state" role="status">
          No candidates awaiting review.
        </div>
      );
    case "populated":
      return (
        <section className="panel" aria-labelledby="candidate-review-heading">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">CANDIDATE REVIEW</p>
              <h2 id="candidate-review-heading">Candidates awaiting review</h2>
            </div>
            <span className="muted">Observed evidence</span>
          </div>
          <div className="table-wrap">
            <table>
              <caption className="sr-only">Candidates awaiting review</caption>
              <thead>
                <tr>
                  <th scope="col">Candidate</th>
                  <th scope="col">Observed command sequence</th>
                  <th scope="col">Occurrences</th>
                  <th scope="col">Status</th>
                  <th scope="col">Finalized</th>
                </tr>
              </thead>
              <tbody>
                {view.rows.map((row) => (
                  <tr key={row.ordinal}>
                    <th scope="row">Candidate {row.ordinal}</th>
                    <td>{row.command_sequence.join(" → ")}</td>
                    <td>{row.occurrence_count}</td>
                    <td>{row.provenance} / {row.review_status}</td>
                    <td>
                      <time dateTime={row.finalized_at}>{row.finalized_at}</time>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      );
  }
}
