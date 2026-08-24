import { CandidateReviewQueue } from "@/components/CandidateReviewQueue";
import { loadCandidateReviewQueue } from "@/lib/candidate-review-server";

export const dynamic = "force-dynamic";

export default async function CandidateReviewPage() {
  const view = await loadCandidateReviewQueue();

  return (
    <div className="page-shell">
      <section className="hero">
        <div>
          <p className="eyebrow">SYNTHETIC REVIEW</p>
          <h1>Candidate review queue</h1>
          <p>Only redacted synthetic evidence and legal bounded review transitions are shown.</p>
        </div>
        <aside className="privacy-note">
          <strong>Server-side authority boundary</strong>
          <span>Raw identifiers and reviewer credentials never enter this page.</span>
        </aside>
      </section>

      <CandidateReviewQueue view={view} />

      {view.status === "populated" ? (
        <section className="panel" aria-labelledby="candidate-actions-heading">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">HUMAN DECISION</p>
              <h2 id="candidate-actions-heading">Review actions</h2>
            </div>
            <span className="muted">Synthetic data only</span>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th scope="col">Candidate</th>
                  <th scope="col">Action</th>
                </tr>
              </thead>
              <tbody>
                {view.rows.map((row) => (
                  <tr key={row.ordinal}>
                    <th scope="row">Candidate {row.ordinal}</th>
                    <td>
                      <form method="post" action="/candidate-review/action">
                        <input type="hidden" name="ordinal" value={row.ordinal} />
                        <button type="submit" name="action" value="approve">
                          Approve
                        </button>
                        {row.review_status === "unreviewed" ? (
                          <button type="submit" name="action" value="start_review">
                            Start review
                          </button>
                        ) : (
                          <>
                            <button type="submit" name="action" value="reject">
                              Reject
                            </button>
                            <button type="submit" name="action" value="needs_changes">
                              Needs changes
                            </button>
                          </>
                        )}
                      </form>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      ) : null}
    </div>
  );
}
