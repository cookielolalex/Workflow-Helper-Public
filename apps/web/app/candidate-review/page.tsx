import { CandidateReviewQueue } from "@/components/CandidateReviewQueue";
import {
  loadCandidateReviewOutcomes,
  loadCandidateReviewQueue,
} from "@/lib/candidate-review-server";

export const dynamic = "force-dynamic";

export default async function CandidateReviewPage() {
  const [view, outcomes] = await Promise.all([
    loadCandidateReviewQueue(),
    loadCandidateReviewOutcomes(),
  ]);

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
                      </form>
                      {row.review_status === "unreviewed" ? (
                        <form method="post" action="/candidate-review/action">
                          <input type="hidden" name="ordinal" value={row.ordinal} />
                          <button type="submit" name="action" value="start_review">
                            Start review
                          </button>
                        </form>
                      ) : (
                        <>
                          <form method="post" action="/candidate-review/action">
                            <input type="hidden" name="ordinal" value={row.ordinal} />
                            <label>
                              Reject reason
                              <select name="reason_code" required defaultValue="">
                                <option value="" disabled>Select a fixed reason</option>
                                <option value="sequence">Sequence mismatch</option>
                                <option value="evidence">Insufficient evidence</option>
                              </select>
                            </label>
                            <button type="submit" name="action" value="reject">
                              Reject
                            </button>
                          </form>
                          <form method="post" action="/candidate-review/action">
                            <input type="hidden" name="ordinal" value={row.ordinal} />
                            <label>
                              Changes reason
                              <select name="reason_code" required defaultValue="">
                                <option value="" disabled>Select a fixed reason</option>
                                <option value="sequence">Sequence mismatch</option>
                                <option value="evidence">Insufficient evidence</option>
                              </select>
                            </label>
                            <button type="submit" name="action" value="needs_changes">
                              Needs changes
                            </button>
                          </form>
                        </>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      ) : null}

      <section className="panel" aria-labelledby="review-outcomes-heading">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">TERMINAL HISTORY</p>
            <h2 id="review-outcomes-heading">Review outcomes</h2>
          </div>
          <span className="muted">Redacted synthetic evidence</span>
        </div>
        {outcomes.status === "populated" ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th scope="col">Outcome</th>
                  <th scope="col">Commands</th>
                  <th scope="col">Status</th>
                  <th scope="col">Reason</th>
                  <th scope="col">Decision time</th>
                </tr>
              </thead>
              <tbody>
                {outcomes.rows.map((row) => (
                  <tr key={row.ordinal}>
                    <th scope="row">Outcome {row.ordinal}</th>
                    <td>{row.command_sequence.join(" → ")}</td>
                    <td>{row.review_status}</td>
                    <td>
                      {row.reason_code === "sequence"
                        ? "Sequence mismatch"
                        : row.reason_code === "evidence"
                          ? "Insufficient evidence"
                          : "No reason code"}
                    </td>
                    <td>{row.decided_at}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : outcomes.status === "empty" ? (
          <p>No terminal review outcomes.</p>
        ) : (
          <p>Review outcomes are unavailable.</p>
        )}
      </section>
    </div>
  );
}
