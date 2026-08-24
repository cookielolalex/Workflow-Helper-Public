import Link from "next/link";

import { loadApprovedWorkflows } from "@/lib/candidate-review-server";

export const dynamic = "force-dynamic";

export default async function ApprovedWorkflowsPage() {
  const catalog = await loadApprovedWorkflows();

  return (
    <div className="page-shell">
      <section className="hero">
        <div>
          <p className="eyebrow">SYNTHETIC CATALOG</p>
          <h1>Approved workflows</h1>
          <p>Only bounded, redacted workflows with a durable approved outcome are shown.</p>
        </div>
        <aside className="privacy-note">
          <strong>Safe export boundary</strong>
          <span>Identifiers, reasons, credentials, and raw evidence are never exported.</span>
        </aside>
      </section>

      <section className="panel" aria-labelledby="approved-workflows-heading">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">APPROVED ONLY</p>
            <h2 id="approved-workflows-heading">Workflow catalog</h2>
          </div>
          <Link href="/candidate-review">Review candidates →</Link>
        </div>
        {catalog.status === "unavailable" ? (
          <div className="empty-state">
            <strong>Approved workflows unavailable</strong>
            <p>The sealed synthetic outcome authority could not be read.</p>
          </div>
        ) : catalog.status === "empty" ? (
          <div className="empty-state">
            <strong>No approved workflows yet</strong>
            <p>Approve a synthetic candidate to make a bounded export available.</p>
          </div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th scope="col">Workflow</th>
                  <th scope="col">Commands</th>
                  <th scope="col">Occurrences</th>
                  <th scope="col">Decision</th>
                  <th scope="col"><span className="sr-only">Download</span></th>
                </tr>
              </thead>
              <tbody>
                {catalog.rows.map((row) => (
                  <tr key={row.ordinal}>
                    <th scope="row">Approved workflow {row.ordinal}</th>
                    <td>{row.command_sequence.join(" → ")}</td>
                    <td>{row.occurrence_count}</td>
                    <td>{row.provenance} / {row.approval_status}</td>
                    <td>
                      <a href={`/approved-workflows/download?ordinal=${row.ordinal}`}>
                        Download JSON
                      </a>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
