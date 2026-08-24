import Link from "next/link";

import { StatusCard } from "@/components/StatusCard";
import { formatDuration, getSessions } from "@/lib/api";


export default async function DashboardPage() {
  const sessionResult = await getSessions();
  const dashboard =
    sessionResult.status === "available"
      ? {
          sessions: sessionResult.sessions,
          processed: sessionResult.sessions.items.filter(
            (item) => item.processing_status === "processed",
          ).length,
          failed: sessionResult.sessions.items.filter(
            (item) => item.processing_status === "failed",
          ).length,
          pendingReview: sessionResult.sessions.items.filter(
            (item) => item.review_status === "pending",
          ).length,
        }
      : null;

  return (
    <div className="page-shell">
      <section className="hero">
        <div>
          <p className="eyebrow">CONTROL PLANE</p>
          <h1>Expert CAD workflow, made traceable.</h1>
          <p>
            Monitor approved capture sessions, inspect deterministic processing,
            and validate candidate knowledge without retaining raw evidence forever.
          </p>
        </div>
        <aside className="privacy-note">
          <strong>Privacy boundary active</strong>
          <span>Approved AutoCAD context only · recording disabled by default</span>
        </aside>
      </section>

      {dashboard ? (
        <section className="status-grid" aria-label="System status">
          <StatusCard
            label="Sessions"
            value={dashboard.sessions.count}
            detail="registered in this API process"
          />
          <StatusCard
            label="Processed"
            value={dashboard.processed}
            detail="compact timeline available"
            tone="good"
          />
          <StatusCard
            label="Pending review"
            value={dashboard.pendingReview}
            detail="expert decision required"
            tone="warning"
          />
          <StatusCard
            label="Failures"
            value={dashboard.failed}
            detail="requires operator attention"
            tone={dashboard.failed ? "warning" : "neutral"}
          />
        </section>
      ) : null}

      <section className="panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">RECENT ACTIVITY</p>
            <h2>CAD sessions</h2>
          </div>
          <span className="muted">Synthetic data only until pilot approval</span>
        </div>
        {!dashboard ? (
          <div className="empty-state">
            <strong>Control plane unavailable</strong>
            <p>Session state could not be loaded. Try again later.</p>
          </div>
        ) : dashboard.sessions.items.length === 0 ? (
          <div className="empty-state">
            <strong>No sessions registered yet</strong>
            <p>Run the synthetic vertical slice to verify capture → upload → processing → review.</p>
          </div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Started</th>
                  <th>Machine</th>
                  <th>Duration</th>
                  <th>Processing</th>
                  <th>Review</th>
                  <th><span className="sr-only">Open</span></th>
                </tr>
              </thead>
              <tbody>
                {dashboard.sessions.items.map((session) => (
                  <tr key={session.session_id}>
                    <td>{new Date(session.started_at).toLocaleString()}</td>
                    <td><code>{session.machine_id}</code></td>
                    <td>{formatDuration(session.active_duration_seconds)}</td>
                    <td><span className={`pill pill--${session.processing_status}`}>{session.processing_status}</span></td>
                    <td>{session.review_status.replaceAll("_", " ")}</td>
                    <td><Link href={`/sessions/${session.session_id}`}>Inspect →</Link></td>
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
