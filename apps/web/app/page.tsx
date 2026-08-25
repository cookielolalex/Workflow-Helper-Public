import Link from "next/link";

import { StatusCard } from "@/components/StatusCard";
import { formatDuration, getSessions } from "@/lib/api";
import {
  loadCandidateReviewOutcomes,
  loadCandidateReviewQueue,
} from "@/lib/candidate-review-server";

export const dynamic = "force-dynamic";

export default async function DashboardPage() {
  const [sessionResult, reviewQueue, reviewOutcomes] = await Promise.all([
    getSessions(),
    loadCandidateReviewQueue(),
    loadCandidateReviewOutcomes(),
  ]);
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
        }
      : null;
  const activeReviewMetric =
    reviewQueue.status === "unavailable"
      ? {
          value: "Unavailable",
          detail: "Active review count unavailable",
          tone: "warning" as const,
        }
      : reviewQueue.status === "loading"
        ? {
            value: "Unavailable",
            detail: "Active review count unavailable",
            tone: "warning" as const,
          }
      : reviewQueue.status === "empty"
        ? {
            value: 0,
            detail: "No candidates awaiting review",
            tone: "neutral" as const,
          }
        : {
            value: reviewQueue.rows.length,
            detail: `${reviewQueue.rows.length} ${reviewQueue.rows.length === 1 ? "candidate" : "candidates"} awaiting review · independent queue snapshot`,
            tone: "warning" as const,
          };
  const outcomeCount =
    reviewOutcomes.status === "populated" ? reviewOutcomes.rows.length : null;
  const approvedCount =
    reviewOutcomes.status === "populated"
      ? reviewOutcomes.rows.filter((row) => row.review_status === "approved").length
      : 0;
  const reviewOutcomesMetric =
    reviewOutcomes.status === "unavailable"
      ? {
          value: "Unavailable",
          detail: "Review outcome count unavailable",
          tone: "warning" as const,
        }
      : reviewOutcomes.status === "empty"
        ? {
            value: 0,
            detail: "No terminal outcomes recorded",
            tone: "neutral" as const,
          }
        : {
            value: outcomeCount!,
            detail: `${outcomeCount} ${outcomeCount === 1 ? "terminal outcome" : "terminal outcomes"} · independent outcomes snapshot`,
            tone: "neutral" as const,
          };
  const approvedWorkflowsMetric =
    reviewOutcomes.status === "unavailable"
      ? {
          value: "Unavailable",
          detail: "Approved workflow count unavailable",
          tone: "warning" as const,
        }
      : {
          value: approvedCount,
          detail:
            approvedCount === 0
              ? "No approved workflows yet"
              : `${approvedCount} approved ${approvedCount === 1 ? "workflow" : "workflows"} · derived from outcomes snapshot`,
          tone: approvedCount ? ("good" as const) : ("neutral" as const),
        };

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

      <section className="status-grid" aria-label="System status">
        <StatusCard
          label="Sessions"
          value={dashboard?.sessions.count ?? "Unavailable"}
          detail={dashboard ? "registered in this API process" : "Session count unavailable"}
          tone={dashboard ? "neutral" : "warning"}
        />
        <StatusCard
          label="Processed"
          value={dashboard?.processed ?? "Unavailable"}
          detail={dashboard ? "compact timeline available" : "Processed count unavailable"}
          tone={dashboard ? "good" : "warning"}
        />
        <StatusCard
          label="Active review"
          value={activeReviewMetric.value}
          detail={activeReviewMetric.detail}
          tone={activeReviewMetric.tone}
        />
        <StatusCard
          label="Review outcomes"
          value={reviewOutcomesMetric.value}
          detail={reviewOutcomesMetric.detail}
          tone={reviewOutcomesMetric.tone}
        />
        <StatusCard
          label="Approved workflows"
          value={approvedWorkflowsMetric.value}
          detail={approvedWorkflowsMetric.detail}
          tone={approvedWorkflowsMetric.tone}
        />
        <StatusCard
          label="Failures"
          value={dashboard?.failed ?? "Unavailable"}
          detail={dashboard ? "requires operator attention" : "Failure count unavailable"}
          tone={dashboard ? (dashboard.failed ? "warning" : "neutral") : "warning"}
        />
      </section>

      <section className="panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">RECENT ACTIVITY</p>
            <h2>CAD sessions</h2>
          </div>
          <div>
            <span className="muted">Synthetic data only until pilot approval</span>
            <br />
            <Link href="/candidate-review">Review candidates →</Link>
            <br />
            <Link href="/approved-workflows">Approved workflows →</Link>
          </div>
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
