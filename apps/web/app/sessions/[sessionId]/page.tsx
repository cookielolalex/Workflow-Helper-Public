import Link from "next/link";
import { notFound } from "next/navigation";

import {
  formatDuration,
  formatOffset,
  getProcessedTimeline,
  getSession,
  selectSessionPresentationState,
} from "@/lib/api";


type SessionPageProps = { params: Promise<{ sessionId: string }> };

export default async function SessionPage({ params }: SessionPageProps) {
  const { sessionId } = await params;
  const sessionResult = await getSession(sessionId);
  const timelineResult =
    sessionResult.status === "available" &&
    sessionResult.session.processing_status === "processed"
    ? await getProcessedTimeline(sessionId)
    : null;
  const presentation = selectSessionPresentationState(sessionResult, timelineResult);

  if (presentation.status === "not_found") notFound();
  if (presentation.status === "unavailable") {
    return (
      <div className="page-shell">
        <Link className="back-link" href="/">← Dashboard</Link>
        <section className="panel">
          <div className="empty-state">
            <strong>Session unavailable</strong>
            <p>Session details could not be loaded. Try again later.</p>
          </div>
        </section>
      </div>
    );
  }

  const { session, timeline: processedTimeline } = presentation;

  const facts = [
    ["Machine", session.machine_id],
    ["Project", session.project_id ?? "Not assigned"],
    ["Approved process", session.approved_process],
    ["Active duration", formatDuration(session.active_duration_seconds)],
    ["Processing", session.processing_status],
    ["Review", session.review_status.replaceAll("_", " ")],
    ["Raw expires", new Date(session.raw_expires_at).toLocaleString()],
  ];

  return (
    <div className="page-shell">
      <Link className="back-link" href="/">← Dashboard</Link>
      <section className="panel detail-panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">SESSION</p>
            <h1>{session.session_id}</h1>
          </div>
          <span className={`pill pill--${session.processing_status}`}>{session.processing_status}</span>
        </div>
        <dl className="fact-grid">
          {facts.map(([term, value]) => (
            <div key={term}>
              <dt>{term}</dt>
              <dd>{value}</dd>
            </div>
          ))}
        </dl>
      </section>

      <section className="split-grid">
        <article className="panel timeline-panel">
          <p className="eyebrow">TIMELINE</p>
          <h2>Meaningful operations</h2>
          {processedTimeline?.timeline.length ? (
            <>
              <p className="timeline-summary">
                {processedTimeline.meaningful_event_count} meaningful operations from{" "}
                {processedTimeline.event_count} observed events.
              </p>
              <ol className="timeline-list">
                {processedTimeline.timeline.map((item) => (
                  <li key={item.source_event_id}>
                    <time dateTime={`PT${item.offset_seconds}S`}>
                      {formatOffset(item.offset_seconds)}
                    </time>
                    <div>
                      <strong>{item.summary}</strong>
                      <span>{item.event_type.replaceAll("_", " ")}</span>
                    </div>
                  </li>
                ))}
              </ol>
              {processedTimeline.warnings.length > 0 && (
                <div className="timeline-warnings" role="note">
                  <strong>Processing notes</strong>
                  <ul>
                    {processedTimeline.warnings.map((warning) => (
                      <li key={warning}>{warning}</li>
                    ))}
                  </ul>
                </div>
              )}
            </>
          ) : (
            <p className="timeline-empty">
              {session.processing_status === "processed"
                ? "Processing completed, but no meaningful operations were returned."
                : "The worker’s compact timeline will appear here after processing."}
            </p>
          )}
          {processedTimeline?.schema_version === "2.0" && (
            <>
              <h3>Deterministic operation segments</h3>
              {processedTimeline.operation_segments.length > 0 ? (
                <ol className="timeline-list">
                  {processedTimeline.operation_segments.map((segment) => (
                    <li key={`${segment.sequence}-${segment.source_event_ids.join("-")}`}>
                      <time dateTime={`PT${segment.start_offset_seconds}S`}>
                        {formatOffset(segment.start_offset_seconds)}–
                        {formatOffset(segment.end_offset_seconds)}
                      </time>
                      <div>
                        <strong>{segment.summary}</strong>
                        <span>Segment {segment.sequence}</span>
                        <span>Commands: {segment.command_names.join(", ")}</span>
                        <span>Drawing: {segment.drawing_ref}</span>
                        <span>Evidence: {segment.source_event_ids.join(", ")}</span>
                      </div>
                    </li>
                  ))}
                </ol>
              ) : (
                <p className="timeline-empty">No deterministic operation segments were returned.</p>
              )}
            </>
          )}
        </article>
        <article className="panel placeholder-panel">
          <p className="eyebrow">EXPERT REVIEW</p>
          <h2>High-information questions</h2>
          <p>Review mutations are deferred until authentication and audit logging are implemented.</p>
        </article>
      </section>
    </div>
  );
}
