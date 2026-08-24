export type ProcessingStatus =
  | "registered"
  | "uploaded"
  | "processing"
  | "processed"
  | "failed";

export type ReviewStatus =
  | "not_ready"
  | "pending"
  | "approved"
  | "rejected"
  | "needs_changes";

export type Session = {
  schema_version: "1.0";
  session_id: string;
  machine_id: string;
  project_id: string | null;
  started_at: string;
  ended_at: string;
  active_duration_seconds: number;
  approved_process: string;
  processing_status: ProcessingStatus;
  review_status: ReviewStatus;
  raw_expires_at: string;
  raw_object_key: string | null;
  processed_prefix: string | null;
};

export type TimelineItem = {
  offset_seconds: number;
  event_type: string;
  summary: string;
  source_event_id: string;
};

type ProcessedTimelineFields = {
  session_id: string;
  event_count: number;
  meaningful_event_count: number;
  timeline: TimelineItem[];
  keyframes: string[];
  warnings: string[];
};

export type OperationSegment = {
  sequence: number;
  start_offset_seconds: number;
  end_offset_seconds: number;
  command_names: string[];
  drawing_ref: string;
  summary: string;
  source_event_ids: string[];
};

export type ProcessedTimelineV1 = ProcessedTimelineFields & {
  schema_version: "1.0";
};

export type ProcessedTimelineV2 = ProcessedTimelineFields & {
  schema_version: "2.0";
  operation_segments: OperationSegment[];
};

export type ProcessedTimeline = ProcessedTimelineV1 | ProcessedTimelineV2;

export type SessionList = { items: Session[]; count: number };

export type SessionListResult =
  | { status: "available"; sessions: SessionList }
  | { status: "unavailable" };

export type SessionResult =
  | { status: "available"; session: Session }
  | { status: "not_found" }
  | { status: "unavailable" };

export type ProcessedTimelineResult =
  | { status: "available"; timeline: ProcessedTimeline }
  | { status: "unavailable" };

export type SessionPresentationState =
  | { status: "available"; session: Session; timeline: ProcessedTimeline | null }
  | { status: "not_found" }
  | { status: "unavailable" };

const API_BASE_URL =
  process.env.API_BASE_URL ??
  process.env.NEXT_PUBLIC_API_BASE_URL ??
  "http://localhost:8000";

export async function getSessions(): Promise<SessionListResult> {
  try {
    const response = await fetch(`${API_BASE_URL}/v1/sessions`, { cache: "no-store" });
    if (!response.ok) return { status: "unavailable" };
    return {
      status: "available",
      sessions: (await response.json()) as SessionList,
    };
  } catch {
    return { status: "unavailable" };
  }
}

export async function getSession(sessionId: string): Promise<SessionResult> {
  try {
    const response = await fetch(`${API_BASE_URL}/v1/sessions/${sessionId}`, {
      cache: "no-store",
    });
    if (response.status === 404) return { status: "not_found" };
    if (!response.ok) return { status: "unavailable" };
    const session = (await response.json()) as unknown;
    if (!isRecord(session) || session.schema_version !== "1.0") {
      return { status: "unavailable" };
    }
    return {
      status: "available",
      session: session as Session,
    };
  } catch {
    return { status: "unavailable" };
  }
}

export async function getProcessedTimeline(
  sessionId: string,
): Promise<ProcessedTimelineResult> {
  try {
    const response = await fetch(`${API_BASE_URL}/v1/sessions/${sessionId}/timeline`, {
      cache: "no-store",
    });
    if (!response.ok) return { status: "unavailable" };
    const timeline = parseProcessedTimeline(await response.json());
    return timeline
      ? { status: "available", timeline }
      : { status: "unavailable" };
  } catch {
    return { status: "unavailable" };
  }
}

export function selectSessionPresentationState(
  sessionResult: SessionResult,
  timelineResult: ProcessedTimelineResult | null,
): SessionPresentationState {
  switch (sessionResult.status) {
    case "not_found":
      return { status: "not_found" };
    case "unavailable":
      return { status: "unavailable" };
    case "available":
      if (sessionResult.session.processing_status !== "processed") {
        return {
          status: "available",
          session: sessionResult.session,
          timeline: null,
        };
      }
      if (timelineResult?.status === "available") {
        return {
          status: "available",
          session: sessionResult.session,
          timeline: timelineResult.timeline,
        };
      }
      return { status: "unavailable" };
  }
}

function parseProcessedTimeline(value: unknown): ProcessedTimeline | null {
  if (!isRecord(value) || (value.schema_version !== "1.0" && value.schema_version !== "2.0")) {
    return null;
  }

  const timeline = parseTimelineItems(value.timeline);
  const keyframes = parseStringArray(value.keyframes);
  const warnings = parseStringArray(value.warnings);
  if (
    typeof value.session_id !== "string" ||
    typeof value.event_count !== "number" ||
    typeof value.meaningful_event_count !== "number" ||
    !timeline ||
    !keyframes ||
    !warnings
  ) {
    return null;
  }

  const fields: ProcessedTimelineFields = {
    session_id: value.session_id,
    event_count: value.event_count,
    meaningful_event_count: value.meaningful_event_count,
    timeline,
    keyframes,
    warnings,
  };

  if (value.schema_version === "1.0") {
    return { schema_version: "1.0", ...fields };
  }

  const operationSegments = parseOperationSegments(value.operation_segments);
  return operationSegments
    ? {
        schema_version: "2.0",
        ...fields,
        operation_segments: operationSegments,
      }
    : null;
}

function parseTimelineItems(value: unknown): TimelineItem[] | null {
  if (!Array.isArray(value)) return null;
  const items: TimelineItem[] = [];
  for (const item of value) {
    if (
      !isRecord(item) ||
      typeof item.offset_seconds !== "number" ||
      typeof item.event_type !== "string" ||
      typeof item.summary !== "string" ||
      typeof item.source_event_id !== "string"
    ) {
      return null;
    }
    items.push({
      offset_seconds: item.offset_seconds,
      event_type: item.event_type,
      summary: item.summary,
      source_event_id: item.source_event_id,
    });
  }
  return items;
}

function parseOperationSegments(value: unknown): OperationSegment[] | null {
  if (!Array.isArray(value)) return null;
  const segments: OperationSegment[] = [];
  for (const segment of value) {
    if (!isRecord(segment)) return null;
    const commandNames = parseStringArray(segment.command_names);
    const sourceEventIds = parseStringArray(segment.source_event_ids);
    if (
      typeof segment.sequence !== "number" ||
      typeof segment.start_offset_seconds !== "number" ||
      typeof segment.end_offset_seconds !== "number" ||
      !commandNames ||
      typeof segment.drawing_ref !== "string" ||
      typeof segment.summary !== "string" ||
      !sourceEventIds
    ) {
      return null;
    }
    segments.push({
      sequence: segment.sequence,
      start_offset_seconds: segment.start_offset_seconds,
      end_offset_seconds: segment.end_offset_seconds,
      command_names: commandNames,
      drawing_ref: segment.drawing_ref,
      summary: segment.summary,
      source_event_ids: sourceEventIds,
    });
  }
  return segments;
}

function parseStringArray(value: unknown): string[] | null {
  return Array.isArray(value) && value.every((item) => typeof item === "string")
    ? [...value]
    : null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function formatDuration(totalSeconds: number): string {
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return `${minutes}m ${seconds.toString().padStart(2, "0")}s`;
}


export function formatOffset(totalSeconds: number): string {
  const roundedSeconds = Math.max(0, Math.floor(totalSeconds));
  const hours = Math.floor(roundedSeconds / 3600);
  const minutes = Math.floor((roundedSeconds % 3600) / 60);
  const seconds = roundedSeconds % 60;
  return hours > 0
    ? `${hours}:${minutes.toString().padStart(2, "0")}:${seconds.toString().padStart(2, "0")}`
    : `${minutes}:${seconds.toString().padStart(2, "0")}`;
}
