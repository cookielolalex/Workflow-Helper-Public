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

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const DATE_PATTERN =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)$/;
const MAX_SESSIONS = 100;
const MAX_TIMELINE_ITEMS = 10_000;
const MAX_TEXT_ARRAY_ITEMS = 1_000;
const MAX_EVENT_COUNT = 1_000_000;
const SESSION_KEYS = [
  "schema_version",
  "session_id",
  "machine_id",
  "project_id",
  "started_at",
  "ended_at",
  "active_duration_seconds",
  "approved_process",
  "package_sha256",
  "package_size_bytes",
  "processing_status",
  "review_status",
  "raw_object_key",
  "processed_prefix",
  "processing_output",
  "processing_completion_id",
  "processing_completed_at",
  "raw_expires_at",
  "created_at",
  "updated_at",
] as const;
const TIMELINE_KEYS = [
  "schema_version",
  "session_id",
  "event_count",
  "meaningful_event_count",
  "timeline",
  "keyframes",
  "warnings",
] as const;
const TIMELINE_V2_KEYS = [...TIMELINE_KEYS, "operation_segments"] as const;
const TIMELINE_ITEM_KEYS = [
  "offset_seconds",
  "event_type",
  "summary",
  "source_event_id",
] as const;
const SEGMENT_KEYS = [
  "sequence",
  "start_offset_seconds",
  "end_offset_seconds",
  "command_names",
  "drawing_ref",
  "summary",
  "source_event_ids",
] as const;
const PROCESSING_STATUSES = new Set<ProcessingStatus>([
  "registered",
  "uploaded",
  "processing",
  "processed",
  "failed",
]);
const REVIEW_STATUSES = new Set<ReviewStatus>([
  "not_ready",
  "pending",
  "approved",
  "rejected",
  "needs_changes",
]);
const EVENT_TYPES = new Set([
  "session_started",
  "session_paused",
  "session_resumed",
  "session_ended",
  "drawing_opened",
  "drawing_saved",
  "drawing_closed",
  "cad_command",
  "foreground_changed",
  "idle_started",
  "idle_ended",
]);

export async function getSessions(): Promise<SessionListResult> {
  try {
    const response = await getSyntheticSessionRoute({ route: "list" });
    if (response?.status !== 200) return { status: "unavailable" };
    const sessions = parseSessionList(response.body);
    return sessions === null
      ? { status: "unavailable" }
      : { status: "available", sessions };
  } catch {
    return { status: "unavailable" };
  }
}

export async function getSession(sessionId: string): Promise<SessionResult> {
  try {
    if (!canonicalUuid(sessionId)) return { status: "unavailable" };
    const response = await getSyntheticSessionRoute({
      route: "detail",
      session_id: sessionId,
    });
    if (response?.status === 404) return { status: "not_found" };
    if (response?.status !== 200) return { status: "unavailable" };
    const session = parseSession(response.body, sessionId);
    if (session === null) return { status: "unavailable" };
    return {
      status: "available",
      session,
    };
  } catch {
    return { status: "unavailable" };
  }
}

export async function getProcessedTimeline(
  sessionId: string,
): Promise<ProcessedTimelineResult> {
  try {
    if (!canonicalUuid(sessionId)) return { status: "unavailable" };
    const response = await getSyntheticSessionRoute({
      route: "timeline",
      session_id: sessionId,
    });
    if (response?.status !== 200) return { status: "unavailable" };
    const timeline = parseProcessedTimeline(response.body, sessionId);
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

function parseSessionList(value: unknown): SessionList | null {
  if (!hasExactKeys(value, ["items", "count"]) || !Array.isArray(value.items)) {
    return null;
  }
  if (
    !safeInteger(value.count, 0, MAX_SESSIONS) ||
    value.items.length !== value.count ||
    value.items.length > MAX_SESSIONS
  ) {
    return null;
  }
  const items: Session[] = [];
  const identities = new Set<string>();
  for (const raw of value.items) {
    const item = parseSession(raw);
    if (item === null || identities.has(item.session_id)) return null;
    identities.add(item.session_id);
    items.push(item);
  }
  return { items, count: items.length };
}

function parseSession(value: unknown, expectedId?: string): Session | null {
  if (!hasExactKeys(value, SESSION_KEYS)) return null;
  const processingStatus = value.processing_status;
  const reviewStatus = value.review_status;
  if (
    value.schema_version !== "1.0" ||
    !canonicalUuid(value.session_id) ||
    (expectedId !== undefined && value.session_id !== expectedId) ||
    !boundedString(value.machine_id, 8, 128) ||
    !(value.project_id === null || boundedString(value.project_id, 1, 128)) ||
    !validDate(value.started_at) ||
    !validDate(value.ended_at) ||
    Date.parse(value.ended_at) < Date.parse(value.started_at) ||
    !safeInteger(value.active_duration_seconds, 0, 604_800) ||
    !boundedString(value.approved_process, 1, 128) ||
    typeof value.package_sha256 !== "string" ||
    !SHA256_PATTERN.test(value.package_sha256) ||
    !safeInteger(value.package_size_bytes, 1, 536_870_912) ||
    typeof processingStatus !== "string" ||
    !PROCESSING_STATUSES.has(processingStatus as ProcessingStatus) ||
    typeof reviewStatus !== "string" ||
    !REVIEW_STATUSES.has(reviewStatus as ReviewStatus) ||
    !nullableBoundedString(value.raw_object_key, 1, 1024) ||
    !nullableBoundedString(value.processed_prefix, 1, 1024) ||
    !nullableBoundedString(value.processing_completion_id, 1, 128) ||
    !(value.processing_completed_at === null || validDate(value.processing_completed_at)) ||
    !validDate(value.raw_expires_at) ||
    !validDate(value.created_at) ||
    !validDate(value.updated_at)
  ) {
    return null;
  }
  if (value.processing_output !== null) {
    const output = parseProcessedTimeline(value.processing_output, value.session_id);
    if (output === null) return null;
  }
  return {
    schema_version: "1.0",
    session_id: value.session_id,
    machine_id: value.machine_id,
    project_id: value.project_id,
    started_at: value.started_at,
    ended_at: value.ended_at,
    active_duration_seconds: value.active_duration_seconds,
    approved_process: value.approved_process,
    processing_status: processingStatus as ProcessingStatus,
    review_status: reviewStatus as ReviewStatus,
    raw_expires_at: value.raw_expires_at,
    raw_object_key: value.raw_object_key,
    processed_prefix: value.processed_prefix,
  };
}

function parseProcessedTimeline(
  value: unknown,
  expectedSessionId?: string,
): ProcessedTimeline | null {
  if (
    !isRecord(value) ||
    (value.schema_version !== "1.0" && value.schema_version !== "2.0") ||
    !hasExactKeys(value, value.schema_version === "1.0" ? TIMELINE_KEYS : TIMELINE_V2_KEYS)
  ) {
    return null;
  }

  const timeline = parseTimelineItems(value.timeline);
  const keyframes = parseStringArray(value.keyframes, 0, MAX_TEXT_ARRAY_ITEMS, 1024);
  const warnings = parseStringArray(value.warnings, 0, MAX_TEXT_ARRAY_ITEMS, 2000);
  if (
    !canonicalUuid(value.session_id) ||
    (expectedSessionId !== undefined && value.session_id !== expectedSessionId) ||
    !safeInteger(value.event_count, 0, MAX_EVENT_COUNT) ||
    !safeInteger(value.meaningful_event_count, 0, value.event_count) ||
    value.meaningful_event_count !== timeline?.length ||
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
  return operationSegments && segmentsMatchTimeline(operationSegments, timeline)
    ? {
        schema_version: "2.0",
        ...fields,
        operation_segments: operationSegments,
      }
    : null;
}

function segmentsMatchTimeline(
  segments: OperationSegment[],
  timeline: TimelineItem[],
): boolean {
  const offsets = new Map(timeline.map((item) => [item.source_event_id, item.offset_seconds]));
  for (const segment of segments) {
    for (const sourceEventId of segment.source_event_ids) {
      const offset = offsets.get(sourceEventId);
      if (
        offset === undefined ||
        offset < segment.start_offset_seconds ||
        offset > segment.end_offset_seconds
      ) {
        return false;
      }
    }
  }
  return true;
}

function parseTimelineItems(value: unknown): TimelineItem[] | null {
  if (!Array.isArray(value) || value.length > MAX_TIMELINE_ITEMS) return null;
  const items: TimelineItem[] = [];
  const identities = new Set<string>();
  let previousOffset = -1;
  for (const item of value) {
    if (
      !hasExactKeys(item, TIMELINE_ITEM_KEYS) ||
      !finiteNumber(item.offset_seconds, 0, 604_800) ||
      item.offset_seconds < previousOffset ||
      typeof item.event_type !== "string" ||
      !EVENT_TYPES.has(item.event_type) ||
      !boundedString(item.summary, 1, 512) ||
      !canonicalUuid(item.source_event_id) ||
      identities.has(item.source_event_id)
    ) {
      return null;
    }
    identities.add(item.source_event_id);
    previousOffset = item.offset_seconds;
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
  if (!Array.isArray(value) || value.length > 1000) return null;
  const segments: OperationSegment[] = [];
  const usedEvidence = new Set<string>();
  let previousEnd = -1;
  for (const segment of value) {
    if (!hasExactKeys(segment, SEGMENT_KEYS)) return null;
    const commandNames = parseStringArray(segment.command_names, 1, 64, 128, true);
    const sourceEventIds = parseUuidArray(segment.source_event_ids, 1, 256);
    if (
      !safeInteger(segment.sequence, 1, 1000) ||
      segment.sequence !== segments.length + 1 ||
      !finiteNumber(segment.start_offset_seconds, 0, 604_800) ||
      !finiteNumber(segment.end_offset_seconds, 0, 604_800) ||
      segment.start_offset_seconds > segment.end_offset_seconds ||
      segment.start_offset_seconds < previousEnd ||
      !commandNames ||
      !boundedString(segment.drawing_ref, 1, 255) ||
      !boundedString(segment.summary, 1, 512) ||
      !sourceEventIds ||
      sourceEventIds.some((id) => usedEvidence.has(id))
    ) {
      return null;
    }
    sourceEventIds.forEach((id) => usedEvidence.add(id));
    previousEnd = segment.end_offset_seconds;
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

function parseStringArray(
  value: unknown,
  minimum = 0,
  maximum = MAX_TEXT_ARRAY_ITEMS,
  maxLength = 2000,
  unique = false,
): string[] | null {
  if (
    !Array.isArray(value) ||
    value.length < minimum ||
    value.length > maximum ||
    !value.every((item) => boundedString(item, 1, maxLength)) ||
    (unique && new Set(value).size !== value.length)
  ) {
    return null;
  }
  return [...value];
}

function parseUuidArray(value: unknown, minimum: number, maximum: number): string[] | null {
  if (
    !Array.isArray(value) ||
    value.length < minimum ||
    value.length > maximum ||
    !value.every(canonicalUuid) ||
    new Set(value).size !== value.length
  ) {
    return null;
  }
  return [...value];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function hasExactKeys<T extends readonly string[]>(
  value: unknown,
  keys: T,
): value is Record<T[number], unknown> {
  if (!isRecord(value)) return false;
  const ownKeys = Reflect.ownKeys(value);
  return (
    ownKeys.length === keys.length &&
    ownKeys.every((key) => typeof key === "string" && keys.includes(key)) &&
    keys.every((key) => Object.prototype.propertyIsEnumerable.call(value, key))
  );
}

function canonicalUuid(value: unknown): value is string {
  return typeof value === "string" && UUID_PATTERN.test(value);
}

function boundedString(value: unknown, minimum: number, maximum: number): value is string {
  return typeof value === "string" && value.length >= minimum && value.length <= maximum;
}

function nullableBoundedString(
  value: unknown,
  minimum: number,
  maximum: number,
): value is string | null {
  return value === null || boundedString(value, minimum, maximum);
}

function safeInteger(value: unknown, minimum: number, maximum: number): value is number {
  return (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= minimum &&
    value <= maximum
  );
}

function finiteNumber(value: unknown, minimum: number, maximum: number): value is number {
  return (
    typeof value === "number" &&
    Number.isFinite(value) &&
    value >= minimum &&
    value <= maximum
  );
}

function validDate(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length <= 35 &&
    DATE_PATTERN.test(value) &&
    Number.isFinite(Date.parse(value))
  );
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
// @ts-ignore Focused Node tests require the explicit source extension.
import { getSyntheticSessionRoute } from "./candidate-review-server.ts";
