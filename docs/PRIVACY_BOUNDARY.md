# Privacy boundary

The system captures approved CAD work, not general employee activity.

## Allowed

- Foreground state of an allowlisted AutoCAD executable
- Pseudonymous workstation identifier
- Approved drawing/job identifier
- AutoCAD command events obtained through supported integration
- Before/after copies of approved company drawing artifacts
- Recording of the approved capture surface during a logical CAD session
- Timestamps, idle intervals, and processing/review state

## Prohibited

- Password fields, personal messages, banking, email, or unrelated applications
- Keystroke logging
- Hidden deployment or use without employee notice
- Productivity rankings, performance scoring, or generalized monitoring
- Permanent raw-video retention by default
- Promotion of an AI-inferred pattern to a drafting rule without human approval

## Fail-closed behavior

If the process, window, drawing, configuration, or consent state is uncertain,
capture does not start. Losing approved foreground status pauses recording.
Upload verification must succeed before local temporary evidence can be removed.

## Pilot checklist

- Written purpose and employee notice approved
- Capture indicator and pause/stop control tested
- Workstation and executable allowlists reviewed
- Raw-retention deletion tested end to end
- Access roles and audit logs tested
- Incident owner named
- One controlled workstation only

## Drive-first and ChatGPT controls

The Drive-first architecture does not authorize live capture or real-data
processing. Before a live pilot, Drive must be organization-owned and private,
with least-privileged workload identities, tested inherited permissions, and no
public, domain-wide, or external sharing. Browser and Site clients must never
receive Drive credentials or unrestricted artifact links.

Folder movement is not deletion or approval. A retention ledger must reconcile
workstation spool, Drive files and revisions, processor temporary data, Site
caches, and analysis artifacts against the 14-day raw target. Promotion to an
approved dataset requires separate domain and privacy/data-steward decisions,
immutable source hashes, provenance, allowed purpose, expiry, and withdrawal
rules.

Each analysis job must use fresh isolated context, minimum selected evidence,
schema-constrained output, and no cross-session history. Untrusted filenames,
comments, archives, and embedded instructions must be neutralized or
quarantined before analysis.

Hard stop triggers include authorization or capture-control failure; unexpected
sharing; wrong identity or workspace; checksum, revision, or permission drift;
credential exposure; audit outage; overdue deletion; and queue, retry, time,
data, or subscription-credit caps being exceeded.
