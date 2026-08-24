# Lean MVP scope

## Included in this scaffold

- Foreground AutoCAD detection and logical session lifecycle
- Versioned session/event/label JSON contracts
- Atomic local metadata package writer
- API endpoints for health, registration, listing, and upload completion
- Reference PostgreSQL schema for sessions, labels, skills, evidence, and audit
- Processing pipeline interface and deterministic timeline summarization
- Web dashboard and session detail route
- Private S3 buckets with raw lifecycle expiration
- SQS queue with dead-letter handling
- CI and dependency-light repository validation

## Deferred behind explicit interfaces

- Real screen capture and user-visible recording controls
- AutoCAD command plug-in and DWG-safe snapshot integration
- Resumable multipart upload implementation
- PostgreSQL repository and migrations
- Authentication, device enrollment, RBAC, and audit persistence
- AI labeling and candidate-skill extraction
- Expert review mutations
- Production compute/deployment and operational alerting

## Checkpoint acceptance criteria

1. Contracts load and examples validate structurally.
2. Python sources compile and unit tests pass when dependencies are installed.
3. The Windows project builds on `windows-latest`.
4. Web and infrastructure TypeScript compile in CI.
5. Raw storage has an explicit expiration policy.
6. No recorder can capture by default.
7. No secret or real customer/employee artifact exists in the repository.

## Next milestone

Run a synthetic session on one controlled Windows workstation, upload a small
generated package, process it into a timeline, and display it in the session
viewer. Use synthetic data until the privacy and security pilot gate is signed.
