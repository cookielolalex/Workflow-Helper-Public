# Security policy

## Reporting

Do not open a public issue for a vulnerability or for captured employee/client
data. Contact the repository owner privately and include only the minimum
information needed to reproduce the problem.

## Data handling rules

- Never commit DWG, PDF, recordings, session packages, credentials, employee
  identifiers, client names, or signed artifact URLs.
- Use pseudonymous workstation IDs and keep the identity mapping outside this
  system.
- Production uploads must use short-lived credentials or narrowly scoped
  presigned URLs.
- Buckets must block public access, enforce TLS, and apply explicit retention.
- Authorization must be enforced server-side before any artifact URL is issued.
- Treat screen capture and AutoCAD telemetry as sensitive company data.

## Production readiness gate

The initial scaffold is not approved for production capture. Before a pilot,
complete threat modeling, employee notice/consent, access-control testing,
retention verification, audit logging, and incident-response ownership.
