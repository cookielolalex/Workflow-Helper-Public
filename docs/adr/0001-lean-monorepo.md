# ADR 0001: Lean polyglot monorepo

- Status: accepted for scaffold
- Date: 2026-08-16

## Decision

Use a monorepo with .NET for Windows-native capture, Python for API/video
processing, TypeScript/Next.js for the control plane, and TypeScript CDK for
AWS resources.

## Rationale

Each runtime matches its operating surface while versioned JSON contracts keep
the boundaries explicit. A monorepo makes the first vertical slice reviewable
without introducing service-repository coordination.

## Consequences

CI must validate several runtimes. Shared business logic belongs in contracts,
not duplicated implicit assumptions. This does not authorize microservice or
Kubernetes complexity.
