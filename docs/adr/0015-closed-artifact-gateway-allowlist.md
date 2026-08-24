# ADR 0015: Closed artifact-gateway allowlist

- Status: accepted
- Date: 2026-08-18
- Scope: sealed synthetic runtime admission only; no provider activation

## Context

ADR 0012 sealed the synthetic runtime bundle around the exact no-network
artifact oracle. A separately preconstructed AWS compatibility gateway now needs
to cross that boundary without turning structural compatibility into runtime
authority or changing the inert default application.

## Decision

The bundle admits a closed set of exactly two concrete gateway types:
`NoNetworkArtifactGateway` and `AwsGateway`. Subclasses, structural impostors,
and every other object are rejected before gateway properties or methods are
accessed. The admitted object is preserved by identity.

Every admitted gateway must expose the configured ticket TTL and package-size
cap, and both values must equal the bundle's explicit `Settings` snapshot. An
exact `AwsGateway` must additionally retain that same `Settings` object by
identity. It is supplied preconstructed; bundle admission neither constructs
it nor creates provider clients. The AWS module is imported lazily only during
an explicit non-no-network bundle construction attempt.

The module-level and default `create_app()` remain unchanged: they install no
bundle, import or construct no AWS gateway or provider client, expose health,
and fail protected operations closed. The route dependency returns the exact
stored gateway through the existing `ArtifactGateway` protocol. No adapter,
fallback, route, settings rule, or other authority seam is widened.

## Consequences

Future gateway types require a separate decision and explicit exact-type
admission. Drive-first storage authority is unchanged. GCS and Phase 0B storage
authority remain undecided. This decision activates no provider, credentials,
network, resource, live-data path, deployment, permission, or recurring cost.
