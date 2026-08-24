# ProcessingJobV2 result digest v1

This contract defines a dormant, pure identity for an ordered set of result artifact
bindings. It performs no provider, filesystem, network, environment, queue, route,
callback, publication, resolver, store, SQL, API, control-plane, or runtime work.

## Identity and admission

The scheme identifier is
`workflow-helper.processing-job-v2.result.sha256-jcs.v1`. Its preimage is:

```text
UTF8("workflow-helper\0processing-job-v2\0result-digest\0sha256-jcs-v1\0")
|| restricted-RFC8785-JCS-UTF8(exact-result-manifest)
```

The complete preimage, including the domain prefix, MUST NOT exceed 16,777,216
bytes. The digest is the lowercase hexadecimal SHA-256 of that preimage.

Every public builder, canonicalization, and digest operation takes an exact
`ProcessingJobV2` and ordered output bindings. It independently invokes the existing
`admit_package_input()` gate and the approved payload digest v1 implementation. The
builder derives `job_id`, `session_id`, `payload_digest_scheme`, and `payload_digest`;
callers cannot choose those values. A verifier presented with a manifest requires the
expected job and compares all four bound identity values before canonicalization.
Implementations defensively snapshot accepted input so later caller mutation has no
effect.

All rejection paths expose only `ValueError("result digest rejected")`, without a
cause, input value, canonical bytes, namespace, partial digest, or log entry.

## Exact manifest

The manifest is the closed object described by
`processing-job-v2-result-manifest-v1.schema.json`. Its exact members are
`schema_version` (`1.0`), `job_id`, `session_id`, `payload_digest_scheme`,
`payload_digest`, and `outputs`. `outputs` is an order-preserving array of 1 through
1,024 closed objects. Each output has exactly `store_namespace` and `artifact_ref`.
The artifact reference has exactly the current seven structural fields: `provider`,
`file_id`, `revision`, `sha256`, `size_bytes`, `mime_type`, and `role`.

The immutable locator tuple
`(provider, store_namespace, file_id, revision)` MUST be unique across the whole
ordered output array, regardless of metadata. Any repeated locator is rejected.
Array order is identity-bearing and therefore digest-sensitive.

`file_id` and `revision` are exact opaque Unicode scalar sequences. They are never
trimmed, case-folded, normalized, decoded, or provider-interpreted. Revision is
nonempty and limited to both 255 Unicode scalars and 1,024 UTF-8 bytes. All seven
artifact fields retain the current `ArtifactRef` structural bounds. `size_bytes` is a
mathematical integer from 1 through 536,870,912; structural admission may converge
JSON `1.0` to integer `1`, but booleans, fractions, nonfinite numbers, zero, and
out-of-range values reject.

The only role/MIME pairs are `timeline`/`application/json`,
`manifest`/`application/json`, and `crop`/`image/png`. `raw_package` is never a result
output. A manifest-role artifact can describe a separate nonrecursive manifest
artifact; the result digest manifest being constructed MUST NOT itself appear as one
of its outputs.

## Store namespaces

Google Drive uses exactly:

```text
google-drive://<workspace-customer-id>/<shared-drive-id>
```

Both components are ASCII `[A-Za-z0-9_-]{1,128}`, and the bound provider must be
`google_drive`.

S3 uses exactly:

```text
aws-s3://<partition>/<account-id>/<region>/<bucket>
```

The partition is exactly `aws`, `aws-cn`, or `aws-us-gov`; account ID is 12 digits;
region is lowercase ASCII `[a-z]{2}(?:-[a-z0-9]+)+-[0-9]` with at most 32 characters;
and the dot-free bucket is
`[a-z0-9][a-z0-9-]{1,61}[a-z0-9]` with length 3 through 63. The bound provider must
be `s3`. There is no decoding, normalization, or fallback.

Provider eligibility here is structural only. It is not provider proof and performs
no I/O. A future Google Drive adapter must require a Shared Drive object, pin exact
`Revision.id`, read that revision back, and verify whole-body SHA-256, size, and MIME.
A future S3 adapter must require bucket versioning `Enabled`, a non-null `VersionId`,
version-qualified readback, and whole-body SHA-256 and size verification. Those
adapter prerequisites are outside this contract.

## Canonicalization exclusions

The restricted serializer supports only objects, arrays, strings, and integers. It
sorts object names by UTF-16 code units, preserves array order and exact Unicode,
uses ECMAScript string escaping, and rejects lone surrogates. It emits no floats.

This result digest is not a completion idempotency key, publication bytes, an ETag,
a provider checksum, pretty JSON, the legacy control-plane `result_digest`, or the
ProcessingJobV2 payload digest. None of those values can substitute for this digest.
The manifest is identity material only and does not authorize or imply publication.

All examples are synthetic. They contain no real Drive or S3 identifiers, filenames,
customer information, employee information, or CAD data.
