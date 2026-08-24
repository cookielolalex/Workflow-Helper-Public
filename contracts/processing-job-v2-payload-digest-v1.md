# ProcessingJobV2 payload digest v1

Status: dormant contract. This digest is not connected to processing, completion,
idempotency, storage, queues, routes, callbacks, or provider APIs.

## Scheme identifier

`workflow-helper.processing-job-v2.payload.sha256-jcs.v1`

The scheme identifier is metadata naming this contract. It is not substituted for
the domain prefix below.

## Admitted input and normalization

An implementation MUST hash only an exact, independently admitted
`ProcessingJobV2` snapshot. It MAY obtain that snapshot by invoking the dormant,
pure `admit_package_input()` gate. Admission MUST finish before hashing begins.
Objects with missing or additional properties, impostor objects, unsupported
scalar types, or invalid package semantics MUST be rejected.

The normalized semantic object contains exactly these members:

```text
schema_version
job_id
session_id
input_artifact.provider
input_artifact.file_id
input_artifact.revision
input_artifact.sha256
input_artifact.size_bytes
input_artifact.mime_type
input_artifact.role
```

`job_id` and `session_id` are serialized as canonical lowercase, hyphenated UUID
strings. `size_bytes` is the admitted mathematical integer. Every other string is
the exact admitted Unicode scalar sequence. Implementations MUST NOT trim,
case-fold, infer, normalize as NFC or NFD, reinterpret provider or revision values,
or supply fallback values. A string containing an unpaired UTF-16 surrogate MUST
be rejected.

## Canonical bytes

The normalized semantic object is serialized using RFC 8785 JSON Canonicalization
Scheme (JCS). For this fixed schema, the required subset is:

- object member names are sorted lexicographically by UTF-16 code units;
- no insignificant whitespace is emitted;
- strings use ECMAScript-compatible JSON escaping: quotation mark and reverse
  solidus are escaped, the five short control escapes are used, every other
  U+0000 through U+001F character uses lowercase `\u00xx`, and all other Unicode
  scalar values are emitted unchanged as UTF-8;
- the admitted integer is emitted as its base-ten integer representation; and
- booleans, null, fractional or non-finite numbers, arrays, and all other scalar
  or container types are unsupported by this restricted serializer.

The canonical preimage is the exact concatenation of:

```text
UTF-8("workflow-helper\0processing-job-v2\0payload-digest\0sha256-jcs-v1\0")
|| RFC8785_JCS_UTF8(normalized_semantic_object)
```

Here, each `\0` denotes one zero byte (`00`), not two printable characters. The
digest is lowercase hexadecimal SHA-256 of that preimage.

The `payload-digest` domain component deliberately separates this identity from
any result or completion digest. No result fields or result digest mapping are
defined by this contract.

## Failure and privacy behavior

All rejection paths expose only the fixed message `payload digest rejected` and
MUST NOT include input values, metadata, partial canonical bytes, or a partial
digest. The implementation is pure: it performs no environment, filesystem,
network, provider, queue, runtime, resolver, store, parser, callback, or logging
I/O.

## Golden vectors

`contracts/examples/processing-job-v2-payload-digest-v1.json` contains standalone
inputs, exact canonical JCS text, its UTF-8 hexadecimal encoding, the complete
preimage hexadecimal encoding, and the expected lowercase SHA-256 digest. A
consumer can verify the vectors without importing production code.
