# AWS infrastructure scaffold

This stack creates only the low-risk shared data-plane primitives needed for the
first vertical slice:

- private encrypted raw S3 bucket with automatic expiration;
- private versioned processed S3 bucket;
- encrypted SQS processing queue; and
- dead-letter queue.

It deliberately does not deploy application compute, public endpoints,
authentication, or PostgreSQL. Those resources must follow a reviewed network,
identity, backup, and cost design.

## Synthesize

```bash
npm ci
npm run build
npm run synth
```

Default region is `ap-northeast-1` (Tokyo). Override the CDK environment when a
Taiwan-region or company-account decision is made. Synthesis is safe; deployment
creates billable AWS resources and requires explicit approval.
