# 7. DynamoDB Local over LocalStack for integration tests

Date: 2026-05-14

## Status

Accepted.

## Context

The brief (§3) leaves the DynamoDB integration-test backend choice open: "LocalStack for DynamoDB or
`amazon/dynamodb-local`: pick whichever is faster on a cold CI run and document the choice in an
ADR." pk-auth's persistence module needs a backend it can spin up via Testcontainers, run thousands
of small operations against, and tear down cleanly.

Two practical options:

- `amazon/dynamodb-local` is Amazon's official local emulator. It is JAR-based and single-purpose.
  The Docker image is about 250 MB, and it starts in 1 to 3 seconds. It supports a strict subset of
  the production API (recent CRUD, GSI, and TTL) and matches the wire format exactly. It has no IAM,
  no STS, no auto-scaling, and no streams.
- LocalStack is a multi-AWS-service emulator (DynamoDB, S3, SQS, Lambda, and others). The Docker
  image is about 1.5 GB, and it starts in 5 to 10 seconds on a warm cache and longer cold. Its
  DynamoDB implementation is itself a wrapper around `dynamodb-local`. It adds value when a test
  needs IAM, STS, or cross-service flows.

## Decision

Use `amazon/dynamodb-local:latest` via Testcontainers. pk-auth's persistence tests exercise only
the DynamoDB control-plane and data-plane operations the production module uses, and never touch
IAM, STS, KMS, or any other service. The smaller image, lower cold-start time, and tighter API
surface make `dynamodb-local` the better fit.

Concretely, `DynamoDbLocalFixture` starts one container per JVM (Testcontainers reuse enabled), then
the `DynamoDbCeremonyIntegrationTest` creates a fresh pair of tables (random suffix) so concurrent
test classes do not collide.

## Consequences

- Positive, faster CI: about 5 to 7 seconds saved on every cold persistence-test run versus
  LocalStack. Local dev iteration is also noticeably faster.
- Positive, a smaller surface with fewer surprises: `dynamodb-local` matches the production API more
  faithfully than LocalStack's reimplementation.
- Negative, no IAM, STS, or cross-service tests from this container: Phase 5 does not need them,
  and a future module that wires AWS IAM into auth would need a different fixture (LocalStack or
  real cloud).
- Negative, no DynamoDB Streams: pk-auth does not use streams. If a future module does, it needs a
  different backend or must accept the LocalStack startup cost.

## Open follow-ups

- If pk-auth adds stream-based cache invalidation or KMS-encrypted attributes, the choice is
  revisited and recorded in a successor ADR.
