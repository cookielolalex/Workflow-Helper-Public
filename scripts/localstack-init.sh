#!/usr/bin/env sh
set -eu

create_bucket_if_missing() {
  bucket="$1"
  if ! awslocal s3api head-bucket --bucket "$bucket" >/dev/null 2>&1; then
    awslocal s3api create-bucket \
      --bucket "$bucket" \
      --create-bucket-configuration LocationConstraint=ap-northeast-1
  fi
}

create_bucket_if_missing workflow-helper-raw-dev
create_bucket_if_missing workflow-helper-processed-dev

awslocal sqs create-queue \
  --queue-name workflow-helper-processing-dlq \
  >/dev/null

queue_url="$(awslocal sqs create-queue \
  --queue-name workflow-helper-processing \
  --query QueueUrl \
  --output text)"

awslocal sqs set-queue-attributes \
  --queue-url "$queue_url" \
  --attributes '{"RedrivePolicy":"{\"deadLetterTargetArn\":\"arn:aws:sqs:ap-northeast-1:000000000000:workflow-helper-processing-dlq\",\"maxReceiveCount\":\"3\"}"}'
