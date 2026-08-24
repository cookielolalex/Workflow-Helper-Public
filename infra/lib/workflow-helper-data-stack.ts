import * as cdk from "aws-cdk-lib";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as sqs from "aws-cdk-lib/aws-sqs";
import { Construct } from "constructs";


export interface WorkflowHelperDataStackProps extends cdk.StackProps {
  readonly stage: string;
  readonly rawRetentionDays: number;
}

export class WorkflowHelperDataStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: WorkflowHelperDataStackProps) {
    super(scope, id, props);

    if (!Number.isInteger(props.rawRetentionDays) || props.rawRetentionDays < 1) {
      throw new Error("rawRetentionDays must be a positive integer");
    }

    const rawBucket = new s3.Bucket(this, "RawCapture", {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      lifecycleRules: [
        {
          id: "ExpireRawEvidence",
          enabled: true,
          expiration: cdk.Duration.days(props.rawRetentionDays),
          abortIncompleteMultipartUploadAfter: cdk.Duration.days(1),
        },
      ],
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      versioned: false,
    });

    const processedBucket = new s3.Bucket(this, "ProcessedKnowledge", {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      versioned: true,
    });

    const deadLetterQueue = new sqs.Queue(this, "ProcessingDeadLetterQueue", {
      encryption: sqs.QueueEncryption.SQS_MANAGED,
      retentionPeriod: cdk.Duration.days(14),
    });

    const processingQueue = new sqs.Queue(this, "ProcessingQueue", {
      deadLetterQueue: { queue: deadLetterQueue, maxReceiveCount: 3 },
      encryption: sqs.QueueEncryption.SQS_MANAGED,
      retentionPeriod: cdk.Duration.days(4),
      visibilityTimeout: cdk.Duration.minutes(5),
    });

    cdk.Tags.of(this).add("Project", "WorkflowHelper");
    cdk.Tags.of(this).add("Stage", props.stage);
    cdk.Tags.of(rawBucket).add("DataClass", "SensitiveRawEvidence");
    cdk.Tags.of(processedBucket).add("DataClass", "DerivedWorkflowKnowledge");

    new cdk.CfnOutput(this, "RawBucketName", { value: rawBucket.bucketName });
    new cdk.CfnOutput(this, "ProcessedBucketName", { value: processedBucket.bucketName });
    new cdk.CfnOutput(this, "ProcessingQueueUrl", { value: processingQueue.queueUrl });
    new cdk.CfnOutput(this, "ProcessingDeadLetterQueueUrl", {
      value: deadLetterQueue.queueUrl,
    });
  }
}
