#!/usr/bin/env node
import "source-map-support/register";
import * as cdk from "aws-cdk-lib";
import { WorkflowHelperDataStack } from "../lib/workflow-helper-data-stack";

const app = new cdk.App();
const stage = String(app.node.tryGetContext("stage") ?? "dev");
const rawRetentionDays = Number(app.node.tryGetContext("rawRetentionDays") ?? 14);

new WorkflowHelperDataStack(app, `WorkflowHelperData-${stage}`, {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION ?? "ap-northeast-1",
  },
  rawRetentionDays,
  stage,
});
