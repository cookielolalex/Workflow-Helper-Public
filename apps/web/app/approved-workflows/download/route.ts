import { downloadApprovedWorkflow } from "@/lib/candidate-review-server";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(request: Request): Promise<Response> {
  return downloadApprovedWorkflow(request);
}
