import {
  candidateReviewRedirect,
  parseCandidateReviewActionRequest,
  submitCandidateReviewAction,
} from "@/lib/candidate-review-server";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function POST(request: Request): Promise<Response> {
  try {
    const action = await parseCandidateReviewActionRequest(request);
    if (action !== null) {
      await submitCandidateReviewAction(action.ordinal, action.action);
    }
  } catch {
    // The browser receives one fixed non-oracular response for every outcome.
  }
  return candidateReviewRedirect();
}
