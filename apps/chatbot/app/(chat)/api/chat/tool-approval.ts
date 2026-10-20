import type { DBMessage } from "@/lib/db/schema";

type SubmittedMessage = { id: string; role: string; parts: unknown[] };

type ToolPart = {
  toolCallId?: unknown;
  state?: unknown;
  approval?: { id?: unknown; approved?: unknown };
};

const ANSWERED_STATES = new Set(["approval-responded", "output-denied"]);

function toolParts(parts: unknown): ToolPart[] {
  return Array.isArray(parts)
    ? parts.filter(
        (part): part is ToolPart =>
          typeof part === "object" && part !== null && "toolCallId" in part
      )
    : [];
}

export type PendingApprovalClaim = {
  messageId: string;
  toolCallId: string;
  approvalId: string;
};

/**
 * Locate a stored assistant message part that is still waiting on approval
 * (`state === "approval-requested"`) and is answered by `submitted` (#1092).
 *
 * Returns the claim descriptor so the caller can atomically transition only
 * that matching part to `"approval-claimed"` in the database (and roll back
 * only that part if the stream fails before finishing).
 */
export function findPendingApprovalClaim(
  stored: Pick<DBMessage, "id" | "role" | "parts">[],
  submitted: SubmittedMessage[]
): PendingApprovalClaim | null {
  for (const message of stored) {
    if (message.role !== "assistant" || !Array.isArray(message.parts)) continue;
    const reply = submitted.find(
      (m) => m.id === message.id && m.role === "assistant"
    );
    if (!reply) continue;

    for (let i = 0; i < message.parts.length; i++) {
      const part = message.parts[i];
      if (typeof part !== "object" || part === null || !("toolCallId" in part)) {
        continue;
      }
      const pending = part as ToolPart;
      if (
        pending.state !== "approval-requested" ||
        typeof pending.toolCallId !== "string" ||
        typeof pending.approval?.id !== "string"
      ) {
        continue;
      }
      const answer = toolParts(reply.parts).find(
        (candidate) => candidate.toolCallId === pending.toolCallId
      );
      if (
        answer &&
        typeof answer.state === "string" &&
        ANSWERED_STATES.has(answer.state) &&
        answer.approval?.id === pending.approval.id &&
        typeof answer.approval.approved === "boolean"
      ) {
        return {
          messageId: message.id,
          toolCallId: pending.toolCallId,
          approvalId: pending.approval.id,
        };
      }
    }
  }
  return null;
}

/**
 * True when `submitted` answers at least one tool approval that the model
 * requested and that is still pending in the stored chat (#1092).
 */
export function answersPendingApproval(
  stored: Pick<DBMessage, "id" | "role" | "parts">[],
  submitted: SubmittedMessage[]
): boolean {
  return findPendingApprovalClaim(stored, submitted) !== null;
}

/**
 * Merge a finished stream's `incomingParts` against the message's latest
 * `storedParts` so any sibling tool part whose stored state has already moved
 * past `"approval-requested"` (for example `"approval-claimed"`,
 * `"approval-responded"`, `"output-available"`, or `"output-denied"`) is never
 * downgraded back to `"approval-requested"` by a stale snapshot (#1092).
 */
export function mergeFinishedMessageParts(
  storedParts: unknown,
  incomingParts: unknown
): unknown[] {
  if (!Array.isArray(incomingParts)) {
    return [];
  }
  const existingTools = toolParts(storedParts);
  return incomingParts.map((item) => {
    if (typeof item !== "object" || item === null || !("toolCallId" in item)) {
      return item;
    }
    const incomingTool = item as ToolPart;
    if (
      incomingTool.state === "approval-requested" &&
      typeof incomingTool.toolCallId === "string"
    ) {
      const existing = existingTools.find(
        (candidate) =>
          candidate.toolCallId === incomingTool.toolCallId &&
          typeof candidate.state === "string" &&
          candidate.state !== "approval-requested"
      );
      if (existing) {
        return existing;
      }
    }
    return item;
  });
}

