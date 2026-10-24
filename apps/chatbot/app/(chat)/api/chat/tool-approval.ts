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

/**
 * True when `submitted` answers at least one tool approval that the model
 * requested and that is still pending in the stored chat (#1092).
 *
 * An approval continuation stores no user row, so the hourly limit does not
 * see it. Requiring a stored, still-pending approval ties every such
 * generation to a model request that a counted user turn produced. Once the
 * tool runs, onFinish rewrites the stored part, so the same answer cannot be
 * replayed.
 */
export function answersPendingApproval(
  stored: Pick<DBMessage, "id" | "role" | "parts">[],
  submitted: SubmittedMessage[]
): boolean {
  for (const message of stored) {
    if (message.role !== "assistant") continue;
    const reply = submitted.find(
      (m) => m.id === message.id && m.role === "assistant"
    );
    if (!reply) continue;

    for (const pending of toolParts(message.parts)) {
      if (
        pending.state !== "approval-requested" ||
        typeof pending.approval?.id !== "string"
      ) {
        continue;
      }
      const answer = toolParts(reply.parts).find(
        (part) => part.toolCallId === pending.toolCallId
      );
      if (
        answer &&
        typeof answer.state === "string" &&
        ANSWERED_STATES.has(answer.state) &&
        answer.approval?.id === pending.approval.id &&
        typeof answer.approval.approved === "boolean"
      ) {
        return true;
      }
    }
  }
  return false;
}
