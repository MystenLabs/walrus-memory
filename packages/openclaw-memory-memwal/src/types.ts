/**
 * Shared types for the Walrus Memory OpenClaw plugin.
 */

export interface PluginConfig {
  /** Ed25519 private key (hex). */
  privateKey: string;
  /** Walrus Memory account object ID on Sui. */
  accountId: string;
  /** Walrus Memory server URL. */
  serverUrl: string;
  /** Default namespace for memory scoping (default: "default"). */
  defaultNamespace: string;
  /** Auto-inject relevant memories before each agent turn. */
  autoRecall: boolean;
  /** Auto-extract and store facts after each agent turn. */
  autoCapture: boolean;
  /** Max memories to inject per auto-recall. */
  maxRecallResults: number;
  /** Min relevance threshold (0-1) for auto-recall filtering. */
  minRelevance: number;
  /** Number of recent messages to send for auto-capture. */
  captureMaxMessages: number;
  /** Per-request deadline in ms for every relayer call. */
  requestTimeoutMs: number;
  /** Isolate memories by sender or user sub-namespace (default: false). */
  isolateBySender: boolean;
  /** Include base shared namespace memories when recalling in isolated mode (default: false). */
  includeSharedNamespaceOnRecall: boolean;
}

export interface PluginHookContext {
  sessionKey?: string;
  senderId?: string;
  userId?: string;
  from?: string;
  sessionId?: string;
  metadata?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface AgentStartEvent {
  prompt?: string;
  senderId?: string;
  userId?: string;
  sessionId?: string;
  metadata?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface AgentEndEvent {
  success?: boolean;
  messages?: unknown[];
  senderId?: string;
  userId?: string;
  sessionId?: string;
  metadata?: Record<string, unknown>;
  occurredAt?: unknown;
  createdAt?: unknown;
  created_at?: unknown;
  timestamp?: unknown;
  [key: string]: unknown;
}
