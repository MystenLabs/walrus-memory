/**
 * Config parsing, validation, and namespace resolution.
 */

import { createHash } from "node:crypto";
import { z } from "zod";
import type { PluginConfig } from "./types.js";
import { DEFAULT_REQUEST_TIMEOUT_MS } from "./constants.js";

// ============================================================================
// Schema
// ============================================================================

const ConfigSchema = z.object({
  privateKey: z.string()
    .min(1, "required")
    .regex(/^[0-9a-fA-F]{64}$/, "must be a 64-character hex string (delegate key)"),
  accountId: z.string()
    .min(1, "required")
    .regex(/^0x[0-9a-fA-F]{10,}$/, "must be a Sui object ID (0x...)"),
  serverUrl: z.string()
    .min(1, "required")
    .url("must be a valid URL"),
  defaultNamespace: z.string()
    .min(1, "must not be empty")
    .refine((ns) => !/[\r\n"]/.test(ns), {
      message: 'defaultNamespace must not contain quotes (") or newline characters',
    })
    .default("default"),
  autoRecall: z.boolean().default(true),
  autoCapture: z.boolean().default(true),
  maxRecallResults: z.number().min(1).max(20).default(5),
  minRelevance: z.number().min(0).max(1).default(0.3),
  captureMaxMessages: z.number().min(1).max(50).default(10),
  requestTimeoutMs: z.number().min(1000).max(60000).default(DEFAULT_REQUEST_TIMEOUT_MS),
});

// ============================================================================
// Env Var Resolution
// ============================================================================

function resolveEnvVar(value: string): string {
  return value.replace(/\$\{([^}]+)\}/g, (_, name) => {
    const v = process.env[name];
    if (!v) throw new Error(`Environment variable ${name} is not set`);
    return v;
  });
}

function resolveEnvVars(raw: Record<string, unknown>): Record<string, unknown> {
  const resolved: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(raw)) {
    resolved[key] = key === "privateKey" && typeof value === "string" ? resolveEnvVar(value) : value;
  }
  return resolved;
}

// ============================================================================
// Config Parser
// ============================================================================

export function parseConfig(raw: unknown): PluginConfig {
  if (!raw || typeof raw !== "object") {
    throw new Error("memory-memwal: config is required");
  }

  const resolved = resolveEnvVars(raw as Record<string, unknown>);
  const result = ConfigSchema.safeParse(resolved);
  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `  - ${i.path.join(".")}: ${i.message}`)
      .join("\n");
    throw new Error(`memory-memwal: invalid config:\n${issues}`);
  }

  return result.data;
}

// ============================================================================
// Agent + Namespace Resolution
// ============================================================================

export interface ResolvedAgent {
  namespace: string;
  legacyNamespace?: string;
  agentName: string;
}

/** Derive a collision-resistant namespace for an agent name. */
export function deriveAgentNamespace(rawName: string): string {
  const normalized = rawName.normalize("NFKC").trim();
  const lower = normalized.toLowerCase();

  // Domain 1: Safe standard names (1-64 ASCII alphanumeric/hyphen/underscore)
  if (/^[a-zA-Z0-9_-]{1,64}$/.test(normalized)) {
    return lower;
  }

  // Domain 2: Unsafe names (hash length >= 68 chars prevents domain collision)
  const slug = lower
    .replace(/[^a-z0-9_-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 32);
  const hash = createHash("sha256").update(lower).digest("hex");
  return slug && slug !== "main" ? `_h_${slug}_${hash}` : `_h_agent_${hash}`;
}

/** Resolve agent namespace and human-readable name from sessionKey. */
export function resolveAgent(defaultNamespace: string, sessionKey?: string): ResolvedAgent {
  if (!sessionKey) return { namespace: defaultNamespace, agentName: "main" };

  const match = sessionKey.match(/^agent:([^:]+):/);
  const rawName = match?.[1];
  if (!rawName || rawName === "main") {
    return { namespace: defaultNamespace, agentName: "main" };
  }

  const trimmed = rawName.trim();
  if (trimmed === "main" || trimmed.toLowerCase() === "main") {
    return { namespace: defaultNamespace, agentName: "main" };
  }

  let namespace = deriveAgentNamespace(rawName);
  if (namespace === defaultNamespace) {
    const lower = trimmed.normalize("NFKC").toLowerCase();
    const slug = lower
      .replace(/[^a-z0-9_-]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 32);
    const hash = createHash("sha256")
      .update(`subagent:${defaultNamespace}\0${lower}`)
      .digest("hex");
    namespace = slug ? `_h_${slug}_${hash}` : `_h_agent_${hash}`;
  }
  const legacyCandidate =
    rawName !== namespace && /^[a-zA-Z0-9_-]{1,64}$/.test(trimmed) ? rawName : undefined;
  const legacyNamespace =
    legacyCandidate && legacyCandidate !== defaultNamespace ? legacyCandidate : undefined;
  const agentName = trimmed.normalize("NFKC").slice(0, 64) || namespace;
  return { namespace, legacyNamespace, agentName };
}

/**
 * Namespace a memory tool may use for this session.
 * Omitted or empty uses the calling agent. A supplied value must be that
 * agent's namespace or, when present, its legacy namespace. Anything else
 * (including the main namespace from a sub-agent) is rejected.
 */
export function resolveToolNamespace(
  defaultNamespace: string,
  sessionKey: string | undefined,
  requested: unknown,
): string | undefined {
  const { namespace, legacyNamespace, agentName } = resolveAgent(defaultNamespace, sessionKey);
  if (requested == null || requested === "") return namespace;
  if (typeof requested !== "string") return undefined;
  if (agentName !== "main" && requested === defaultNamespace) return undefined;
  if (requested === namespace || requested === legacyNamespace) return requested;
  return undefined;
}

export function keyPreview(key: string): string {
  return key.length > 8 ? `${key.slice(0, 4)}...${key.slice(-4)}` : "****";
}
