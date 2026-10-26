import { createOpenAI } from "@ai-sdk/openai";
import {
  customProvider,
  extractReasoningMiddleware,
  wrapLanguageModel,
} from "ai";
import { withMemWal } from "@mysten-incubation/memwal/ai";
import { isTestEnvironment } from "../constants";
import {
  ARTIFACT_MODEL,
  baseOpenRouterId,
  isReasoningModelId,
  TITLE_MODEL,
} from "./models";

// OpenRouter provider (OpenAI-compatible)
const openrouter = createOpenAI({
  baseURL: "https://openrouter.ai/api/v1",
  apiKey: process.env.OPENROUTER_API_KEY || "",
});

export const myProvider = isTestEnvironment
  ? (() => {
    const {
      artifactModel,
      chatModel,
      reasoningModel,
      titleModel,
    } = require("./models.mock");
    return customProvider({
      languageModels: {
        "chat-model": chatModel,
        "chat-model-reasoning": reasoningModel,
        "title-model": titleModel,
        "artifact-model": artifactModel,
      },
    });
  })()
  : null;

export function getLanguageModel(modelId: string) {
  // The mock provider registers behaviours, not catalog ids, so every real id
  // has to land on one of its aliases — asking it for "openai/gpt-4o-mini"
  // throws NoSuchModelError and fails the turn.
  if (isTestEnvironment && myProvider) {
    return myProvider.languageModel(
      isReasoningModelId(modelId) ? "chat-model-reasoning" : "chat-model"
    );
  }

  if (isReasoningModelId(modelId)) {
    return wrapLanguageModel({
      model: openrouter.chat(baseOpenRouterId(modelId)),
      middleware: extractReasoningMiddleware({ tagName: "thinking" }),
    });
  }

  return openrouter.chat(modelId);
}

export function getTitleModel() {
  if (isTestEnvironment && myProvider) {
    return myProvider.languageModel("title-model");
  }
  return openrouter.chat(TITLE_MODEL);
}

export function getArtifactModel() {
  if (isTestEnvironment && myProvider) {
    return myProvider.languageModel("artifact-model");
  }
  return openrouter.chat(ARTIFACT_MODEL);
}

/**
 * Wrap a language model with Walrus Memory layer.
 * Requires MEMWAL_PRIVATE_KEY env var. Falls back to base model if not configured.
 */
export function getMemWalModel(
  modelId: string,
  {
    namespace,
    memwalKey,
    memwalAccountId,
  }: {
    namespace: string;
    memwalKey?: string;
    memwalAccountId?: string;
  }
) {
  const baseModel = getLanguageModel(modelId);

  const key = memwalKey || process.env.MEMWAL_PRIVATE_KEY;
  const memwalServerUrl = process.env.MEMWAL_SERVER_URL;
  const accountId = memwalAccountId || process.env.MEMWAL_ACCOUNT_ID;

  if (!namespace.trim()) {
    console.warn("[Walrus Memory] authenticated user namespace missing — memory layer disabled");
    return baseModel;
  }

  if (!key) {
    console.warn("[Walrus Memory] MEMWAL_PRIVATE_KEY not set — memory layer disabled");
    return baseModel;
  }

  if (!accountId) {
    console.warn("[Walrus Memory] MEMWAL_ACCOUNT_ID not set — memory layer disabled");
    return baseModel;
  }

  return withMemWal(baseModel, {
    key,
    accountId,
    serverUrl: memwalServerUrl || "http://localhost:8000",
    namespace,
    maxMemories: 5,
    autoSave: true,
    // No minRelevance override: the SDK default (0.3) drops unrelated hits
    // instead of injecting all `maxMemories` into every prompt (#1099).
    debug: process.env.NODE_ENV !== "production",
  });
}
