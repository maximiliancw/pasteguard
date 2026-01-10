import type { SecretsDetectionConfig } from "../config";
import type { ChatCompletionRequest } from "../services/llm-client";
import { extractTextContent } from "../utils/content";

/**
 * All supported secret entity types
 */
export type SecretEntityType =
  | "OPENSSH_PRIVATE_KEY"
  | "PEM_PRIVATE_KEY"
  | "API_KEY_OPENAI"
  | "API_KEY_AWS"
  | "API_KEY_GITHUB"
  | "JWT_TOKEN"
  | "BEARER_TOKEN";

export interface SecretsMatch {
  type: SecretEntityType;
  count: number;
}

export interface SecretsRedaction {
  start: number;
  end: number;
  type: SecretEntityType;
}

export interface SecretsDetectionResult {
  detected: boolean;
  matches: SecretsMatch[];
  redactions?: SecretsRedaction[];
}

/**
 * Extracts all text content from an OpenAI chat completion request
 *
 * Concatenates content from all messages (system, user, assistant) for secrets scanning.
 * Handles both string content (text-only) and array content (multimodal messages).
 *
 * Returns concatenated text for secrets scanning.
 */
export function extractTextFromRequest(body: ChatCompletionRequest): string {
  return body.messages
    .map((message) => extractTextContent(message.content))
    .filter((text) => text.length > 0)
    .join("\n");
}

/**
 * Helper to detect secrets matching a pattern and add to matches/redactions
 */
function detectPattern(
  textToScan: string,
  pattern: RegExp,
  entityType: SecretEntityType,
  matches: SecretsMatch[],
  redactions: SecretsRedaction[],
  existingPositions?: Set<number>,
): number {
  let count = 0;
  for (const match of textToScan.matchAll(pattern)) {
    if (match.index !== undefined) {
      // Skip if this position was already matched by another pattern
      if (existingPositions?.has(match.index)) continue;

      count++;
      existingPositions?.add(match.index);
      redactions.push({
        start: match.index,
        end: match.index + match[0].length,
        type: entityType,
      });
    }
  }
  if (count > 0) {
    matches.push({ type: entityType, count });
  }
  return count;
}

/**
 * Detects secret material (e.g. private keys, API keys, tokens) in text
 *
 * Scans for:
 * - OpenSSH private keys: -----BEGIN OPENSSH PRIVATE KEY-----
 * - PEM private keys: RSA, PRIVATE KEY, ENCRYPTED PRIVATE KEY
 * - OpenAI API keys: sk-... (48+ chars)
 * - AWS access keys: AKIA... (20 chars)
 * - GitHub tokens: ghp_, gho_, ghu_, ghs_, ghr_ (40+ chars)
 * - JWT tokens: eyJ... (three base64 segments)
 * - Bearer tokens: Bearer ... (in Authorization-style contexts)
 *
 * Respects max_scan_chars limit for performance.
 */
export function detectSecrets(
  text: string,
  config: SecretsDetectionConfig,
): SecretsDetectionResult {
  if (!config.enabled) {
    return { detected: false, matches: [] };
  }

  // Apply max_scan_chars limit
  const textToScan = config.max_scan_chars > 0 ? text.slice(0, config.max_scan_chars) : text;

  const matches: SecretsMatch[] = [];
  const redactions: SecretsRedaction[] = [];

  // Track which entities to detect based on config
  const entitiesToDetect = new Set(config.entities);

  // OpenSSH private key pattern
  if (entitiesToDetect.has("OPENSSH_PRIVATE_KEY")) {
    const opensshPattern =
      /-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----/g;
    detectPattern(textToScan, opensshPattern, "OPENSSH_PRIVATE_KEY", matches, redactions);
  }

  // PEM private key patterns
  if (entitiesToDetect.has("PEM_PRIVATE_KEY")) {
    // Track all matched positions to avoid double counting
    const matchedPositions = new Set<number>();

    // RSA PRIVATE KEY
    const rsaPattern = /-----BEGIN RSA PRIVATE KEY-----[\s\S]*?-----END RSA PRIVATE KEY-----/g;
    detectPattern(textToScan, rsaPattern, "PEM_PRIVATE_KEY", matches, redactions, matchedPositions);

    // Remove PEM_PRIVATE_KEY from matches to accumulate all PEM types together
    const pemMatch = matches.find((m) => m.type === "PEM_PRIVATE_KEY");
    if (pemMatch) {
      matches.splice(matches.indexOf(pemMatch), 1);
    }
    let totalPemCount = pemMatch?.count || 0;

    // PRIVATE KEY (generic) - exclude RSA matches
    const privateKeyPattern = /-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----/g;
    const tempMatches: SecretsMatch[] = [];
    detectPattern(
      textToScan,
      privateKeyPattern,
      "PEM_PRIVATE_KEY",
      tempMatches,
      redactions,
      matchedPositions,
    );
    totalPemCount += tempMatches[0]?.count || 0;

    // ENCRYPTED PRIVATE KEY
    const encryptedPattern =
      /-----BEGIN ENCRYPTED PRIVATE KEY-----[\s\S]*?-----END ENCRYPTED PRIVATE KEY-----/g;
    const tempMatches2: SecretsMatch[] = [];
    detectPattern(
      textToScan,
      encryptedPattern,
      "PEM_PRIVATE_KEY",
      tempMatches2,
      redactions,
      matchedPositions,
    );
    totalPemCount += tempMatches2[0]?.count || 0;

    if (totalPemCount > 0) {
      matches.push({ type: "PEM_PRIVATE_KEY", count: totalPemCount });
    }
  }

  // OpenAI API keys: sk-... followed by alphanumeric chars
  // Modern format: sk-proj-... or sk-... with 48+ total chars
  if (entitiesToDetect.has("API_KEY_OPENAI")) {
    // Match sk- followed by optional prefix (proj-, etc.) and alphanumeric/dash/underscore
    const openaiPattern = /sk-[a-zA-Z0-9_-]{45,}/g;
    detectPattern(textToScan, openaiPattern, "API_KEY_OPENAI", matches, redactions);
  }

  // AWS access keys: AKIA followed by 16 uppercase alphanumeric chars
  if (entitiesToDetect.has("API_KEY_AWS")) {
    const awsPattern = /AKIA[0-9A-Z]{16}/g;
    detectPattern(textToScan, awsPattern, "API_KEY_AWS", matches, redactions);
  }

  // GitHub tokens: ghp_, gho_, ghu_, ghs_, ghr_ followed by 36+ alphanumeric chars
  if (entitiesToDetect.has("API_KEY_GITHUB")) {
    const githubPattern = /gh[pousr]_[a-zA-Z0-9]{36,}/g;
    detectPattern(textToScan, githubPattern, "API_KEY_GITHUB", matches, redactions);
  }

  // JWT tokens: three base64url segments separated by dots
  // Header starts with eyJ (base64 for {"...), minimum 20 chars per segment
  if (entitiesToDetect.has("JWT_TOKEN")) {
    const jwtPattern = /eyJ[a-zA-Z0-9_-]{20,}\.eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}/g;
    detectPattern(textToScan, jwtPattern, "JWT_TOKEN", matches, redactions);
  }

  // Bearer tokens in Authorization-style contexts
  // Matches "Bearer " followed by a token (at least 40 chars to reduce placeholder matches)
  if (entitiesToDetect.has("BEARER_TOKEN")) {
    const bearerPattern = /Bearer\s+[a-zA-Z0-9._-]{40,}/gi;
    detectPattern(textToScan, bearerPattern, "BEARER_TOKEN", matches, redactions);
  }

  // Sort redactions by start position (descending) for safe replacement
  redactions.sort((a, b) => b.start - a.start);

  return {
    detected: matches.length > 0,
    matches,
    redactions: redactions.length > 0 ? redactions : undefined,
  };
}
