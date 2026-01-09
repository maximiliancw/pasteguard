import { describe, expect, test } from "bun:test";
import { Hono } from "hono";
import { proxyRoutes } from "./proxy";

const app = new Hono();
app.route("/openai/v1", proxyRoutes);

describe("POST /openai/v1/chat/completions", () => {
  test("returns 400 for missing messages", async () => {
    const res = await app.request("/openai/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({}),
      headers: { "Content-Type": "application/json" },
    });

    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { type: string } };
    expect(body.error.type).toBe("invalid_request_error");
  });

  test("returns 400 for invalid message format", async () => {
    const res = await app.request("/openai/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({
        messages: [{ invalid: "format" }],
      }),
      headers: { "Content-Type": "application/json" },
    });

    expect(res.status).toBe(400);
  });

  test("returns 400 for invalid role", async () => {
    const res = await app.request("/openai/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({
        messages: [{ role: "invalid", content: "test" }],
      }),
      headers: { "Content-Type": "application/json" },
    });

    expect(res.status).toBe(400);
  });
});

describe("GET /openai/v1/models", () => {
  test("forwards to upstream (returns error without auth)", async () => {
    const res = await app.request("/openai/v1/models");
    // Without auth, upstream returns 401
    expect([200, 401, 500, 502]).toContain(res.status);
  });
});

describe("POST /openai/v1/chat/completions - Secrets Detection", () => {
  const opensshKey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAIEAyK8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v
5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v
5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v
-----END OPENSSH PRIVATE KEY-----`;

  test("blocks request with OpenSSH private key when action=block", async () => {
    const res = await app.request("/openai/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({
        messages: [
          {
            role: "user",
            content: `Here is my SSH key: ${opensshKey}`,
          },
        ],
        model: "gpt-4",
      }),
      headers: { "Content-Type": "application/json" },
    });

    expect(res.status).toBe(422);
    const body = (await res.json()) as {
      error: { message: string; type: string; details: { secrets_detected: string[] } };
    };
    expect(body.error.type).toBe("invalid_request_error");
    expect(body.error.message).toContain("Request blocked");
    expect(body.error.message).toContain("secret material");
    expect(body.error.details.secrets_detected).toContain("OPENSSH_PRIVATE_KEY");

    // Check headers
    expect(res.headers.get("X-LLM-Shield-Secrets-Detected")).toBe("true");
    expect(res.headers.get("X-LLM-Shield-Secrets-Types")).toContain("OPENSSH_PRIVATE_KEY");
  });

  test("blocks request with PEM private key", async () => {
    const rsaKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAyK8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v
5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v
5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v
-----END RSA PRIVATE KEY-----`;

    const res = await app.request("/openai/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({
        messages: [
          {
            role: "user",
            content: `My RSA key: ${rsaKey}`,
          },
        ],
        model: "gpt-4",
      }),
      headers: { "Content-Type": "application/json" },
    });

    expect(res.status).toBe(422);
    const body = (await res.json()) as {
      error: { details: { secrets_detected: string[] } };
    };
    expect(body.error.details.secrets_detected).toContain("PEM_PRIVATE_KEY");
    expect(res.headers.get("X-LLM-Shield-Secrets-Detected")).toBe("true");
  });

  test("allows request without secrets", async () => {
    const res = await app.request("/openai/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({
        messages: [
          {
            role: "user",
            content: "This is just normal text with no secrets",
          },
        ],
        model: "gpt-4",
      }),
      headers: { "Content-Type": "application/json" },
    });

    // Should not be blocked (may fail for other reasons like missing auth, but not 422)
    expect(res.status).not.toBe(422);
    // Should not have secrets detection headers
    expect(res.headers.get("X-LLM-Shield-Secrets-Detected")).toBeNull();
  });

  test("does not set secrets headers when no secrets detected", async () => {
    const res = await app.request("/openai/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({
        messages: [
          {
            role: "user",
            content: "Normal message without any private keys",
          },
        ],
        model: "gpt-4",
      }),
      headers: { "Content-Type": "application/json" },
    });

    // Should not have secrets headers
    expect(res.headers.get("X-LLM-Shield-Secrets-Detected")).toBeNull();
    expect(res.headers.get("X-LLM-Shield-Secrets-Types")).toBeNull();
  });
});
