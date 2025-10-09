const { describe, it, before, after, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");

function createCodeChallenge(verifier) {
  return crypto.createHash("sha256").update(verifier).digest("base64url");
}

const app = require("../index.js");

describe("OAuth state handling", () => {
  let server;
  let baseUrl;
  let originalFetch;
  let originalClientId;
  let originalClientSecret;

  before(async () => {
    server = app.listen(0);
    await new Promise((resolve) => server.once("listening", resolve));
    const address = server.address();
    baseUrl = `http://127.0.0.1:${address.port}`;
  });

  after(async () => {
    if (server) {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  beforeEach(() => {
    originalFetch = global.fetch;
    originalClientId = process.env.GOOGLE_CLIENT_ID;
    originalClientSecret = process.env.GOOGLE_CLIENT_SECRET;

    process.env.GOOGLE_CLIENT_ID = "test-client-id";
    process.env.GOOGLE_CLIENT_SECRET = "test-client-secret";
  });

  afterEach(() => {
    if (originalClientId === undefined) {
      delete process.env.GOOGLE_CLIENT_ID;
    } else {
      process.env.GOOGLE_CLIENT_ID = originalClientId;
    }

    if (originalClientSecret === undefined) {
      delete process.env.GOOGLE_CLIENT_SECRET;
    } else {
      process.env.GOOGLE_CLIENT_SECRET = originalClientSecret;
    }

    global.fetch = originalFetch;
  });

  it("should redirect to Google with proper redirect_uri", async () => {
    const verifier = "sample-code-verifier";
    const challenge = createCodeChallenge(verifier);

    const authorizeUrl = new URL(`${baseUrl}/oauth/authorize`);
    authorizeUrl.searchParams.set("client_id", "goodseeds-chatgpt");
    authorizeUrl.searchParams.set(
      "redirect_uri",
      "https://chatgpt.com/connector_platform_oauth_redirect"
    );
    authorizeUrl.searchParams.set("response_type", "code");
    authorizeUrl.searchParams.set("state", "sample-state");
    authorizeUrl.searchParams.set("code_challenge", challenge);
    authorizeUrl.searchParams.set("code_challenge_method", "S256");

    const response = await fetch(authorizeUrl, { redirect: "manual" });

    assert.equal(response.status, 302);
    const location = response.headers.get("location");
    assert.ok(location.includes("accounts.google.com"));

    const redirectUrl = new URL(location);
    assert.equal(
      redirectUrl.searchParams.get("redirect_uri"),
      "https://goodseeds-mcp.vercel.app/oauth/callback"
    );
  });

  it("should return ChatGPT state in the final redirect when provided", async () => {
    const nodeFetch = originalFetch;
    global.fetch = async (input, init) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      if (typeof url === "string" && url.startsWith("https://oauth2.googleapis.com/")) {
        return {
          ok: true,
          json: async () => ({
            access_token: "test-access-token",
            refresh_token: "test-refresh-token",
            expires_in: 3600,
            token_type: "Bearer"
          }),
          text: async () => "ok"
        };
      }

      return nodeFetch(input, init);
    };

    const verifier = "sample-code-verifier";
    const challenge = createCodeChallenge(verifier);

    const authorizeUrl = new URL(`${baseUrl}/oauth/authorize`);
    authorizeUrl.searchParams.set("client_id", "goodseeds-chatgpt");
    authorizeUrl.searchParams.set(
      "redirect_uri",
      "https://chatgpt.com/connector_platform_oauth_redirect"
    );
    authorizeUrl.searchParams.set("response_type", "code");
    authorizeUrl.searchParams.set("state", "sample-chatgpt-state");
    authorizeUrl.searchParams.set("code_challenge", challenge);
    authorizeUrl.searchParams.set("code_challenge_method", "S256");

    const authorizeResponse = await fetch(authorizeUrl, { redirect: "manual" });
    assert.equal(authorizeResponse.status, 302);

    const googleLocation = authorizeResponse.headers.get("location");
    const googleUrl = new URL(googleLocation);
    const googleState = googleUrl.searchParams.get("state");
    assert.ok(googleState);
    assert.notEqual(googleState, "sample-chatgpt-state");

    const callbackUrl = new URL(`${baseUrl}/oauth/callback`);
    callbackUrl.searchParams.set("code", "test-code");
    callbackUrl.searchParams.set("state", googleState);

    const response = await fetch(callbackUrl, { redirect: "manual" });

    assert.equal(response.status, 302);
    const location = response.headers.get("location");
    assert.ok(location.includes("chatgpt.com"));

    const redirectUrl = new URL(location);
    assert.ok(redirectUrl.searchParams.get("code"));
    assert.equal(redirectUrl.searchParams.get("state"), "sample-chatgpt-state");
  });

  it("should return an error when callback is called with broken state", async () => {
    const nodeFetch = originalFetch;
    global.fetch = async (input, init) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      if (typeof url === "string" && url.startsWith("https://oauth2.googleapis.com/")) {
        return {
          ok: true,
          json: async () => ({
            access_token: "test-access-token",
            refresh_token: "test-refresh-token",
            expires_in: 3600,
            token_type: "Bearer"
          }),
          text: async () => "ok"
        };
      }

      return nodeFetch(input, init);
    };

    const warnings = [];
    const originalWarn = console.warn;
    console.warn = (...args) => {
      warnings.push(args.map(String).join(" "));
      if (typeof originalWarn === "function") {
        originalWarn(...args);
      }
    };

    try {
      const callbackUrl = new URL(`${baseUrl}/oauth/callback`);
      callbackUrl.searchParams.set("code", "test-code");
      callbackUrl.searchParams.set("state", "!!!invalid-state!!!");

      const response = await fetch(callbackUrl, { redirect: "manual" });

      assert.equal(response.status, 400);
      assert.ok(
        warnings.some((message) => message.includes("Invalid Google state payload"))
      );
    } finally {
      console.warn = originalWarn;
    }
  });
});
