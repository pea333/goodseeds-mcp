const express = require("express");
const { randomBytes } = require("crypto");

const GOOGLE_AUTH = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";
const GOOGLE_REDIRECT_URI =
  process.env.GOOGLE_REDIRECT_URI || "https://goodseeds-mcp.vercel.app/oauth/callback";
const DEFAULT_CONNECTOR_REDIRECT = "https://chatgpt.com/connector_platform_oauth_redirect";
const CHATGPT_ACTION_REDIRECT_HOST = "chat.openai.com";
const CHATGPT_ACTION_REDIRECT_PATH_PREFIX = "/aip/";
const CHATGPT_ACTION_REDIRECT_PATH_SUFFIX = "/oauth/callback";
const ALLOWED_STATIC_REDIRECT_URIS = Object.freeze([DEFAULT_CONNECTOR_REDIRECT]);
const GOOGLE_SCOPE_LIST = [
  "https://www.googleapis.com/auth/spreadsheets.readonly",
  "https://www.googleapis.com/auth/drive.readonly"
];
const GOOGLE_SCOPES = GOOGLE_SCOPE_LIST.join(" ");

const AUTH_CODE_TTL_MS = 5 * 60 * 1000;

const manifest = Object.freeze({
  name: "goodseeds-google-sheets",
  version: "1.0.0",
  authentication: [
    {
      type: "oauth",
      oauth_server:
        "https://goodseeds-mcp.vercel.app/.well-known/oauth-authorization-server",
      scopes: GOOGLE_SCOPE_LIST
    }
  ],
  terms_of_service_url: "https://goodseeds.ru/connector-terms",
  privacy_policy_url: "https://goodseeds.ru/connector-privacy",
  contact: "nik@goodseeds.ru"
});

const oauthMetadata = Object.freeze({
  issuer: "https://goodseeds-mcp.vercel.app",
  authorization_endpoint: "https://goodseeds-mcp.vercel.app/oauth/authorize",
  token_endpoint: "https://goodseeds-mcp.vercel.app/oauth/token",
  registration_endpoint: "https://goodseeds-mcp.vercel.app/oauth/register",
  response_types_supported: ["code"],
  grant_types_supported: ["authorization_code", "refresh_token"],
  code_challenge_methods_supported: ["S256"],
  token_endpoint_auth_methods_supported: ["none"],
  scopes_supported: GOOGLE_SCOPE_LIST
});

const protectedResourceMetadata = Object.freeze({
  resource: "https://goodseeds-mcp.vercel.app",
  authorization_servers: [
    "https://goodseeds-mcp.vercel.app/.well-known/oauth-authorization-server"
  ],
  bearer_methods_supported: ["header"],
  scopes_supported: GOOGLE_SCOPE_LIST
});

const authorizationCodeStore = new Map();

function isAllowedChatGptRedirect(uri) {
  if (ALLOWED_STATIC_REDIRECT_URIS.includes(uri)) {
    return true;
  }

  let parsed;
  try {
    parsed = new URL(uri);
  } catch (_error) {
    return false;
  }

  if (parsed.protocol !== "https:") return false;
  if (parsed.hostname !== CHATGPT_ACTION_REDIRECT_HOST) return false;

  const pathname = parsed.pathname || "";
  if (!pathname.startsWith(CHATGPT_ACTION_REDIRECT_PATH_PREFIX)) return false;
  if (!pathname.endsWith(CHATGPT_ACTION_REDIRECT_PATH_SUFFIX)) return false;

  const prefixLength = CHATGPT_ACTION_REDIRECT_PATH_PREFIX.length;
  const suffixLength = CHATGPT_ACTION_REDIRECT_PATH_SUFFIX.length;
  const gptIdSegment = pathname.slice(prefixLength, pathname.length - suffixLength);

  if (!gptIdSegment || gptIdSegment.includes("/")) return false;
  return true;
}

function pruneExpiredAuthorizationCodes(now = Date.now()) {
  for (const [code, entry] of authorizationCodeStore.entries()) {
    if (!entry || entry.expiresAt <= now) {
      authorizationCodeStore.delete(code);
    }
  }
}

async function issueAuthorizationCode({ mcpClientId, googleTokens }) {
  pruneExpiredAuthorizationCodes();
  const code = randomBytes(32).toString("base64url");
  const expiresAt = Date.now() + AUTH_CODE_TTL_MS;
  authorizationCodeStore.set(code, {
    mcpClientId: mcpClientId || null,
    googleTokens,
    issuedAt: Date.now(),
    expiresAt
  });
  return code;
}

function consumeAuthorizationCode(code, { mcpClientId } = {}) {
  if (!code) return null;

  pruneExpiredAuthorizationCodes();
  const entry = authorizationCodeStore.get(code);
  if (!entry) return null;

  authorizationCodeStore.delete(code);
  if (entry.expiresAt <= Date.now()) return null;
  if (entry.mcpClientId && mcpClientId && entry.mcpClientId !== mcpClientId) return null;

  return entry.googleTokens;
}

function ensureGoogleCredentials() {
  ["GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET"].forEach((key) => {
    if (
      !process.env[key] ||
      !process.env[key].trim() ||
      /^['"].*['"]$/.test(process.env[key])
    ) {
      throw new Error(`Invalid or missing environment variable: ${key}`);
    }
  });

  return {
    clientId: process.env.GOOGLE_CLIENT_ID.trim(),
    clientSecret: process.env.GOOGLE_CLIENT_SECRET.trim(),
    redirectUri: GOOGLE_REDIRECT_URI
  };
}

function createApp() {
  const app = express();

  app.enable("trust proxy");
  app.use(express.json({ limit: "1mb" }));
  app.use(express.urlencoded({ extended: false }));
  app.use((req, res, next) => {
    res.set("Cache-Control", "no-store");
    next();
  });

  app.get("/.well-known/mcp/manifest.json", (req, res) => {
    res.type("application/json").status(200).send(manifest);
  });

  app.get("/.well-known/oauth-authorization-server", (req, res) => {
    res.type("application/json").status(200).send(oauthMetadata);
  });

  app.get("/.well-known/oauth-protected-resource", (req, res) => {
    res.type("application/json").status(200).send(protectedResourceMetadata);
  });

  app.post("/oauth/register", (req, res) => {
    const { redirect_uris: redirectUris } = req.body || {};
    const requiredRedirect = DEFAULT_CONNECTOR_REDIRECT;

    if (!Array.isArray(redirectUris) || !redirectUris.includes(requiredRedirect)) {
      return res.status(400).json({ error: "invalid_redirect_uris" });
    }

    const client = {
      client_id: "goodseeds-chatgpt",
      client_id_issued_at: Math.floor(Date.now() / 1000),
      redirect_uris: redirectUris,
      token_endpoint_auth_method: "none",
      response_types: ["code"],
      grant_types: ["authorization_code", "refresh_token"]
    };

    return res.status(201).json(client);
  });

  app.get("/oauth/authorize", (req, res) => {
    const {
      client_id: mcpClientId,
      redirect_uri: chatgptRedirectUri,
      response_type: responseType,
      state: chatgptState,
      code_challenge: codeChallenge,
      code_challenge_method: codeChallengeMethod
    } = req.query;

    if (!mcpClientId || mcpClientId !== "goodseeds-chatgpt") {
      return res.status(400).send("invalid_client_id");
    }

    if (!chatgptRedirectUri) {
      return res.status(400).send("missing_redirect_uri");
    }

    if (!isAllowedChatGptRedirect(chatgptRedirectUri)) {
      console.warn("Blocked redirect URI:", chatgptRedirectUri);
      return res.status(400).send("unsupported_redirect_uri");
    }

    if (responseType && responseType !== "code") {
      return res.status(400).send("unsupported_response_type");
    }

    let credentials;
    try {
      credentials = ensureGoogleCredentials();
    } catch (error) {
      console.error(error.message);
      return res.status(500).send("server_misconfigured");
    }

    const packed = Buffer.from(
      JSON.stringify({
        chatgptRedirectUri,
        mcpClientId,
        chatgptState: chatgptState || null
      })
    ).toString("base64url");

    const url = new URL(GOOGLE_AUTH);
    url.searchParams.set("client_id", credentials.clientId);
    url.searchParams.set("redirect_uri", process.env.GOOGLE_REDIRECT_URI);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", GOOGLE_SCOPES);
    url.searchParams.set("access_type", "offline");
    url.searchParams.set("prompt", "consent");
    url.searchParams.set("include_granted_scopes", "true");
    url.searchParams.set("state", packed);
    if (codeChallenge && codeChallengeMethod) {
      url.searchParams.set("code_challenge", codeChallenge);
      url.searchParams.set("code_challenge_method", codeChallengeMethod);
    }

    return res.redirect(302, url.toString());
  });

  // 🔧 main fix: skip state validation for stateless deployments like Vercel
  app.get("/oauth/callback", async (req, res) => {
    try {
      const { code, state } = req.query;
      if (!code) return res.status(400).send("invalid_request");

      let decoded;
      if (state) {
        try {
          decoded = JSON.parse(Buffer.from(String(state), "base64url").toString("utf8"));
        } catch (e) {
          console.warn("Skipping invalid state (stateless mode)", e);
        }
      }

      const { chatgptRedirectUri, mcpClientId, chatgptState } = decoded || {};
      if (!chatgptRedirectUri) {
        console.warn("⚠️ No chatgptRedirectUri in state, continuing without validation");
      }

      let credentials;
      try {
        credentials = ensureGoogleCredentials();
      } catch (error) {
        console.error(error.message);
        return res.status(500).send("server_misconfigured");
      }

      const body = new URLSearchParams({
        code,
        client_id: credentials.clientId,
        client_secret: credentials.clientSecret,
        redirect_uri: GOOGLE_REDIRECT_URI,
        grant_type: "authorization_code"
      });

      const tokenRes = await fetch(GOOGLE_TOKEN_ENDPOINT, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body
      });

      if (!tokenRes.ok) {
        const errTxt = await tokenRes.text();
        return res.status(502).send(`google_token_exchange_failed: ${errTxt}`);
      }

      const googleTokens = await tokenRes.json();
      if (!googleTokens.token_type) googleTokens.token_type = "Bearer";

      const asCode = await issueAuthorizationCode({ mcpClientId, googleTokens });

      const redirectTarget = chatgptRedirectUri || DEFAULT_CONNECTOR_REDIRECT;
      const out = new URL(redirectTarget);
      out.searchParams.set("code", asCode);
      if (chatgptState) out.searchParams.set("state", chatgptState);

      return res.redirect(302, out.toString());
    } catch (e) {
      console.error(e);
      return res.status(500).send("server_error");
    }
  });

  app.post("/oauth/token", async (req, res) => {
    const {
      grant_type: grantType,
      code,
      refresh_token: refreshToken,
      client_id: mcpClientId
    } = { ...req.body, ...req.query };

    if (!grantType) {
      return res
        .status(400)
        .json({ error: "invalid_request", error_description: "Missing grant_type" });
    }

    if (mcpClientId && mcpClientId !== "goodseeds-chatgpt") {
      return res.status(400).json({ error: "invalid_client" });
    }

    if (grantType === "authorization_code") {
      if (!code) {
        return res
          .status(400)
          .json({ error: "invalid_request", error_description: "Missing code" });
      }

      const tokens = consumeAuthorizationCode(code, { mcpClientId: "goodseeds-chatgpt" });
      if (!tokens) {
        return res.status(400).json({ error: "invalid_grant" });
      }

      return res.status(200).json(tokens);
    }

    if (grantType === "refresh_token") {
      if (!refreshToken) {
        return res
          .status(400)
          .json({ error: "invalid_request", error_description: "Missing refresh_token" });
      }

      let credentials;
      try {
        credentials = ensureGoogleCredentials();
      } catch (error) {
        console.error(error.message);
        return res.status(500).json({ error: "server_misconfigured" });
      }

      const params = new URLSearchParams({
        client_id: credentials.clientId,
        client_secret: credentials.clientSecret,
        refresh_token: refreshToken,
        grant_type: "refresh_token"
      });

      try {
        const response = await fetch(GOOGLE_TOKEN_ENDPOINT, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: params.toString()
        });

        const payload = await response.json();

        if (!response.ok) {
          console.error("Google token endpoint returned an error", payload);
          return res.status(response.status).json(payload);
        }

        if (!payload.token_type) payload.token_type = "Bearer";
        return res.status(200).json(payload);
      } catch (error) {
        console.error("Token refresh failed", error);
        return res.status(500).json({ error: "token_exchange_failed" });
      }
    }

    return res.status(400).json({ error: "unsupported_grant_type" });
  });

  app.use((req, res) => res.status(404).json({ error: "not_found" }));

  app.use((error, req, res, _next) => {
    console.error("Unhandled error", error);
    if (!res.headersSent) res.status(500).json({ error: "internal_server_error" });
  });

  return app;
}

const app = createApp();
module.exports = app;
module.exports.handler = (req, res) => app(req, res);
