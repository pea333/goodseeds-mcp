const express = require("express");
const {
  randomBytes,
  randomUUID,
  createHash,
  createHmac,
  timingSafeEqual
} = require("crypto");

const GOOGLE_AUTH = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";
const GOOGLE_REDIRECT_URI =
  (process.env.GOOGLE_REDIRECT_URI && process.env.GOOGLE_REDIRECT_URI.trim()) ||
  "https://goodseeds-mcp.vercel.app/oauth/callback";
const DEFAULT_CONNECTOR_REDIRECT = "https://chatgpt.com/connector_platform_oauth_redirect";
const CHATGPT_ACTION_REDIRECT_HOST = "chat.openai.com";
const CHATGPT_WEB_HOST = "chatgpt.com";
const CHATGPT_ACTION_REDIRECT_PATH_PREFIX = "/aip/";
const CHATGPT_ACTION_REDIRECT_PATH_SUFFIX = "/oauth/callback";
const ALLOWED_STATIC_REDIRECT_URIS = Object.freeze([
  DEFAULT_CONNECTOR_REDIRECT
]);
const GOOGLE_SCOPE_LIST = [
  "https://www.googleapis.com/auth/spreadsheets.readonly",
  "https://www.googleapis.com/auth/drive.readonly"
];
const GOOGLE_SCOPES = GOOGLE_SCOPE_LIST.join(" ");

const MCP_CODE_TTL_MS = 5 * 60 * 1000;
const ACCESS_TOKEN_TTL_MS = 60 * 60 * 1000;
const REFRESH_TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const STATE_TTL_SECONDS = 5 * 60;
 
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

// NOTE: In-memory storage is used only as a temporary solution. For production,
// this MUST be replaced with a persistent and shared store (e.g. KV/Redis).
const mcpCodeStore = new Map();
const accessTokenStore = new Map();
const refreshTokenStore = new Map();

function ensureStateSecret() {
  const secret = process.env.STATE_SECRET;
  if (!secret || !secret.trim() || /^['"].*['"]$/.test(secret)) {
    throw new Error("Invalid or missing environment variable: STATE_SECRET");
  }

  return secret.trim();
}

function generateJti() {
  if (typeof randomUUID === "function") {
    return randomUUID();
  }

  return randomBytes(16).toString("hex");
}

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

  if (parsed.protocol !== "https:") {
    return false;
  }

  if (parsed.hostname === CHATGPT_WEB_HOST) {
    return true;
  }

  if (parsed.hostname !== CHATGPT_ACTION_REDIRECT_HOST) {
    return false;
  }

  const pathname = parsed.pathname || "";
  if (!pathname.startsWith(CHATGPT_ACTION_REDIRECT_PATH_PREFIX)) {
    return false;
  }

  if (!pathname.endsWith(CHATGPT_ACTION_REDIRECT_PATH_SUFFIX)) {
    return false;
  }

  const prefixLength = CHATGPT_ACTION_REDIRECT_PATH_PREFIX.length;
  const suffixLength = CHATGPT_ACTION_REDIRECT_PATH_SUFFIX.length;
  const gptIdSegment = pathname.slice(prefixLength, pathname.length - suffixLength);

  if (!gptIdSegment || gptIdSegment.includes("/")) {
    return false;
  }

  return true;
}

function encodeStatePayload(payload) {
  const secret = ensureStateSecret();
  const payloadJson = JSON.stringify(payload);
  const signature = createHmac("sha256", secret).update(payloadJson).digest("base64url");
  const envelope = {
    payload,
    sig: signature
  };
  return Buffer.from(JSON.stringify(envelope)).toString("base64url");
}

function decodeStatePayload(encoded) {
  const secret = ensureStateSecret();
  let decoded;
  try {
    decoded = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
  } catch (error) {
    throw new Error("invalid_state_format");
  }

  if (!decoded || typeof decoded !== "object" || Array.isArray(decoded)) {
    throw new Error("invalid_state_payload");
  }

  const { payload, sig } = decoded;
  if (!payload || typeof payload !== "object" || Array.isArray(payload) || typeof sig !== "string") {
    throw new Error("invalid_state_payload");
  }

  const payloadJson = JSON.stringify(payload);
  const expectedSignature = createHmac("sha256", secret).update(payloadJson).digest("base64url");
  const expectedBuffer = Buffer.from(expectedSignature);
  const actualBuffer = Buffer.from(sig);

  if (
    expectedBuffer.length !== actualBuffer.length ||
    !timingSafeEqual(expectedBuffer, actualBuffer)
  ) {
    throw new Error("invalid_state_signature");
  }

  const nowSeconds = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== "number" || payload.exp <= nowSeconds) {
    throw new Error("state_expired");
  }

  return payload;
}

function pruneExpiredAccessTokens(now = Date.now()) {
  for (const [token, entry] of accessTokenStore.entries()) {
    if (!entry || entry.expiresAt <= now) {
      accessTokenStore.delete(token);
    }
  }

  for (const [token, entry] of refreshTokenStore.entries()) {
    if (!entry || entry.expiresAt <= now) {
      refreshTokenStore.delete(token);
    }
  }
}

function pruneExpiredMcpCodes(now = Date.now()) {
  for (const [code, entry] of mcpCodeStore.entries()) {
    if (!entry || entry.expiresAt <= now) {
      mcpCodeStore.delete(code);
    }
  }
}

function storeMcpCode(code, entry) {
  pruneExpiredMcpCodes();
  const issuedAt = Date.now();
  mcpCodeStore.set(code, {
    ...entry,
    issuedAt,
    expiresAt: issuedAt + MCP_CODE_TTL_MS
  });
}

function consumeMcpCode(code) {
  if (!code) {
    return null;
  }

  pruneExpiredMcpCodes();
  const entry = mcpCodeStore.get(code);
  if (!entry) {
    return null;
  }

  mcpCodeStore.delete(code);
  if (entry.expiresAt <= Date.now()) {
    return null;
  }

  return entry;
}

function verifyPkceS256({ codeVerifier, codeChallenge, codeChallengeMethod }) {
  if (!codeVerifier || !codeChallenge) {
    return false;
  }

  const method = (codeChallengeMethod || "S256").trim();
  if (method !== "S256") {
    return false;
  }

  const digest = createHash("sha256").update(codeVerifier).digest("base64url");
  return digest === codeChallenge;
}

function issueAccessToken({ googleTokens, mcpClientId, refreshToken, googleRefreshToken }) {
  pruneExpiredAccessTokens();
  const accessToken = randomBytes(32).toString("base64url");
  const issuedAt = Date.now();
  const expiresAt = issuedAt + ACCESS_TOKEN_TTL_MS;

  accessTokenStore.set(accessToken, {
    googleTokens,
    googleRefreshToken: googleRefreshToken || null,
    mcpClientId: mcpClientId || null,
    issuedAt,
    expiresAt,
    refreshToken: refreshToken || null
  });

  return { accessToken, expiresAt };
}

function issueRefreshToken({ googleRefreshToken, mcpClientId }) {
  if (!googleRefreshToken) {
    return null;
  }

  pruneExpiredAccessTokens();
  const refreshToken = randomBytes(32).toString("base64url");
  const issuedAt = Date.now();
  const expiresAt = issuedAt + REFRESH_TOKEN_TTL_MS;

  refreshTokenStore.set(refreshToken, {
    googleRefreshToken,
    mcpClientId: mcpClientId || null,
    issuedAt,
    expiresAt
  });

  return refreshToken;
}

function ensureGoogleCredentials() {
  ["GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET"].forEach((key) => {
    if (!process.env[key] || !process.env[key].trim() || /^['"].*['"]$/.test(process.env[key])) {
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

  app.head("/.well-known/mcp/manifest.json", (req, res) => {
    res.status(200).end();
  });

  app.get("/.well-known/oauth-authorization-server", (req, res) => {
    res.type("application/json").status(200).send(oauthMetadata);
  });

  app.head("/.well-known/oauth-authorization-server", (req, res) => {
    res.status(200).end();
  });

  app.get("/.well-known/oauth-protected-resource", (req, res) => {
    res.type("application/json").status(200).send(protectedResourceMetadata);
  });

  app.head("/.well-known/oauth-protected-resource", (req, res) => {
    res.status(200).end();
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

    if (!chatgptState) {
      return res.status(400).send("missing_state");
    }

    const normalizedChatgptState = String(chatgptState);

    if (!codeChallenge || typeof codeChallenge !== "string") {
      return res.status(400).send("missing_code_challenge");
    }

    const normalizedCodeChallenge = codeChallenge.trim();
    if (!normalizedCodeChallenge) {
      return res.status(400).send("invalid_code_challenge");
    }

    const normalizedCodeChallengeMethod = (codeChallengeMethod || "S256").trim();
    if (normalizedCodeChallengeMethod !== "S256") {
      return res.status(400).send("unsupported_code_challenge_method");
    }

    let credentials;
    try {
      credentials = ensureGoogleCredentials();
      ensureStateSecret();
    } catch (error) {
      console.error(error.message);
      return res.status(500).send("server_misconfigured");
    }

    const nowSeconds = Math.floor(Date.now() / 1000);
    const statePayload = {
      chatgptState: normalizedChatgptState,
      chatgptRedirectUri,
      codeChallenge: normalizedCodeChallenge,
      codeChallengeMethod: normalizedCodeChallengeMethod,
      iat: nowSeconds,
      exp: nowSeconds + STATE_TTL_SECONDS,
      jti: generateJti()
    };

    let googleState;
    try {
      googleState = encodeStatePayload(statePayload);
    } catch (error) {
      console.error("State encoding failed", error);
      return res.status(500).send("server_error");
    }

    console.log(
      `[authorize] Schatgpt_in=${normalizedChatgptState} redirect_uri_in=${chatgptRedirectUri} ` +
        `Sgoogle_out_len=${googleState.length} google_client_id=${credentials.clientId}`
    );

    const url = new URL(GOOGLE_AUTH);
    url.searchParams.set("client_id", credentials.clientId);
    url.searchParams.set("redirect_uri", credentials.redirectUri);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", GOOGLE_SCOPES);
    url.searchParams.set("access_type", "offline");
    url.searchParams.set("prompt", "consent");
    url.searchParams.set("include_granted_scopes", "true");
    url.searchParams.set("state", googleState);
    url.searchParams.set("code_challenge", normalizedCodeChallenge);
    url.searchParams.set("code_challenge_method", normalizedCodeChallengeMethod);

    return res.redirect(302, url.toString());
  });

  app.get("/oauth/callback", async (req, res) => {
    try {
      const { code, state: googleState } = req.query;
      if (!code) {
        return res.status(400).send("invalid_request");
      }

      if (!googleState) {
        return res.status(400).send("missing_state");
      }

      let payload;
      try {
        payload = decodeStatePayload(String(googleState));
      } catch (error) {
        if (error.message === "Invalid or missing environment variable: STATE_SECRET") {
          console.error(error.message);
          return res.status(500).send("server_misconfigured");
        }

        if (error.message === "invalid_state_format") {
          console.warn("Invalid Google state payload", error);
        } else {
          console.warn("State validation failed", error);
        }
        return res.status(400).send("invalid_state");
      }

      const {
        chatgptState,
        chatgptRedirectUri,
        codeChallenge,
        codeChallengeMethod
      } = payload;

      if (!chatgptState || typeof chatgptState !== "string") {
        return res.status(400).send("invalid_state");
      }

      if (!chatgptRedirectUri || !isAllowedChatGptRedirect(chatgptRedirectUri)) {
        return res.status(400).send("invalid_redirect_uri");
      }

      if (!codeChallenge || typeof codeChallenge !== "string") {
        return res.status(400).send("invalid_state");
      }

      if ((codeChallengeMethod || "").trim() !== "S256") {
        return res.status(400).send("invalid_state");
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
        redirect_uri: credentials.redirectUri,
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
      if (!googleTokens.token_type) {
        googleTokens.token_type = "Bearer";
      }

      const sanitizedGoogleTokens = { ...googleTokens };
      const googleRefreshToken = sanitizedGoogleTokens.refresh_token || null;
      if (googleRefreshToken) {
        delete sanitizedGoogleTokens.refresh_token;
      }

      const mcpCode = randomBytes(32).toString("base64url");
      storeMcpCode(mcpCode, {
        googleTokens: sanitizedGoogleTokens,
        googleRefreshToken,
        codeChallenge,
        codeChallengeMethod,
        mcpClientId: "goodseeds-chatgpt"
      });

      let out;
      try {
        out = new URL(chatgptRedirectUri);
      } catch (redirectError) {
        console.error("Invalid ChatGPT redirect URI", redirectError);
        return res.status(400).send("invalid_redirect_uri");
      }

      out.searchParams.set("code", mcpCode);
      out.searchParams.set("state", chatgptState);

      console.log(
        `[callback] Sgoogle_in=OK Schatgpt_in=${chatgptState} redirect_uri_in=${chatgptRedirectUri} Schatgpt_out=${chatgptState}`
      );

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
      client_id: mcpClientId,
      code_verifier: codeVerifier
    } = { ...req.body, ...req.query };

    if (!grantType) {
      return res.status(400).json({ error: "invalid_request", error_description: "Missing grant_type" });
    }

    if (mcpClientId && mcpClientId !== "goodseeds-chatgpt") {
      return res.status(400).json({ error: "invalid_client" });
    }

    if (grantType === "authorization_code") {
      if (!code) {
        return res.status(400).json({ error: "invalid_request", error_description: "Missing code" });
      }

      if (!codeVerifier) {
        return res
          .status(400)
          .json({ error: "invalid_request", error_description: "Missing code_verifier" });
      }

      const entry = consumeMcpCode(code);
      if (!entry || entry.mcpClientId !== "goodseeds-chatgpt") {
        console.log("[token] pkce_check=FAIL");
        return res.status(400).json({ error: "invalid_grant" });
      }

      const pkceValid = verifyPkceS256({
        codeVerifier: String(codeVerifier),
        codeChallenge: entry.codeChallenge,
        codeChallengeMethod: entry.codeChallengeMethod
      });

      console.log(`[token] pkce_check=${pkceValid ? "PASS" : "FAIL"}`);

      if (!pkceValid) {
        return res
          .status(400)
          .json({ error: "invalid_grant", error_description: "pkce_failed" });
      }

      const sanitizedGoogleTokens = { ...(entry.googleTokens || {}) };
      const googleRefreshToken = entry.googleRefreshToken || null;

      const issuedRefreshToken = issueRefreshToken({
        googleRefreshToken,
        mcpClientId: entry.mcpClientId || "goodseeds-chatgpt"
      });

      const { accessToken, expiresAt } = issueAccessToken({
        googleTokens: sanitizedGoogleTokens,
        mcpClientId: entry.mcpClientId || "goodseeds-chatgpt",
        refreshToken: issuedRefreshToken,
        googleRefreshToken
      });

      const responsePayload = {
        token_type: "Bearer",
        access_token: accessToken,
        expires_in: Math.max(1, Math.floor((expiresAt - Date.now()) / 1000))
      };

      if (issuedRefreshToken) {
        responsePayload.refresh_token = issuedRefreshToken;
      }

      return res.status(200).json(responsePayload);
    }

    if (grantType === "refresh_token") {
      if (!refreshToken) {
        return res
          .status(400)
          .json({ error: "invalid_request", error_description: "Missing refresh_token" });
      }

      pruneExpiredAccessTokens();
      const storedRefresh = refreshTokenStore.get(refreshToken);
      if (!storedRefresh || storedRefresh.expiresAt <= Date.now()) {
        refreshTokenStore.delete(refreshToken);
        return res.status(400).json({ error: "invalid_grant" });
      }

      refreshTokenStore.delete(refreshToken);

      if (storedRefresh.mcpClientId && storedRefresh.mcpClientId !== "goodseeds-chatgpt") {
        return res.status(400).json({ error: "invalid_grant" });
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
        refresh_token: storedRefresh.googleRefreshToken,
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

        if (!payload.token_type) {
          payload.token_type = "Bearer";
        }

        const sanitizedGoogleTokens = { ...payload };
        const newGoogleRefreshToken = sanitizedGoogleTokens.refresh_token || storedRefresh.googleRefreshToken;
        if (sanitizedGoogleTokens.refresh_token) {
          delete sanitizedGoogleTokens.refresh_token;
        }

        const issuedRefreshToken = issueRefreshToken({
          googleRefreshToken: newGoogleRefreshToken,
          mcpClientId: storedRefresh.mcpClientId || "goodseeds-chatgpt"
        });

        const { accessToken, expiresAt } = issueAccessToken({
          googleTokens: sanitizedGoogleTokens,
          mcpClientId: storedRefresh.mcpClientId || "goodseeds-chatgpt",
          refreshToken: issuedRefreshToken,
          googleRefreshToken: newGoogleRefreshToken
        });

        const responsePayload = {
          token_type: "Bearer",
          access_token: accessToken,
          expires_in: Math.max(1, Math.floor((expiresAt - Date.now()) / 1000))
        };

        if (issuedRefreshToken) {
          responsePayload.refresh_token = issuedRefreshToken;
        }

        return res.status(200).json(responsePayload);
      } catch (error) {
        console.error("Token refresh failed", error);
        return res.status(500).json({ error: "token_exchange_failed" });
      }
    }

    return res.status(400).json({ error: "unsupported_grant_type" });
  });

  app.use((req, res) => {
    res.status(404).json({ error: "not_found" });
  });

  app.use((error, req, res, _next) => {
    console.error("Unhandled error", error);
    if (res.headersSent) {
      return;
    }

    res.status(500).json({ error: "internal_server_error" });
  });

  return app;
}

const app = createApp();

module.exports = app;
module.exports.handler = (req, res) => app(req, res);
