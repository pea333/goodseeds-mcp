const express = require("express");

const GOOGLE_AUTH_BASE = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";
const DEFAULT_CONNECTOR_REDIRECT = "https://chatgpt.com/connector_platform_oauth_redirect";
const DEFAULT_CALLBACK = "https://goodseeds-mcp.vercel.app/oauth/callback";
const DEFAULT_SCOPES = [
  "https://www.googleapis.com/auth/spreadsheets.readonly",
  "https://www.googleapis.com/auth/drive.readonly",
  "offline_access"
];
 
const manifest = Object.freeze({
  name: "goodseeds-google-sheets",
  version: "1.0.0",
  authentication: [
    {
      type: "oauth",
      oauth_server:
        "https://goodseeds-mcp.vercel.app/.well-known/oauth-authorization-server",
      scopes: DEFAULT_SCOPES
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
  scopes_supported: DEFAULT_SCOPES
});

const protectedResourceMetadata = Object.freeze({
  resource: "https://goodseeds-mcp.vercel.app",
  authorization_servers: [
    "https://goodseeds-mcp.vercel.app/.well-known/oauth-authorization-server"
  ],
  bearer_methods_supported: ["header"],
  scopes_supported: DEFAULT_SCOPES
});

function base64UrlEncode(value) {
  return Buffer.from(value, "utf8")
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function base64UrlDecode(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padding = normalized.length % 4 === 0 ? "" : "=".repeat(4 - (normalized.length % 4));
  return Buffer.from(normalized + padding, "base64").toString("utf8");
}

function buildStateEnvelope({ redirectUri, upstreamState }) {
  const payload = {
    redirect_uri: redirectUri || DEFAULT_CONNECTOR_REDIRECT,
    upstream_state: upstreamState || null
  };
  return base64UrlEncode(JSON.stringify(payload));
}

function parseStateEnvelope(value) {
  if (!value) {
    return {
      redirect_uri: DEFAULT_CONNECTOR_REDIRECT,
      upstream_state: null
    };
  }

  try {
    const decoded = base64UrlDecode(value);
    const parsed = JSON.parse(decoded);
    return {
      redirect_uri: parsed.redirect_uri || DEFAULT_CONNECTOR_REDIRECT,
      upstream_state: parsed.upstream_state || null
    };
  } catch (error) {
    console.error("Failed to parse OAuth state payload", error);
    return {
      redirect_uri: DEFAULT_CONNECTOR_REDIRECT,
      upstream_state: null
    };
  }
}

function ensureGoogleCredentials() {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;

  if (!clientId) {
    throw new Error("Missing GOOGLE_CLIENT_ID environment variable");
  }

  if (!clientSecret) {
    throw new Error("Missing GOOGLE_CLIENT_SECRET environment variable");
  }

  return {
    clientId,
    clientSecret,
    redirectUri:
      process.env.GOOGLE_REDIRECT_URI || process.env.REDIRECT_URI || DEFAULT_CALLBACK
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
      client_id: clientId,
      redirect_uri: connectorRedirect,
      response_type: responseType,
      scope,
      state,
      code_challenge: codeChallenge,
      code_challenge_method: codeChallengeMethod
    } = req.query;

    if (!clientId || clientId !== "goodseeds-chatgpt") {
      return res.status(400).send("invalid_client_id");
    }

    if (!connectorRedirect) {
      return res.status(400).send("missing_redirect_uri");
    }

    if (connectorRedirect !== DEFAULT_CONNECTOR_REDIRECT) {
      return res.status(400).send("unsupported_redirect_uri");
    }

    if (responseType !== "code") {
      return res.status(400).send("unsupported_response_type");
    }

    let credentials;
    try {
      credentials = ensureGoogleCredentials();
    } catch (error) {
      console.error(error.message);
      return res.status(500).send("server_misconfigured");
    }

    const requestedScopes = (scope || DEFAULT_SCOPES.join(" ")).split(/\s+/).filter(Boolean);
    const stateEnvelope = buildStateEnvelope({
      redirectUri: connectorRedirect,
      upstreamState: state || null
    });

    const googleParams = new URLSearchParams({
      client_id: credentials.clientId,
      redirect_uri: credentials.redirectUri,
      response_type: "code",
      access_type: "offline",
      include_granted_scopes: "true",
      prompt: "consent",
      scope: requestedScopes.join(" "),
      state: stateEnvelope
    });

    if (codeChallenge && codeChallengeMethod) {
      googleParams.set("code_challenge", codeChallenge);
      googleParams.set("code_challenge_method", codeChallengeMethod);
    }

    console.log("Using client_id:", credentials.clientId);
    console.log("Redirect URI:", credentials.redirectUri);

    const redirectTarget = `${GOOGLE_AUTH_BASE}?${googleParams.toString()}`;
    return res.redirect(302, redirectTarget);
  });

  app.get("/oauth/callback", (req, res) => {
    const { code, state, error, error_description: errorDescription } = req.query;

    if (error) {
      console.error("Google OAuth error", { error, errorDescription });
      return res.status(400).send(errorDescription || error);
    }

    if (!code) {
      return res.status(400).send("missing_code");
    }

    const { redirect_uri: connectorRedirect, upstream_state: upstreamState } =
      parseStateEnvelope(state);

    const redirectUrl = new URL(connectorRedirect || DEFAULT_CONNECTOR_REDIRECT);
    redirectUrl.searchParams.set("code", code);
    if (upstreamState) {
      redirectUrl.searchParams.set("state", upstreamState);
    }

    return res.redirect(302, redirectUrl.toString());
  });

  app.post("/oauth/token", async (req, res) => {
    const {
      grant_type: grantType,
      code,
      refresh_token: refreshToken,
      code_verifier: codeVerifier
    } = { ...req.body, ...req.query };

    let credentials;
    try {
      credentials = ensureGoogleCredentials();
    } catch (error) {
      console.error(error.message);
      return res.status(500).json({ error: "server_misconfigured" });
    }

    const params = new URLSearchParams({
      client_id: credentials.clientId,
      client_secret: credentials.clientSecret
    });

    if (grantType === "authorization_code") {
      if (!code) {
        return res.status(400).json({ error: "invalid_request", error_description: "Missing code" });
      }

      params.set("grant_type", "authorization_code");
      params.set("code", code);
      params.set("redirect_uri", credentials.redirectUri);
      if (codeVerifier) {
        params.set("code_verifier", codeVerifier);
      }
    } else if (grantType === "refresh_token") {
      if (!refreshToken) {
        return res
          .status(400)
          .json({ error: "invalid_request", error_description: "Missing refresh_token" });
      }

      params.set("grant_type", "refresh_token");
      params.set("refresh_token", refreshToken);
    } else {
      return res.status(400).json({ error: "unsupported_grant_type" });
    }

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

      return res.status(200).json(payload);
    } catch (error) {
      console.error("Token exchange failed", error);
      return res.status(500).json({ error: "token_exchange_failed" });
    }
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

if (require.main === module) {
  const port = process.env.PORT || 3000;
  app.listen(port, () => {
    console.log(`Goodseeds MCP OAuth connector listening on port ${port}`);
  });
}

module.exports = app;
module.exports.handler = (req, res) => app(req, res);
