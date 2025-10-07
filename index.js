const express = require("express");
const https = require("https");

const app = express();
app.use(express.json());

// ===================== 1. MCP manifest =====================
const manifest = {
  name: "goodseeds-google-sheets",
  version: "1.0.0",
  authentication: [
    {
      type: "oauth",
      oauth_server: "https://goodseeds-mcp.vercel.app/.well-known/oauth-authorization-server",
      scopes: [
        "https://www.googleapis.com/auth/spreadsheets.readonly",
        "https://www.googleapis.com/auth/drive.readonly",
        "offline_access"
      ]
    }
  ],
  terms_of_service_url: "https://goodseeds.ru/connector-terms",
  privacy_policy_url: "https://goodseeds.ru/page84131506.html",
  contact: "nik@goodseeds.ru"
};

app.get("/.well-known/mcp/manifest.json", (req, res) => {
  res.type("application/json").json(manifest);
});
app.head("/.well-known/mcp/manifest.json", (req, res) => res.status(200).send("OK"));

// ===================== 2. OAuth Server Metadata =====================
const oauthMetadata = {
  issuer: "https://goodseeds-mcp.vercel.app",
  authorization_endpoint: "https://goodseeds-mcp.vercel.app/oauth/authorize",
  token_endpoint: "https://goodseeds-mcp.vercel.app/oauth/token",
  registration_endpoint: "https://goodseeds-mcp.vercel.app/oauth/register",
  response_types_supported: ["code"],
  grant_types_supported: ["authorization_code", "refresh_token"],
  code_challenge_methods_supported: ["S256"],
  token_endpoint_auth_methods_supported: ["none"],
  scopes_supported: [
    "https://www.googleapis.com/auth/spreadsheets.readonly",
    "https://www.googleapis.com/auth/drive.readonly",
    "offline_access"
  ]
};

app.get("/.well-known/oauth-authorization-server", (req, res) => {
  res.type("application/json").json(oauthMetadata);
});
app.head("/.well-known/oauth-authorization-server", (req, res) => res.status(200).send("OK"));

// ===================== 3. Protected Resource Metadata =====================
const protectedResourceMetadata = {
  resource: "https://goodseeds-mcp.vercel.app",
  authorization_servers: [
    "https://goodseeds-mcp.vercel.app/.well-known/oauth-authorization-server"
  ],
  bearer_methods_supported: ["header"],
  scopes_supported: [
    "https://www.googleapis.com/auth/spreadsheets.readonly",
    "https://www.googleapis.com/auth/drive.readonly",
    "offline_access"
  ]
};

app.get("/.well-known/oauth-protected-resource", (req, res) => {
  res.type("application/json").json(protectedResourceMetadata);
});
app.head("/.well-known/oauth-protected-resource", (req, res) => res.status(200).send("OK"));

// ===================== 4. Dynamic client registration =====================
app.post("/oauth/register", (req, res) => {
  const { redirect_uris } = req.body || {};
  const requiredRedirect = "https://chatgpt.com/connector_platform_oauth_redirect";
  if (!Array.isArray(redirect_uris) || !redirect_uris.includes(requiredRedirect)) {
    return res.status(400).json({ error: "Invalid redirect URIs" });
  }

  const client = {
    client_id: "goodseeds-chatgpt",
    client_id_issued_at: Math.floor(Date.now() / 1000),
    redirect_uris,
    token_endpoint_auth_method: "none",
    response_types: ["code"],
    grant_types: ["authorization_code", "refresh_token"]
  };

  res.status(201).json(client);
});

// ===================== 5. Authorization + Token exchange =====================
app.get("/oauth/authorize", (req, res) => {
  const { client_id, redirect_uri, response_type } = req.query;
  if (!client_id || !redirect_uri || response_type !== "code") {
    return res.status(400).send("Invalid authorization request");
  }

  const redirectUrl = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  redirectUrl.search = new URLSearchParams({
    client_id: process.env.GOOGLE_CLIENT_ID,
    redirect_uri: process.env.REDIRECT_URI || "https://goodseeds-mcp.vercel.app/oauth/callback",
    response_type: "code",
    access_type: "offline",
    prompt: "consent",
    scope: [
      "https://www.googleapis.com/auth/spreadsheets.readonly",
      "https://www.googleapis.com/auth/drive.readonly"
    ].join(" ")
  }).toString();

  res.redirect(302, redirectUrl.toString());
});

app.get("/oauth/callback", async (req, res) => {
  const { code } = req.query;
  if (!code) return res.status(400).send("Missing code");

  try {
    const params = new URLSearchParams({
      code,
      client_id: process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
      redirect_uri: process.env.REDIRECT_URI || "https://goodseeds-mcp.vercel.app/oauth/callback",
      grant_type: "authorization_code"
    });

    const response = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params.toString()
    });

    const data = await response.json();
    if (!response.ok) {
      console.error("Google token exchange error:", data);
      return res.status(400).json(data);
    }

    res.json(data);
  } catch (err) {
    console.error("Callback error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ===================== 6. Sheets proxy =====================
app.get("/sheets/:id", async (req, res) => {
  const { id } = req.params;
  const accessToken = process.env.GOOGLE_ACCESS_TOKEN;
  if (!accessToken) return res.status(500).json({ error: "GOOGLE_ACCESS_TOKEN not set" });

  const options = {
    hostname: "sheets.googleapis.com",
    path: `/v4/spreadsheets/${id}`,
    method: "GET",
    headers: { Authorization: `Bearer ${accessToken}` }
  };

  const proxyReq = https.request(options, (proxyRes) => {
    let data = "";
    proxyRes.on("data", (chunk) => (data += chunk));
    proxyRes.on("end", () => {
      try {
        res.json(JSON.parse(data));
      } catch {
        res.status(500).json({ error: "Invalid sheet response" });
      }
    });
  });

  proxyReq.on("error", (err) => res.status(500).json({ error: err.message }));
  proxyReq.end();
});

module.exports = app;
