const express = require('express');
const https = require('https');

//
// This file implements a simple OAuth‑enabled MCP connector for ChatGPT.
//
// The server exposes several well‑known endpoints under the `.well‑known`
// path which comply with Model Context Protocol (MCP) specifications as
// published by OpenAI, as well as OAuth 2.0 metadata standards RFC 8414
// and OAuth Protected Resource Metadata RFC 9728.  These endpoints
// advertise how ChatGPT can authenticate with this service, discover
// authorization endpoints and supported scopes, and dynamically register
// as a client.  See `README.md` or the OpenAI documentation for more
// details.

const app = express();

// Enable JSON parsing for POST bodies
app.use(express.json());

// -----------------------------------------------------------------------------
// MCP manifest
//
// ChatGPT looks up a manifest file to understand how to talk to this
// connector.  The manifest must be served under
// `/.well-known/mcp/manifest.json` and contain the fields described in the
// specification.  In particular, the `authentication` property MUST be an
// array of authentication methods.  For OAuth, the object must include a
// `type` of "oauth", the `oauth_server` pointing at our own OAuth discovery
// endpoint, and a list of `scopes` requested from the user.  Terms of
// service and privacy policy URLs and a contact email are also provided.
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
  privacy_policy_url: "https://goodseeds.ru/connector-privacy.html",
  contact: "nik@goodseeds.ru"
};

// Serve the manifest for GET requests
app.get('/.well-known/mcp/manifest.json', (req, res) => {
  res.set('Content-Type', 'application/json; charset=utf-8');
  res.json(manifest);
});

// Respond to HEAD requests on the manifest path with a 200 and no body
app.head('/.well-known/mcp/manifest.json', (req, res) => {
  res.set('Content-Type', 'application/json; charset=utf-8');
  res.status(200).end();
});

// -----------------------------------------------------------------------------
// OAuth Authorization Server Metadata (RFC 8414)
//
// This endpoint advertises the metadata for our authorization server.  Clients
// use it to discover the correct endpoints for user authorization, token
// issuance and dynamic client registration.  The issuer must match the fully
// qualified origin of this deployment and the endpoints must be absolute
// URLs.  We support PKCE (code challenge method S256) and public clients
// (token_endpoint_auth_methods_supported = ["none"]).
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

app.get('/.well-known/oauth-authorization-server', (req, res) => {
  res.set('Content-Type', 'application/json; charset=utf-8');
  res.json(oauthMetadata);
});

app.head('/.well-known/oauth-authorization-server', (req, res) => {
  res.set('Content-Type', 'application/json; charset=utf-8');
  res.status(200).end();
});

// -----------------------------------------------------------------------------
// OAuth Protected Resource Metadata (RFC 9728)
//
// While not strictly required by the MCP spec, OpenAI recommends exposing
// protected resource metadata for OAuth resource servers.  This document
// describes which authorization servers can issue tokens for this resource and
// which scopes are understood.  Clients such as ChatGPT use it during the
// discovery process to understand how to access the protected API.
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

app.get('/.well-known/oauth-protected-resource', (req, res) => {
  res.set('Content-Type', 'application/json; charset=utf-8');
  res.json(protectedResourceMetadata);
});

app.head('/.well-known/oauth-protected-resource', (req, res) => {
  res.set('Content-Type', 'application/json; charset=utf-8');
  res.status(200).end();
});

// -----------------------------------------------------------------------------
// Dynamic client registration (RFC 7591)
//
// ChatGPT uses dynamic registration to obtain a client_id for our AS.  We
// accept a JSON body describing the client and verify that it includes the
// required redirect URI pointing back to ChatGPT.  We do not issue a
// client_secret since ChatGPT acts as a public client using PKCE.  This
// endpoint returns a 201 Created status with the registered client metadata.
app.post('/oauth/register', (req, res) => {
  const { redirect_uris, response_types, grant_types, token_endpoint_auth_method } = req.body || {};
  // Enforce that the redirect URI for ChatGPT is present
  const requiredRedirect = 'https://chatgpt.com/connector_platform_oauth_redirect';
  if (!Array.isArray(redirect_uris) || !redirect_uris.includes(requiredRedirect)) {
    return res.status(400).json({ error: 'Invalid redirect URIs' });
  }
  // Build a simple public client record
  const clientId = `goodseeds-chatgpt`;
  const client = {
    client_id: clientId,
    client_id_issued_at: Math.floor(Date.now() / 1000),
    redirect_uris,
    token_endpoint_auth_method: token_endpoint_auth_method || 'none',
    response_types: response_types || ['code'],
    grant_types: grant_types || ['authorization_code', 'refresh_token']
  };
  res.status(201).json(client);
});

// -----------------------------------------------------------------------------
// Sheets proxy
//
// This endpoint proxies requests to the Google Sheets API.  It expects a
// spreadsheet ID in the path and forwards the request to the Google API,
// passing along an OAuth access token via the Authorization header.  The
// access token should be obtained through the OAuth flow and stored in
// process.env.GOOGLE_ACCESS_TOKEN or provided via another mechanism.  In
// practice, you would implement proper token storage and refresh logic.
//
// WARNING: This implementation relies on the `node-fetch` module.  When
// deploying to Vercel, ensure that `node-fetch` is available either as a
// dependency or built‑in.  If you prefer to avoid external dependencies you
// can replace this with the native `https` module.
app.get('/sheets/:id', async (req, res) => {
  const { id } = req.params;
  const accessToken = process.env.GOOGLE_ACCESS_TOKEN;
  if (!accessToken) {
    return res.status(500).json({ error: 'GOOGLE_ACCESS_TOKEN not set' });
  }
  // Build options for the HTTPS request
  const options = {
    hostname: 'sheets.googleapis.com',
    path: `/v4/spreadsheets/${id}`,
    method: 'GET',
    headers: {
      Authorization: `Bearer ${accessToken}`
    }
  };
  const proxyReq = https.request(options, (proxyRes) => {
    let rawData = '';
    proxyRes.setEncoding('utf8');
    proxyRes.on('data', (chunk) => { rawData += chunk; });
    proxyRes.on('end', () => {
      try {
        const json = JSON.parse(rawData);
        res.json(json);
      } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Failed to parse sheet response' });
      }
    });
  });
  proxyReq.on('error', (err) => {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch sheet' });
  });
  proxyReq.end();
});

// -----------------------------------------------------------------------------
// Start the server
//
// Vercel will automatically handle routing and function invocation.  When
// running locally (e.g. for development), you can specify a PORT environment
// variable or default to 3000.
const port = process.env.PORT || 3000;
if (require.main === module) {
  app.listen(port, () => {
    console.log(`MCP connector listening on port ${port}`);
  });
}

module.exports = app;
