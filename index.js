const express = require('express');
const https = require('https');

const app = express();
app.use(express.json());

// -----------------------------------------------------------------------------
// MCP manifest — OpenAI MCP specification
// -----------------------------------------------------------------------------
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

// GET manifest
app.get('/.well-known/mcp/manifest.json', (req, res) => {
  res.set('Content-Type', 'application/json; charset=utf-8');
  res.json(manifest);
});

// HEAD manifest (возвращает тело “OK”, чтобы Vercel не отдал 404)
app.head('/.well-known/mcp/manifest.json', (req, res) => {
  res.set('Content-Type', 'application/json; charset=utf-8');
  res.status(200).send('OK');
});

// -----------------------------------------------------------------------------
// OAuth Authorization Server Metadata (RFC 8414)
// -----------------------------------------------------------------------------
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
  res.status(200).send('OK');
});

// -----------------------------------------------------------------------------
// OAuth Protected Resource Metadata (RFC 9728)
// -----------------------------------------------------------------------------
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
  res.status(200).send('OK');
});

// -----------------------------------------------------------------------------
// OAuth dynamic client registration (RFC 7591)
// -----------------------------------------------------------------------------
app.post('/oauth/register', (req, res) => {
  const { redirect_uris, response_types, grant_types, token_endpoint_auth_method } = req.body || {};
  const requiredRedirect = 'https://chatgpt.com/connector_platform_oauth_redirect';
  if (!Array.isArray(redirect_uris) || !redirect_uris.includes(requiredRedirect)) {
    return res.status(400).json({ error: 'Invalid redirect URIs' });
  }
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
// OAuth authorization and token endpoints (stubs for ChatGPT validation)
// -----------------------------------------------------------------------------
app.get('/oauth/authorize', (req, res) => {
  res.status(200).send('Authorization endpoint alive');
});

app.post('/oauth/token', (req, res) => {
  res.set('Content-Type', 'application/json; charset=utf-8');
  res.json({
    access_token: 'dummy-token',
    token_type: 'Bearer',
    expires_in: 3600
  });
});

// -----------------------------------------------------------------------------
// Google Sheets proxy (optional production use)
// -----------------------------------------------------------------------------
app.get('/sheets/:id', async (req, res) => {
  const { id } = req.params;
  const accessToken = process.env.GOOGLE_ACCESS_TOKEN;
  if (!accessToken) {
    return res.status(500).json({ error: 'GOOGLE_ACCESS_TOKEN not set' });
  }
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
// Server startup
// -----------------------------------------------------------------------------
const port = process.env.PORT || 3000;
if (require.main === module) {
  app.listen(port, () => {
    console.log(`✅ GoodSeeds MCP connector running on port ${port}`);
  });
}

module.exports = app;
