import express from "express";
import fetch from "node-fetch";

const app = express();
app.use(express.json());

// === CORS (чтобы ChatGPT мог обращаться к серверу) ===
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization");
  next();
});

// === 1. MCP manifest ===
app.get("/.well-known/mcp/manifest.json", (req, res) => {
  console.log("GET /.well-known/mcp/manifest.json");
  res.json({
    name: "GoodSeeds Google Sheets Connector",
    version: "1.0.0",
    authentication: {
      type: "oauth",
      authorization_url: "https://accounts.google.com/o/oauth2/auth",
      token_url: "https://oauth2.googleapis.com/token",
      client_id: "930233734207-qp010p8gj8tc9emhbanjeca93rrne8f6.apps.googleusercontent.com",
      client_secret: "GOCSPX-IhmUaQVLmZvPHEhGnHLARjgWlN-",
      scopes: [
        "https://www.googleapis.com/auth/spreadsheets",
        "https://www.googleapis.com/auth/drive"
      ]
    },
    oauth_server: "https://goodseeds-mcp.vercel.app/.well-known/oauth-authorization-server",
    description: "MCP connector for accessing Google Sheets through ChatGPT",
    contact_email: "nik@goodseeds.ru",
"terms_of_service_url": "https://goodseeds.ru/connector-terms",
"privacy_policy_url": "https://goodseeds.ru/page84131506.html"
  });
});

// === 2. OAuth discovery endpoint ===
app.get("/.well-known/oauth-authorization-server", (req, res) => {
  console.log("GET /.well-known/oauth-authorization-server");
  res.json({
    issuer: "https://accounts.google.com",
    authorization_endpoint: "https://accounts.google.com/o/oauth2/auth",
    token_endpoint: "https://oauth2.googleapis.com/token",
    scopes_supported: [
      "https://www.googleapis.com/auth/spreadsheets",
      "https://www.googleapis.com/auth/drive"
    ]
  });
});

// === 3. OpenID configuration endpoint ===
app.get("/.well-known/openid-configuration", (req, res) => {
  console.log("GET /.well-known/openid-configuration");
  res.json({
    issuer: "https://accounts.google.com",
    authorization_endpoint: "https://accounts.google.com/o/oauth2/auth",
    token_endpoint: "https://oauth2.googleapis.com/token",
    scopes_supported: [
      "https://www.googleapis.com/auth/spreadsheets",
      "https://www.googleapis.com/auth/drive"
    ],
    response_types_supported: ["code", "token"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"]
  });
});

// === 4. Example proxy for reading a sheet ===
app.get("/sheets/:id", async (req, res) => {
  const { id } = req.params;
  const accessToken = req.headers.authorization?.split(" ")[1];

  if (!accessToken) {
    console.warn("Missing access token in /sheets/:id");
    return res.status(401).json({ error: "Missing token" });
  }

  try {
    const response = await fetch(
      `https://sheets.googleapis.com/v4/spreadsheets/${id}/values/Sheet1!A1:D10`,
      {
        headers: { Authorization: `Bearer ${accessToken}` },
      }
    );

    const data = await response.json();
    res.json(data);
  } catch (err) {
    console.error("Error fetching Google Sheets data:", err);
    res.status(500).json({ error: "Failed to fetch data from Google Sheets" });
  }
});

// === 5. Start server ===
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ MCP server running on port ${PORT}`));
