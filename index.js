import express from "express";
import fetch from "node-fetch";

const app = express();
app.use(express.json());

// === 1. MCP manifest ===
app.get("/.well-known/mcp/manifest.json", (req, res) => {
  res.json({
    name: "GoodSeeds Google Sheets Connector",
    version: "1.0.0",
    authentication: {
      type: "oauth",
      authorization_url: "https://accounts.google.com/o/oauth2/auth",
      token_url: "https://oauth2.googleapis.com/token",
      scopes: [
        "https://www.googleapis.com/auth/spreadsheets",
        "https://www.googleapis.com/auth/drive"
      ]
    }
  });
});

// === 2. OAuth discovery endpoint ===
app.get("/.well-known/oauth-authorization-server", (req, res) => {
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

// === 3. OAuth callback (ChatGPT expects it exists) ===
app.get("/oauth/callback", (req, res) => {
  res.send("OAuth callback received. You can close this tab.");
});

// === 4. Example: read Google Sheet data ===
app.get("/sheets/:id", async (req, res) => {
  const sheetId = req.params.id;
  const response = await fetch(`https://sheets.googleapis.com/v4/spreadsheets/${sheetId}`);
  const data = await response.json();
  res.json(data);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ GoodSeeds MCP running on port ${PORT}`));
// === 6. Root MCP manifest for ChatGPT autodetect ===
app.get("/.well-known/mcp/manifest.json", (req, res) => {
  res.json({
    name: "GoodSeeds Sheets MCP",
    version: "1.0.0",
    description: "Google Sheets connector for Good Seeds production planning",
    authentication: {
      type: "oauth",
      authorization_url: "https://accounts.google.com/o/oauth2/auth",
      token_url: "https://oauth2.googleapis.com/token",
      scopes: [
        "https://www.googleapis.com/auth/spreadsheets",
        "https://www.googleapis.com/auth/drive"
      ]
    },
    endpoints: {
      oauth_discovery: "https://goodseeds-mcp.vercel.app/.well-known/oauth-authorization-server"
    }
  });
});
