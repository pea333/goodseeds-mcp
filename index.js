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
      client_id: "930233734207-qp010p8gj8tc9emhbanjeca93rrne8f6.apps.googleusercontent.com",
      client_secret: "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",
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

// === 3. Example proxy for reading sheet ===
app.get("/sheets/:id", async (req, res) => {
  const { id } = req.params;
  const accessToken = req.headers.authorization?.split(" ")[1];
  if (!accessToken) return res.status(401).json({ error: "Missing token" });

  const response = await fetch(
    `https://sheets.googleapis.com/v4/spreadsheets/${id}/values/Sheet1!A1:D10`,
    {
      headers: { Authorization: `Bearer ${accessToken}` },
    }
  );

  const data = await response.json();
  res.json(data);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`MCP server running on port ${PORT}`));
