import express from "express";
import fetch from "node-fetch";

const app = express();
app.use(express.json());

// 🔹 MCP manifest endpoint
app.get("/.well-known/mcp/manifest.json", (req, res) => {
  res.json({
    name: "GoodSeeds Google Sheets Connector",
    version: "1.0.1",
    description: "MCP-compatible proxy for Google Sheets API",
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

// 🔹 OAuth 2.0 metadata endpoint (MCP expects this)
app.get("/.well-known/oauth-authorization-server", (req, res) => {
  res.json({
    authorization_endpoint: "https://accounts.google.com/o/oauth2/auth",
    token_endpoint: "https://oauth2.googleapis.com/token",
    scopes_supported: [
      "https://www.googleapis.com/auth/spreadsheets",
      "https://www.googleapis.com/auth/drive"
    ]
  });
});

// 🔹 Simple proxy to Google Sheets API
app.get("/sheets/:id", async (req, res) => {
  const { id } = req.params;
  const accessToken = req.headers.authorization?.split(" ")[1];

  if (!accessToken) {
    return res.status(401).json({ error: "Missing Authorization header" });
  }

  try {
    const response = await fetch(
      `https://sheets.googleapis.com/v4/spreadsheets/${id}`,
      { headers: { Authorization: `Bearer ${accessToken}` } }
    );
    const data = await response.json();
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch from Google Sheets API", details: err.message });
  }
});

// 🔹 Default route
app.get("/", (req, res) => {
  res.send("✅ GoodSeeds MCP server is running.");
});

// 🔹 Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
