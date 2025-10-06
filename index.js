import express from "express";
import fetch from "node-fetch";

const app = express();
app.use(express.json());

// MCP manifest
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

// Simple proxy example: read spreadsheet values
app.get("/sheets/:id", async (req, res) => {
  const { id } = req.params;
  const accessToken = req.headers.authorization?.split(" ")[1];
  const r = await fetch(
    `https://sheets.googleapis.com/v4/spreadsheets/${id}`,
    { headers: { Authorization: `Bearer ${accessToken}` } }
  );
  res.json(await r.json());
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on ${PORT}`));
