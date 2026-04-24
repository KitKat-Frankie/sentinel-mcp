// src/server.js
// Sentinel MCP Server - HTTP/SSE transport

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import express from "express";
import { ALL_TOOLS } from "./tools/registry.js";

const PORT = process.env.PORT || 3001;
const HOST = process.env.HOST || "0.0.0.0";
const AUTH_TOKEN = process.env.MCP_AUTH_TOKEN || "";

function createServer() {
  const server = new McpServer({
    name: "sentinel",
    version: "1.0.0",
    description: "Self-hosted security testing MCP server - no credits, no limits",
  });

  for (const tool of ALL_TOOLS) {
    server.tool(tool.name, tool.description, tool.schema, async (args) => {
      console.log(`[sentinel] > ${tool.name}`, JSON.stringify(args).slice(0, 200));
      const start = Date.now();
      try {
        const result = await tool.execute(args);
        const elapsed = ((Date.now() - start) / 1000).toFixed(1);
        console.log(`[sentinel] done ${tool.name} in ${elapsed}s`);
        return result;
      } catch (err) {
        console.error(`[sentinel] error ${tool.name}:`, err.message);
        return {
          content: [{ type: "text", text: `Error running ${tool.name}: ${err.message}` }],
        };
      }
    });
  }

  return server;
}

const app = express();

if (AUTH_TOKEN) {
  app.use((req, res, next) => {
    if (req.path === "/health") return next();
    const token = req.headers.authorization?.replace("Bearer ", "");
    if (token !== AUTH_TOKEN) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    next();
  });
}

app.get("/health", (_req, res) => {
  res.json({
    status: "ok",
    server: "sentinel",
    version: "1.0.0",
    tools: ALL_TOOLS.length,
    uptime: process.uptime(),
  });
});

app.get("/tools", (_req, res) => {
  res.json(
    ALL_TOOLS.map((t) => ({
      name: t.name,
      description: t.description,
      category: t.category,
    }))
  );
});

const transports = {};

app.get("/sse", async (req, res) => {
  const transport = new SSEServerTransport("/messages", res);
  transports[transport.sessionId] = transport;
  const server = createServer();
  res.on("close", () => {
    delete transports[transport.sessionId];
    server.close();
  });
  await server.connect(transport);
});

app.post("/messages", async (req, res) => {
  const sessionId = req.query.sessionId;
  const transport = transports[sessionId];
  if (!transport) {
    return res.status(404).json({ error: "Session not found" });
  }
  await transport.handlePostMessage(req, res);
});

app.listen(PORT, HOST, () => {
  console.log(`\nSENTINEL MCP - http://${HOST}:${PORT}`);
  console.log(`MCP endpoint: http://${HOST}:${PORT}/sse`);
  console.log(`Tools: ${ALL_TOOLS.length} registered`);
  console.log(`Auth: ${AUTH_TOKEN ? "enabled" : "disabled"}\n`);

  const categories = {};
  for (const t of ALL_TOOLS) {
    (categories[t.category] ??= []).push(t.name);
  }
  for (const [cat, tools] of Object.entries(categories)) {
    console.log(`  ${cat}: ${tools.join(", ")}`);
  }
  console.log();
});
