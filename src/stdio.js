// src/stdio.js
// Sentinel MCP Server - Stdio transport (for Claude Code / CLI clients)

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { ALL_TOOLS } from "./tools/registry.js";

const server = new McpServer({
  name: "sentinel",
  version: "1.0.0",
  description: "Self-hosted security testing MCP server - no credits, no limits",
});

for (const tool of ALL_TOOLS) {
  server.tool(tool.name, tool.description, tool.schema, async (args) => {
    try {
      return await tool.execute(args);
    } catch (err) {
      return {
        content: [{ type: "text", text: `Error running ${tool.name}: ${err.message}` }],
      };
    }
  });
}

const transport = new StdioServerTransport();
await server.connect(transport);
