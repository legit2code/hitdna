import { Express, Request, Response } from "express";
import { ServiceContainer } from "../services/container.ts";
import { requireDiagnosticAccess } from "../middleware/security.ts";
import {
  SyntaxIntelligencePipeline,
  ParserRegistry,
  EncodingDetector,
  ProtocolDetector,
  FrameworkDetector,
  ConfigExtractor,
} from "@caim/syntax";

export function registerSyntaxRoutes(app: Express, _container: ServiceContainer) {
  app.post("/api/dev/syntax/inspect-file", requireDiagnosticAccess, (req: Request, res: Response) => {
    try {
      const { path: filePath, content } = req.body || {};
      if (!filePath || content === undefined) {
        return res.status(400).json({ error: "Missing 'path' or 'content' in request body" });
      }
      const fileType = EncodingDetector.detect(filePath, content);
      const facts = ParserRegistry.parseFile(filePath, content, fileType);
      res.json(facts);
    } catch (err: any) {
      res.status(500).json({ error: err.message || "File syntax inspection failed" });
    }
  });

  app.post("/api/dev/syntax/process-artifact", requireDiagnosticAccess, (req: Request, res: Response) => {
    try {
      const { artifact_id, files } = req.body || {};
      if (!files || !Array.isArray(files)) {
        return res.status(400).json({ error: "Missing 'files' array in request body" });
      }
      const artId = artifact_id || `artifact-${Date.now()}`;
      const result = SyntaxIntelligencePipeline.processArtifact(artId, files);
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message || "Artifact processing failed" });
    }
  });

  app.get("/api/dev/syntax/sample-fixtures", requireDiagnosticAccess, (_req: Request, res: Response) => {
    if (process.env.NODE_ENV === "production") {
      return res.status(403).json({ error: "Fixture endpoints are strictly disabled in production mode." });
    }
    res.json({
      mcp_agent: {
        path: "agent/mcp_server.ts",
        content: `import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { ListToolsRequestSchema, CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { OpenAI } from "openai";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

const server = new Server(
  { name: "memory-analyst-mcp", version: "1.2.0" },
  { capabilities: { tools: {}, prompts: {} } }
);

server.tool("query_knowledge_base", "Queries knowledge vectors", async (args: { query: string }) => {
  const model = "gpt-4o";
  const temp = 0.2;
  return { content: [{ type: "text", text: "Knowledge vector result" }] };
});

const transport = new StdioServerTransport();
await server.connect(transport);`
      },
      python_agent: {
        path: "src/autogen_agent.py",
        content: `import os
from autogen import ConversableAgent, UserProxyAgent
from langchain_core.tools import tool
import requests

API_TOKEN = os.getenv("AUTOGEN_API_TOKEN", "default-dev-token")

@tool
def fetch_financial_metrics(ticker: str) -> dict:
    """Fetches real-time stock ticker fundamentals and SEC filings."""
    url = f"https://api.marketdata.com/v1/{ticker}"
    response = requests.get(url, headers={"Authorization": f"Bearer {API_TOKEN}"})
    return response.json()

assistant = ConversableAgent(
    name="FinancialAnalyst",
    system_message="You are a senior financial analyst analyzing SEC 10-K filings.",
    llm_config={"model": "claude-3-5-sonnet", "temperature": 0.1, "max_tokens": 4096}
)`
      },
      go_service: {
        path: "cmd/gateway/main.go",
        content: `package main

import (
	"context"
	"net/http"
	"os"
	"github.com/gin-gonic/gin"
)

type GatewayServer struct {
	Port string
}

func (s *GatewayServer) HandleAgentProxy(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "proxied"})
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	r := gin.Default()
	server := &GatewayServer{Port: port}
	r.POST("/api/v1/agent/invoke", server.HandleAgentProxy)
	r.Run(":" + port)
}`
      },
      dockerfile: {
        path: "Dockerfile",
        content: `FROM python:3.11-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1
ENV MODEL_ENDPOINT=https://models.internal.net
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost:8000/health || exit 1
ENTRYPOINT ["python", "main.py"]`
      }
    });
  });

  // 16. P15 — Static Analysis & Control Flow Engine

}
