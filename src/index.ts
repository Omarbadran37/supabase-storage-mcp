#!/usr/bin/env node

// Supabase Storage MCP Server - Main Entry Point
// Enhanced security features and batch operations for file management

import 'dotenv/config';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import crypto from 'crypto';
import { createClient, SupabaseClient } from '@supabase/supabase-js';
import { getErrorMessage } from './utils/error-handling.js';
import { toolDefinitions, toolHandlers } from './tools/index.js';
import { checkRateLimit, auditRequest, generateSecureHash } from './modules/security.js';

// MCP Server Setup
const server = new Server(
  {
    name: 'supabase-storage-mcp',
    version: '1.0.0',
    description: 'Supabase Storage MCP Server with enhanced security features and batch operations'
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Initialize Supabase client
const supabase = createClient(
  process.env.SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_KEY!,
  {
    auth: {
      persistSession: false,
      autoRefreshToken: false
    }
  }
);

// Tool Registration with proper MCP SDK syntax
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: toolDefinitions,
  };
});

// Main request handler with security and modular dispatch
server.setRequestHandler(CallToolRequestSchema, async (request: any) => {
  const { name, arguments: args } = request.params;
  const requestId = crypto.randomUUID();
  const startTime = Date.now();
  
  // Rate limiting check
  const rateLimitCheck = checkRateLimit('global');
  if (!rateLimitCheck.allowed) {
    auditRequest(name, false, generateSecureHash(JSON.stringify(args)), `Rate limit exceeded. Retry after ${rateLimitCheck.retryAfter}s`);
    throw new Error(`Rate limit exceeded. Please try again in ${rateLimitCheck.retryAfter} seconds.`);
  }

  try {
    const handler = toolHandlers[name];
    if (!handler) {
      throw new Error(`Unknown tool: ${name}`);
    }

    // The 'get_security_status' tool has a different signature.
    if (name === 'get_security_status') {
      return await (handler as () => Promise<any>)();
    } else {
      return await (handler as (
        supabase: SupabaseClient,
        args: any,
        requestId: string,
        startTime: number
      ) => Promise<any>)(supabase, args, requestId, startTime);
    }
  } catch (error) {
    return {
      content: [
        {
          type: 'text',
          text: `Error: ${getErrorMessage(error)}`
        }
      ],
      isError: true
    };
  }
});

// Start the server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('Supabase Storage MCP Server running on stdio');
}

main().catch((error) => {
  console.error('Failed to start server:', getErrorMessage(error));
  process.exit(1);
});