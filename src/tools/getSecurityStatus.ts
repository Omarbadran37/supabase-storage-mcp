import {
  SECURITY_CONFIG,
  getAuditLog,
  getRateLimitStoreSize
} from '../modules/security.js';
import { SecurityStatusResponse } from '../modules/types.js';

export const getSecurityStatusDefinition = {
  name: 'get_security_status',
  description: 'Get current security configuration and audit information',
  inputSchema: {
    type: 'object',
    properties: {},
    additionalProperties: false
  }
};

export async function handleGetSecurityStatus() {
  const auditLog = getAuditLog();
  const securityStatus: SecurityStatusResponse = {
    security_config: SECURITY_CONFIG,
    rate_limit_status: {
      active_limits: getRateLimitStoreSize(),
      current_window: SECURITY_CONFIG.RATE_LIMIT_WINDOW
    },
    audit_log: {
      total_entries: auditLog.length,
      recent_entries: auditLog.slice(-10).map(entry => ({
        timestamp: new Date(entry.timestamp).toISOString(),
        tool: entry.toolName,
        success: entry.success,
        error: entry.error || 'none'
      }))
    },
    server_info: {
      name: 'supabase-storage-mcp',
      version: '1.0.0',
      uptime: process.uptime(),
      node_version: process.version
    }
  };

  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify(securityStatus, null, 2)
      }
    ]
  };
}
