// Comprehensive error handling utilities for Supabase Storage MCP

import { SecurityError, ValidationError, SecurityContext, SecuritySeverity } from '../modules/types.js';

export function getErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  if (typeof error === 'string') {
    return error;
  }
  return 'An unknown error occurred';
}

export function createSecurityError(
  message: string,
  code: string,
  severity: SecuritySeverity = 'medium',
  context?: SecurityContext,
  riskScore?: number
): SecurityError {
  const error = new Error(message) as SecurityError;
  error.name = 'SecurityError';
  error.code = code;
  error.severity = severity;
  error.context = context;
  error.riskScore = riskScore;
  return error;
}

export function createValidationError(
  message: string,
  field: string,
  value: any,
  rule: string,
  context?: string
): ValidationError {
  const error = new Error(message) as ValidationError;
  error.name = 'ValidationError';
  error.field = field;
  error.value = value;
  error.rule = rule;
  error.context = context;
  return error;
}

export function isSecurityError(error: unknown): error is SecurityError {
  return error instanceof Error && error.name === 'SecurityError';
}

export function isValidationError(error: unknown): error is ValidationError {
  return error instanceof Error && error.name === 'ValidationError';
}

export function formatSecurityError(error: SecurityError): string {
  let message = `[${error.severity.toUpperCase()}] ${error.code}: ${error.message}`;
  
  if (error.context) {
    message += `\nContext: ${error.context.toolName || 'unknown'} from ${error.context.ipAddress}`;
  }
  
  if (error.riskScore !== undefined) {
    message += `\nRisk Score: ${error.riskScore}`;
  }
  
  return message;
}

export function formatValidationError(error: ValidationError): string {
  let message = `Validation failed for field '${error.field}': ${error.message}`;
  
  if (error.context) {
    message += `\nContext: ${error.context}`;
  }
  
  message += `\nValue: ${JSON.stringify(error.value)}`;
  message += `\nRule: ${error.rule}`;
  
  return message;
}

export function handleToolError(error: unknown, toolName: string, context?: SecurityContext): {
  content: Array<{ type: string; text: string }>;
  isError: boolean;
} {
  let errorMessage: string;
  let errorCode = 'unknown_error';
  let severity: SecuritySeverity = 'medium';

  if (isSecurityError(error)) {
    errorMessage = formatSecurityError(error);
    errorCode = error.code;
    severity = error.severity;
  } else if (isValidationError(error)) {
    errorMessage = formatValidationError(error);
    errorCode = 'validation_error';
    severity = 'low';
  } else {
    errorMessage = `Error in ${toolName}: ${getErrorMessage(error)}`;
  }

  // Log error for debugging
  console.error(`[ERROR] ${toolName}:`, {
    error: errorMessage,
    code: errorCode,
    severity,
    context: context ? {
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
      requestId: context.requestId
    } : null
  });

  return {
    content: [
      {
        type: 'text',
        text: errorMessage
      }
    ],
    isError: true
  };
}

export function createMCPResponse(
  success: boolean,
  data: any,
  error?: unknown,
  toolName?: string,
  context?: SecurityContext
): {
  content: Array<{ type: string; text: string }>;
  isError?: boolean;
} {
  if (success) {
    return {
      content: [
        {
          type: 'text',
          text: typeof data === 'string' ? data : JSON.stringify(data, null, 2)
        }
      ]
    };
  } else {
    return handleToolError(error, toolName || 'unknown', context);
  }
}

export function validateEnvironmentVariable(
  name: string,
  value: string | undefined,
  required: boolean = true
): string {
  if (required && (!value || value.trim() === '')) {
    throw createValidationError(
      `Missing required environment variable: ${name}`,
      name,
      value,
      'required',
      'environment configuration'
    );
  }
  
  return value || '';
}

export function validateSupabaseConfig(config: {
  url?: string;
  serviceKey?: string;
}): { url: string; serviceKey: string } {
  const url = validateEnvironmentVariable('SUPABASE_URL', config.url);
  const serviceKey = validateEnvironmentVariable('SUPABASE_SERVICE_KEY', config.serviceKey);
  
  // Validate URL format
  try {
    new URL(url);
  } catch {
    throw createValidationError(
      'Invalid Supabase URL format',
      'SUPABASE_URL',
      url,
      'url_format',
      'environment configuration'
    );
  }
  
  // Validate service key format (basic check)
  if (serviceKey.length < 50) {
    throw createValidationError(
      'Supabase service key appears to be invalid (too short)',
      'SUPABASE_SERVICE_KEY',
      serviceKey.substring(0, 10) + '...',
      'key_length',
      'environment configuration'
    );
  }
  
  return { url, serviceKey };
}

export class ErrorCounter {
  private errorCounts: Map<string, number> = new Map();
  private errorHistory: Array<{ timestamp: number; error: string; severity: SecuritySeverity }> = [];
  private maxHistorySize: number = 1000;

  recordError(error: unknown, context?: string): void {
    const errorKey = this.getErrorKey(error, context);
    const currentCount = this.errorCounts.get(errorKey) || 0;
    this.errorCounts.set(errorKey, currentCount + 1);

    const severity = isSecurityError(error) ? error.severity : 'low';
    this.errorHistory.push({
      timestamp: Date.now(),
      error: errorKey,
      severity
    });

    // Maintain history size
    if (this.errorHistory.length > this.maxHistorySize) {
      this.errorHistory = this.errorHistory.slice(-this.maxHistorySize);
    }
  }

  getErrorCount(error: unknown, context?: string): number {
    const errorKey = this.getErrorKey(error, context);
    return this.errorCounts.get(errorKey) || 0;
  }

  getErrorStats(): {
    totalErrors: number;
    uniqueErrors: number;
    recentErrors: number;
    severityBreakdown: Record<SecuritySeverity, number>;
  } {
    const now = Date.now();
    const oneHourAgo = now - (60 * 60 * 1000);
    
    const recentErrors = this.errorHistory.filter(e => e.timestamp > oneHourAgo);
    const severityBreakdown: Record<SecuritySeverity, number> = {
      low: 0,
      medium: 0,
      high: 0,
      critical: 0
    };

    this.errorHistory.forEach(error => {
      severityBreakdown[error.severity]++;
    });

    return {
      totalErrors: this.errorHistory.length,
      uniqueErrors: this.errorCounts.size,
      recentErrors: recentErrors.length,
      severityBreakdown
    };
  }

  private getErrorKey(error: unknown, context?: string): string {
    const baseKey = getErrorMessage(error);
    return context ? `${context}:${baseKey}` : baseKey;
  }

  reset(): void {
    this.errorCounts.clear();
    this.errorHistory = [];
  }
}

// Global error counter instance
export const globalErrorCounter = new ErrorCounter();