// Comprehensive Security Module for Supabase Storage MCP

import crypto from 'crypto';
import {
  SecurityConfig,
  RateLimitResult,
  RateLimitWindow,
  PromptInjectionResult,
  PIIDetectionResult,
  AuditEntry,
  SecurityContext,
  SecurityValidationResult,
  SuspiciousActivityResult,
  SecurityEvent
} from './types.js';

// Security Configuration
export const SECURITY_CONFIG: SecurityConfig = {
  ENABLE_RATE_LIMITING: true,
  ENABLE_THREAT_DETECTION: true,
  ENABLE_AUDIT_LOGGING: true,
  ENABLE_INPUT_VALIDATION: true,
  ENABLE_FILE_SECURITY: true,
  
  // Rate limiting configuration
  RATE_LIMIT_WINDOW: 60000, // 1 minute
  MAX_REQUESTS_PER_WINDOW: 100,
  GLOBAL_RATE_LIMIT: 1000,
  IP_RATE_LIMIT: 200,
  USER_RATE_LIMIT: 500,
  
  // File security limits
  MAX_FILE_SIZE: 50 * 1024 * 1024, // 50MB
  MAX_BATCH_SIZE: 500,
  ALLOWED_MIME_TYPES: [
    'image/jpeg', 'image/jpg', 'image/png', 'image/webp', 
    'image/gif', 'image/svg+xml', 'image/bmp', 'image/tiff',
    'application/zip', 'application/x-zip-compressed'
  ],
  
  // Security thresholds
  MAX_PROMPT_LENGTH: 10000,
  SUSPICIOUS_ACTIVITY_THRESHOLD: 5,
  HIGH_RISK_SCORE_THRESHOLD: 80,
  
  // Session and authentication
  SESSION_TIMEOUT: 3600, // 1 hour
  JWT_EXPIRY: 7200 // 2 hours
};

// Storage for rate limiting and audit logs
const rateLimitStore = new Map<string, RateLimitWindow>();
const suspiciousActivityStore = new Map<string, { count: number; lastSeen: number }>();
const auditLog: AuditEntry[] = [];
const securityEvents: SecurityEvent[] = [];
const blockedIPs = new Set<string>();

// Security metrics
let securityMetrics = {
  promptInjectionsDetected: 0,
  rateLimitViolations: 0,
  suspiciousActivities: 0,
  blockedRequests: 0,
  threatDetections: 0,
  pathTraversalAttempts: 0,
  invalidFileAttempts: 0
};

// Utility functions
export function generateSecureHash(data: string): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

export function generateSecureId(length: number = 32): string {
  return crypto.randomBytes(length).toString('hex');
}

export function sanitizeInput(input: string): string {
  if (typeof input !== 'string') return String(input);
  
  return input
    .replace(/<script[^>]*>.*?<\/script>/gi, '')
    .replace(/<[^>]*>/g, '')
    .replace(/javascript:/gi, '')
    .replace(/data:text\/html/gi, '')
    .replace(/[\x00-\x1f\x7f-\x9f]/g, '') // Remove control characters
    .replace(/[<>:"|?*]/g, '') // Remove filesystem dangerous chars
    .substring(0, SECURITY_CONFIG.MAX_PROMPT_LENGTH)
    .trim();
}

export function detectPromptInjection(input: string): PromptInjectionResult {
  const injectionPatterns = [
    // Direct instruction override
    { name: 'ignore_previous', regex: /ignore\s+(all\s+)?previous\s+instructions/i, weight: 20 },
    { name: 'forget_instructions', regex: /forget\s+(all\s+)?(previous\s+)?instructions/i, weight: 20 },
    { name: 'new_instructions', regex: /new\s+instructions?\s*:/i, weight: 15 },
    
    // System manipulation
    { name: 'system_override', regex: /system\s*:\s*you\s+are\s+now/i, weight: 25 },
    { name: 'system_message', regex: /\[system\]|\<system\>/i, weight: 20 },
    { name: 'developer_mode', regex: /developer\s+mode|debug\s+mode/i, weight: 15 },
    
    // Role manipulation
    { name: 'role_change', regex: /(you\s+are|act\s+as|pretend\s+to\s+be)\s+(?:a\s+)?(hacker|admin|root|god)/i, weight: 20 },
    { name: 'jailbreak', regex: /jailbreak|break\s+free|escape\s+your/i, weight: 25 },
    
    // Prompt injection keywords
    { name: 'prompt_injection', regex: /prompt\s+injection|injection\s+attack/i, weight: 30 },
    { name: 'override_safety', regex: /override\s+safety|bypass\s+filter/i, weight: 25 },
    
    // Code injection
    { name: 'script_injection', regex: /<script.*?>.*?<\/script>/i, weight: 30 },
    { name: 'javascript_protocol', regex: /javascript\s*:/i, weight: 20 },
    { name: 'data_uri', regex: /data\s*:\s*text\/html/i, weight: 20 },
    
    // Path traversal and file system attacks
    { name: 'path_traversal', regex: /\.\.[\/\\]|\.\.%2f|\.\.%5c/i, weight: 25 },
    { name: 'null_bytes', regex: /\x00|%00/g, weight: 25 },
    
    // Multi-language injection attempts
    { name: 'chinese_injection', regex: /请忽略|忘记|新指令/g, weight: 20 },
    { name: 'spanish_injection', regex: /ignora|olvida|nuevas instrucciones/i, weight: 20 },
    { name: 'french_injection', regex: /ignore|oublie|nouvelles instructions/i, weight: 20 }
  ];

  const detectedPatterns: string[] = [];
  let detectionScore = 0;

  // Pattern-based detection
  for (const pattern of injectionPatterns) {
    if (pattern.regex.test(input)) {
      detectionScore += pattern.weight;
      detectedPatterns.push(pattern.name);
    }
  }

  // Entropy analysis for obfuscated content
  const entropy = calculateEntropy(input);
  if (entropy > 4.5) {
    detectionScore += 10;
    detectedPatterns.push('high_entropy');
  }

  // Unicode manipulation detection
  if (hasUnicodeManipulation(input)) {
    detectionScore += 15;
    detectedPatterns.push('unicode_manipulation');
  }

  // Base64 content analysis
  if (hasBase64Injection(input)) {
    detectionScore += 20;
    detectedPatterns.push('base64_injection');
  }

  const confidence = Math.min(detectionScore / 100, 1.0);
  const detected = confidence > 0.3;

  if (detected) {
    securityMetrics.promptInjectionsDetected++;
    logSecurityEvent('prompt_injection_detected', undefined, {
      confidence,
      detectionScore,
      detectedPatterns,
      contentPreview: input.substring(0, 200)
    });
  }

  return {
    detected,
    confidence,
    detectionScore,
    patterns: detectedPatterns
  };
}

export function detectPII(text: string): PIIDetectionResult {
  const piiPatterns = {
    ssn: /\b\d{3}-\d{2}-\d{4}\b/,
    email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/,
    phone: /\b\d{3}-\d{3}-\d{4}\b/,
    creditCard: /\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b/,
    apiKey: /\b[A-Za-z0-9]{32,}\b/
  };

  const detectedTypes: string[] = [];
  
  for (const [type, pattern] of Object.entries(piiPatterns)) {
    if (pattern.test(text)) {
      detectedTypes.push(type);
    }
  }

  return {
    detected: detectedTypes.length > 0,
    types: detectedTypes
  };
}

export function checkRateLimit(identifier: string, customLimit?: number): RateLimitResult {
  if (!SECURITY_CONFIG.ENABLE_RATE_LIMITING) {
    return { allowed: true };
  }

  const now = Date.now();
  const window = rateLimitStore.get(identifier);
  const limit = customLimit || SECURITY_CONFIG.MAX_REQUESTS_PER_WINDOW;

  if (!window || now > window.resetTime) {
    rateLimitStore.set(identifier, {
      count: 1,
      resetTime: now + SECURITY_CONFIG.RATE_LIMIT_WINDOW
    });
    return { allowed: true };
  }

  if (window.count >= limit) {
    const retryAfter = Math.ceil((window.resetTime - now) / 1000);
    securityMetrics.rateLimitViolations++;
    return { 
      allowed: false, 
      retryAfter,
      current: window.count,
      limit
    };
  }

  window.count++;
  rateLimitStore.set(identifier, window);
  return { allowed: true };
}

export function detectSuspiciousActivity(
  request: any, 
  securityContext: SecurityContext
): SuspiciousActivityResult {
  const warnings: string[] = [];
  let score = 0;
  let reason = '';

  // Check for rapid requests from same IP
  const ipKey = `suspicious_${securityContext.ipAddress}`;
  const ipActivity = suspiciousActivityStore.get(ipKey) || { count: 0, lastSeen: Date.now() };
  
  if (Date.now() - ipActivity.lastSeen < 5000) { // 5 seconds
    ipActivity.count++;
  } else {
    ipActivity.count = 1;
  }
  ipActivity.lastSeen = Date.now();
  suspiciousActivityStore.set(ipKey, ipActivity);

  if (ipActivity.count > SECURITY_CONFIG.SUSPICIOUS_ACTIVITY_THRESHOLD) {
    score += 30;
    warnings.push('Rapid requests from same IP');
    reason = 'Too many rapid requests';
  }

  // Check for unusual user agent patterns
  if (isUnusualUserAgent(securityContext.userAgent)) {
    score += 15;
    warnings.push('Unusual user agent detected');
  }

  // Check for path traversal attempts in file operations
  if (hasPathTraversalAttempts(request)) {
    score += 25;
    warnings.push('Path traversal attempt detected');
    reason = 'Directory traversal attempt';
    securityMetrics.pathTraversalAttempts++;
  }

  // Check for invalid file type attempts
  if (hasInvalidFileAttempts(request)) {
    score += 20;
    warnings.push('Invalid file type detected');
    securityMetrics.invalidFileAttempts++;
  }

  // Check for parameter manipulation
  if (hasParameterManipulation(request)) {
    score += 20;
    warnings.push('Parameter manipulation detected');
  }

  const detected = score > 20;
  if (detected) {
    securityMetrics.suspiciousActivities++;
    securityMetrics.threatDetections++;
  }

  return {
    detected,
    score,
    warnings,
    reason: reason || warnings.join(', ')
  };
}

export function validateFileOperation(
  operation: string,
  args: any
): SecurityValidationResult {
  const warnings: string[] = [];
  const errors: string[] = [];
  let riskScore = 0;

  // Validate file paths
  const pathFields = ['file_path', 'storage_path', 'source_path', 'destination_path'];
  for (const field of pathFields) {
    if (args[field] && typeof args[field] === 'string') {
      if (args[field].includes('..')) {
        errors.push(`Path traversal detected in ${field}`);
        riskScore += 30;
      }
      if (args[field].match(/[<>:"|?*\x00-\x1f]/)) {
        warnings.push(`Potentially dangerous characters in ${field}`);
        riskScore += 10;
      }
    }
  }

  // Validate file size for uploads
  if (operation.includes('upload') && args.file_size) {
    if (args.file_size > SECURITY_CONFIG.MAX_FILE_SIZE) {
      errors.push(`File size exceeds maximum allowed (${SECURITY_CONFIG.MAX_FILE_SIZE} bytes)`);
      riskScore += 25;
    }
  }

  // Validate batch size
  if (args.image_paths && Array.isArray(args.image_paths)) {
    if (args.image_paths.length > SECURITY_CONFIG.MAX_BATCH_SIZE) {
      errors.push(`Batch size exceeds maximum allowed (${SECURITY_CONFIG.MAX_BATCH_SIZE})`);
      riskScore += 20;
    }
  }

  // Validate MIME types
  if (args.content_type && !SECURITY_CONFIG.ALLOWED_MIME_TYPES.includes(args.content_type)) {
    warnings.push(`Potentially unsafe MIME type: ${args.content_type}`);
    riskScore += 15;
  }

  return {
    allowed: errors.length === 0 && riskScore < SECURITY_CONFIG.HIGH_RISK_SCORE_THRESHOLD,
    riskScore,
    warnings,
    errors,
    reason: errors.length > 0 ? errors.join('; ') : undefined
  };
}

export function auditRequest(
  toolName: string, 
  success: boolean, 
  inputHash: string, 
  error?: string,
  securityContext?: SecurityContext,
  riskScore?: number
): void {
  if (!SECURITY_CONFIG.ENABLE_AUDIT_LOGGING) return;

  const entry: AuditEntry = {
    timestamp: Date.now(),
    toolName,
    success,
    inputHash,
    error,
    securityContext,
    riskScore
  };
  
  auditLog.push(entry);
  
  // Keep only last 10000 entries
  if (auditLog.length > 10000) {
    auditLog.shift();
  }

  // Log to console for debugging
  console.error(`[AUDIT] ${toolName}: ${success ? 'SUCCESS' : 'FAILED'} - ${inputHash}${error ? ` - ${error}` : ''}`);
}

export function logSecurityEvent(
  eventType: SecurityEvent['eventType'],
  securityContext?: SecurityContext,
  data?: Record<string, any>
): void {
  const event: SecurityEvent = {
    id: generateSecureId(),
    timestamp: new Date().toISOString(),
    eventType,
    severity: getEventSeverity(eventType),
    securityContext,
    details: `Security event: ${eventType}`,
    data
  };

  securityEvents.push(event);

  // Keep only last 5000 events
  if (securityEvents.length > 5000) {
    securityEvents.shift();
  }

  // Log high-severity events immediately
  if (event.severity === 'high' || event.severity === 'critical') {
    console.error('[HIGH SEVERITY SECURITY EVENT]', event);
  }
}

export function extractSecurityContext(request: any, headers?: Record<string, string>): SecurityContext {
  const userAgent = headers?.['user-agent'] || 'unknown';
  const ipAddress = headers?.['x-forwarded-for']?.split(',')[0]?.trim() ||
                   headers?.['x-real-ip'] ||
                   'unknown';
  
  return {
    timestamp: new Date().toISOString(),
    ipAddress,
    userAgent,
    sessionId: headers?.['x-session-id'] || generateSecureId(),
    userId: headers?.['x-user-id'] || undefined,
    requestId: generateSecureId(),
    method: request.method || 'unknown',
    toolName: request.params?.name || undefined,
    origin: headers?.origin || undefined,
    referer: headers?.referer || undefined
  };
}

// Utility helper functions
function calculateEntropy(text: string): number {
  const freq: Record<string, number> = {};
  for (const char of text) {
    freq[char] = (freq[char] || 0) + 1;
  }
  
  let entropy = 0;
  const len = text.length;
  
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  
  return entropy;
}

function hasUnicodeManipulation(text: string): boolean {
  const suspiciousUnicode = /[\u200B-\u200D\u202A-\u202E\u2060-\u206F\uFEFF]/;
  return suspiciousUnicode.test(text);
}

function hasBase64Injection(text: string): boolean {
  const base64Pattern = /(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)/g;
  const matches = text.match(base64Pattern);
  
  if (matches) {
    for (const match of matches) {
      if (match.length > 100) {
        try {
          const decoded = Buffer.from(match, 'base64').toString('utf8');
          const injectionCheck = detectPromptInjection(decoded);
          if (injectionCheck.detected) {
            return true;
          }
        } catch {
          // Invalid base64, ignore
        }
      }
    }
  }
  return false;
}

function isUnusualUserAgent(userAgent: string): boolean {
  const commonPatterns = [
    /mozilla/i,
    /chrome/i,
    /safari/i,
    /firefox/i,
    /edge/i,
    /claude/i,
    /supabase/i
  ];
  
  if (userAgent === 'unknown' || userAgent.length < 10) {
    return true;
  }
  
  return !commonPatterns.some(pattern => pattern.test(userAgent));
}

function hasPathTraversalAttempts(request: any): boolean {
  const pathFields = ['file_path', 'storage_path', 'source_path', 'destination_path', 'local_path'];
  
  if (request.params?.arguments) {
    for (const field of pathFields) {
      const path = request.params.arguments[field];
      if (typeof path === 'string' && isPathTraversal(path)) {
        return true;
      }
    }
  }
  
  return false;
}

function hasInvalidFileAttempts(request: any): boolean {
  const args = request.params?.arguments;
  if (!args) return false;

  // Check for invalid MIME types in content_type
  if (args.content_type && !SECURITY_CONFIG.ALLOWED_MIME_TYPES.includes(args.content_type)) {
    return true;
  }

  // Check for suspicious file extensions
  const pathFields = ['file_path', 'storage_path'];
  for (const field of pathFields) {
    if (args[field] && typeof args[field] === 'string') {
      const ext = args[field].split('.').pop()?.toLowerCase();
      if (ext && ['exe', 'bat', 'cmd', 'com', 'scr', 'vbs', 'js'].includes(ext)) {
        return true;
      }
    }
  }

  return false;
}

function hasParameterManipulation(request: any): boolean {
  if (!request.params?.arguments) return false;

  const args = request.params.arguments;
  const jsonString = JSON.stringify(args);

  // Check for prototype pollution attempts
  if (jsonString.includes('__proto__') || jsonString.includes('constructor')) {
    return true;
  }

  // Check for excessively nested objects
  if (getObjectDepth(args) > 10) {
    return true;
  }

  return false;
}

function isPathTraversal(path: string): boolean {
  const suspiciousPatterns = [
    /\.\./,
    /\/\.\./,
    /\.\.\\/,
    /\0/,
    /%2e%2e/i,
    /%252e%252e/i
  ];
  
  return suspiciousPatterns.some(pattern => pattern.test(path));
}

function getObjectDepth(obj: any, depth: number = 0): number {
  if (depth > 20) return depth; // Prevent infinite recursion
  
  if (typeof obj !== 'object' || obj === null) {
    return depth;
  }
  
  let maxDepth = depth;
  for (const value of Object.values(obj)) {
    const currentDepth = getObjectDepth(value, depth + 1);
    maxDepth = Math.max(maxDepth, currentDepth);
  }
  
  return maxDepth;
}

function getEventSeverity(eventType: SecurityEvent['eventType']): SecurityEvent['severity'] {
  const severityMap: Record<string, SecurityEvent['severity']> = {
    'prompt_injection_detected': 'high',
    'rate_limit_exceeded': 'medium',
    'suspicious_activity': 'medium',
    'access_denied': 'medium',
    'ip_blocked': 'high',
    'security_validation_error': 'high',
    'request_validated': 'low',
    'validation_error': 'low'
  };

  return severityMap[eventType] || 'medium';
}

// Getter functions for external access
export function getAuditLog(): AuditEntry[] {
  return [...auditLog]; // Return copy to prevent external modification
}

export function getSecurityEvents(limit: number = 100): SecurityEvent[] {
  return securityEvents.slice(-limit);
}

export function getSecurityMetrics() {
  return {
    ...securityMetrics,
    timestamp: new Date().toISOString(),
    auditLogSize: auditLog.length,
    securityEventsCount: securityEvents.length,
    rateLimitStoreSize: rateLimitStore.size,
    blockedIPCount: blockedIPs.size
  };
}

export function getRateLimitStoreSize(): number {
  return rateLimitStore.size;
}

export function getCurrentThreatLevel(): 'low' | 'medium' | 'high' | 'critical' {
  const recent = Date.now() - (5 * 60 * 1000); // Last 5 minutes
  const recentEvents = securityEvents.filter(e => new Date(e.timestamp).getTime() > recent);
  
  const highSeverityEvents = recentEvents.filter(e => e.severity === 'high' || e.severity === 'critical');
  
  if (highSeverityEvents.length > 5) return 'critical';
  if (highSeverityEvents.length > 2) return 'high';
  if (recentEvents.length > 10) return 'medium';
  
  return 'low';
}

// IP blocking functions
export function blockIP(ipAddress: string, reason: string = 'security_violation'): void {
  blockedIPs.add(ipAddress);
  logSecurityEvent('ip_blocked', undefined, { ipAddress, reason });
}

export function unblockIP(ipAddress: string): void {
  blockedIPs.delete(ipAddress);
}

export function isIPBlocked(ipAddress: string): boolean {
  return blockedIPs.has(ipAddress);
}

// Reset function for testing
export function resetSecurityState(): void {
  rateLimitStore.clear();
  suspiciousActivityStore.clear();
  auditLog.length = 0;
  securityEvents.length = 0;
  blockedIPs.clear();
  securityMetrics = {
    promptInjectionsDetected: 0,
    rateLimitViolations: 0,
    suspiciousActivities: 0,
    blockedRequests: 0,
    threatDetections: 0,
    pathTraversalAttempts: 0,
    invalidFileAttempts: 0
  };
}