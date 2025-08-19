// TypeScript interfaces and types for Supabase Storage MCP

export interface SecurityConfig {
  ENABLE_RATE_LIMITING: boolean;
  ENABLE_THREAT_DETECTION: boolean;
  ENABLE_AUDIT_LOGGING: boolean;
  ENABLE_INPUT_VALIDATION: boolean;
  ENABLE_FILE_SECURITY: boolean;
  
  // Rate limiting configuration
  RATE_LIMIT_WINDOW: number; // milliseconds
  MAX_REQUESTS_PER_WINDOW: number;
  GLOBAL_RATE_LIMIT: number;
  IP_RATE_LIMIT: number;
  USER_RATE_LIMIT: number;
  
  // File security limits
  MAX_FILE_SIZE: number; // bytes
  MAX_BATCH_SIZE: number;
  ALLOWED_MIME_TYPES: string[];
  
  // Security thresholds
  MAX_PROMPT_LENGTH: number;
  SUSPICIOUS_ACTIVITY_THRESHOLD: number;
  HIGH_RISK_SCORE_THRESHOLD: number;
  
  // Session and authentication
  SESSION_TIMEOUT: number; // seconds
  JWT_EXPIRY: number; // seconds
}

export interface RateLimitWindow {
  count: number;
  resetTime: number;
}

export interface RateLimitResult {
  allowed: boolean;
  retryAfter?: number;
  current?: number;
  limit?: number;
}

export interface SecurityContext {
  timestamp: string;
  ipAddress: string;
  userAgent: string;
  sessionId: string;
  userId?: string;
  requestId: string;
  method: string;
  toolName?: string;
  origin?: string;
  referer?: string;
}

export interface SecurityValidationResult {
  allowed: boolean;
  reason?: string;
  riskScore: number;
  warnings: string[];
  errors: string[];
  securityContext?: SecurityContext;
}

export interface PromptInjectionResult {
  detected: boolean;
  confidence: number;
  detectionScore?: number;
  patterns: string[];
}

export interface PIIDetectionResult {
  detected: boolean;
  types: string[];
}

export interface SuspiciousActivityResult {
  detected: boolean;
  score: number;
  warnings: string[];
  reason: string;
}

export interface AuditEntry {
  timestamp: number;
  toolName: string;
  success: boolean;
  inputHash: string;
  error?: string;
  securityContext?: SecurityContext;
  riskScore?: number;
}

export interface SecurityEvent {
  id: string;
  timestamp: string;
  eventType: 'validation_error' | 'suspicious_activity' | 'access_denied' | 'rate_limit_exceeded' | 'prompt_injection_detected' | 'request_validated' | 'ip_blocked' | 'security_validation_error';
  severity: 'low' | 'medium' | 'high' | 'critical';
  securityContext?: SecurityContext;
  details: string;
  data?: Record<string, any>;
}

export interface SecurityStatusResponse {
  security_config: SecurityConfig;
  rate_limit_status: {
    active_limits: number;
    current_window: number;
  };
  audit_log: {
    total_entries: number;
    recent_entries: Array<{
      timestamp: string;
      tool: string;
      success: boolean;
      error: string;
    }>;
  };
  server_info: {
    name: string;
    version: string;
    uptime: number;
    node_version: string;
  };
}

export interface SecurityAlertsResponse {
  alerts: Array<{
    id: string;
    timestamp: string;
    severity: string;
    type: string;
    message: string;
    source_ip?: string;
    user_id?: string;
    acknowledged: boolean;
    response_actions: string[];
  }>;
  total_count: number;
  unacknowledged_count: number;
}

export interface SecurityReportResponse {
  report_id: string;
  generated_at: string;
  time_period: {
    start: string;
    end: string;
  };
  summary: {
    total_requests: number;
    blocked_requests: number;
    threat_detections: number;
    rate_limit_violations: number;
    success_rate: string;
  };
  threat_analysis: {
    prompt_injections: number;
    suspicious_activities: number;
    path_traversal_attempts: number;
    rate_limit_violations: number;
  };
  top_threats: Array<{
    threat_type: string;
    count: number;
    severity: string;
    first_seen: string;
    last_seen: string;
  }>;
  recommendations: string[];
  compliance_status: {
    gdpr_compliant: boolean;
    soc2_compliant: boolean;
    nist_compliant: boolean;
    owasp_compliant: boolean;
  };
}

// Tool-specific interfaces
export interface UploadResult {
  original_path: string;
  storage_path: string;
  file_id: string;
  success: boolean;
  error?: string;
  security_validation?: SecurityValidationResult;
}

export interface BatchUploadResult {
  successful: UploadResult[];
  failed: UploadResult[];
  total: number;
  success_count: number;
  error_count: number;
  batch_id: string;
  security_summary: {
    validations_passed: number;
    validations_failed: number;
    risk_score_average: number;
  };
}

export interface FileOperationResult {
  success: boolean;
  message: string;
  data?: any;
  security_validation?: SecurityValidationResult;
  operation_id: string;
  timestamp: string;
}

export interface BucketOperationResult {
  success: boolean;
  message: string;
  bucket_name: string;
  security_configuration?: {
    public: boolean;
    file_size_limit?: number;
    allowed_mime_types?: string[];
    audit_logging_enabled: boolean;
    threat_detection_enabled: boolean;
  };
  operation_id: string;
  timestamp: string;
}

export interface SetupBucketsResult {
  success: boolean;
  buckets_created: string[];
  message: string;
  security_configuration: {
    images_bucket: {
      public: boolean;
      file_size_limit: number;
      allowed_mime_types: string[];
      audit_logging_enabled: boolean;
      threat_detection_enabled: boolean;
    };
    exports_bucket: {
      public: boolean;
      file_size_limit: number;
      allowed_mime_types: string[];
      audit_logging_enabled: boolean;
      threat_detection_enabled: boolean;
    };
  };
}

export interface FileListResult {
  files: Array<{
    name: string;
    path: string;
    size: number;
    mime_type: string;
    last_modified: string;
    metadata?: Record<string, any>;
  }>;
  total_count: number;
  total_size: number;
  folder_structure?: Record<string, any>;
}

export interface SignedUrlResult {
  signedUrl: string;
  expiresAt: string;
  fileSize: number;
  mimeType: string;
}

export interface SignedUrlBatchResult {
  urls: Array<{
    file_path: string;
    signed_url: string;
    expires_at: string;
    success: boolean;
    error?: string;
  }>;
  total_files: number;
  successful_urls: number;
  failed_urls: number;
  success_rate: string;
  expires_in: number;
}

export interface DownloadFileResult {
  success: boolean;
  file_path: string;
  file_name: string;
  content: string; // base64 or binary data
  content_type: string;
  file_size: number;
  format: 'base64' | 'binary';
  transformed: boolean;
  transform_options?: {
    width?: number;
    height?: number;
    quality?: number;
  };
  metadata?: {
    last_modified: string;
    etag?: string;
    cache_control?: string;
  };
}

export interface AutoDownloadFileResult {
  success: boolean;
  file_path?: string;
  file_name: string;
  download_url?: string;
  content?: string;
  content_type: string;
  file_size?: number;
  format: 'base64' | 'binary' | 'signed_url';
  auto_download_enabled: boolean;
  expires_at?: string;
  transformed: boolean;
  transform_options?: {
    width?: number;
    height?: number;
    quality?: number;
  };
  javascript_trigger?: string;
  metadata?: {
    last_modified: string;
    cache_control?: string;
  };
}

export interface BatchDownloadResult {
  success: boolean;
  batch_summary: {
    total_files: number;
    successful_downloads: number;
    failed_downloads: number;
    success_rate: string;
  };
  downloads: Array<{
    file_path: string;
    file_name?: string;
    download_url?: string;
    content?: string;
    content_type?: string;
    file_size?: number;
    expires_at?: string;
    success: boolean;
    error?: string;
  }>;
  auto_download_enabled: boolean;
  javascript_trigger?: string;
  expires_in?: number;
}

// Configuration validation schemas
export interface SupabaseConfig {
  url: string;
  serviceKey: string;
  validateConnection?: boolean;
  enableSecurity?: boolean;
}

export interface MCPToolSchema {
  name: string;
  description: string;
  inputSchema: {
    type: string;
    properties: Record<string, any>;
    required: string[];
    additionalProperties?: boolean;
  };
}

// Error handling interfaces
export interface SecurityError extends Error {
  code: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  context?: SecurityContext;
  riskScore?: number;
}

export interface ValidationError extends Error {
  field: string;
  value: any;
  rule: string;
  context?: string;
}

// Utility types
export type AnalysisType = 'lifestyle' | 'product';
export type SecurityEventType = SecurityEvent['eventType'];
export type SecuritySeverity = SecurityEvent['severity'];
export type ThreatLevel = 'low' | 'medium' | 'high' | 'critical';

// Re-export common types for convenience
export type { SecurityConfig as Config };
export type { SecurityValidationResult as ValidationResult };
export type { SecurityContext as Context };
export type { AuditEntry as Audit };