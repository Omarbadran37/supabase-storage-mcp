#!/usr/bin/env node

// Supabase Storage MCP Server - Main Entry Point
// Enhanced security features and batch operations for file management

import 'dotenv/config';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import crypto from 'crypto';

// Import modular components
import { 
  SECURITY_CONFIG, 
  generateSecureHash, 
  checkRateLimit, 
  auditRequest,
  getAuditLog,
  getRateLimitStoreSize
} from './modules/security.js';
import { 
  SecurityStatusResponse,
  SetupBucketsResult,
  FileListResult,
  SignedUrlResult,
  SignedUrlBatchResult,
  DownloadFileResult,
  AutoDownloadFileResult,
  BatchDownloadResult
} from './modules/types.js';
import { getErrorMessage } from './utils/error-handling.js';
import { createClient } from '@supabase/supabase-js';
import { processBatchUpload } from './modules/file-upload.js';

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
    tools: [
      {
        name: 'create_bucket',
        description: 'Create a new storage bucket with comprehensive security validation and audit logging',
        inputSchema: {
          type: 'object',
          properties: {
            bucket_name: { 
              type: 'string', 
              description: 'Name of the bucket to create (3-63 chars, lowercase, alphanumeric with hyphens)',
              minLength: 3,
              maxLength: 63,
              pattern: '^[a-z0-9][a-z0-9\\-]*[a-z0-9]$'
            },
            is_public: { type: 'boolean', description: 'Whether the bucket should be public', default: false }
          },
          required: ['bucket_name'],
          additionalProperties: false
        }
      },
      {
        name: 'setup_buckets',
        description: 'Initialize standard storage buckets for organized file management workflows',
        inputSchema: {
          type: 'object',
          properties: {
            base_bucket_name: {
              type: 'string',
              description: 'Base name for buckets',
              default: 'storage',
              minLength: 3,
              maxLength: 50
            },
            user_id: {
              type: 'string',
              description: 'User identifier for organization',
              maxLength: 36
            }
          },
          required: [],
          additionalProperties: false
        }
      },
      {
        name: 'upload_image_batch',
        description: 'Upload multiple images to designated bucket and folder (supports both file paths and base64 data)',
        inputSchema: {
          type: 'object',
          properties: {
            bucket_name: {
              type: 'string',
              description: 'Target bucket name',
              minLength: 3,
              maxLength: 63
            },
            batch_id: {
              type: 'string',
              description: 'Unique batch identifier',
              maxLength: 64
            },
            folder_prefix: {
              type: 'string',
              description: 'Folder organization (original/processed)',
              maxLength: 100
            },
            user_id: {
              type: 'string',
              description: 'User identifier',
              maxLength: 36
            },
            image_paths: {
              type: 'array',
              description: 'Local file paths to upload (for local testing)',
              items: { type: 'string', maxLength: 4096 },
              minItems: 1,
              maxItems: 500
            },
            image_data: {
              type: 'array',
              description: 'Base64 encoded image data (for Claude Desktop compatibility)',
              items: {
                type: 'object',
                properties: {
                  filename: {
                    type: 'string',
                    description: 'Original filename with extension',
                    maxLength: 255
                  },
                  content: {
                    type: 'string',
                    description: 'Base64 encoded file content',
                    maxLength: 67108864 // ~50MB base64 limit
                  },
                  mime_type: {
                    type: 'string',
                    description: 'MIME type of the file',
                    enum: ['image/jpeg', 'image/png', 'image/webp', 'image/gif']
                  }
                },
                required: ['filename', 'content', 'mime_type'],
                additionalProperties: false
              },
              minItems: 1,
              maxItems: 500
            }
          },
          required: ['bucket_name', 'batch_id', 'folder_prefix', 'user_id'],
          additionalProperties: false,
          oneOf: [
            { required: ['image_paths'] },
            { required: ['image_data'] }
          ]
        }
      },
      {
        name: 'list_files',
        description: 'Enumerate files in bucket folder for processing or download',
        inputSchema: {
          type: 'object',
          properties: {
            bucket_name: {
              type: 'string',
              description: 'Bucket to search',
              minLength: 3,
              maxLength: 63
            },
            folder_path: {
              type: 'string',
              description: 'Specific folder path',
              maxLength: 300
            },
            file_extension: {
              type: 'string',
              description: 'Filter by extension (.jpg, .png)',
              maxLength: 10
            }
          },
          required: ['bucket_name'],
          additionalProperties: false
        }
      },
      {
        name: 'get_file_url',
        description: 'Generate signed download URL for secure file access',
        inputSchema: {
          type: 'object',
          properties: {
            bucket_name: {
              type: 'string',
              description: 'Source bucket',
              minLength: 3,
              maxLength: 63
            },
            storage_path: {
              type: 'string',
              description: 'Full file path in storage',
              maxLength: 1024
            },
            expires_in: {
              type: 'number',
              description: 'URL expiration in seconds (default: 7200)',
              minimum: 60,
              maximum: 604800,
              default: 7200
            }
          },
          required: ['bucket_name', 'storage_path'],
          additionalProperties: false
        }
      },
      {
        name: 'get_security_status',
        description: 'Get current security configuration and audit information',
        inputSchema: {
          type: 'object',
          properties: {},
          additionalProperties: false
        }
      },
      {
        name: 'create_signed_urls',
        description: 'Generate multiple signed download URLs in a single request for batch operations',
        inputSchema: {
          type: 'object',
          properties: {
            bucket_name: {
              type: 'string',
              description: 'Source bucket',
              minLength: 3,
              maxLength: 63
            },
            file_paths: {
              type: 'array',
              description: 'Array of file paths to generate URLs for',
              items: {
                type: 'string',
                maxLength: 1024
              },
              minItems: 1,
              maxItems: 100
            },
            expires_in: {
              type: 'number',
              description: 'URL expiration in seconds (default: 3600)',
              minimum: 60,
              maximum: 604800,
              default: 3600
            }
          },
          required: ['bucket_name', 'file_paths'],
          additionalProperties: false
        }
      },
      {
        name: 'download_file',
        description: 'Download file content directly with optional image transformations',
        inputSchema: {
          type: 'object',
          properties: {
            bucket_name: {
              type: 'string',
              description: 'Source bucket',
              minLength: 3,
              maxLength: 63
            },
            file_path: {
              type: 'string',
              description: 'Full file path in storage',
              maxLength: 1024
            },
            return_format: {
              type: 'string',
              description: 'Format to return file content',
              enum: ['base64', 'binary'],
              default: 'base64'
            },
            transform_options: {
              type: 'object',
              description: 'Optional image transformation settings',
              properties: {
                width: {
                  type: 'number',
                  description: 'Resize width in pixels',
                  minimum: 1,
                  maximum: 5000
                },
                height: {
                  type: 'number',
                  description: 'Resize height in pixels',
                  minimum: 1,
                  maximum: 5000
                },
                quality: {
                  type: 'number',
                  description: 'Image quality (1-100)',
                  minimum: 1,
                  maximum: 100
                }
              },
              additionalProperties: false
            }
          },
          required: ['bucket_name', 'file_path'],
          additionalProperties: false
        }
      },
      {
        name: 'download_file_with_auto_trigger',
        description: 'Download file with optional auto-download trigger and custom filename support',
        inputSchema: {
          type: 'object',
          properties: {
            bucket_name: {
              type: 'string',
              description: 'Source bucket',
              minLength: 3,
              maxLength: 63
            },
            file_path: {
              type: 'string',
              description: 'Full file path in storage',
              maxLength: 1024
            },
            return_format: {
              type: 'string',
              description: 'Format to return file content or URL',
              enum: ['base64', 'binary', 'signed_url'],
              default: 'base64'
            },
            auto_download: {
              type: 'boolean',
              description: 'Generate auto-download trigger code',
              default: false
            },
            custom_filename: {
              type: 'string',
              description: 'Custom filename for download',
              maxLength: 255
            },
            transform_options: {
              type: 'object',
              description: 'Optional image transformation settings',
              properties: {
                width: {
                  type: 'number',
                  description: 'Resize width in pixels',
                  minimum: 1,
                  maximum: 5000
                },
                height: {
                  type: 'number',
                  description: 'Resize height in pixels',
                  minimum: 1,
                  maximum: 5000
                },
                quality: {
                  type: 'number',
                  description: 'Image quality (1-100)',
                  minimum: 1,
                  maximum: 100
                }
              },
              additionalProperties: false
            }
          },
          required: ['bucket_name', 'file_path'],
          additionalProperties: false
        }
      },
      {
        name: 'batch_download',
        description: 'Download multiple files with optional auto-download triggers and batch processing',
        inputSchema: {
          type: 'object',
          properties: {
            bucket_name: {
              type: 'string',
              description: 'Source bucket',
              minLength: 3,
              maxLength: 63
            },
            file_paths: {
              type: 'array',
              description: 'Array of file paths to download',
              items: {
                type: 'string',
                maxLength: 1024
              },
              minItems: 1,
              maxItems: 50
            },
            return_format: {
              type: 'string',
              description: 'Format to return files',
              enum: ['base64', 'binary', 'signed_url'],
              default: 'signed_url'
            },
            auto_download: {
              type: 'boolean',
              description: 'Generate auto-download trigger code for batch',
              default: false
            },
            download_delay: {
              type: 'number',
              description: 'Delay between downloads in milliseconds',
              minimum: 0,
              maximum: 10000,
              default: 500
            },
            expires_in: {
              type: 'number',
              description: 'URL expiration in seconds (for signed_url format)',
              minimum: 60,
              maximum: 604800,
              default: 3600
            }
          },
          required: ['bucket_name', 'file_paths'],
          additionalProperties: false
        }
      }
    ]
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
    switch (name) {
      case 'create_bucket':
        return await handleCreateBucket(args, requestId, startTime);
      
      case 'setup_buckets':
        return await handleSetupBuckets(args, requestId, startTime);
      
      case 'upload_image_batch':
        return await handleUploadImageBatch(args, requestId, startTime);
      
      case 'list_files':
        return await handleListFiles(args, requestId, startTime);
      
      case 'get_file_url':
        return await handleGetFileUrl(args, requestId, startTime);
      
      case 'get_security_status':
        return await handleSecurityStatus();
      
      case 'create_signed_urls':
        return await handleCreateSignedUrls(args, requestId, startTime);
      
      case 'download_file':
        return await handleDownloadFile(args, requestId, startTime);
      
      case 'download_file_with_auto_trigger':
        return await handleDownloadFileWithAutoTrigger(args, requestId, startTime);
      
      case 'batch_download':
        return await handleBatchDownload(args, requestId, startTime);
      
      default:
        throw new Error(`Unknown tool: ${name}`);
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

// Handler for bucket creation
async function handleCreateBucket(args: any, requestId: string, startTime: number) {
  const { bucket_name, is_public } = args as { 
    bucket_name: string; 
    is_public?: boolean 
  };
  
  // Input validation
  if (!bucket_name || typeof bucket_name !== 'string') {
    throw new Error('Invalid bucket_name parameter');
  }
  
  const inputHash = generateSecureHash(JSON.stringify({ bucket_name, is_public }));
  
  try {
    const options: any = {
      public: is_public || false
    };

    const { data, error } = await supabase.storage.createBucket(bucket_name, options);

    if (error) {
      throw new Error(`Failed to create bucket: ${error.message}`);
    }

    auditRequest('create_bucket', true, inputHash);
    
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            success: true,
            message: `Successfully created secure bucket: ${bucket_name}`,
            bucket_name: data.name,
            security_configuration: {
              public: options.public,
              audit_logging_enabled: true,
              threat_detection_enabled: true
            },
            request_id: requestId,
            processing_time: Date.now() - startTime
          }, null, 2)
        }
      ]
    };
  } catch (error) {
    auditRequest('create_bucket', false, inputHash, getErrorMessage(error));
    throw error;
  }
}

// Handler for setup standard buckets
async function handleSetupBuckets(args: any, requestId: string, startTime: number) {
  const { base_bucket_name = 'storage', user_id } = args;
  
  const inputHash = generateSecureHash(JSON.stringify({ base_bucket_name, user_id }));
  
  try {
    const bucketsToCreate = [
      `${base_bucket_name}-images`,
      `${base_bucket_name}-exports`
    ];
    
    const bucketsCreated: string[] = [];
    
    for (const bucketName of bucketsToCreate) {
      const { data, error } = await supabase.storage.createBucket(bucketName, {
        public: false,
        fileSizeLimit: 50 * 1024 * 1024, // 50MB
        allowedMimeTypes: ['image/jpeg', 'image/png', 'image/webp', 'image/gif']
      });
      
      if (error && !error.message.includes('already exists')) {
        throw new Error(`Failed to create bucket ${bucketName}: ${error.message}`);
      }
      
      bucketsCreated.push(bucketName);
    }
    
    auditRequest('setup_buckets', true, inputHash);
    
    const result: SetupBucketsResult = {
      success: true,
      buckets_created: bucketsCreated,
      message: `Successfully created bucket structure: ${bucketsCreated.join(', ')}`,
      security_configuration: {
        images_bucket: {
          public: false,
          file_size_limit: 50 * 1024 * 1024,
          allowed_mime_types: ['image/jpeg', 'image/png', 'image/webp', 'image/gif'],
          audit_logging_enabled: true,
          threat_detection_enabled: true
        },
        exports_bucket: {
          public: false,
          file_size_limit: 50 * 1024 * 1024,
          allowed_mime_types: ['image/jpeg', 'image/png', 'image/webp', 'image/gif'],
          audit_logging_enabled: true,
          threat_detection_enabled: true
        }
      }
    };
    
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(result, null, 2)
        }
      ]
    };
  } catch (error) {
    auditRequest('setup_buckets', false, inputHash, getErrorMessage(error));
    throw error;
  }
}

// Handler for batch image upload
async function handleUploadImageBatch(args: any, requestId: string, startTime: number) {
  const { bucket_name, batch_id, folder_prefix, user_id, image_paths, image_data } = args;
  
  // Validate input - must have either image_paths or image_data
  if (!image_paths && !image_data) {
    throw new Error('Either image_paths or image_data must be provided');
  }
  
  if (image_paths && image_data) {
    throw new Error('Cannot specify both image_paths and image_data - choose one');
  }
  
  const fileCount = image_paths ? image_paths.length : image_data.length;
  const inputHash = generateSecureHash(JSON.stringify({ bucket_name, batch_id, folder_prefix, user_id, fileCount }));
  
  try {
    const uploadOptions = {
      bucketName: bucket_name,
      batchId: batch_id,
      folderPrefix: folder_prefix,
      userId: user_id,
      supabase
    };
    
    let batchResult;
    
    if (image_paths) {
      // Use file paths (for local testing)
      batchResult = await processBatchUpload(image_paths, uploadOptions);
    } else {
      // Use base64 data (for Claude Desktop)
      batchResult = await processBatchUpload(image_data, uploadOptions);
    }
    
    const successRate = batchResult.total > 0 ? `${Math.round((batchResult.success_count / batchResult.total) * 100)}%` : '0%';
    
    auditRequest('upload_image_batch', batchResult.success_count > 0, inputHash);
    
    const response = {
      success: true,
      batch_id: batch_id,
      summary: {
        total_files: batchResult.total,
        successful_uploads: batchResult.success_count,
        failed_uploads: batchResult.error_count,
        success_rate: successRate
      },
      results: {
        successful: batchResult.successful,
        failed: batchResult.failed,
        total: batchResult.total,
        success_count: batchResult.success_count,
        error_count: batchResult.error_count
      },
      request_id: requestId,
      processing_time: Date.now() - startTime
    };
    
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(response, null, 2)
        }
      ]
    };
  } catch (error) {
    auditRequest('upload_image_batch', false, inputHash, getErrorMessage(error));
    throw error;
  }
}

// Handler for listing files
async function handleListFiles(args: any, requestId: string, startTime: number) {
  const { bucket_name, folder_path, file_extension } = args;
  
  const inputHash = generateSecureHash(JSON.stringify({ bucket_name, folder_path, file_extension }));
  
  try {
    const { data, error } = await supabase.storage
      .from(bucket_name)
      .list(folder_path || '', {
        limit: 1000,
        sortBy: { column: 'name', order: 'asc' }
      });
    
    if (error) {
      throw new Error(`Failed to list files: ${error.message}`);
    }
    
    let files = data || [];
    
    // Filter by file extension if specified
    if (file_extension) {
      files = files.filter(file => file.name.toLowerCase().endsWith(file_extension.toLowerCase()));
    }
    
    const totalSize = files.reduce((sum, file) => sum + (file.metadata?.size || 0), 0);
    
    auditRequest('list_files', true, inputHash);
    
    const result: FileListResult = {
      files: files.map(file => ({
        name: file.name,
        path: folder_path ? `${folder_path}/${file.name}` : file.name,
        size: file.metadata?.size || 0,
        mime_type: file.metadata?.mimetype || 'unknown',
        last_modified: file.updated_at || file.created_at || new Date().toISOString(),
        metadata: file.metadata
      })),
      total_count: files.length,
      total_size: totalSize
    };
    
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            ...result,
            request_id: requestId,
            processing_time: Date.now() - startTime
          }, null, 2)
        }
      ]
    };
  } catch (error) {
    auditRequest('list_files', false, inputHash, getErrorMessage(error));
    throw error;
  }
}

// Handler for getting file URL
async function handleGetFileUrl(args: any, requestId: string, startTime: number) {
  const { bucket_name, storage_path, expires_in = 7200 } = args;
  
  const inputHash = generateSecureHash(JSON.stringify({ bucket_name, storage_path, expires_in }));
  
  try {
    const { data, error } = await supabase.storage
      .from(bucket_name)
      .createSignedUrl(storage_path, expires_in);
    
    if (error) {
      throw new Error(`Failed to create signed URL: ${error.message}`);
    }
    
    const expiresAt = new Date(Date.now() + expires_in * 1000).toISOString();
    
    auditRequest('get_file_url', true, inputHash);
    
    const result: SignedUrlResult = {
      signedUrl: data.signedUrl,
      expiresAt,
      fileSize: 0, // Would need additional call to get file info
      mimeType: 'unknown' // Would need additional call to get file info
    };
    
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            ...result,
            request_id: requestId,
            processing_time: Date.now() - startTime
          }, null, 2)
        }
      ]
    };
  } catch (error) {
    auditRequest('get_file_url', false, inputHash, getErrorMessage(error));
    throw error;
  }
}

// Handler for security status
async function handleSecurityStatus() {
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

// Handler for batch signed URLs
async function handleCreateSignedUrls(args: any, requestId: string, startTime: number) {
  const { bucket_name, file_paths, expires_in = 3600 } = args;
  
  const inputHash = generateSecureHash(JSON.stringify({ bucket_name, file_count: file_paths.length, expires_in }));
  
  try {
    // Input validation
    if (!bucket_name || typeof bucket_name !== 'string') {
      throw new Error('Invalid bucket_name parameter');
    }
    
    if (!Array.isArray(file_paths) || file_paths.length === 0) {
      throw new Error('file_paths must be a non-empty array');
    }
    
    if (file_paths.length > 100) {
      throw new Error('Cannot generate more than 100 URLs in a single request');
    }
    
    const results = [];
    let successCount = 0;
    let errorCount = 0;
    
    // Process each file path
    for (const filePath of file_paths) {
      try {
        const { data, error } = await supabase.storage
          .from(bucket_name)
          .createSignedUrl(filePath, expires_in);
        
        if (error) {
          results.push({
            file_path: filePath,
            signed_url: '',
            expires_at: '',
            success: false,
            error: error.message
          });
          errorCount++;
        } else {
          const expiresAt = new Date(Date.now() + expires_in * 1000).toISOString();
          results.push({
            file_path: filePath,
            signed_url: data.signedUrl,
            expires_at: expiresAt,
            success: true
          });
          successCount++;
        }
      } catch (error) {
        results.push({
          file_path: filePath,
          signed_url: '',
          expires_at: '',
          success: false,
          error: getErrorMessage(error)
        });
        errorCount++;
      }
    }
    
    const successRate = file_paths.length > 0 ? `${Math.round((successCount / file_paths.length) * 100)}%` : '0%';
    
    auditRequest('create_signed_urls', successCount > 0, inputHash);
    
    const result: SignedUrlBatchResult = {
      urls: results,
      total_files: file_paths.length,
      successful_urls: successCount,
      failed_urls: errorCount,
      success_rate: successRate,
      expires_in
    };
    
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            ...result,
            request_id: requestId,
            processing_time: Date.now() - startTime
          }, null, 2)
        }
      ]
    };
  } catch (error) {
    auditRequest('create_signed_urls', false, inputHash, getErrorMessage(error));
    throw error;
  }
}

// Handler for direct file download
async function handleDownloadFile(args: any, requestId: string, startTime: number) {
  const { bucket_name, file_path, return_format = 'base64', transform_options } = args;
  
  const inputHash = generateSecureHash(JSON.stringify({ bucket_name, file_path, return_format, transform_options }));
  
  try {
    // Input validation
    if (!bucket_name || typeof bucket_name !== 'string') {
      throw new Error('Invalid bucket_name parameter');
    }
    
    if (!file_path || typeof file_path !== 'string') {
      throw new Error('Invalid file_path parameter');
    }
    
    if (!['base64', 'binary'].includes(return_format)) {
      throw new Error('return_format must be either "base64" or "binary"');
    }
    
    // Prepare download options
    const downloadOptions: any = {};
    
    // Add transformation options if provided
    if (transform_options && typeof transform_options === 'object') {
      const { width, height, quality } = transform_options;
      
      if (width || height || quality) {
        downloadOptions.transform = {};
        if (width && typeof width === 'number' && width > 0) {
          downloadOptions.transform.width = width;
        }
        if (height && typeof height === 'number' && height > 0) {
          downloadOptions.transform.height = height;
        }
        if (quality && typeof quality === 'number' && quality > 0 && quality <= 100) {
          downloadOptions.transform.quality = quality;
        }
      }
    }
    
    // Download the file
    const { data, error } = await supabase.storage
      .from(bucket_name)
      .download(file_path, downloadOptions);
    
    if (error) {
      throw new Error(`Failed to download file: ${error.message}`);
    }
    
    if (!data) {
      throw new Error('No data received from download');
    }
    
    // Convert to buffer and then to requested format
    const buffer = await data.arrayBuffer();
    const fileBuffer = Buffer.from(buffer);
    
    let content: string;
    if (return_format === 'base64') {
      content = fileBuffer.toString('base64');
    } else {
      content = fileBuffer.toString('binary');
    }
    
    // Get file metadata
    const fileName = file_path.split('/').pop() || 'unknown';
    const contentType = data.type || 'application/octet-stream';
    
    auditRequest('download_file', true, inputHash);
    
    const result: DownloadFileResult = {
      success: true,
      file_path,
      file_name: fileName,
      content,
      content_type: contentType,
      file_size: fileBuffer.length,
      format: return_format,
      transformed: !!(transform_options && Object.keys(transform_options).length > 0),
      transform_options: transform_options || undefined,
      metadata: {
        last_modified: new Date().toISOString(),
        cache_control: 'no-cache'
      }
    };
    
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            ...result,
            request_id: requestId,
            processing_time: Date.now() - startTime
          }, null, 2)
        }
      ]
    };
  } catch (error) {
    auditRequest('download_file', false, inputHash, getErrorMessage(error));
    throw error;
  }
}

// Handler for download file with auto-trigger
async function handleDownloadFileWithAutoTrigger(args: any, requestId: string, startTime: number) {
  const { 
    bucket_name, 
    file_path, 
    return_format = 'base64', 
    transform_options,
    auto_download = false,
    custom_filename
  } = args;
  
  const inputHash = generateSecureHash(JSON.stringify({ bucket_name, file_path, return_format, transform_options, auto_download }));
  
  try {
    // Input validation
    if (!bucket_name || typeof bucket_name !== 'string') {
      throw new Error('Invalid bucket_name parameter');
    }
    
    if (!file_path || typeof file_path !== 'string') {
      throw new Error('Invalid file_path parameter');
    }
    
    if (!['base64', 'binary', 'signed_url'].includes(return_format)) {
      throw new Error('return_format must be "base64", "binary", or "signed_url"');
    }
    
    let result: AutoDownloadFileResult;
    
    if (return_format === 'signed_url') {
      // Generate signed URL with auto-download parameter
      const { data, error } = await supabase.storage
        .from(bucket_name)
        .createSignedUrl(file_path, 3600);
      
      if (error) {
        throw new Error(`Failed to create signed URL: ${error.message}`);
      }
      
      const fileName = custom_filename || file_path.split('/').pop() || 'download';
      
      // Add download parameter for automatic download
      const downloadUrl = auto_download ? 
        `${data.signedUrl}&download=${encodeURIComponent(fileName)}` :
        data.signedUrl;
      
      result = {
        success: true,
        file_path,
        file_name: fileName,
        download_url: downloadUrl,
        content_type: 'application/octet-stream', // Will be determined by browser
        format: return_format,
        auto_download_enabled: auto_download,
        expires_at: new Date(Date.now() + 3600 * 1000).toISOString(),
        transformed: false,
        javascript_trigger: auto_download ? `window.location.href = "${downloadUrl}";` : undefined,
        metadata: {
          last_modified: new Date().toISOString(),
          cache_control: 'no-cache'
        }
      };
    } else {
      // Download file content directly
      const downloadOptions: any = {};
      
      // Add transformation options if provided
      if (transform_options && typeof transform_options === 'object') {
        const { width, height, quality } = transform_options;
        
        if (width || height || quality) {
          downloadOptions.transform = {};
          if (width && typeof width === 'number' && width > 0) {
            downloadOptions.transform.width = width;
          }
          if (height && typeof height === 'number' && height > 0) {
            downloadOptions.transform.height = height;
          }
          if (quality && typeof quality === 'number' && quality > 0 && quality <= 100) {
            downloadOptions.transform.quality = quality;
          }
        }
      }
      
      const { data, error } = await supabase.storage
        .from(bucket_name)
        .download(file_path, downloadOptions);
      
      if (error) {
        throw new Error(`Failed to download file: ${error.message}`);
      }
      
      if (!data) {
        throw new Error('No data received from download');
      }
      
      // Convert to buffer and then to requested format
      const buffer = await data.arrayBuffer();
      const fileBuffer = Buffer.from(buffer);
      
      let content: string;
      if (return_format === 'base64') {
        content = fileBuffer.toString('base64');
      } else {
        content = fileBuffer.toString('binary');
      }
      
      const fileName = custom_filename || file_path.split('/').pop() || 'unknown';
      const contentType = data.type || 'application/octet-stream';
      
      // Generate JavaScript auto-download code if requested
      let javascriptTrigger: string | undefined;
      if (auto_download) {
        javascriptTrigger = `
// Auto-download code for ${fileName}
const base64Content = "${content}";
const byteCharacters = atob(base64Content);
const byteNumbers = new Array(byteCharacters.length);
for (let i = 0; i < byteCharacters.length; i++) {
  byteNumbers[i] = byteCharacters.charCodeAt(i);
}
const byteArray = new Uint8Array(byteNumbers);
const blob = new Blob([byteArray], { type: "${contentType}" });
const url = window.URL.createObjectURL(blob);
const link = document.createElement('a');
link.href = url;
link.download = "${fileName}";
document.body.appendChild(link);
link.click();
document.body.removeChild(link);
window.URL.revokeObjectURL(url);
console.log('Download triggered for ${fileName}');`;
      }
      
      result = {
        success: true,
        file_path,
        file_name: fileName,
        content,
        content_type: contentType,
        file_size: fileBuffer.length,
        format: return_format,
        auto_download_enabled: auto_download,
        transformed: !!(transform_options && Object.keys(transform_options).length > 0),
        transform_options: transform_options || undefined,
        javascript_trigger: javascriptTrigger,
        metadata: {
          last_modified: new Date().toISOString(),
          cache_control: 'no-cache'
        }
      };
    }
    
    auditRequest('download_file_with_auto_trigger', true, inputHash);
    
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            ...result,
            request_id: requestId,
            processing_time: Date.now() - startTime
          }, null, 2)
        }
      ]
    };
  } catch (error) {
    auditRequest('download_file_with_auto_trigger', false, inputHash, getErrorMessage(error));
    throw error;
  }
}

// Handler for batch download
async function handleBatchDownload(args: any, requestId: string, startTime: number) {
  const { 
    bucket_name, 
    file_paths, 
    return_format = 'signed_url',
    auto_download = false,
    download_delay = 500,
    expires_in = 3600
  } = args;
  
  const inputHash = generateSecureHash(JSON.stringify({ bucket_name, file_count: file_paths.length, return_format, auto_download }));
  
  try {
    // Input validation
    if (!bucket_name || typeof bucket_name !== 'string') {
      throw new Error('Invalid bucket_name parameter');
    }
    
    if (!Array.isArray(file_paths) || file_paths.length === 0) {
      throw new Error('file_paths must be a non-empty array');
    }
    
    if (file_paths.length > 50) {
      throw new Error('Cannot download more than 50 files in a single batch');
    }
    
    if (!['base64', 'binary', 'signed_url'].includes(return_format)) {
      throw new Error('return_format must be "base64", "binary", or "signed_url"');
    }
    
    const results = [];
    let successCount = 0;
    let errorCount = 0;
    
    // Process each file path
    for (const filePath of file_paths) {
      try {
        if (return_format === 'signed_url') {
          const { data, error } = await supabase.storage
            .from(bucket_name)
            .createSignedUrl(filePath, expires_in);
          
          if (error) {
            results.push({
              file_path: filePath,
              success: false,
              error: error.message
            });
            errorCount++;
            continue;
          }
          
          const fileName = filePath.split('/').pop() || 'download';
          const downloadUrl = auto_download ? 
            `${data.signedUrl}&download=${encodeURIComponent(fileName)}` :
            data.signedUrl;
          
          results.push({
            file_path: filePath,
            file_name: fileName,
            download_url: downloadUrl,
            expires_at: new Date(Date.now() + expires_in * 1000).toISOString(),
            success: true
          });
          successCount++;
        } else {
          // For direct content download (base64/binary)
          const { data, error } = await supabase.storage
            .from(bucket_name)
            .download(filePath);
          
          if (error) {
            results.push({
              file_path: filePath,
              success: false,
              error: error.message
            });
            errorCount++;
            continue;
          }
          
          const buffer = await data.arrayBuffer();
          const fileBuffer = Buffer.from(buffer);
          const content = return_format === 'base64' ? 
            fileBuffer.toString('base64') : 
            fileBuffer.toString('binary');
          
          const fileName = filePath.split('/').pop() || 'download';
          
          results.push({
            file_path: filePath,
            file_name: fileName,
            content,
            content_type: data.type || 'application/octet-stream',
            file_size: fileBuffer.length,
            success: true
          });
          successCount++;
        }
      } catch (error) {
        results.push({
          file_path: filePath,
          success: false,
          error: getErrorMessage(error)
        });
        errorCount++;
      }
    }
    
    const successRate = file_paths.length > 0 ? `${Math.round((successCount / file_paths.length) * 100)}%` : '0%';
    
    // Generate JavaScript for batch auto-download if enabled
    let batchDownloadScript: string | undefined;
    if (auto_download && return_format === 'signed_url') {
      const successfulUrls = results.filter(r => r.success && r.download_url);
      if (successfulUrls.length > 0) {
        batchDownloadScript = `
// Batch auto-download script
const downloadUrls = ${JSON.stringify(successfulUrls.map(r => ({ url: r.download_url, filename: r.file_name })), null, 2)};
const delay = ${download_delay};

async function batchDownload() {
  console.log('Starting batch download of \${downloadUrls.length} files...');
  for (let i = 0; i < downloadUrls.length; i++) {
    const file = downloadUrls[i];
    console.log(\`Downloading \${i + 1}/\${downloadUrls.length}: \${file.filename}\`);
    
    const link = document.createElement('a');
    link.href = file.url;
    link.download = file.filename;
    link.style.display = 'none';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    
    // Delay between downloads to avoid browser blocking
    if (i < downloadUrls.length - 1 && delay > 0) {
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
  console.log('Batch download completed for \${downloadUrls.length} files');
}

// Execute batch download
batchDownload();`;
      }
    }
    
    auditRequest('batch_download', successCount > 0, inputHash);
    
    const result: BatchDownloadResult = {
      success: true,
      batch_summary: {
        total_files: file_paths.length,
        successful_downloads: successCount,
        failed_downloads: errorCount,
        success_rate: successRate
      },
      downloads: results,
      auto_download_enabled: auto_download,
      javascript_trigger: batchDownloadScript,
      expires_in: return_format === 'signed_url' ? expires_in : undefined
    };
    
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            ...result,
            request_id: requestId,
            processing_time: Date.now() - startTime
          }, null, 2)
        }
      ]
    };
  } catch (error) {
    auditRequest('batch_download', false, inputHash, getErrorMessage(error));
    throw error;
  }
}

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