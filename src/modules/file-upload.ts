// File Upload Module for Supabase Storage MCP
// Handles secure file reading, validation, and batch uploading

import fs from 'fs/promises';
import path from 'path';
import crypto from 'crypto';
import { 
  BatchUploadResult, 
  UploadResult, 
  SecurityValidationResult 
} from './types.js';
import { generateSecureId, auditRequest, generateSecureHash, sanitizeInput } from './security.js';
import { getErrorMessage } from '../utils/error-handling.js';

export interface FileInfo {
  path?: string;         // For file path uploads
  filename: string;
  size: number;
  mimeType: string;
  buffer?: Buffer;
  base64Content?: string; // For base64 uploads
}

export interface UploadOptions {
  bucketName: string;
  batchId: string;
  folderPrefix: string;
  userId: string;
  supabase: any;
}

export interface Base64ImageData {
  filename: string;
  content: string;    // Base64 encoded content
  mime_type: string;
}

// Supported MIME types for image operations
export const SUPPORTED_MIME_TYPES = [
  'image/jpeg',
  'image/jpg', 
  'image/png',
  'image/webp',
  'image/gif'
];

// MIME type detection by file extension
const MIME_TYPE_MAP: Record<string, string> = {
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.png': 'image/png',
  '.webp': 'image/webp',
  '.gif': 'image/gif'
};

/**
 * Validate file path for security
 */
function validateFilePath(filePath: string): void {
  if (!filePath || typeof filePath !== 'string') {
    throw new Error('Invalid file path provided');
  }
  
  // Check for path traversal attempts
  if (filePath.includes('..')) {
    throw new Error('Path traversal detected in file path');
  }
  
  // Check for dangerous characters
  if (filePath.match(/[<>:"|?*\x00-\x1f]/)) {
    throw new Error('Dangerous characters detected in file path');
  }
}

/**
 * Validate filename for security
 */
function validateFilename(filename: string): void {
  if (!filename || typeof filename !== 'string') {
    throw new Error('Invalid filename provided');
  }
  
  // Check for dangerous characters in filename
  if (filename.match(/[<>:"|?*\x00-\x1f]/)) {
    throw new Error('Dangerous characters detected in filename');
  }
  
  // Check for system files
  if (filename.startsWith('.') && filename !== '.gitkeep') {
    throw new Error('System files not allowed');
  }
}

/**
 * Validate batch size
 */
function validateBatchSize(size: number): void {
  if (size <= 0) {
    throw new Error('Batch size must be greater than 0');
  }
  
  if (size > 500) {
    throw new Error('Batch size exceeds maximum allowed (500)');
  }
}

/**
 * Validate and read file information
 */
export async function validateAndReadFile(filePath: string): Promise<FileInfo> {
  try {
    // Security: Validate file path
    validateFilePath(filePath);

    // Check if file exists and is readable
    const stats = await fs.stat(filePath);
    
    if (!stats.isFile()) {
      throw new Error(`Path is not a file: ${filePath}`);
    }

    // Security: Check file size limits (50MB per file)
    const maxFileSize = 50 * 1024 * 1024; // 50MB
    if (stats.size > maxFileSize) {
      throw new Error(`File size ${formatFileSize(stats.size)} exceeds maximum allowed ${formatFileSize(maxFileSize)}`);
    }

    if (stats.size === 0) {
      throw new Error(`File is empty: ${filePath}`);
    }

    // Get filename and extension
    const filename = path.basename(filePath);
    const extension = path.extname(filePath).toLowerCase();
    
    // Validate filename
    validateFilename(filename);
    
    // Validate file extension and determine MIME type
    const mimeType = MIME_TYPE_MAP[extension];
    if (!mimeType || !SUPPORTED_MIME_TYPES.includes(mimeType)) {
      throw new Error(`Unsupported file type: ${extension}. Supported types: ${Object.keys(MIME_TYPE_MAP).join(', ')}`);
    }

    return {
      path: filePath,
      filename,
      size: stats.size,
      mimeType
    };
  } catch (error) {
    throw new Error(`File validation failed for ${filePath}: ${getErrorMessage(error)}`);
  }
}

/**
 * Validate and read base64 file information
 */
export async function validateAndReadBase64File(base64Data: Base64ImageData): Promise<FileInfo> {
  try {
    // Validate input
    if (!base64Data || typeof base64Data !== 'object') {
      throw new Error('Invalid base64 data provided');
    }
    
    const { filename, content, mime_type } = base64Data;
    
    if (!filename || !content || !mime_type) {
      throw new Error('Missing required fields: filename, content, or mime_type');
    }
    
    // Validate filename
    validateFilename(filename);
    
    // Validate MIME type
    if (!SUPPORTED_MIME_TYPES.includes(mime_type)) {
      throw new Error(`Unsupported MIME type: ${mime_type}. Supported types: ${SUPPORTED_MIME_TYPES.join(', ')}`);
    }
    
    // Validate and decode base64 content
    let buffer: Buffer;
    try {
      // Remove data URL prefix if present (e.g., "data:image/png;base64,")
      const base64Content = content.includes(',') ? content.split(',')[1] : content;
      buffer = Buffer.from(base64Content, 'base64');
    } catch (error) {
      throw new Error('Invalid base64 content provided');
    }
    
    // Security: Check file size limits (50MB per file)
    const maxFileSize = 50 * 1024 * 1024; // 50MB
    if (buffer.length > maxFileSize) {
      throw new Error(`File size ${formatFileSize(buffer.length)} exceeds maximum allowed ${formatFileSize(maxFileSize)}`);
    }
    
    if (buffer.length === 0) {
      throw new Error('File content is empty');
    }
    
    // Basic file signature validation
    if (!isValidImageFile(buffer, mime_type)) {
      throw new Error(`Invalid file signature for ${mime_type}`);
    }
    
    return {
      filename,
      size: buffer.length,
      mimeType: mime_type,
      buffer,
      base64Content: content
    };
  } catch (error) {
    throw new Error(`Base64 file validation failed for ${base64Data?.filename || 'unknown'}: ${getErrorMessage(error)}`);
  }
}

/**
 * Read file buffer with security validation
 */
export async function readFileBuffer(fileInfo: FileInfo): Promise<Buffer> {
  try {
    let buffer: Buffer;
    
    if (fileInfo.buffer) {
      // Use existing buffer (from base64 data)
      buffer = fileInfo.buffer;
    } else if (fileInfo.path) {
      // Read from file path
      buffer = await fs.readFile(fileInfo.path);
    } else {
      throw new Error('No file path or buffer provided');
    }
    
    // Verify buffer size matches file info
    if (buffer.length !== fileInfo.size) {
      throw new Error(`File size mismatch: expected ${fileInfo.size}, got ${buffer.length}`);
    }

    // Basic file signature validation
    if (!isValidImageFile(buffer, fileInfo.mimeType)) {
      throw new Error(`Invalid file signature for ${fileInfo.mimeType}`);
    }

    return buffer;
  } catch (error) {
    const identifier = fileInfo.path || fileInfo.filename || 'unknown';
    throw new Error(`Failed to read file ${identifier}: ${getErrorMessage(error)}`);
  }
}

/**
 * Validate image file signature
 */
function isValidImageFile(buffer: Buffer, mimeType: string): boolean {
  if (buffer.length < 8) return false;

  const header = buffer.subarray(0, 8);
  
  switch (mimeType) {
    case 'image/jpeg':
      return header[0] === 0xFF && header[1] === 0xD8;
    case 'image/png':
      return header[0] === 0x89 && header[1] === 0x50 && header[2] === 0x4E && header[3] === 0x47;
    case 'image/webp':
      return header.subarray(0, 4).toString('ascii') === 'RIFF' && header.subarray(8, 12).toString('ascii') === 'WEBP';
    case 'image/gif':
      const gifHeader = header.subarray(0, 6).toString('ascii');
      return gifHeader === 'GIF87a' || gifHeader === 'GIF89a';
    default:
      return false;
  }
}

/**
 * Generate storage path with security sanitization
 */
export function generateStoragePath(
  folderPrefix: string,
  userId: string,
  batchId: string,
  filename: string
): string {
  // Security: Sanitize all components
  const sanitizedPrefix = sanitizeInput(folderPrefix);
  const sanitizedUserId = sanitizeInput(userId);
  const sanitizedBatchId = sanitizeInput(batchId);
  const sanitizedFilename = sanitizeInput(filename);

  return `${sanitizedPrefix}/${sanitizedUserId}/${sanitizedBatchId}/${sanitizedFilename}`;
}

/**
 * Upload single file to Supabase Storage
 */
export async function uploadSingleFile(
  fileInfo: FileInfo,
  storagePath: string,
  options: UploadOptions
): Promise<UploadResult> {
  try {
    // Read file buffer
    const buffer = await readFileBuffer(fileInfo);

    // Upload to Supabase
    const { data, error } = await options.supabase.storage
      .from(options.bucketName)
      .upload(storagePath, buffer, {
        contentType: fileInfo.mimeType,
        cacheControl: '3600',
        upsert: false // Don't overwrite existing files
      });

    if (error) {
      return {
        original_path: fileInfo.path || fileInfo.filename,
        storage_path: storagePath,
        file_id: '',
        success: false,
        error: error.message
      };
    }

    return {
      original_path: fileInfo.path || fileInfo.filename,
      storage_path: storagePath,
      file_id: generateSecureId(), // Generate UUID for tracking
      success: true
    };
  } catch (error) {
    return {
      original_path: fileInfo.path || fileInfo.filename,
      storage_path: storagePath,
      file_id: '',
      success: false,
      error: getErrorMessage(error)
    };
  }
}

/**
 * Process batch upload with progress tracking and error handling
 */
export async function processBatchUpload(
  inputData: string[] | Base64ImageData[],
  options: UploadOptions
): Promise<BatchUploadResult> {
  const results: UploadResult[] = [];
  let successCount = 0;
  let errorCount = 0;

  // Security: Validate batch size
  validateBatchSize(inputData.length);

  // Determine if input is file paths or base64 data
  const isBase64Input = inputData.length > 0 && typeof inputData[0] === 'object';

  // Process each file
  for (let i = 0; i < inputData.length; i++) {
    const input = inputData[i];
    let fileInfo: FileInfo;
    let identifier: string = `batch_item_${i}`;
    
    try {
      if (isBase64Input) {
        // Handle base64 input
        const base64Data = input as Base64ImageData;
        fileInfo = await validateAndReadBase64File(base64Data);
        identifier = base64Data.filename;
      } else {
        // Handle file path input
        const filePath = input as string;
        fileInfo = await validateAndReadFile(filePath);
        identifier = filePath;
      }
      
      // Generate storage path
      const storagePath = generateStoragePath(
        options.folderPrefix,
        options.userId,
        options.batchId,
        fileInfo.filename
      );

      // Upload file
      const result = await uploadSingleFile(fileInfo, storagePath, options);
      results.push(result);

      if (result.success) {
        successCount++;
      } else {
        errorCount++;
      }

    } catch (error) {
      const result: UploadResult = {
        original_path: identifier || `batch_item_${i}`,
        storage_path: '',
        file_id: '',
        success: false,
        error: getErrorMessage(error)
      };
      results.push(result);
      errorCount++;
    }
  }

  // Audit the batch operation
  auditRequest('upload_image_batch', successCount > 0, generateSecureHash(JSON.stringify({
    batch_id: options.batchId,
    bucket_name: options.bucketName,
    total_files: inputData.length,
    success_count: successCount
  })));

  return {
    successful: results.filter(r => r.success),
    failed: results.filter(r => !r.success),
    total: inputData.length,
    success_count: successCount,
    error_count: errorCount,
    batch_id: options.batchId,
    security_summary: {
      validations_passed: successCount,
      validations_failed: errorCount,
      risk_score_average: 0 // Low risk for successful file uploads
    }
  };
}

/**
 * Format file size for human readable output
 */
function formatFileSize(bytes: number): string {
  const units = ['B', 'KB', 'MB', 'GB'];
  let size = bytes;
  let unitIndex = 0;
  
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex++;
  }
  
  return `${size.toFixed(1)} ${units[unitIndex]}`;
}