import { SupabaseClient } from '@supabase/supabase-js';
import { getErrorMessage } from '../utils/error-handling.js';
import { generateSecureHash, auditRequest } from '../modules/security.js';
import { processBatchUpload } from '../modules/file-upload.js';

export const uploadImageBatchDefinition = {
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
};

export async function handleUploadImageBatch(
  supabase: SupabaseClient,
  args: any,
  requestId: string,
  startTime: number
) {
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
