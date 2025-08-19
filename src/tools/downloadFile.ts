import { SupabaseClient } from '@supabase/supabase-js';
import { getErrorMessage } from '../utils/error-handling.js';
import { generateSecureHash, auditRequest } from '../modules/security.js';
import { DownloadFileResult } from '../modules/types.js';

export const downloadFileDefinition = {
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
};

export async function handleDownloadFile(
  supabase: SupabaseClient,
  args: any,
  requestId: string,
  startTime: number
) {
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
