import { SupabaseClient } from '@supabase/supabase-js';
import { getErrorMessage } from '../utils/error-handling.js';
import { generateSecureHash, auditRequest } from '../modules/security.js';
import { AutoDownloadFileResult } from '../modules/types.js';

export const downloadFileWithAutoTriggerDefinition = {
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
};

export async function handleDownloadFileWithAutoTrigger(
  supabase: SupabaseClient,
  args: any,
  requestId: string,
  startTime: number
) {
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
