import { SupabaseClient } from '@supabase/supabase-js';
import { getErrorMessage } from '../utils/error-handling.js';
import { generateSecureHash, auditRequest } from '../modules/security.js';
import { BatchDownloadResult } from '../modules/types.js';

export const batchDownloadDefinition = {
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
};

export async function handleBatchDownload(
  supabase: SupabaseClient,
  args: any,
  requestId: string,
  startTime: number
) {
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
