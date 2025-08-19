import { SupabaseClient } from '@supabase/supabase-js';
import { getErrorMessage } from '../utils/error-handling.js';
import { generateSecureHash, auditRequest } from '../modules/security.js';
import { SignedUrlBatchResult } from '../modules/types.js';

export const createSignedUrlsDefinition = {
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
};

export async function handleCreateSignedUrls(
  supabase: SupabaseClient,
  args: any,
  requestId: string,
  startTime: number
) {
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
