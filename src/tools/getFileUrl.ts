import { SupabaseClient } from '@supabase/supabase-js';
import { getErrorMessage } from '../utils/error-handling.js';
import { generateSecureHash, auditRequest } from '../modules/security.js';
import { SignedUrlResult } from '../modules/types.js';

export const getFileUrlDefinition = {
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
};

export async function handleGetFileUrl(
  supabase: SupabaseClient,
  args: any,
  requestId: string,
  startTime: number
) {
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
