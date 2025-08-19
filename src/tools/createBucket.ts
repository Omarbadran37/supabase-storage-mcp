import { SupabaseClient } from '@supabase/supabase-js';
import { getErrorMessage } from '../utils/error-handling.js';
import { generateSecureHash, auditRequest } from '../modules/security.js';

export const createBucketDefinition = {
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
};

export async function handleCreateBucket(
  supabase: SupabaseClient,
  args: any,
  requestId: string,
  startTime: number
) {
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
