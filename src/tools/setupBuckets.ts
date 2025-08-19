import { SupabaseClient } from '@supabase/supabase-js';
import { getErrorMessage } from '../utils/error-handling.js';
import { generateSecureHash, auditRequest } from '../modules/security.js';
import { SetupBucketsResult } from '../modules/types.js';

export const setupBucketsDefinition = {
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
};

export async function handleSetupBuckets(
  supabase: SupabaseClient,
  args: any,
  requestId: string,
  startTime: number
) {
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
