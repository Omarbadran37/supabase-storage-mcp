import { SupabaseClient } from '@supabase/supabase-js';
import { getErrorMessage } from '../utils/error-handling.js';
import { generateSecureHash, auditRequest } from '../modules/security.js';
import { FileListResult } from '../modules/types.js';

export const listFilesDefinition = {
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
};

export async function handleListFiles(
  supabase: SupabaseClient,
  args: any,
  requestId: string,
  startTime: number
) {
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
