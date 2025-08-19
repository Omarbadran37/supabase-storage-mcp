import { SupabaseClient } from '@supabase/supabase-js';
import { handleCreateBucket, createBucketDefinition } from './createBucket.js';
import { handleSetupBuckets, setupBucketsDefinition } from './setupBuckets.js';
import { handleUploadImageBatch, uploadImageBatchDefinition } from './uploadImageBatch.js';
import { handleListFiles, listFilesDefinition } from './listFiles.js';
import { handleGetFileUrl, getFileUrlDefinition } from './getFileUrl.js';
import { handleGetSecurityStatus, getSecurityStatusDefinition } from './getSecurityStatus.js';
import { handleCreateSignedUrls, createSignedUrlsDefinition } from './createSignedUrls.js';
import { handleDownloadFile, downloadFileDefinition } from './downloadFile.js';
import { handleDownloadFileWithAutoTrigger, downloadFileWithAutoTriggerDefinition } from './downloadFileWithAutoTrigger.js';
import { handleBatchDownload, batchDownloadDefinition } from './batchDownload.js';

export const toolDefinitions = [
  createBucketDefinition,
  setupBucketsDefinition,
  uploadImageBatchDefinition,
  listFilesDefinition,
  getFileUrlDefinition,
  getSecurityStatusDefinition,
  createSignedUrlsDefinition,
  downloadFileDefinition,
  downloadFileWithAutoTriggerDefinition,
  batchDownloadDefinition,
];

type ToolHandler = (
  supabase: SupabaseClient,
  args: any,
  requestId: string,
  startTime: number
) => Promise<any>;

type SecurityToolHandler = () => Promise<any>;

export const toolHandlers: Record<string, ToolHandler | SecurityToolHandler> = {
  create_bucket: handleCreateBucket,
  setup_buckets: handleSetupBuckets,
  upload_image_batch: handleUploadImageBatch,
  list_files: handleListFiles,
  get_file_url: handleGetFileUrl,
  get_security_status: handleGetSecurityStatus,
  create_signed_urls: handleCreateSignedUrls,
  download_file: handleDownloadFile,
  download_file_with_auto_trigger: handleDownloadFileWithAutoTrigger,
  batch_download: handleBatchDownload,
};
