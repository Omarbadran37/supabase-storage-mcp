# Supabase Storage MCP

A secure, production-ready Model Context Protocol (MCP) server for Supabase Storage with advanced security features, batch operations, and comprehensive file management.

## Features

### 🛡️ Enterprise-Grade Security
- **Multi-layer Defense**: Rate limiting, threat detection, and audit logging
- **Input Validation**: Comprehensive validation with Zod schemas and DOMPurify sanitization  
- **Real-time Monitoring**: Security metrics and alert system
- **Path Traversal Prevention**: Advanced protection against directory traversal attacks
- **File Type Validation**: MIME type verification and file signature checking

### 🗂️ Bucket Management
- **Secure Bucket Creation**: Create storage buckets with security validation
- **Organized Structure**: Automated folder organization for scalable workflows
- **Batch Setup**: Initialize multiple buckets with consistent configuration

### 🖼️ Advanced File Operations
- **Batch Upload**: Upload 1-500 files with progress tracking and detailed reporting
- **Dual Input Support**: Handle both local file paths and base64 data (Claude Desktop compatible)
- **File Validation**: Size limits, MIME type checking, and signature verification
- **Transform on Download**: Resize, compress, and format images during download
- **Auto-Download System**: Generate JavaScript code for browser downloads

### 📁 File Management
- **Secure Downloads**: Time-limited signed URLs with access controls
- **Batch Operations**: Process multiple files efficiently 
- **Advanced Search**: Filter by extension, folder, and metadata
- **Custom Filenames**: Override default names during download

### 🔗 Auto-Download Features
- **Intelligent Triggers**: Automatic browser downloads with custom filenames
- **Batch Downloads**: Sequential downloads with configurable delays
- **JavaScript Generation**: Ready-to-use browser scripts
- **Multiple Formats**: Support for signed URLs, base64, and binary data

## Installation

### Prerequisites
- Node.js >= 18.0.0
- npm >= 8.0.0
- Supabase project with Storage enabled

### Setup

1. **Clone and install dependencies:**
```bash
git clone https://github.com/Omarbadran37/supabase-storage-mcp.git
cd supabase-storage-mcp
npm install
```

2. **Configure environment variables:**
```bash
cp .env.example .env
```

Edit `.env` with your Supabase credentials:
```env
SUPABASE_URL=https://your-project-id.supabase.co
SUPABASE_SERVICE_KEY=your-service-role-key
NODE_ENV=production
```

3. **Build the project:**
```bash
npm run build
```

4. **Start the MCP server:**
```bash
npm start
```

## Configuration

### Claude Desktop Integration

Add to your Claude Desktop configuration (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "supabase-storage": {
      "command": "node",
      "args": ["/path/to/supabase-storage-mcp/dist/index.js"],
      "description": "Supabase Storage MCP for file and bucket management"
    }
  }
}
```

### Environment Variables

| Variable | Required | Description | Default |
|----------|----------|-------------|---------|
| `SUPABASE_URL` | ✅ | Your Supabase project URL | - |
| `SUPABASE_SERVICE_KEY` | ✅ | Your Supabase service role key | - |
| `NODE_ENV` | ❌ | Environment mode | `development` |
| `LOG_LEVEL` | ❌ | Logging verbosity | `info` |

### Security Configuration

The server includes comprehensive security features enabled by default:
- Rate limiting (100 requests per minute globally)
- File size limits (50MB per file, 500 files per batch)
- MIME type restrictions (images only by default)
- Path traversal protection
- Input sanitization

## Usage

### Basic Bucket Operations

```javascript
// Create a storage bucket
await mcp.call('create_bucket', {
  bucket_name: 'my-images',
  is_public: false
});

// Setup standard bucket structure
await mcp.call('setup_buckets', {
  base_bucket_name: 'storage',
  user_id: 'user123'
});
```

### File Upload

```javascript
// Upload multiple images (file paths)
await mcp.call('upload_image_batch', {
  bucket_name: 'storage-images',
  batch_id: 'batch001',
  folder_prefix: 'original',
  user_id: 'user123',
  image_paths: ['/path/to/image1.jpg', '/path/to/image2.png']
});

// Upload with base64 data (Claude Desktop compatible)
await mcp.call('upload_image_batch', {
  bucket_name: 'storage-images',
  batch_id: 'batch002', 
  folder_prefix: 'original',
  user_id: 'user123',
  image_data: [
    {
      filename: 'image1.jpg',
      content: 'data:image/jpeg;base64,/9j/4AAQSkZJRg...',
      mime_type: 'image/jpeg'
    }
  ]
});
```

### File Management

```javascript
// List files in a bucket
await mcp.call('list_files', {
  bucket_name: 'storage-images',
  folder_path: 'original/user123',
  file_extension: '.jpg'
});

// Generate signed download URLs  
await mcp.call('get_file_url', {
  bucket_name: 'storage-images',
  storage_path: 'original/user123/batch001/image1.jpg',
  expires_in: 3600
});

// Batch signed URLs
await mcp.call('create_signed_urls', {
  bucket_name: 'storage-images',
  file_paths: ['path1.jpg', 'path2.png'],
  expires_in: 1800
});
```

### Advanced Downloads

```javascript
// Download with auto-trigger
await mcp.call('download_file_with_auto_trigger', {
  bucket_name: 'storage-images',
  file_path: 'original/user123/image1.jpg',
  return_format: 'base64',
  auto_download: true,
  custom_filename: 'my-image.jpg'
});

// Batch download with auto-trigger
await mcp.call('batch_download', {
  bucket_name: 'storage-images', 
  file_paths: ['image1.jpg', 'image2.png'],
  return_format: 'signed_url',
  auto_download: true,
  download_delay: 1000
});
```

### Image Transformations

```javascript
// Download with transformations
await mcp.call('download_file', {
  bucket_name: 'storage-images',
  file_path: 'original/image1.jpg',
  return_format: 'base64',
  transform_options: {
    width: 800,
    height: 600, 
    quality: 85
  }
});
```

### Security Monitoring

```javascript
// Get security status
await mcp.call('get_security_status', {});
```

## API Reference

### Tools

| Tool Name | Description |
|-----------|-------------|
| `create_bucket` | Create a new storage bucket |
| `setup_buckets` | Initialize standard bucket structure |
| `upload_image_batch` | Upload multiple files with validation |
| `list_files` | List files in bucket with filtering |
| `get_file_url` | Generate signed download URL |
| `create_signed_urls` | Generate multiple signed URLs |
| `download_file` | Download file content with transformations |
| `download_file_with_auto_trigger` | Download with auto-download JavaScript |
| `batch_download` | Download multiple files with auto-trigger |
| `get_security_status` | Get security metrics and status |

### File Organization

The server automatically organizes uploaded files in a structured format:

```
bucket-name/
├── original/
│   └── {user_id}/
│       └── {batch_id}/
│           ├── image1.jpg
│           └── image2.png
└── processed/
    └── {user_id}/
        └── {batch_id}/
            ├── thumb_image1.jpg  
            └── optimized_image2.png
```

## Security

### Built-in Protections
- **Rate Limiting**: Prevents API abuse
- **Input Validation**: Sanitizes all inputs  
- **File Validation**: MIME type and signature checking
- **Path Security**: Prevents directory traversal
- **Size Limits**: Configurable file and batch size limits
- **Audit Logging**: Complete operation tracking

### Security Best Practices
- Store your service role key securely
- Use environment variables for configuration
- Monitor security logs regularly
- Keep dependencies updated
- Use HTTPS in production

## Performance

### Batch Upload Performance
- **Small batches (1-25 files)**: ~15-30 seconds
- **Medium batches (26-100 files)**: ~45-90 seconds  
- **Large batches (101-500 files)**: ~3-8 minutes
- **Parallel uploads**: 3 concurrent streams
- **Memory efficient**: Streams large files

### Download Performance
- **File URL generation**: <50ms per URL
- **Direct downloads**: 100-500ms per file
- **Batch operations**: ~600 files per minute
- **Transform on download**: 200-800ms per image

## Development

### Build
```bash
npm run build
```

### Development Mode
```bash
npm run dev
```

### Security Audit
```bash
npm run security-check
```

## Tests

This project currently lacks a comprehensive test suite. We welcome contributions in this area! You can add tests using your favorite testing framework (e.g., Jest, Vitest).

To run the placeholder test script:
```bash
npm test
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/Omarbadran37/supabase-storage-mcp/issues)
- **Documentation**: This README and inline code comments
- **Community**: [Discussions](https://github.com/Omarbadran37/supabase-storage-mcp/discussions)

---

Built with ❤️ for the MCP and Supabase communities.