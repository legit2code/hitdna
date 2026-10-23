import { FileTypeInfo, FileFormatCategory, DetectedEncoding } from './types.ts';

export class EncodingDetector {
  /**
   * Detects encoding, MIME type, format category, and language for a given file
   */
  public static detect(filePath: string, bufferOrString: Buffer | Uint8Array | string): FileTypeInfo {
    const rawBuffer = typeof bufferOrString === 'string' 
      ? Buffer.from(bufferOrString, 'utf-8') 
      : Buffer.from(bufferOrString);
    
    const byteSize = rawBuffer.length;
    const fileName = filePath.split('/').pop() || filePath;
    const extension = fileName.includes('.') ? `.${fileName.split('.').pop()!.toLowerCase()}` : '';

    // 1. Magic byte inspection
    const magicSignature = this.detectMagicBytes(rawBuffer);
    const isBinaryByMagic = this.isBinarySignature(magicSignature);

    // 2. Encoding detection
    const encoding = this.detectEncoding(rawBuffer, isBinaryByMagic);
    const isBinary = encoding === 'binary' || isBinaryByMagic || this.containsNullBytes(rawBuffer);

    // 3. Format categorization & Language identification
    const { formatCategory, language, mimeType } = this.categorizeFormatAndLanguage(fileName, extension, isBinary, rawBuffer);

    return {
      format_category: formatCategory,
      language,
      mime_type: mimeType,
      encoding,
      extension,
      is_binary: isBinary,
      magic_signature: magicSignature || undefined,
      byte_size: byteSize,
    };
  }

  private static detectMagicBytes(buf: Buffer): string | null {
    if (buf.length < 2) return null;

    // UTF BOMs
    if (buf.length >= 3 && buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf) return 'BOM_UTF8';
    if (buf[0] === 0xff && buf[1] === 0xfe) return 'BOM_UTF16_LE';
    if (buf[0] === 0xfe && buf[1] === 0xff) return 'BOM_UTF16_BE';

    // Executable / Compiled binary headers
    if (buf.length >= 4 && buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) return 'ELF_BINARY';
    if (buf.length >= 4 && buf[0] === 0x00 && buf[1] === 0x61 && buf[2] === 0x73 && buf[3] === 0x6d) return 'WASM_BINARY';
    if (buf.length >= 4 && buf[0] === 0xca && buf[1] === 0xfe && buf[2] === 0xba && buf[3] === 0xbe) return 'JAVA_CLASS_MACH_O';
    if (buf.length >= 2 && buf[0] === 0x4d && buf[1] === 0x5a) return 'DOS_PE_BINARY';

    // Archive / Compression headers
    if (buf.length >= 4 && buf[0] === 0x50 && buf[1] === 0x4b && buf[2] === 0x03 && buf[3] === 0x04) return 'ZIP_ARCHIVE';
    if (buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b) return 'GZIP_COMPRESSED';
    if (buf.length >= 3 && buf[0] === 0x42 && buf[1] === 0x5a && buf[2] === 0x68) return 'BZIP2_COMPRESSED';
    if (buf.length >= 6 && buf.subarray(0, 6).toString('ascii') === '7z\xbc\xaf\x27\x1c') return '7ZIP_ARCHIVE';

    // Image / Media headers
    if (buf.length >= 8 && buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47) return 'PNG_IMAGE';
    if (buf.length >= 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return 'JPEG_IMAGE';
    if (buf.length >= 4 && buf.subarray(0, 4).toString('ascii') === 'GIF8') return 'GIF_IMAGE';

    // Model weight formats
    if (buf.length >= 12 && buf.subarray(0, 4).toString('ascii') === 'ONNX') return 'ONNX_MODEL';
    if (buf.length >= 8) {
      // Safetensors begins with 8-byte little-endian header length (usually JSON follows)
      try {
        const headerLen = buf.readBigUInt64LE(0);
        if (headerLen > 0n && headerLen < 100_000_000n && buf.length > 8) {
          const firstChar = String.fromCharCode(buf[8]);
          if (firstChar === '{') return 'SAFETENSORS_MODEL';
        }
      } catch {}
    }

    return null;
  }

  private static isBinarySignature(magic: string | null): boolean {
    if (!magic) return false;
    return [
      'ELF_BINARY',
      'WASM_BINARY',
      'JAVA_CLASS_MACH_O',
      'DOS_PE_BINARY',
      'ZIP_ARCHIVE',
      'GZIP_COMPRESSED',
      'BZIP2_COMPRESSED',
      '7ZIP_ARCHIVE',
      'PNG_IMAGE',
      'JPEG_IMAGE',
      'GIF_IMAGE',
      'ONNX_MODEL',
      'SAFETENSORS_MODEL'
    ].includes(magic);
  }

  private static detectEncoding(buf: Buffer, isBinaryByMagic: boolean): DetectedEncoding {
    if (isBinaryByMagic) return 'binary';

    if (buf.length >= 3 && buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf) return 'utf-8';
    if (buf.length >= 2 && buf[0] === 0xff && buf[1] === 0xfe) return 'utf-16le';
    if (buf.length >= 2 && buf[0] === 0xfe && buf[1] === 0xff) return 'utf-16be';

    // Sample first 4KB to check character validity
    const sampleSize = Math.min(buf.length, 4096);
    let nullCount = 0;
    let isAscii = true;

    for (let i = 0; i < sampleSize; i++) {
      const b = buf[i];
      if (b === 0) nullCount++;
      if (b > 127) isAscii = false;
    }

    // Binary heuristic: null bytes in initial sample
    if (nullCount > 0 && sampleSize > 10 && nullCount / sampleSize > 0.01) {
      return 'binary';
    }

    // Test UTF-8 decoding
    try {
      const decoder = new TextDecoder('utf-8', { fatal: true });
      decoder.decode(buf.subarray(0, sampleSize));
      return isAscii ? 'ascii' : 'utf-8';
    } catch {
      return 'iso-8859-1';
    }
  }

  private static containsNullBytes(buf: Buffer): boolean {
    const sampleSize = Math.min(buf.length, 1024);
    for (let i = 0; i < sampleSize; i++) {
      if (buf[i] === 0) return true;
    }
    return false;
  }

  private static categorizeFormatAndLanguage(
    fileName: string, 
    ext: string, 
    isBinary: boolean, 
    rawBuffer: Buffer
  ): { formatCategory: FileFormatCategory; language: string; mimeType: string } {
    const lowerName = fileName.toLowerCase();

    // 1. Binary or Weights
    if (isBinary || ['.safetensors', '.onnx', '.pt', '.pth', '.bin', '.pkl', '.wasm', '.h5', '.tflite', '.so', '.dylib', '.dll', '.exe', '.class', '.pyc'].includes(ext)) {
      return {
        formatCategory: 'BINARY_COMPILED',
        language: ext.replace('.', '') || 'binary',
        mimeType: 'application/octet-stream',
      };
    }

    // 2. Container & Infrastructure
    if (lowerName === 'dockerfile' || lowerName.startsWith('dockerfile.') || lowerName === 'containerfile' || lowerName.startsWith('containerfile.')) {
      return { formatCategory: 'CONTAINER_INFRA', language: 'dockerfile', mimeType: 'text/x-dockerfile' };
    }
    if (lowerName === 'docker-compose.yml' || lowerName === 'docker-compose.yaml' || lowerName.startsWith('compose.')) {
      return { formatCategory: 'CONTAINER_INFRA', language: 'docker-compose', mimeType: 'application/x-yaml' };
    }
    if (lowerName === 'vagrantfile' || lowerName === 'procfile') {
      return { formatCategory: 'CONTAINER_INFRA', language: lowerName, mimeType: 'text/plain' };
    }

    // 3. Structured Data & Manifests
    if (['.json', '.jsonc', '.json5'].includes(ext)) {
      if (lowerName === 'package.json') return { formatCategory: 'STRUCTURED_DATA', language: 'json-package', mimeType: 'application/json' };
      if (lowerName === 'tsconfig.json') return { formatCategory: 'STRUCTURED_DATA', language: 'json-tsconfig', mimeType: 'application/json' };
      return { formatCategory: 'STRUCTURED_DATA', language: 'json', mimeType: 'application/json' };
    }
    if (['.yaml', '.yml'].includes(ext)) {
      return { formatCategory: 'STRUCTURED_DATA', language: 'yaml', mimeType: 'application/x-yaml' };
    }
    if (ext === '.toml') {
      if (lowerName === 'pyproject.toml') return { formatCategory: 'STRUCTURED_DATA', language: 'toml-pyproject', mimeType: 'application/toml' };
      if (lowerName === 'cargo.toml') return { formatCategory: 'STRUCTURED_DATA', language: 'toml-cargo', mimeType: 'application/toml' };
      return { formatCategory: 'STRUCTURED_DATA', language: 'toml', mimeType: 'application/toml' };
    }
    if (['.xml', '.xsd', '.wsdl'].includes(ext) || lowerName === 'pom.xml') {
      return { formatCategory: 'STRUCTURED_DATA', language: 'xml', mimeType: 'application/xml' };
    }
    if (['.ini', '.cfg', '.conf', '.properties'].includes(ext) || lowerName === 'setup.cfg') {
      return { formatCategory: 'STRUCTURED_DATA', language: 'ini', mimeType: 'text/plain' };
    }
    if (lowerName === '.env' || lowerName.startsWith('.env.')) {
      return { formatCategory: 'STRUCTURED_DATA', language: 'dotenv', mimeType: 'text/plain' };
    }
    if (lowerName === 'requirements.txt' || lowerName.startsWith('requirements-')) {
      return { formatCategory: 'STRUCTURED_DATA', language: 'requirements.txt', mimeType: 'text/plain' };
    }
    if (lowerName === 'pipfile') {
      return { formatCategory: 'STRUCTURED_DATA', language: 'pipfile', mimeType: 'text/plain' };
    }
    if (lowerName === 'go.mod') {
      return { formatCategory: 'STRUCTURED_DATA', language: 'go.mod', mimeType: 'text/plain' };
    }
    if (lowerName === 'go.sum') {
      return { formatCategory: 'STRUCTURED_DATA', language: 'go.sum', mimeType: 'text/plain' };
    }

    // 4. Specification & Schema Definitions
    if (['.proto', '.protodefs'].includes(ext)) {
      return { formatCategory: 'SPECIFICATION_SCHEMA', language: 'protobuf', mimeType: 'application/x-protobuf' };
    }
    if (['.graphql', '.gql'].includes(ext)) {
      return { formatCategory: 'SPECIFICATION_SCHEMA', language: 'graphql', mimeType: 'application/graphql' };
    }
    if (lowerName.includes('openapi') || lowerName.includes('swagger') || lowerName.includes('asyncapi')) {
      return { formatCategory: 'SPECIFICATION_SCHEMA', language: 'api-specification', mimeType: ext.includes('json') ? 'application/json' : 'application/x-yaml' };
    }

    // 5. Source Code
    if (['.ts', '.mts', '.cts'].includes(ext)) return { formatCategory: 'SOURCE_CODE', language: 'typescript', mimeType: 'application/typescript' };
    if (['.tsx'].includes(ext)) return { formatCategory: 'SOURCE_CODE', language: 'typescriptreact', mimeType: 'application/typescript' };
    if (['.js', '.mjs', '.cjs'].includes(ext)) return { formatCategory: 'SOURCE_CODE', language: 'javascript', mimeType: 'application/javascript' };
    if (['.jsx'].includes(ext)) return { formatCategory: 'SOURCE_CODE', language: 'javascriptreact', mimeType: 'application/javascript' };
    if (['.py', '.pyi', '.pyx'].includes(ext)) return { formatCategory: 'SOURCE_CODE', language: 'python', mimeType: 'text/x-python' };
    if (['.go'].includes(ext)) return { formatCategory: 'SOURCE_CODE', language: 'go', mimeType: 'text/x-go' };
    if (['.rs'].includes(ext)) return { formatCategory: 'SOURCE_CODE', language: 'rust', mimeType: 'text/x-rust' };
    if (['.java'].includes(ext)) return { formatCategory: 'SOURCE_CODE', language: 'java', mimeType: 'text/x-java-source' };
    if (['.kt', '.kts'].includes(ext)) return { formatCategory: 'SOURCE_CODE', language: 'kotlin', mimeType: 'text/x-kotlin' };
    if (['.c', '.h'].includes(ext)) return { formatCategory: 'SOURCE_CODE', language: 'c', mimeType: 'text/x-c' };
    if (['.cpp', '.hpp', '.cc', '.cxx'].includes(ext)) return { formatCategory: 'SOURCE_CODE', language: 'cpp', mimeType: 'text/x-c++src' };
    if (['.rb'].includes(ext)) return { formatCategory: 'SOURCE_CODE', language: 'ruby', mimeType: 'text/x-ruby' };
    if (['.php'].includes(ext)) return { formatCategory: 'SOURCE_CODE', language: 'php', mimeType: 'text/x-php' };
    if (['.sh', '.bash', '.zsh'].includes(ext)) return { formatCategory: 'SOURCE_CODE', language: 'shell', mimeType: 'application/x-sh' };

    // 6. Documentation
    if (['.md', '.markdown'].includes(ext)) return { formatCategory: 'DOCUMENTATION', language: 'markdown', mimeType: 'text/markdown' };
    if (['.rst', '.txt', '.adoc'].includes(ext)) return { formatCategory: 'DOCUMENTATION', language: 'plaintext', mimeType: 'text/plain' };
    if (['.html', '.htm'].includes(ext)) return { formatCategory: 'DOCUMENTATION', language: 'html', mimeType: 'text/html' };

    // 7. Fallback / Unknown
    return {
      formatCategory: 'UNKNOWN_UNSUPPORTED',
      language: ext.replace('.', '') || 'unknown',
      mimeType: 'text/plain',
    };
  }
}
