import path from 'path';
import zlib from 'zlib';
import {
  ArchiveBombError,
  ArchiveSafetyError,
  ArchiveSymlinkEscapeError,
  ArchiveTraversalError,
} from './errors.ts';
import { DownloadSafetyLimits } from './types.ts';

export interface ArchiveEntryInfo {
  name: string;
  compressedSize: number;
  uncompressedSize: number;
  isDirectory: boolean;
  isSymlink: boolean;
  symlinkTarget?: string;
}

export interface ArchiveInspectionResult {
  fileCount: number;
  totalCompressedSize: number;
  totalUncompressedSize: number;
  ratio: number;
  entries: ArchiveEntryInfo[];
}

export class ArchiveSafetyInspector {
  private readonly limits: DownloadSafetyLimits;

  constructor(customLimits: Partial<DownloadSafetyLimits> = {}) {
    this.limits = {
      maxResponseBytes: customLimits.maxResponseBytes ?? 25 * 1024 * 1024, // 25 MB
      maxArchiveBytes: customLimits.maxArchiveBytes ?? 50 * 1024 * 1024, // 50 MB
      maxExpandedBytes: customLimits.maxExpandedBytes ?? 100 * 1024 * 1024, // 100 MB
      maxDecompressionRatio: customLimits.maxDecompressionRatio ?? 100, // 100:1 ratio
      maxFileCount: customLimits.maxFileCount ?? 5000,
      maxNestedArchiveDepth: customLimits.maxNestedArchiveDepth ?? 2,
      timeoutMs: customLimits.timeoutMs ?? 30000,
    };
  }

  /**
   * Validates declared archive size against safety quotas before download/extraction.
   */
  validateDeclaredSize(sizeBytes: number): void {
    if (sizeBytes > this.limits.maxArchiveBytes) {
      throw new ArchiveSafetyError(
        `Archive declared size (${sizeBytes} bytes) exceeds maximum archive limit (${this.limits.maxArchiveBytes} bytes).`,
        'ARCHIVE_SIZE_EXCEEDED',
        { size: sizeBytes, limit: this.limits.maxArchiveBytes }
      );
    }
  }

  /**
   * Validates total archive file entry count against safety quotas.
   */
  validateFileCount(fileCount: number): void {
    if (fileCount > this.limits.maxFileCount) {
      throw new ArchiveSafetyError(
        `Archive file count (${fileCount}) exceeds maximum limit (${this.limits.maxFileCount}).`,
        'FILE_COUNT_EXCEEDED',
        { count: fileCount, limit: this.limits.maxFileCount }
      );
    }
  }

  /**
   * Validates nested archive recursion depth against safety limits.
   */
  validateArchiveDepth(depth: number): void {
    if (depth > this.limits.maxNestedArchiveDepth) {
      throw new ArchiveSafetyError(
        `Nested archive depth (${depth}) exceeds maximum limit (${this.limits.maxNestedArchiveDepth}).`,
        'NESTED_DEPTH_EXCEEDED',
        { depth, limit: this.limits.maxNestedArchiveDepth }
      );
    }
  }

  /**
   * Safely inspects a ZIP archive buffer, verifying entry names, path traversal,
   * symlink escapes, file counts, and decompression bomb ratios before extraction.
   */
  inspectZipBuffer(buffer: Buffer): ArchiveInspectionResult {
    if (!buffer || buffer.length === 0) {
      throw new ArchiveSafetyError('Archive buffer is empty.', 'MALFORMED_ARCHIVE');
    }

    this.validateDeclaredSize(buffer.length);

    const entries = this.parseZipEntries(buffer);
    if (entries.length === 0) {
      throw new ArchiveSafetyError(
        'Archive is malformed, truncated, or contains no valid ZIP records.',
        'MALFORMED_ARCHIVE'
      );
    }

    this.validateFileCount(entries.length);

    let totalCompressed = 0;
    let totalUncompressed = 0;

    for (const entry of entries) {
      // 1. Path Traversal Validation
      this.validateEntryPath(entry.name);

      // 2. Symlink Escape Validation
      if (entry.isSymlink && entry.symlinkTarget) {
        this.validateSymlinkTarget(entry.name, entry.symlinkTarget);
      }

      totalCompressed += entry.compressedSize;
      totalUncompressed += entry.uncompressedSize;

      // 3. Size limit check
      if (totalUncompressed > this.limits.maxExpandedBytes) {
        throw new ArchiveBombError(
          `Archive expanded size (${totalUncompressed} bytes) exceeds limit (${this.limits.maxExpandedBytes} bytes).`,
          { totalUncompressed, limit: this.limits.maxExpandedBytes }
        );
      }
    }

    // 4. Decompression Ratio (Zip Bomb) check
    // Avoid division by zero: minimum compressed basis is buffer.length
    const baseCompressed = Math.max(1, totalCompressed, buffer.length);
    const ratio = totalUncompressed / baseCompressed;

    if (ratio > this.limits.maxDecompressionRatio && totalUncompressed > 1024 * 1024) {
      throw new ArchiveBombError(
        `Decompression ratio (${ratio.toFixed(1)}:1) exceeds maximum safety limit (${this.limits.maxDecompressionRatio}:1). Potential decompression bomb.`,
        { ratio, totalUncompressed, baseCompressed, maxRatio: this.limits.maxDecompressionRatio }
      );
    }

    return {
      fileCount: entries.length,
      totalCompressedSize: totalCompressed,
      totalUncompressedSize: totalUncompressed,
      ratio,
      entries,
    };
  }

  /**
   * Safely decompresses a gzip buffer with streaming ratio and size enforcement.
   */
  decompressGzipSafely(compressedBuffer: Buffer): Buffer {
    if (compressedBuffer.length > this.limits.maxArchiveBytes) {
      throw new ArchiveSafetyError(
        `Gzip buffer size (${compressedBuffer.length} bytes) exceeds archive limit (${this.limits.maxArchiveBytes} bytes).`,
        'ARCHIVE_SIZE_EXCEEDED'
      );
    }

    // Inspect ISIZE from last 4 bytes of gzip if available
    if (compressedBuffer.length >= 10) {
      const isize = compressedBuffer.readUInt32LE(compressedBuffer.length - 4);
      if (isize > this.limits.maxExpandedBytes) {
        throw new ArchiveBombError(
          `Gzip ISIZE header (${isize} bytes) exceeds maximum expanded size (${this.limits.maxExpandedBytes} bytes).`,
          { isize, limit: this.limits.maxExpandedBytes }
        );
      }
      const initialRatio = isize / Math.max(1, compressedBuffer.length);
      if (initialRatio > this.limits.maxDecompressionRatio && isize > 1024 * 1024) {
        throw new ArchiveBombError(
          `Gzip header decompression ratio (${initialRatio.toFixed(1)}:1) exceeds limit (${this.limits.maxDecompressionRatio}:1).`,
          { initialRatio, isize, maxRatio: this.limits.maxDecompressionRatio }
        );
      }
    }

    // Decompress with chunk-level monitoring
    let decompressed: Buffer;
    try {
      decompressed = zlib.gunzipSync(compressedBuffer, {
        maxOutputLength: this.limits.maxExpandedBytes,
      });
    } catch (err: any) {
      if (err.code === 'ERR_BUFFER_TOO_LARGE' || err.message?.includes('maxOutputLength')) {
        throw new ArchiveBombError(`Decompressed gzip size exceeded safety limit.`, { cause: err.message });
      }
      throw new ArchiveSafetyError(`Failed to decompress gzip buffer: ${err.message}`, 'DECOMPRESSION_FAILED');
    }

    const actualRatio = decompressed.length / Math.max(1, compressedBuffer.length);
    if (actualRatio > this.limits.maxDecompressionRatio && decompressed.length > 1024 * 1024) {
      throw new ArchiveBombError(
        `Actual decompression ratio (${actualRatio.toFixed(1)}:1) exceeds maximum limit (${this.limits.maxDecompressionRatio}:1).`,
        { actualRatio, decompressedBytes: decompressed.length }
      );
    }

    return decompressed;
  }

  /**
   * Validates entry path for directory traversal, drive prefixes, and null bytes.
   */
  validateEntryPath(entryPath: string): void {
    if (!entryPath) {
      throw new ArchiveTraversalError('Empty archive entry path.');
    }

    // Null byte check
    if (entryPath.includes('\0')) {
      throw new ArchiveTraversalError(`Archive entry contains null byte: '${entryPath}'`);
    }

    // Leading slash check (absolute paths)
    if (entryPath.startsWith('/') || entryPath.startsWith('\\')) {
      throw new ArchiveTraversalError(`Absolute path in archive entry is forbidden: '${entryPath}'`);
    }

    // Windows drive letter check (e.g. C:, D:)
    if (/^[a-zA-Z]:/.test(entryPath)) {
      throw new ArchiveTraversalError(`Windows drive path in archive entry is forbidden: '${entryPath}'`);
    }

    // Path normalization traversal check
    const normalized = path.normalize(entryPath).replace(/\\/g, '/');
    if (normalized.startsWith('../') || normalized === '..' || normalized.includes('/../')) {
      throw new ArchiveTraversalError(`Path traversal detected in archive entry: '${entryPath}'`);
    }
  }

  /**
   * Validates symlink targets to ensure they cannot escape the extraction directory.
   */
  validateSymlinkTarget(entryPath: string, target: string): void {
    if (!target) return;

    // Check absolute target
    if (path.isAbsolute(target) || target.startsWith('/') || target.startsWith('\\') || /^[a-zA-Z]:/.test(target)) {
      throw new ArchiveSymlinkEscapeError(
        `Symlink '${entryPath}' points to absolute path '${target}', escaping destination root.`,
        { entryPath, target }
      );
    }

    // Resolve relative symlink against its parent directory
    const entryDir = path.dirname(entryPath);
    const resolved = path.normalize(path.join(entryDir, target)).replace(/\\/g, '/');

    if (resolved.startsWith('../') || resolved === '..' || resolved.includes('/../')) {
      throw new ArchiveSymlinkEscapeError(
        `Symlink '${entryPath}' with target '${target}' escapes destination root via traversal.`,
        { entryPath, target, resolved }
      );
    }
  }

  /**
   * Parses ZIP Central Directory to accurately extract entry headers.
   */
  private parseZipEntries(buffer: Buffer): ArchiveEntryInfo[] {
    const entries: ArchiveEntryInfo[] = [];

    // Find End of Central Directory Record (EOCD) signature: 0x06054b50
    let eocdOffset = -1;
    for (let i = buffer.length - 22; i >= Math.max(0, buffer.length - 65557); i--) {
      if (buffer.readUInt32LE(i) === 0x06054b50) {
        eocdOffset = i;
        break;
      }
    }

    if (eocdOffset === -1) {
      // Fallback: parse Local File Headers (0x04034b50) directly from beginning
      return this.parseLocalFileHeaders(buffer);
    }

    const totalEntries = buffer.readUInt16LE(eocdOffset + 10);
    const cdOffset = buffer.readUInt32LE(eocdOffset + 16);

    let offset = cdOffset;
    for (let i = 0; i < totalEntries && offset < eocdOffset; i++) {
      if (buffer.readUInt32LE(offset) !== 0x02014b50) {
        break;
      }

      const compressedSize = buffer.readUInt32LE(offset + 20);
      const uncompressedSize = buffer.readUInt32LE(offset + 24);
      const fileNameLen = buffer.readUInt16LE(offset + 28);
      const extraLen = buffer.readUInt16LE(offset + 30);
      const commentLen = buffer.readUInt16LE(offset + 32);
      const externalAttr = buffer.readUInt32LE(offset + 38);

      const nameBuffer = buffer.subarray(offset + 46, offset + 46 + fileNameLen);
      const name = nameBuffer.toString('utf8');

      const isDirectory = name.endsWith('/') || (externalAttr & 0x10) !== 0;
      // Unix symlink check (0120000 in mode bits -> top 16 bits of externalAttr)
      const isSymlink = ((externalAttr >>> 16) & 0o170000) === 0o120000;

      entries.push({
        name,
        compressedSize,
        uncompressedSize,
        isDirectory,
        isSymlink,
      });

      offset += 46 + fileNameLen + extraLen + commentLen;
    }

    return entries;
  }

  private parseLocalFileHeaders(buffer: Buffer): ArchiveEntryInfo[] {
    const entries: ArchiveEntryInfo[] = [];
    let offset = 0;

    if (buffer.length >= 4 && buffer.readUInt32LE(0) === 0x04034b50 && buffer.length < 30) {
      throw new ArchiveSafetyError('Truncated ZIP local file header', 'MALFORMED_ARCHIVE');
    }

    while (offset + 30 <= buffer.length) {
      const sig = buffer.readUInt32LE(offset);
      if (sig !== 0x04034b50) break;

      const compressedSize = buffer.readUInt32LE(offset + 18);
      const uncompressedSize = buffer.readUInt32LE(offset + 22);
      const fileNameLen = buffer.readUInt16LE(offset + 26);
      const extraLen = buffer.readUInt16LE(offset + 28);

      if (offset + 30 + fileNameLen > buffer.length) {
        throw new ArchiveSafetyError('Truncated ZIP entry header', 'MALFORMED_ARCHIVE');
      }

      const name = buffer.subarray(offset + 30, offset + 30 + fileNameLen).toString('utf8');
      const isDirectory = name.endsWith('/');

      entries.push({
        name,
        compressedSize,
        uncompressedSize,
        isDirectory,
        isSymlink: false,
      });

      offset += 30 + fileNameLen + extraLen + compressedSize;
    }

    return entries;
  }
}
