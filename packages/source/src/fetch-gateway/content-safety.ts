import { ResponseSizeExceededError, ContentTypeBlockedError } from './errors.ts';

export class ContentSafetyValidator {
  private static readonly DEFAULT_BLOCKED_CONTENT_TYPES = [
    'application/x-dosexec',
    'application/x-msdownload',
    'application/x-executable',
    'application/x-sharedlib',
    'application/x-sh',
    'application/x-csh',
    'application/x-bat',
  ];

  constructor(
    private readonly defaultMaxBytes: number = 25 * 1024 * 1024, // 25 MB
    private readonly blockedMimeTypes: string[] = ContentSafetyValidator.DEFAULT_BLOCKED_CONTENT_TYPES
  ) {}

  /**
   * Validates headers before downloading the payload.
   */
  validateHeaders(headers: Record<string, string>, maxBytesOverride?: number): void {
    const maxBytes = maxBytesOverride ?? this.defaultMaxBytes;

    // 1. Content-Length check
    const contentLengthHeader = headers['content-length'];
    if (contentLengthHeader) {
      const length = parseInt(contentLengthHeader, 10);
      if (!isNaN(length) && length > maxBytes) {
        throw new ResponseSizeExceededError(
          `Response Content-Length (${length} bytes) exceeds maximum permitted limit (${maxBytes} bytes).`,
          { declaredBytes: length, limitBytes: maxBytes }
        );
      }
    }

    // 2. Content-Type check
    const contentTypeHeader = headers['content-type'];
    if (contentTypeHeader) {
      const mime = contentTypeHeader.split(';')[0].trim().toLowerCase();
      for (const blocked of this.blockedMimeTypes) {
        if (mime === blocked.toLowerCase()) {
          throw new ContentTypeBlockedError(
            `Response Content-Type '${mime}' is blocked by untrusted content security policy.`,
            { mime }
          );
        }
      }
    }
  }

  /**
   * Validates received buffer size.
   */
  validateReceivedBytes(receivedBytes: number, maxBytesOverride?: number): void {
    const maxBytes = maxBytesOverride ?? this.defaultMaxBytes;
    if (receivedBytes > maxBytes) {
      throw new ResponseSizeExceededError(
        `Received content stream size (${receivedBytes} bytes) exceeded maximum permitted limit (${maxBytes} bytes).`,
        { receivedBytes, limitBytes: maxBytes }
      );
    }
  }
}
