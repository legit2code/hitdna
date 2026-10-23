import { SourceSpan } from './types.ts';

export function cryptoHash(data: string | Uint8Array): string {
  // 1. If in Node environment with node crypto available
  if (typeof globalThis !== 'undefined' && (globalThis as any).process?.versions?.node) {
    try {
      // Dynamic require or global crypto
      const nodeCrypto = (globalThis as any).crypto || (typeof require !== 'undefined' ? require('crypto') : null);
      if (nodeCrypto?.createHash) {
        return nodeCrypto.createHash('sha256').update(data).digest('hex');
      }
    } catch {
      // fallback to fast deterministic hashing below
    }
  }

  // 2. Browser & Universal deterministic fallback
  const str = typeof data === 'string' ? data : new TextDecoder().decode(data);
  let h1 = 0xdeadbeef ^ 0;
  let h2 = 0x41c6ce57 ^ 0;
  for (let i = 0, ch: number; i < str.length; i++) {
    ch = str.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  const part1 = (4294967296 * (2097151 & h2) + (h1 >>> 0)).toString(16).padStart(16, '0');
  const part2 = (4294967296 * (2097151 & h1) + (h2 >>> 0)).toString(16).padStart(16, '0');
  return (part1 + part2 + part1 + part2).slice(0, 64);
}

export class SourceSpanUtil {
  /**
   * Precomputes newline indices for fast O(log N) line and column calculations
   */
  public static createLineIndex(sourceText: string): number[] {
    const lineStarts: number[] = [0];
    for (let i = 0; i < sourceText.length; i++) {
      if (sourceText[i] === '\n') {
        lineStarts.push(i + 1);
      }
    }
    return lineStarts;
  }

  /**
   * Converts a byte/character offset range to a SourceSpan
   */
  public static offsetToSpan(
    filePath: string,
    sourceText: string,
    startIndex: number,
    endIndex: number,
    lineStarts: number[],
    symbolHint?: string
  ): SourceSpan {
    const safeStart = Math.max(0, Math.min(startIndex, sourceText.length));
    const safeEnd = Math.max(safeStart, Math.min(endIndex, sourceText.length));

    const start = this.indexToLineCol(safeStart, lineStarts);
    const end = this.indexToLineCol(safeEnd, lineStarts);

    const slice = sourceText.substring(safeStart, safeEnd);

    return {
      file_path: filePath,
      start_line: start.line,
      start_col: start.col,
      end_line: end.line,
      end_col: end.col,
      byte_offset_start: safeStart,
      byte_offset_end: safeEnd,
      text_slice: slice.length > 200 ? slice.substring(0, 197) + '...' : slice,
      symbol_hint: symbolHint,
    };
  }

  /**
   * Fast binary search for finding the line number (1-indexed) and column (1-indexed)
   */
  public static indexToLineCol(index: number, lineStarts: number[]): { line: number; col: number } {
    let low = 0;
    let high = lineStarts.length - 1;
    let lineIdx = 0;

    while (low <= high) {
      const mid = Math.floor((low + high) / 2);
      if (lineStarts[mid] <= index) {
        lineIdx = mid;
        low = mid + 1;
      } else {
        high = mid - 1;
      }
    }

    const line = lineIdx + 1;
    const col = index - lineStarts[lineIdx] + 1;
    return { line, col };
  }
}
