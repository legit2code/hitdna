/**
 * Summary CSV Generator for Auditing & Compliance
 * Produces deterministic, tabular summaries of findings, risks, and dependencies.
 */

export interface SummaryRow {
  itemType: 'FINDING' | 'RISK_SCORE' | 'POLICY' | 'VALIDATION' | 'DEPENDENCY' | 'APPROVAL';
  identifier: string;
  severity: string;
  category: string;
  status: string;
  details: string;
}

export class SummaryCsvGenerator {
  /**
   * Generates a deterministic CSV string from summary rows.
   */
  static generateCsv(rows: SummaryRow[]): string {
    const headers = ['item_type', 'identifier', 'severity', 'category', 'status', 'details'];
    
    // Sort rows deterministically by itemType, identifier, severity
    const sorted = [...rows].sort((a, b) => {
      const typeCmp = a.itemType.localeCompare(b.itemType);
      if (typeCmp !== 0) return typeCmp;
      const idCmp = a.identifier.localeCompare(b.identifier);
      if (idCmp !== 0) return idCmp;
      return a.severity.localeCompare(b.severity);
    });

    const escapeCsv = (val: string) => {
      const str = String(val ?? '');
      if (str.includes(',') || str.includes('"') || str.includes('\n')) {
        return `"${str.replace(/"/g, '""')}"`;
      }
      return str;
    };

    const lines = [
      headers.join(','),
      ...sorted.map((r) => [
        escapeCsv(r.itemType),
        escapeCsv(r.identifier),
        escapeCsv(r.severity),
        escapeCsv(r.category),
        escapeCsv(r.status),
        escapeCsv(r.details),
      ].join(',')),
    ];

    return lines.join('\n') + '\n';
  }
}
