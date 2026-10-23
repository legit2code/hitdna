/**
 * Software License & Legal Compliance Engine
 * Standard: SPDX 3.0 License Identifiers & Open Source Risk Classification
 */

import { PackageIdentifier, LicenseComplianceResult } from '../types.ts';

export class LicenseComplianceEngine {
  private static readonly PERMISSIVE_LICENSES = new Set([
    'MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC', 'CC0-1.0', 'Unlicense', 'Zlib', '0BSD'
  ]);

  private static readonly WEAK_COPYLEFT_LICENSES = new Set([
    'LGPL-2.1', 'LGPL-3.0', 'MPL-2.0', 'EPL-2.0', 'CDDL-1.0'
  ]);

  private static readonly STRONG_COPYLEFT_LICENSES = new Set([
    'GPL-2.0', 'GPL-3.0', 'AGPL-3.0', 'SSPL-1.0', 'EUPL-1.2'
  ]);

  /**
   * Evaluates legal and license compliance across components
   */
  public static evaluate(components: PackageIdentifier[]): LicenseComplianceResult[] {
    return components.map(comp => {
      const rawLicense = comp.license || 'UNKNOWN';
      const normalizedSpdx = LicenseComplianceEngine.normalizeSpdx(rawLicense);
      
      let classification: LicenseComplianceResult['classification'] = 'UNKNOWN';
      let risk: LicenseComplianceResult['compliance_risk'] = 'LOW';
      let notes = 'Permissive open source license suitable for standard enterprise integration.';

      if (LicenseComplianceEngine.PERMISSIVE_LICENSES.has(normalizedSpdx)) {
        classification = 'PERMISSIVE';
        risk = 'LOW';
      } else if (LicenseComplianceEngine.WEAK_COPYLEFT_LICENSES.has(normalizedSpdx)) {
        classification = 'WEAK_COPYLEFT';
        risk = 'MEDIUM';
        notes = 'Weak copyleft license: dynamic linking permissible, source modifications to library must be disclosed.';
      } else if (LicenseComplianceEngine.STRONG_COPYLEFT_LICENSES.has(normalizedSpdx)) {
        classification = 'STRONG_COPYLEFT';
        risk = 'HIGH';
        notes = 'Strong copyleft / reciprocal license: integration may require disclosing complete proprietary agent source.';
      } else if (rawLicense.toLowerCase().includes('commercial') || rawLicense.toLowerCase().includes('proprietary')) {
        classification = 'COMMERCIAL_RESTRICTIVE';
        risk = 'MEDIUM';
        notes = 'Commercial or proprietary terms apply.';
      } else {
        classification = 'UNKNOWN';
        risk = 'MEDIUM';
        notes = 'Undeclared or custom license requires legal review.';
      }

      return {
        purl: comp.purl,
        package_name: comp.name,
        declared_license: rawLicense,
        normalized_spdx: normalizedSpdx,
        classification,
        compliance_risk: risk,
        notes,
      };
    });
  }

  private static normalizeSpdx(raw: string): string {
    const trimmed = raw.trim();
    if (/^mit$/i.test(trimmed)) return 'MIT';
    if (/^apache[\s\-]?2(?:\.0)?$/i.test(trimmed)) return 'Apache-2.0';
    if (/^bsd[\s\-]?3[\s\-]?clause$/i.test(trimmed)) return 'BSD-3-Clause';
    if (/^bsd[\s\-]?2[\s\-]?clause$/i.test(trimmed)) return 'BSD-2-Clause';
    if (/^isc$/i.test(trimmed)) return 'ISC';
    if (/^gpl[\s\-]?3(?:\.0)?$/i.test(trimmed)) return 'GPL-3.0';
    if (/^gpl[\s\-]?2(?:\.0)?$/i.test(trimmed)) return 'GPL-2.0';
    if (/^agpl[\s\-]?3(?:\.0)?$/i.test(trimmed)) return 'AGPL-3.0';
    if (/^mpl[\s\-]?2(?:\.0)?$/i.test(trimmed)) return 'MPL-2.0';
    if (/^lgpl[\s\-]?3(?:\.0)?$/i.test(trimmed)) return 'LGPL-3.0';
    return trimmed;
  }
}
