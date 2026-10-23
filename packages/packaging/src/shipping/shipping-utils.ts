import crypto from 'node:crypto';
import dns from 'node:dns';
import net from 'node:net';
import { SignedPackageBundle } from '../types.ts';

// Sensitive ports commonly targeted in SSRF attacks
const BLOCKED_PORTS = new Set([
  20, 21,    // FTP
  22,        // SSH
  23,        // Telnet
  25,        // SMTP
  53,        // DNS
  69,        // TFTP
  88,        // Kerberos
  110, 143,  // POP3 / IMAP
  161,       // SNMP
  389, 636,  // LDAP / LDAPS
  2375, 2376,// Docker daemon API
  3306,      // MySQL
  4243,      // Docker alternative
  5432,      // PostgreSQL
  6379,      // Redis
  9200,      // Elasticsearch
  10250,     // Kubelet API
  10255,     // Kubelet Read-Only
  27017,     // MongoDB
]);

/**
 * Parses alternative IPv4 representations (standard dotted, octal, hex, dword/integer, 2/3 part).
 * Returns array of 4 octet numbers [o1, o2, o3, o4] (each 0-255) if valid, or null.
 */
export function parseIpv4String(input: string): number[] | null {
  if (!input || typeof input !== 'string') return null;
  const str = input.trim().toLowerCase();

  const parts = str.split('.');
  if (parts.length < 1 || parts.length > 4) return null;

  const parsedNumbers: number[] = [];
  for (const part of parts) {
    if (part.length === 0) return null;
    let num: number;
    if (part.startsWith('0x')) {
      if (!/^0x[0-9a-f]+$/.test(part)) return null;
      num = parseInt(part, 16);
    } else if (part.length > 1 && part.startsWith('0')) {
      if (!/^0[0-7]+$/.test(part)) return null;
      num = parseInt(part, 8);
    } else {
      if (!/^\d+$/.test(part)) return null;
      num = parseInt(part, 10);
    }
    if (isNaN(num) || num < 0 || num > 0xffffffff) return null;
    parsedNumbers.push(num);
  }

  let o1 = 0, o2 = 0, o3 = 0, o4 = 0;
  if (parsedNumbers.length === 1) {
    const val = parsedNumbers[0];
    if (val > 0xffffffff) return null;
    o1 = (val >>> 24) & 255;
    o2 = (val >>> 16) & 255;
    o3 = (val >>> 8) & 255;
    o4 = val & 255;
  } else if (parsedNumbers.length === 2) {
    if (parsedNumbers[0] > 255 || parsedNumbers[1] > 0xffffff) return null;
    o1 = parsedNumbers[0];
    const val = parsedNumbers[1];
    o2 = (val >>> 16) & 255;
    o3 = (val >>> 8) & 255;
    o4 = val & 255;
  } else if (parsedNumbers.length === 3) {
    if (parsedNumbers[0] > 255 || parsedNumbers[1] > 255 || parsedNumbers[2] > 0xffff) return null;
    o1 = parsedNumbers[0];
    o2 = parsedNumbers[1];
    const val = parsedNumbers[2];
    o3 = (val >>> 8) & 255;
    o4 = val & 255;
  } else if (parsedNumbers.length === 4) {
    if (parsedNumbers.some(p => p > 255)) return null;
    [o1, o2, o3, o4] = parsedNumbers;
  }

  return [o1, o2, o3, o4];
}

/**
 * Checks if 4 octets fall within loopback, RFC1918 private, link-local, carrier-grade NAT, or metadata spaces.
 */
export function isPrivateOrBlockedIpv4(octets: number[]): { blocked: boolean; reason?: string } {
  const [o1, o2, o3, o4] = octets;

  // 0.0.0.0/8 (unspecified / broadcast)
  if (o1 === 0) {
    return { blocked: true, reason: `Unspecified/Current Network IPv4 0.0.0.0/8 (${o1}.${o2}.${o3}.${o4})` };
  }
  // 127.0.0.0/8 (Loopback)
  if (o1 === 127) {
    return { blocked: true, reason: `Loopback IPv4 127.0.0.0/8 (${o1}.${o2}.${o3}.${o4})` };
  }
  // 10.0.0.0/8 (Private RFC1918)
  if (o1 === 10) {
    return { blocked: true, reason: `Private RFC1918 IPv4 10.0.0.0/8 (${o1}.${o2}.${o3}.${o4})` };
  }
  // 172.16.0.0/12 (Private RFC1918: 172.16.0.0 - 172.31.255.255)
  if (o1 === 172 && o2 >= 16 && o2 <= 31) {
    return { blocked: true, reason: `Private RFC1918 IPv4 172.16.0.0/12 (${o1}.${o2}.${o3}.${o4})` };
  }
  // 192.168.0.0/16 (Private RFC1918)
  if (o1 === 192 && o2 === 168) {
    return { blocked: true, reason: `Private RFC1918 IPv4 192.168.0.0/16 (${o1}.${o2}.${o3}.${o4})` };
  }
  // 169.254.0.0/16 (Link-local / AWS / GCP / Azure IMDS Metadata)
  if (o1 === 169 && o2 === 254) {
    return { blocked: true, reason: `Link-Local / Cloud Instance Metadata IPv4 169.254.0.0/16 (${o1}.${o2}.${o3}.${o4})` };
  }
  // 100.64.0.0/10 (Shared Address Space / CGNAT RFC6598)
  if (o1 === 100 && o2 >= 64 && o2 <= 127) {
    return { blocked: true, reason: `Shared Address Space / CGNAT IPv4 100.64.0.0/10 (${o1}.${o2}.${o3}.${o4})` };
  }
  // 192.0.2.0/24 (TEST-NET-1)
  if (o1 === 192 && o2 === 0 && o3 === 2) {
    return { blocked: true, reason: `Documentation TEST-NET-1 IPv4 (${o1}.${o2}.${o3}.${o4})` };
  }
  // 198.51.100.0/24 (TEST-NET-2)
  if (o1 === 198 && o2 === 51 && o3 === 100) {
    return { blocked: true, reason: `Documentation TEST-NET-2 IPv4 (${o1}.${o2}.${o3}.${o4})` };
  }
  // 203.0.113.0/24 (TEST-NET-3)
  if (o1 === 203 && o2 === 0 && o3 === 113) {
    return { blocked: true, reason: `Documentation TEST-NET-3 IPv4 (${o1}.${o2}.${o3}.${o4})` };
  }
  // 224.0.0.0/4 (Multicast)
  if (o1 >= 224 && o1 <= 239) {
    return { blocked: true, reason: `Multicast IPv4 224.0.0.0/4 (${o1}.${o2}.${o3}.${o4})` };
  }
  // 240.0.0.0/4 (Reserved / Broadcast)
  if (o1 >= 240) {
    return { blocked: true, reason: `Reserved/Broadcast IPv4 240.0.0.0/4 (${o1}.${o2}.${o3}.${o4})` };
  }

  return { blocked: false };
}

/**
 * Checks if an IPv6 address falls within loopback, link-local, unique-local, or mapped IPv4 private spaces.
 */
export function isPrivateOrBlockedIpv6(ipv6: string): { blocked: boolean; reason?: string } {
  let clean = ipv6.trim().toLowerCase();
  if (clean.startsWith('[') && clean.endsWith(']')) {
    clean = clean.slice(1, -1);
  }

  // IPv4-mapped IPv6 (::ffff:127.0.0.1 or ::ffff:7f00:1 or ::ffff:169.254.169.254)
  if (clean.startsWith('::ffff:') || clean.startsWith('0:0:0:0:0:ffff:')) {
    const remainder = clean.replace(/^(::ffff:|0:0:0:0:0:ffff:)/, '');
    if (remainder.includes('.')) {
      const octets = parseIpv4String(remainder);
      if (octets) {
        const check = isPrivateOrBlockedIpv4(octets);
        if (check.blocked) {
          return { blocked: true, reason: `IPv4-mapped IPv6 pointing to private address: ${check.reason}` };
        }
      }
    } else {
      const hexParts = remainder.split(':');
      if (hexParts.length === 2) {
        const h1 = parseInt(hexParts[0], 16);
        const h2 = parseInt(hexParts[1], 16);
        if (!isNaN(h1) && !isNaN(h2)) {
          const octets = [(h1 >>> 8) & 255, h1 & 255, (h2 >>> 8) & 255, h2 & 255];
          const check = isPrivateOrBlockedIpv4(octets);
          if (check.blocked) {
            return { blocked: true, reason: `IPv4-mapped IPv6 pointing to private address: ${check.reason}` };
          }
        }
      }
    }
  }

  // IPv4-compatible IPv6 (deprecated ::x.x.x.x)
  if (clean.startsWith('::') && clean.includes('.')) {
    const remainder = clean.slice(2);
    const octets = parseIpv4String(remainder);
    if (octets) {
      const check = isPrivateOrBlockedIpv4(octets);
      if (check.blocked) {
        return { blocked: true, reason: `IPv4-compatible IPv6 pointing to private address: ${check.reason}` };
      }
    }
  }

  // Loopback (::1 or 0:0:0:0:0:0:0:1)
  if (clean === '::1' || clean === '0:0:0:0:0:0:0:1' || /^0*(:0*){6}:0*1$/.test(clean)) {
    return { blocked: true, reason: `Loopback IPv6 ::1 (${clean})` };
  }

  // Unspecified (:: or 0:0:0:0:0:0:0:0)
  if (clean === '::' || clean === '0:0:0:0:0:0:0:0' || /^0*(:0*)+$/.test(clean)) {
    return { blocked: true, reason: `Unspecified IPv6 :: (${clean})` };
  }

  // Link-Local (fe80::/10 -> fe80: to febf:)
  if (/^fe[89ab][0-9a-f]:/i.test(clean) || clean.startsWith('fe80:')) {
    return { blocked: true, reason: `Link-Local IPv6 fe80::/10 (${clean})` };
  }

  // Unique Local Address (fc00::/7 -> fc00: to fdff:, e.g. AWS IMDSv2 fd00:ec2::254)
  if (/^f[cd][0-9a-f]{2}:/i.test(clean)) {
    return { blocked: true, reason: `Unique Local / Cloud Metadata IPv6 fc00::/7 (${clean})` };
  }

  // Multicast (ff00::/8)
  if (clean.startsWith('ff')) {
    return { blocked: true, reason: `Multicast IPv6 ff00::/8 (${clean})` };
  }

  return { blocked: false };
}

/**
 * Validates against Server-Side Request Forgery (SSRF), private address spaces,
 * userinfo injection, blocked ports, and URL manipulation.
 */
export function validateRegistryHost(
  host: string,
  allowedHosts?: string[]
): { valid: boolean; error?: string; cleanHost?: string; port?: number } {
  if (!host || typeof host !== 'string') {
    return { valid: false, error: 'Registry host cannot be empty' };
  }

  // Reject userinfo (e.g. attacker@127.0.0.1 or user:pass@evil.com)
  if (host.includes('@')) {
    return { valid: false, error: `SSRF Violation: Userinfo in registry host is prohibited '${host}'` };
  }

  // Reject path, scheme, or query characters in host string
  if (/[/?#\\]/.test(host)) {
    return { valid: false, error: `SSRF Violation: Path, scheme, or query characters detected in host '${host}'` };
  }

  // Reject whitespace or control characters
  if (/[\s\x00-\x1f\x7f]/.test(host)) {
    return { valid: false, error: `SSRF Violation: Illegal characters in host '${host}'` };
  }

  // Reject percent-encoded host manipulation
  if (host.includes('%')) {
    return { valid: false, error: `SSRF Violation: Percent-encoded characters in host are prohibited '${host}'` };
  }

  let cleanHost = host.trim().toLowerCase();
  let port: number | undefined;

  // Parse IPv6 with bracket format [::1] or [::1]:5000
  if (cleanHost.startsWith('[')) {
    const closingBracket = cleanHost.indexOf(']');
    if (closingBracket === -1) {
      return { valid: false, error: `Malformed IPv6 address in host '${host}'` };
    }
    const ipv6Part = cleanHost.slice(1, closingBracket);
    const portPart = cleanHost.slice(closingBracket + 1);
    if (portPart) {
      if (!portPart.startsWith(':')) {
        return { valid: false, error: `Malformed port after IPv6 in host '${host}'` };
      }
      port = parseInt(portPart.slice(1), 10);
      if (isNaN(port) || port < 1 || port > 65535) {
        return { valid: false, error: `Invalid port number in host '${host}'` };
      }
    }
    cleanHost = ipv6Part;
  } else {
    // Check if host contains single colon for port (host:port)
    const colonIdx = cleanHost.lastIndexOf(':');
    if (colonIdx !== -1 && !cleanHost.includes('::')) {
      const portStr = cleanHost.slice(colonIdx + 1);
      if (/^\d+$/.test(portStr)) {
        port = parseInt(portStr, 10);
        if (isNaN(port) || port < 1 || port > 65535) {
          return { valid: false, error: `Invalid port number in host '${host}'` };
        }
        cleanHost = cleanHost.slice(0, colonIdx);
      }
    }
  }

  // Check port against sensitive internal ports
  if (port !== undefined && BLOCKED_PORTS.has(port)) {
    return { valid: false, error: `SSRF Violation: Connection to sensitive internal port ${port} is prohibited` };
  }

  // Permitted internal testing domains
  const isTestDomain =
    cleanHost === 'registry.internal.caim.security' ||
    cleanHost === 'test.registry.local' ||
    cleanHost === 'mock-registry.local' ||
    cleanHost.endsWith('.registry.internal.caim.security') ||
    cleanHost.endsWith('.test.registry.local');

  if (isTestDomain) {
    return { valid: true, cleanHost, port };
  }

  // Block forbidden hostname keywords & suffixes
  const blockedKeywords = [
    /^localhost$/,
    /\.localhost$/,
    /\.local$/,
    /\.internal$/,
    /\.corp$/,
    /\.home$/,
    /\.lan$/,
    /metadata\.google\.internal/,
    /^instance-data$/,
    /^metadata$/,
  ];

  for (const pattern of blockedKeywords) {
    if (pattern.test(cleanHost)) {
      return { valid: false, error: `SSRF Violation: Forbidden private or metadata hostname '${host}'` };
    }
  }

  // Check alternative IPv4 formats (dword, octal, hex, dotted)
  const ipv4Octets = parseIpv4String(cleanHost);
  if (ipv4Octets) {
    const ipv4Check = isPrivateOrBlockedIpv4(ipv4Octets);
    if (ipv4Check.blocked) {
      return { valid: false, error: `SSRF Violation: ${ipv4Check.reason}` };
    }
  }

  // Check IPv6 addresses
  if (cleanHost.includes(':')) {
    const ipv6Check = isPrivateOrBlockedIpv6(cleanHost);
    if (ipv6Check.blocked) {
      return { valid: false, error: `SSRF Violation: ${ipv6Check.reason}` };
    }
  }

  // Destination allowlist enforcement
  if (allowedHosts && allowedHosts.length > 0) {
    const isAllowed = allowedHosts.some(h => {
      const lower = h.toLowerCase();
      return cleanHost === lower || cleanHost.endsWith('.' + lower);
    });
    if (!isAllowed) {
      return { valid: false, error: `Destination host '${host}' is not in the allowed registry whitelist` };
    }
  }

  return { valid: true, cleanHost, port };
}

/**
 * Validates registry host syntax AND resolves DNS to ensure underlying IP does not resolve
 * to private/loopback/cloud-metadata addresses (prevents DNS rebinding and private CNAMEs).
 */
export async function validateAndResolveRegistryHost(
  host: string,
  allowedHosts?: string[],
  customDnsResolver?: (hostname: string) => Promise<{ address: string; family: number }[]>
): Promise<{ valid: boolean; error?: string; cleanHost?: string; port?: number; resolvedIps?: string[] }> {
  const basicCheck = validateRegistryHost(host, allowedHosts);
  if (!basicCheck.valid || !basicCheck.cleanHost) {
    return basicCheck;
  }

  const cleanHost = basicCheck.cleanHost;

  // Permitted test domains skip live DNS resolution
  if (
    cleanHost === 'registry.internal.caim.security' ||
    cleanHost === 'test.registry.local' ||
    cleanHost === 'mock-registry.local' ||
    cleanHost.endsWith('.registry.internal.caim.security') ||
    cleanHost.endsWith('.test.registry.local')
  ) {
    return { ...basicCheck, resolvedIps: ['127.0.0.1'] };
  }

  // If host is already an IP address, basicCheck already verified it is not private
  if (net.isIP(cleanHost) || parseIpv4String(cleanHost)) {
    return { ...basicCheck, resolvedIps: [cleanHost] };
  }

  // Perform DNS resolution to detect rebinding or domains mapping to 127.0.0.1 / 169.254.169.254
  try {
    let resolvedRecords: { address: string; family: number }[];
    if (customDnsResolver) {
      resolvedRecords = await customDnsResolver(cleanHost);
    } else {
      const lookupResult = await dns.promises.lookup(cleanHost, { all: true, verbatim: true });
      resolvedRecords = lookupResult.map(r => ({ address: r.address, family: r.family }));
    }

    if (!resolvedRecords || resolvedRecords.length === 0) {
      return { valid: false, error: `DNS resolution failed: No addresses found for host '${host}'` };
    }

    for (const record of resolvedRecords) {
      if (record.family === 4 || record.address.includes('.')) {
        const octets = parseIpv4String(record.address);
        if (octets) {
          const ipCheck = isPrivateOrBlockedIpv4(octets);
          if (ipCheck.blocked) {
            return {
              valid: false,
              error: `SSRF Violation: Registry host '${host}' resolves to forbidden private IP '${record.address}' (${ipCheck.reason})`,
            };
          }
        }
      }
      if (record.family === 6 || record.address.includes(':')) {
        const ip6Check = isPrivateOrBlockedIpv6(record.address);
        if (ip6Check.blocked) {
          return {
            valid: false,
            error: `SSRF Violation: Registry host '${host}' resolves to forbidden IPv6 '${record.address}' (${ip6Check.reason})`,
          };
        }
      }
    }

    return { ...basicCheck, resolvedIps: resolvedRecords.map(r => r.address) };
  } catch (dnsErr: any) {
    // If domain cannot be resolved, check if it's explicitly in allowedHosts
    if (allowedHosts && allowedHosts.some(h => cleanHost === h.toLowerCase() || cleanHost.endsWith('.' + h.toLowerCase()))) {
      return { ...basicCheck, resolvedIps: [] };
    }
    return {
      valid: false,
      error: `DNS resolution failed for registry host '${host}': ${dnsErr.message}`,
    };
  }
}

/**
 * Validates a redirect or location URL against SSRF and protocol policies.
 */
export function validateRedirectUrl(
  locationUrl: string,
  allowedHosts?: string[],
  insecure: boolean = false
): { valid: boolean; error?: string; url?: URL } {
  try {
    const url = new URL(locationUrl);
    if (!insecure && url.protocol !== 'https:') {
      return { valid: false, error: `Insecure redirect protocol '${url.protocol}' rejected (must be https:)` };
    }
    if (insecure && url.protocol !== 'https:' && url.protocol !== 'http:') {
      return { valid: false, error: `Invalid redirect protocol '${url.protocol}'` };
    }

    const hostToCheck = url.hostname + (url.port ? `:${url.port}` : '');
    const hostCheck = validateRegistryHost(hostToCheck, allowedHosts);
    if (!hostCheck.valid) {
      return { valid: false, error: `Redirect destination rejected: ${hostCheck.error}` };
    }

    return { valid: true, url };
  } catch (err: any) {
    return { valid: false, error: `Invalid redirect URL '${locationUrl}': ${err.message}` };
  }
}

/**
 * Validates S3 bucket name format and safe key prefixes.
 */
export function validateS3Destination(
  bucket: string,
  key: string,
  options?: { allowedBuckets?: string[]; expectedTenantId?: string }
): { valid: boolean; error?: string } {
  if (!bucket || typeof bucket !== 'string') {
    return { valid: false, error: 'S3 bucket name cannot be empty' };
  }

  // AWS S3 bucket naming rules
  const bucketRegex = /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/;
  if (!bucketRegex.test(bucket) || bucket.includes('..') || /^\d+\.\d+\.\d+\.\d+$/.test(bucket)) {
    return { valid: false, error: `Invalid S3 bucket name '${bucket}'` };
  }

  if (options?.allowedBuckets && options.allowedBuckets.length > 0) {
    if (!options.allowedBuckets.includes(bucket)) {
      return { valid: false, error: `Bucket '${bucket}' is not in the authorized bucket whitelist` };
    }
  }

  // Path traversal prevention
  if (key.includes('..') || key.includes('\\') || key.startsWith('/') || /[\x00-\x1f\x7f]/.test(key)) {
    return { valid: false, error: `Path traversal or illegal character detected in S3 key '${key}'` };
  }

  // Tenant isolation: if expectedTenantId is provided, the key must be scoped to that tenant
  if (options?.expectedTenantId) {
    const tenantPrefix1 = `tenants/${options.expectedTenantId}/`;
    const tenantPrefix2 = `releases/${options.expectedTenantId}/`;
    if (!key.startsWith(tenantPrefix1) && !key.startsWith(tenantPrefix2)) {
      return {
        valid: false,
        error: `Cross-tenant path violation: S3 key '${key}' does not belong to tenant '${options.expectedTenantId}'`,
      };
    }
  }

  return { valid: true };
}

/**
 * Serializes a SignedPackageBundle deterministically into a binary payload for storage/registry transmission.
 */
export function serializePackageBundleToBytes(bundle: SignedPackageBundle): {
  bytes: Buffer;
  sha256Digest: string;
  sizeBytes: number;
} {
  const parts: Buffer[] = [];

  // 1. Manifest bytes
  const manifestJson = JSON.stringify(bundle.manifest);
  const manifestBuf = Buffer.from(manifestJson, 'utf-8');
  parts.push(Buffer.from(`MANIFEST:${manifestBuf.length}:`, 'utf-8'));
  parts.push(manifestBuf);

  // 2. Sorted file entries
  const fileEntries: { path: string; content: Buffer }[] = [];
  for (const [filePath, fileEntry] of bundle.files) {
    const content = Buffer.isBuffer(fileEntry.content)
      ? fileEntry.content
      : typeof fileEntry.content === 'string'
      ? Buffer.from(fileEntry.content, 'utf-8')
      : Buffer.from(fileEntry.content);
    fileEntries.push({ path: filePath, content });
  }

  fileEntries.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));

  for (const entry of fileEntries) {
    const header = Buffer.from(`FILE:${entry.path}:${entry.content.length}:`, 'utf-8');
    parts.push(header);
    parts.push(entry.content);
  }

  // 3. Attestation & signature
  const attestationBuf = Buffer.from(JSON.stringify(bundle.attestation), 'utf-8');
  parts.push(Buffer.from(`ATTESTATION:${attestationBuf.length}:`, 'utf-8'));
  parts.push(attestationBuf);

  const sigBuf = Buffer.from(JSON.stringify(bundle.signature), 'utf-8');
  parts.push(Buffer.from(`SIGNATURE:${sigBuf.length}:`, 'utf-8'));
  parts.push(sigBuf);

  const fullBytes = Buffer.concat(parts);
  const digest = crypto.createHash('sha256').update(fullBytes).digest('hex');

  return {
    bytes: fullBytes,
    sha256Digest: digest,
    sizeBytes: fullBytes.length,
  };
}

/**
 * Standard AWS Signature Version 4 (SigV4) implementation for REST API calls.
 */
export function generateAwsSigV4Headers(options: {
  method: string;
  url: URL;
  headers: Record<string, string>;
  payloadBytes: Buffer;
  region: string;
  service: string;
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
  date?: Date;
}): Record<string, string> {
  const date = options.date || new Date();
  const amzDate = date.toISOString().replace(/[:-]|\.\d{3}/g, '');
  const dateStamp = amzDate.slice(0, 8);

  const payloadHash = crypto.createHash('sha256').update(options.payloadBytes).digest('hex');

  const headers: Record<string, string> = {
    ...options.headers,
    host: options.url.host,
    'x-amz-date': amzDate,
    'x-amz-content-sha256': payloadHash,
  };

  if (options.sessionToken) {
    headers['x-amz-security-token'] = options.sessionToken;
  }

  // Canonical headers
  const sortedHeaderKeys = Object.keys(headers)
    .map(k => k.toLowerCase())
    .sort();

  const canonicalHeaders = sortedHeaderKeys
    .map(k => `${k}:${headers[k].trim()}`)
    .join('\n') + '\n';

  const signedHeaders = sortedHeaderKeys.join(';');

  const canonicalUri = encodeURI(options.url.pathname);
  const canonicalQueryString = Array.from(options.url.searchParams.entries())
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join('&');

  const canonicalRequest = [
    options.method.toUpperCase(),
    canonicalUri,
    canonicalQueryString,
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join('\n');

  const canonicalRequestHash = crypto.createHash('sha256').update(canonicalRequest).digest('hex');

  const credentialScope = `${dateStamp}/${options.region}/${options.service}/aws4_request`;
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    credentialScope,
    canonicalRequestHash,
  ].join('\n');

  const hmac = (key: Buffer | string, data: string) =>
    crypto.createHmac('sha256', key).update(data).digest();

  const kDate = hmac('AWS4' + options.secretAccessKey, dateStamp);
  const kRegion = hmac(kDate, options.region);
  const kService = hmac(kRegion, options.service);
  const kSigning = hmac(kService, 'aws4_request');

  const signature = crypto.createHmac('sha256', kSigning).update(stringToSign).digest('hex');

  headers['authorization'] = `AWS4-HMAC-SHA256 Credential=${options.accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

  return headers;
}
