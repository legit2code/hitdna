import dns from 'dns';
import net from 'net';
import { SsrfBlockedError } from './errors.ts';

export interface ResolvedTarget {
  originalUrl: string;
  parsedUrl: URL;
  hostname: string;
  port: number;
  resolvedIps: string[];
}

export class SsrfFilter {
  // Blocked hostnames / patterns
  private static readonly BLOCKED_HOST_PATTERNS = [
    /^localhost$/i,
    /\.localhost$/i,
    /\.local$/i,
    /\.internal$/i,
    /\.lan$/i,
    /\.corp$/i,
    /\.home$/i,
    /\.test$/i,
    /\.example$/i,
    /\.invalid$/i,
    /^metadata\.google\.internal$/i,
    /^metadata\.internal$/i,
    /^instance-data$/i,
    /^169\.254\.169\.254$/i,
  ];

  // Blocked CIDR ranges (IPv4)
  private static readonly IPV4_BLOCKED_RANGES: Array<{ network: number; mask: number; description: string }> = [
    // 0.0.0.0/8 "This" network
    { network: SsrfFilter.ipv4ToInt('0.0.0.0'), mask: SsrfFilter.cidrToMask(8), description: 'Current network (0.0.0.0/8)' },
    // 127.0.0.0/8 Loopback
    { network: SsrfFilter.ipv4ToInt('127.0.0.0'), mask: SsrfFilter.cidrToMask(8), description: 'Loopback (127.0.0.0/8)' },
    // 10.0.0.0/8 RFC1918 Private
    { network: SsrfFilter.ipv4ToInt('10.0.0.0'), mask: SsrfFilter.cidrToMask(8), description: 'RFC1918 Private (10.0.0.0/8)' },
    // 172.16.0.0/12 RFC1918 Private
    { network: SsrfFilter.ipv4ToInt('172.16.0.0'), mask: SsrfFilter.cidrToMask(12), description: 'RFC1918 Private (172.16.0.0/12)' },
    // 192.168.0.0/16 RFC1918 Private
    { network: SsrfFilter.ipv4ToInt('192.168.0.0'), mask: SsrfFilter.cidrToMask(16), description: 'RFC1918 Private (192.168.0.0/16)' },
    // 169.254.0.0/16 Link-local / Cloud Metadata
    { network: SsrfFilter.ipv4ToInt('169.254.0.0'), mask: SsrfFilter.cidrToMask(16), description: 'Link-local / Cloud Metadata (169.254.0.0/16)' },
    // 100.64.0.0/10 Carrier-Grade NAT
    { network: SsrfFilter.ipv4ToInt('100.64.0.0'), mask: SsrfFilter.cidrToMask(10), description: 'Shared Address Space / CGNAT (100.64.0.0/10)' },
    // 192.0.2.0/24 TEST-NET-1 Documentation
    { network: SsrfFilter.ipv4ToInt('192.0.2.0'), mask: SsrfFilter.cidrToMask(24), description: 'Documentation TEST-NET-1 (192.0.2.0/24)' },
    // 198.51.100.0/24 TEST-NET-2 Documentation
    { network: SsrfFilter.ipv4ToInt('198.51.100.0'), mask: SsrfFilter.cidrToMask(24), description: 'Documentation TEST-NET-2 (198.51.100.0/24)' },
    // 203.0.113.0/24 TEST-NET-3 Documentation
    { network: SsrfFilter.ipv4ToInt('203.0.113.0'), mask: SsrfFilter.cidrToMask(24), description: 'Documentation TEST-NET-3 (203.0.113.0/24)' },
    // 198.18.0.0/15 Benchmarking
    { network: SsrfFilter.ipv4ToInt('198.18.0.0'), mask: SsrfFilter.cidrToMask(15), description: 'Benchmark network (198.18.0.0/15)' },
    // 224.0.0.0/4 Multicast
    { network: SsrfFilter.ipv4ToInt('224.0.0.0'), mask: SsrfFilter.cidrToMask(4), description: 'Multicast (224.0.0.0/4)' },
    // 240.0.0.0/4 Reserved / Future use
    { network: SsrfFilter.ipv4ToInt('240.0.0.0'), mask: SsrfFilter.cidrToMask(4), description: 'Reserved (240.0.0.0/4)' },
    // 255.255.255.255/32 Broadcast
    { network: SsrfFilter.ipv4ToInt('255.255.255.255'), mask: SsrfFilter.cidrToMask(32), description: 'Broadcast (255.255.255.255/32)' },
  ];

  constructor(
    private readonly customBlockedHosts: string[] = [],
    private readonly customBlockedIps: string[] = [],
    private readonly dnsResolver?: (host: string) => Promise<string[]>
  ) {}

  /**
   * Comprehensive SSRF validation on a target URL before any HTTP network connection is established.
   */
  async validate(urlStr: string): Promise<ResolvedTarget> {
    let parsed: URL;
    try {
      parsed = new URL(urlStr);
    } catch {
      throw new SsrfBlockedError(`Malformed URL cannot be fetched: '${urlStr}'`, { url: urlStr });
    }

    // 1. Strict Protocol Enforcement
    const protocol = parsed.protocol.toLowerCase();
    if (protocol !== 'http:' && protocol !== 'https:') {
      throw new SsrfBlockedError(`Disallowed protocol '${protocol}'. Only HTTP and HTTPS are permitted.`, {
        url: urlStr,
        protocol,
      });
    }

    // 2. Normalize Hostname: strip trailing dot and lowercase
    const rawHostname = parsed.hostname;
    const hostname = rawHostname.replace(/\.+$/, '').toLowerCase();
    const port = parsed.port ? parseInt(parsed.port, 10) : (protocol === 'https:' ? 443 : 80);

    // 3. Direct Hostname Pattern Check (Localhost, internal names, cloud metadata)
    for (const pattern of SsrfFilter.BLOCKED_HOST_PATTERNS) {
      if (pattern.test(hostname)) {
        throw new SsrfBlockedError(`Target hostname '${hostname}' is an internal, cloud-metadata, or localhost pattern.`, {
          url: urlStr,
          hostname,
          reason: 'BLOCKED_HOST_PATTERN',
        });
      }
    }

    for (const blocked of this.customBlockedHosts) {
      if (hostname === blocked.toLowerCase()) {
        throw new SsrfBlockedError(`Target hostname '${hostname}' is in the blocked infrastructure list.`, {
          url: urlStr,
          hostname,
          reason: 'CUSTOM_BLOCKED_HOST',
        });
      }
    }

    // 4. IP Resolution & Verification
    let ips: string[] = [];
    const hostForIpCheck = hostname.replace(/^\[|\]$/g, '');

    // Check if host is IPv4 literal (including decimal integer, hex, octal, shorthand)
    const ip4Val = SsrfFilter.parseIpv4(hostForIpCheck);
    if (ip4Val !== null) {
      const canonicalIp4 = `${(ip4Val >>> 24) & 255}.${(ip4Val >>> 16) & 255}.${(ip4Val >>> 8) & 255}.${ip4Val & 255}`;
      ips = [canonicalIp4];
    } else if (hostForIpCheck.includes(':') || rawHostname.startsWith('[')) {
      // Host is IPv6 literal
      const parsedV6 = SsrfFilter.parseIpv6(hostForIpCheck);
      if (!parsedV6) {
        throw new SsrfBlockedError(`Target IPv6 address '${hostForIpCheck}' is unparseable and blocked.`, {
          url: urlStr,
          hostname,
          reason: 'UNPARSEABLE_IPV6',
        });
      }
      ips = [hostForIpCheck];
    } else {
      // Resolve domain via DNS
      ips = await this.resolveDns(hostname, urlStr);
    }

    if (ips.length === 0) {
      throw new SsrfBlockedError(`Domain '${hostname}' could not be resolved to any IP address.`, {
        url: urlStr,
        hostname,
        reason: 'DNS_NO_RECORD',
      });
    }

    // 5. Validate every resolved IP
    for (const ip of ips) {
      const blockReason = this.isIpBlocked(ip);
      if (blockReason) {
        throw new SsrfBlockedError(
          `SSRF protection: Target IP '${ip}' for host '${hostname}' is blocked (${blockReason}).`,
          {
            url: urlStr,
            hostname,
            ip,
            blockReason,
          }
        );
      }
    }

    return {
      originalUrl: urlStr,
      parsedUrl: parsed,
      hostname,
      port,
      resolvedIps: ips,
    };
  }

  /**
   * Resolves hostname via DNS lookup.
   */
  private async resolveDns(hostname: string, urlStr: string): Promise<string[]> {
    if (this.dnsResolver) {
      return this.dnsResolver(hostname);
    }

    try {
      const records = await dns.promises.lookup(hostname, { all: true });
      return records.map((r) => r.address);
    } catch (err: any) {
      throw new SsrfBlockedError(`DNS resolution failure for '${hostname}': ${err.message}`, {
        url: urlStr,
        hostname,
        cause: err.message,
      });
    }
  }

  /**
   * Checks whether a specific IPv4 or IPv6 address falls within any blocked address space.
   */
  isIpBlocked(ipStr: string): string | null {
    if (this.customBlockedIps.includes(ipStr)) {
      return 'Custom blocked IP list';
    }

    const clean = ipStr.replace(/^\[|\]$/g, '').trim().toLowerCase();

    // Check if it's an IPv4 address (including non-standard forms: octal, hex, decimal int, shorthand)
    const ip4Int = SsrfFilter.parseIpv4(clean);
    if (ip4Int !== null) {
      return this.isIpv4IntBlocked(ip4Int);
    }

    // Check if it's an IPv6 address
    if (clean.includes(':')) {
      return this.isIpv6Blocked(clean);
    }

    return 'Invalid IP representation';
  }

  private isIpv4IntBlocked(ipInt: number): string | null {
    for (const range of SsrfFilter.IPV4_BLOCKED_RANGES) {
      if (((ipInt & range.mask) >>> 0) === range.network) {
        return range.description;
      }
    }
    return null;
  }

  private isIpv4Blocked(ipStr: string): string | null {
    const ipInt = SsrfFilter.parseIpv4(ipStr);
    if (ipInt === null) {
      return 'Invalid IPv4 address';
    }
    return this.isIpv4IntBlocked(ipInt);
  }

  private isIpv6Blocked(ipStr: string): string | null {
    const clean = ipStr.replace(/^\[|\]$/g, '').trim().toLowerCase();
    const hextets = SsrfFilter.parseIpv6(clean);
    if (!hextets) {
      return 'Unparseable IPv6 address';
    }

    // 1. ::/128 Unspecified
    if (hextets.every((h) => h === 0)) {
      return 'IPv6 Unspecified (::/128)';
    }

    // 2. ::1/128 Loopback
    if (hextets.slice(0, 7).every((h) => h === 0) && hextets[7] === 1) {
      return 'IPv6 Loopback (::1/128)';
    }

    // 3. fc00::/7 Unique Local Address (fc00:: to fdff::)
    if ((hextets[0] & 0xfe00) === 0xfc00) {
      return 'IPv6 Unique Local Address (fc00::/7)';
    }

    // 4. fe80::/10 Link-Local (fe80:: to febf::)
    if ((hextets[0] & 0xffc0) === 0xfe80) {
      return 'IPv6 Link-Local (fe80::/10)';
    }

    // 5. ff00::/8 Multicast
    if ((hextets[0] & 0xff00) === 0xff00) {
      return 'IPv6 Multicast (ff00::/8)';
    }

    // 6. 2001:db8::/32 Documentation
    if (hextets[0] === 0x2001 && hextets[1] === 0x0db8) {
      return 'IPv6 Documentation (2001:db8::/32)';
    }

    // 7. 2001::/32 Teredo
    if (hextets[0] === 0x2001 && hextets[1] === 0x0000) {
      return 'IPv6 Teredo (2001::/32)';
    }

    // 8. 2002::/16 6to4 (evaluate embedded IPv4 in hextets 1 and 2)
    if (hextets[0] === 0x2002) {
      const embeddedIp4Int = ((hextets[1] << 16) | hextets[2]) >>> 0;
      const blocked = this.isIpv4IntBlocked(embeddedIp4Int);
      if (blocked) {
        return `IPv6 6to4 embedded IPv4: ${blocked}`;
      }
    }

    // 9. IPv4-mapped (::ffff:0:0/96)
    if (
      hextets[0] === 0 &&
      hextets[1] === 0 &&
      hextets[2] === 0 &&
      hextets[3] === 0 &&
      hextets[4] === 0 &&
      hextets[5] === 0xffff
    ) {
      const embeddedIp4Int = ((hextets[6] << 16) | hextets[7]) >>> 0;
      const blocked = this.isIpv4IntBlocked(embeddedIp4Int);
      if (blocked) {
        return `IPv4-mapped IPv6: ${blocked}`;
      }
    }

    // 10. IPv4-compatible (::/96)
    if (
      hextets[0] === 0 &&
      hextets[1] === 0 &&
      hextets[2] === 0 &&
      hextets[3] === 0 &&
      hextets[4] === 0 &&
      hextets[5] === 0
    ) {
      const embeddedIp4Int = ((hextets[6] << 16) | hextets[7]) >>> 0;
      const blocked = this.isIpv4IntBlocked(embeddedIp4Int);
      if (blocked) {
        return `IPv4-compatible IPv6: ${blocked}`;
      }
    }

    // 11. NAT64 Well-Known (64:ff9b::/96)
    if (
      hextets[0] === 0x0064 &&
      hextets[1] === 0xff9b &&
      hextets[2] === 0 &&
      hextets[3] === 0 &&
      hextets[4] === 0 &&
      hextets[5] === 0
    ) {
      const embeddedIp4Int = ((hextets[6] << 16) | hextets[7]) >>> 0;
      const blocked = this.isIpv4IntBlocked(embeddedIp4Int);
      if (blocked) {
        return `NAT64 well-known IPv6: ${blocked}`;
      }
    }

    // 12. NAT64 Local (64:ff9b:1::/48)
    if (
      hextets[0] === 0x0064 &&
      hextets[1] === 0xff9b &&
      hextets[2] === 0x0001
    ) {
      const embeddedIp4Int = ((hextets[6] << 16) | hextets[7]) >>> 0;
      const blocked = this.isIpv4IntBlocked(embeddedIp4Int);
      if (blocked) {
        return `NAT64 local IPv6: ${blocked}`;
      }
    }

    // 13. AWS IPv6 Cloud Metadata (fd00:ec2::254)
    if (clean.includes('fd00:ec2:')) {
      return 'AWS IPv6 Cloud Metadata (fd00:ec2::254)';
    }

    return null;
  }

  public static parseIpv4(ipStr: string): number | null {
    const trimmed = ipStr.trim();
    const parts = trimmed.split('.');
    if (parts.length > 4 || parts.length === 0) return null;

    const vals: number[] = [];
    for (const part of parts) {
      if (!part) return null;
      let val: number;
      if (/^0x[0-9a-f]+$/i.test(part)) {
        val = parseInt(part, 16);
      } else if (/^0[0-7]+$/.test(part)) {
        val = parseInt(part, 8);
      } else if (/^\d+$/.test(part)) {
        val = parseInt(part, 10);
      } else {
        return null;
      }
      if (isNaN(val) || val < 0) return null;
      vals.push(val);
    }

    let ipInt: number;
    if (vals.length === 1) {
      if (vals[0] > 0xffffffff) return null;
      ipInt = vals[0] >>> 0;
    } else if (vals.length === 2) {
      if (vals[0] > 0xff || vals[1] > 0xffffff) return null;
      ipInt = ((vals[0] << 24) | vals[1]) >>> 0;
    } else if (vals.length === 3) {
      if (vals[0] > 0xff || vals[1] > 0xff || vals[2] > 0xffff) return null;
      ipInt = ((vals[0] << 24) | (vals[1] << 16) | vals[2]) >>> 0;
    } else {
      if (vals.some((v) => v > 0xff)) return null;
      ipInt = ((vals[0] << 24) | (vals[1] << 16) | (vals[2] << 8) | vals[3]) >>> 0;
    }
    return ipInt;
  }

  public static parseIpv6(ipStr: string): number[] | null {
    let s = ipStr.replace(/^\[|\]$/g, '').trim().toLowerCase();
    const zoneIdx = s.indexOf('%');
    if (zoneIdx !== -1) s = s.substring(0, zoneIdx);

    // Check for embedded dotted-quad IPv4 (e.g. ::ffff:127.0.0.1 or 64:ff9b::192.0.2.1)
    const lastColon = s.lastIndexOf(':');
    if (lastColon === -1) return null;
    const tail = s.substring(lastColon + 1);
    if (tail.includes('.')) {
      const parts = tail.split('.');
      if (parts.length !== 4) return null;
      const bytes: number[] = [];
      for (const p of parts) {
        if (!/^\d+$/.test(p)) return null;
        const n = parseInt(p, 10);
        if (n < 0 || n > 255) return null;
        bytes.push(n);
      }
      const h6 = ((bytes[0] << 8) | bytes[1]).toString(16);
      const h7 = ((bytes[2] << 8) | bytes[3]).toString(16);
      s = s.substring(0, lastColon + 1) + h6 + ':' + h7;
    }

    const doubleColonCount = (s.match(/::/g) || []).length;
    if (doubleColonCount > 1) return null;

    let hextets: string[];
    if (doubleColonCount === 1) {
      const [leftStr, rightStr] = s.split('::');
      const left = leftStr.length > 0 ? leftStr.split(':') : [];
      const right = rightStr.length > 0 ? rightStr.split(':') : [];
      const total = left.length + right.length;
      if (total > 7) return null;
      const zeros = new Array(8 - total).fill('0');
      hextets = [...left, ...zeros, ...right];
    } else {
      hextets = s.split(':');
      if (hextets.length !== 8) return null;
    }

    if (hextets.length !== 8) return null;

    const result: number[] = [];
    for (const h of hextets) {
      if (!/^[0-9a-f]{1,4}$/.test(h)) return null;
      result.push(parseInt(h, 16));
    }
    return result;
  }

  private static ipv4ToInt(ip: string): number {
    const parsed = SsrfFilter.parseIpv4(ip);
    if (parsed === null) {
      throw new Error(`Invalid IPv4 address: ${ip}`);
    }
    return parsed;
  }

  private static cidrToMask(cidr: number): number {
    if (cidr === 0) return 0;
    return ((0xffffffff << (32 - cidr)) & 0xffffffff) >>> 0;
  }
}
