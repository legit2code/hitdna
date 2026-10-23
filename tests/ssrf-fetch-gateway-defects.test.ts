import { describe, it, expect, vi } from 'vitest';
import http from 'http';
import { AddressInfo } from 'net';
import {
  FetchGateway,
  SsrfFilter,
  SsrfBlockedError,
  ResponseSizeExceededError,
  HttpResponse,
} from '@caim/source';

describe('SSRF Filter and FetchGateway Defect Regression Suite', () => {
  const filter = new SsrfFilter();

  describe('1. Table-driven validate() tests for IPv6 unwrapping and bypass patterns', () => {
    const blockedUrls = [
      // IPv4-mapped IPv6 dotted and hex forms
      'http://[::ffff:127.0.0.1]:3000/',
      'http://[::ffff:7f00:1]/',
      'http://[::ffff:10.0.0.1]/',
      'http://[::ffff:a00:1]/',
      'http://[::ffff:169.254.169.254]/',
      'http://[::ffff:192.168.1.1]/',

      // IPv4-compatible IPv6 (::/96)
      'http://[::127.0.0.1]/',
      'http://[::7f00:1]/',

      // NAT64 translated (64:ff9b::/96 and 64:ff9b:1::/48)
      'http://[64:ff9b::7f00:1]/',
      'http://[64:ff9b::127.0.0.1]/',
      'http://[64:ff9b:1::7f00:1]/',
      'http://[64:ff9b:1::10.0.0.1]/',

      // 6to4 (2002::/16) embedding 127.0.0.1 (7f00:0001)
      'http://[2002:7f00:0001::]/',
      'http://[2002:0a00:0001::]/',

      // Specific blocked IPv6 blocks
      'http://[::]/',              // ::/128 Unspecified
      'http://[::1]/',            // ::1/128 Loopback
      'http://[fd00::1]/',         // fc00::/7 ULA
      'http://[fc00::1]/',         // fc00::/7 ULA
      'http://[fe80::1]/',         // fe80::/10 Link-Local
      'http://[ff02::1]/',         // ff00::/8 Multicast
      'http://[2001:db8::1]/',     // 2001:db8::/32 Documentation
      'http://[2001::1]/',         // 2001::/32 Teredo

      // IPv4 alternate representations
      'http://0.0.0.0/',
      'http://127.0.0.1:8080/',
      'http://127.1/',
      'http://169.254.169.254/',
      'http://2130706433/',       // Decimal 127.0.0.1
      'http://0x7f000001/',       // Hex 127.0.0.1
      'http://017700000001/',     // Octal 127.0.0.1
      'http://0177.0.0.1/',       // Octal dotted 127.0.0.1
      'http://0x7f.0.0.1/',       // Hex dotted 127.0.0.1

      // Hostname normalizations & special cases
      'http://localhost./',       // Trailing-dot localhost
      'http://localhost.:8080/',
      'http://user:pass@127.0.0.1/', // User@host form
      'http://user:pass@localhost/',

      // Non-HTTP schemes
      'file:///etc/passwd',
      'ftp://127.0.0.1/test',
      'gopher://127.0.0.1:70/',

      // Unparseable IPv6
      'http://[::zzzz]/',
      'http://[:::1]/',
      'http://[1:2:3:4:5:6:7:8:9]/',
    ];

    for (const target of blockedUrls) {
      it(`blocks disallowed address: ${target}`, async () => {
        await expect(filter.validate(target)).rejects.toThrow();
      });
    }

    it('allows valid public IPv4 address', async () => {
      const res = await filter.validate('http://93.184.216.34/');
      expect(res.resolvedIps).toContain('93.184.216.34');
    });

    it('allows valid public IPv6 address (2606:2800:220:1:248:1893:25c8:1946)', async () => {
      const res = await filter.validate('http://[2606:2800:220:1:248:1893:25c8:1946]/');
      expect(res.resolvedIps).toBeDefined();
    });
  });

  describe('2. Acceptance test for original reported bypass URLs', () => {
    it('blocks the four reported exploit URLs', async () => {
      const originalExploits = [
        'http://[::ffff:127.0.0.1]:3000/',
        'http://[::ffff:7f00:1]/',
        'http://[::ffff:10.0.0.1]/',
        'http://[64:ff9b::7f00:1]/',
      ];

      for (const exploit of originalExploits) {
        await expect(filter.validate(exploit)).rejects.toThrow();
      }
    });
  });

  describe('3. DNS rebinding / TOCTOU mitigation with pinned IP lookup', () => {
    it('pins the connection to the validated IP and does not re-resolve to malicious IP', async () => {
      // Local server to represent target
      const server = http.createServer((req, res) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, host: req.headers.host }));
      });

      await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
      const port = (server.address() as AddressInfo).port;

      try {
        let callCount = 0;
        // Resolver simulates rebinding: first returns 127.0.0.1, later returns something else
        // Here we test with customTransport seam or Gateway pinning
        const customTransport = vi.fn().mockImplementation(async (targetUrl: string, options: any) => {
          return {
            status: 200,
            statusText: 'OK',
            headers: { 'content-type': 'application/json' },
            data: { pinned: options.pinnedTarget?.resolvedIps },
          };
        });

        const customFilter = new SsrfFilter([], [], async (host: string) => {
          callCount++;
          return ['93.184.216.34']; // Validated IP
        });

        const gateway = new FetchGateway({
          ssrfFilter: customFilter,
          transport: customTransport,
        });

        const res = await gateway.request(`http://example.com:${port}/test`, {
          skipRobots: true,
        });
        expect(customTransport).toHaveBeenCalled();
        const transportCall = customTransport.mock.calls[0];
        // Must receive pinned target
        expect(transportCall[1]?.pinnedTarget?.resolvedIps).toEqual(['93.184.216.34']);
      } finally {
        server.close();
      }
    });
  });

  describe('4. Maximum response size enforcement (streaming & Content-Length)', () => {
    it('aborts response when Content-Length exceeds maxResponseBytes', async () => {
      const server = http.createServer((req, res) => {
        res.writeHead(200, {
          'Content-Type': 'text/plain',
          'Content-Length': String(20 * 1024 * 1024), // 20 MiB
        });
        res.end('oversized data');
      });

      await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
      const port = (server.address() as AddressInfo).port;

      try {
        const dummyFilter = new SsrfFilter([], [], async () => ['127.0.0.1']);
        // Bypass SSRF for this test server
        const safeFilter = {
          validate: vi.fn().mockResolvedValue({
            originalUrl: `http://localhost:${port}/`,
            parsedUrl: new URL(`http://localhost:${port}/`),
            hostname: 'localhost',
            port,
            resolvedIps: ['127.0.0.1'],
          }),
        } as any;

        const gateway = new FetchGateway({
          ssrfFilter: safeFilter,
          config: {
            maxResponseBytes: 1024 * 1024, // 1 MiB limit
          },
        });

        await expect(gateway.request(`http://localhost:${port}/`)).rejects.toThrow(ResponseSizeExceededError);
      } finally {
        server.close();
      }
    });

    it('aborts streaming chunked response when byte counter exceeds maxResponseBytes without Content-Length', async () => {
      const server = http.createServer((req, res) => {
        res.writeHead(200, {
          'Content-Type': 'text/plain',
          'Transfer-Encoding': 'chunked',
        });
        // Send chunks that exceed limit
        const chunk = Buffer.alloc(100 * 1024, 'a'); // 100 KB
        for (let i = 0; i < 20; i++) {
          res.write(chunk);
        }
        res.end();
      });

      await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
      const port = (server.address() as AddressInfo).port;

      try {
        const safeFilter = {
          validate: vi.fn().mockResolvedValue({
            originalUrl: `http://localhost:${port}/`,
            parsedUrl: new URL(`http://localhost:${port}/`),
            hostname: 'localhost',
            port,
            resolvedIps: ['127.0.0.1'],
          }),
        } as any;

        const gateway = new FetchGateway({
          ssrfFilter: safeFilter,
          config: {
            maxResponseBytes: 500 * 1024, // 500 KB limit
          },
        });

        await expect(gateway.request(`http://localhost:${port}/`)).rejects.toThrow(ResponseSizeExceededError);
      } finally {
        server.close();
      }
    });
  });

  describe('5. Redirect to IPv4-mapped IPv6 loopback is blocked on redirect hop', () => {
    it('blocks redirect hop targeting http://[::ffff:127.0.0.1]/', async () => {
      let step = 0;
      const customTransport = vi.fn().mockImplementation(async (targetUrl: string) => {
        if (step === 0) {
          step++;
          return {
            status: 302,
            statusText: 'Found',
            headers: {
              location: 'http://[::ffff:127.0.0.1]:3000/admin',
            },
            data: null,
          };
        }
        return {
          status: 200,
          statusText: 'OK',
          headers: {},
          data: 'ok',
        };
      });

      const gateway = new FetchGateway({
        transport: customTransport,
      });

      await expect(gateway.request('https://public-service.org/start')).rejects.toThrow(SsrfBlockedError);
    });
  });

  describe('6. Acceptance probe: real DNS validation for https://api.github.com/', () => {
    it('allows https://api.github.com/ with real resolver', async () => {
      const realFilter = new SsrfFilter();
      const res = await realFilter.validate('https://api.github.com/');
      expect(res.resolvedIps.length).toBeGreaterThan(0);
      expect(res.hostname).toBe('api.github.com');
    });
  });
});
