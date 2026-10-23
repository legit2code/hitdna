import { z } from 'zod';

export interface RouteDocumentation {
  path: string;
  method: 'get' | 'post' | 'put' | 'delete' | 'patch';
  summary: string;
  description: string;
  tags: string[];
  requiresAuth?: boolean;
  requiredRoles?: string[];
  supportsIdempotency?: boolean;
  requestParams?: z.ZodType<any>;
  requestQuery?: z.ZodType<any>;
  requestBody?: z.ZodType<any>;
  responseSuccessSchema?: z.ZodType<any>;
  responseDescription?: string;
}

export class OpenApiGenerator {
  private readonly routes: RouteDocumentation[] = [];
  private readonly title: string;
  private readonly version: string;
  private readonly description: string;

  constructor(options?: { title?: string; version?: string; description?: string }) {
    this.title = options?.title || 'CAIM Enterprise Intelligence & Lifecycle API';
    this.version = options?.version || '2.0.1';
    this.description = options?.description || 'Architecture V2.0.1 Typed REST/Event API for Agent Governance, Analysis, Packaging, and Operations';
  }

  public registerRoute(doc: RouteDocumentation): void {
    this.routes.push(doc);
  }

  public generateDocument(): Record<string, any> {
    const paths: Record<string, any> = {};

    for (const route of this.routes) {
      if (!paths[route.path]) {
        paths[route.path] = {};
      }

      const parameters: any[] = [];

      // Add query parameters
      if (route.requestQuery) {
        parameters.push({
          name: 'page',
          in: 'query',
          schema: { type: 'integer', default: 1 },
          description: 'Page index for pagination',
        });
        parameters.push({
          name: 'limit',
          in: 'query',
          schema: { type: 'integer', default: 20, maximum: 100 },
          description: 'Maximum items per page',
        });
      }

      // Add idempotency header if supported
      if (route.supportsIdempotency) {
        parameters.push({
          name: 'Idempotency-Key',
          in: 'header',
          required: false,
          schema: { type: 'string' },
          description: 'Unique client-provided key ensuring exactly-once execution semantics across network retries',
        });
      }

      // Security requirements
      const security: any[] = [];
      if (route.requiresAuth) {
        security.push({ BearerAuth: [] }, { ServiceAuth: [] });
      }

      const responses: Record<string, any> = {
        '200': {
          description: route.responseDescription || 'Successful operation wrapped in standard envelope',
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  success: { type: 'boolean', enum: [true] },
                  data: { type: 'object' },
                  meta: {
                    type: 'object',
                    properties: {
                      request_id: { type: 'string' },
                      timestamp: { type: 'string', format: 'date-time' },
                    },
                  },
                },
              },
            },
          },
        },
        '400': {
          description: 'Validation failed with structured field error breakdown',
        },
        '401': {
          description: 'Unauthenticated or invalid bearer credentials',
        },
        '403': {
          description: 'Forbidden: Insufficient role permissions or classification level',
        },
        '404': {
          description: 'Resource not found',
        },
        '409': {
          description: 'Conflict or concurrent in-flight command idempotency key',
        },
        '422': {
          description: 'Unprocessable Entity: Policy Gate Block or Inconclusive Validation',
        },
        '503': {
          description: 'Transient dependency failure (retryable: true)',
        },
      };

      const operation: Record<string, any> = {
        summary: route.summary,
        description: `${route.description}${route.requiredRoles ? `\n\n**Required Roles**: \`${route.requiredRoles.join(', ')}\`` : ''}${route.supportsIdempotency ? '\n\n**Idempotency**: Supported via `Idempotency-Key` header.' : ''}`,
        tags: route.tags,
        parameters,
        security: route.requiresAuth ? security : [],
        responses,
      };

      if (route.requestBody) {
        operation.requestBody = {
          required: true,
          content: {
            'application/json': {
              schema: { type: 'object' },
            },
          },
        };
      }

      paths[route.path][route.method] = operation;
    }

    return {
      openapi: '3.1.0',
      info: {
        title: this.title,
        version: this.version,
        description: this.description,
        contact: {
          name: 'CAIM Enterprise Security Platform',
          url: 'https://caim.security',
        },
      },
      servers: [
        {
          url: '/api/v1',
          description: 'Internal & Public Gateway V1',
        },
      ],
      components: {
        securitySchemes: {
          BearerAuth: {
            type: 'http',
            scheme: 'bearer',
            bearerFormat: 'JWT',
            description: 'Standard Bearer Token identifying authorized principal and tenant context',
          },
          ServiceAuth: {
            type: 'apiKey',
            in: 'header',
            name: 'X-Service-Secret',
            description: 'Cryptographic service shared secret for authorized internal worker calls',
          },
        },
      },
      paths,
    };
  }
}
