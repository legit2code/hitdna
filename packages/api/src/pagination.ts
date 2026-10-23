import { z } from 'zod';
import { EnvelopePaginationMeta } from './envelopes.ts';

export const PaginationQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
  cursor: z.string().optional(),
  sort_by: z.string().optional(),
  sort_order: z.enum(['asc', 'desc']).default('desc'),
});

export type PaginationQuery = z.infer<typeof PaginationQuerySchema>;

export interface FilterCriteria {
  field: string;
  operator: 'eq' | 'neq' | 'in' | 'contains' | 'gte' | 'lte';
  value: unknown;
}

export function parseFilterParams(queryParams: Record<string, any>): FilterCriteria[] {
  const filters: FilterCriteria[] = [];
  const reservedKeys = new Set(['page', 'limit', 'cursor', 'sort_by', 'sort_order']);

  for (const [key, val] of Object.entries(queryParams)) {
    if (reservedKeys.has(key) || val === undefined || val === '') continue;

    if (key.endsWith('_gte')) {
      filters.push({ field: key.replace('_gte', ''), operator: 'gte', value: val });
    } else if (key.endsWith('_lte')) {
      filters.push({ field: key.replace('_lte', ''), operator: 'lte', value: val });
    } else if (key.endsWith('_in')) {
      const parts = typeof val === 'string' ? val.split(',').map((s) => s.trim()) : Array.isArray(val) ? val : [val];
      filters.push({ field: key.replace('_in', ''), operator: 'in', value: parts });
    } else if (key.endsWith('_contains')) {
      filters.push({ field: key.replace('_contains', ''), operator: 'contains', value: val });
    } else {
      filters.push({ field: key, operator: 'eq', value: val });
    }
  }

  return filters;
}

export function paginateAndFilterArray<T extends Record<string, any>>(
  items: T[],
  pagination: PaginationQuery,
  filters: FilterCriteria[] = []
): { data: T[]; meta: EnvelopePaginationMeta } {
  let filtered = [...items];

  // Apply filters
  for (const filter of filters) {
    filtered = filtered.filter((item) => {
      const itemVal = item[filter.field];
      if (itemVal === undefined) return false;

      switch (filter.operator) {
        case 'eq':
          return String(itemVal).toLowerCase() === String(filter.value).toLowerCase();
        case 'neq':
          return String(itemVal).toLowerCase() !== String(filter.value).toLowerCase();
        case 'contains':
          return String(itemVal).toLowerCase().includes(String(filter.value).toLowerCase());
        case 'in':
          return Array.isArray(filter.value) && filter.value.some((v) => String(v).toLowerCase() === String(itemVal).toLowerCase());
        case 'gte':
          return Number(itemVal) >= Number(filter.value);
        case 'lte':
          return Number(itemVal) <= Number(filter.value);
        default:
          return true;
      }
    });
  }

  // Apply sorting if specified
  if (pagination.sort_by) {
    const sortBy = pagination.sort_by;
    const isAsc = pagination.sort_order === 'asc';
    filtered.sort((a, b) => {
      const aVal = a[sortBy];
      const bVal = b[sortBy];
      if (aVal === bVal) return 0;
      if (aVal === undefined) return 1;
      if (bVal === undefined) return -1;
      return isAsc ? (aVal > bVal ? 1 : -1) : (aVal < bVal ? 1 : -1);
    });
  }

  const total = filtered.length;
  const page = pagination.page || 1;
  const limit = pagination.limit || 20;
  const offset = (page - 1) * limit;
  const pagedData = filtered.slice(offset, offset + limit);
  const hasMore = offset + limit < total;

  return {
    data: pagedData,
    meta: {
      page,
      limit,
      total,
      has_more: hasMore,
      sort_by: pagination.sort_by,
      sort_order: pagination.sort_order,
    },
  };
}
