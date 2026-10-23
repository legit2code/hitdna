import {
  OutboxEventRecord,
  OutboxDeliveryRecord,
  OutboxEventStatus,
  OutboxDeliveryStatus,
  CorrelationContext,
} from './types.ts';
import { DatabaseClientLike, generateUuid } from './queue.ts';

export type OutboxSubscriberHandler = (event: OutboxEventRecord) => Promise<void>;

export interface OutboxSubscriber {
  name: string;
  eventTypeFilter?: string | RegExp | ((eventType: string) => boolean);
  handler: OutboxSubscriberHandler;
}

export interface CreateOutboxEventInput<T = unknown> {
  eventType: string;
  aggregateEntityRefId?: string;
  payload: T;
  correlationId: string;
  causationId?: string;
  schemaVersion?: string;
}

export class OutboxService {
  constructor(private db: DatabaseClientLike) {}

  /**
   * Atomically records an outbox event in ops.outbox_events.
   * MUST be executed inside the domain transaction.
   */
  async writeEvent<T = unknown>(
    eventInput: CreateOutboxEventInput<T>,
    dbClient?: DatabaseClientLike
  ): Promise<OutboxEventRecord<T>> {
    const outboxDb = dbClient || this.db;
    const eventId = generateUuid();
    const schemaVersion = eventInput.schemaVersion || '1.0.0';
    const payloadJson = JSON.stringify(eventInput.payload ?? {});

    const res = await outboxDb.query(
      `INSERT INTO ops.outbox_events (
        event_id,
        event_type,
        aggregate_entity_ref_id,
        payload,
        schema_version,
        correlation_id,
        causation_id,
        status,
        occurred_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, 'PENDING', now())
      RETURNING *;`,
      [
        eventId,
        eventInput.eventType,
        eventInput.aggregateEntityRefId || null,
        payloadJson,
        schemaVersion,
        eventInput.correlationId,
        eventInput.causationId || null,
      ]
    );

    const row = res.rows[0];
    return {
      ...row,
      payload: typeof row.payload === 'string' ? JSON.parse(row.payload) : row.payload,
    } as OutboxEventRecord<T>;
  }

  /**
   * Get pending events ready for dispatch.
   */
  async getPendingEvents(limit = 100): Promise<OutboxEventRecord[]> {
    const res = await this.db.query(
      `SELECT * FROM ops.outbox_events
       WHERE status = 'PENDING'
       ORDER BY occurred_at ASC
       LIMIT $1;`,
      [limit]
    );

    return (res.rows || []).map((row) => ({
      ...row,
      payload: typeof row.payload === 'string' ? JSON.parse(row.payload) : row.payload,
    }));
  }
}

export class OutboxDispatcher {
  private subscribers: Map<string, OutboxSubscriber> = new Map();
  private isRunning = false;

  constructor(
    private db: DatabaseClientLike,
    private outboxService = new OutboxService(db)
  ) {}

  /**
   * Register a subscriber listener.
   */
  registerSubscriber(subscriber: OutboxSubscriber): this {
    this.subscribers.set(subscriber.name, subscriber);
    return this;
  }

  /**
   * Dispatch pending events to all matching subscribers.
   */
  async dispatchPending(limit = 50): Promise<{
    processedCount: number;
    deliveredCount: number;
    failedCount: number;
  }> {
    const pendingEvents = await this.outboxService.getPendingEvents(limit);
    let processedCount = 0;
    let deliveredCount = 0;
    let failedCount = 0;

    for (const event of pendingEvents) {
      processedCount++;
      let allDelivered = true;

      // Find matching subscribers
      const matchedSubscribers = Array.from(this.subscribers.values()).filter((sub) => {
        if (!sub.eventTypeFilter) return true;
        if (typeof sub.eventTypeFilter === 'string') {
          return sub.eventTypeFilter === event.event_type || sub.eventTypeFilter === '*';
        }
        if (sub.eventTypeFilter instanceof RegExp) {
          return sub.eventTypeFilter.test(event.event_type);
        }
        if (typeof sub.eventTypeFilter === 'function') {
          return sub.eventTypeFilter(event.event_type);
        }
        return false;
      });

      if (matchedSubscribers.length === 0) {
        // No subscribers matched, mark delivered directly
        await this.markEventDelivered(event.event_id);
        deliveredCount++;
        continue;
      }

      for (const sub of matchedSubscribers) {
        const deliveryId = generateUuid();
        try {
          // Record delivery attempt
          await this.db.query(
            `INSERT INTO ops.outbox_deliveries (
              delivery_id,
              event_id,
              target_subscriber,
              status,
              attempt_count
            ) VALUES ($1, $2, $3, 'PENDING', 1);`,
            [deliveryId, event.event_id, sub.name]
          );

          // Execute subscriber handler
          await sub.handler(event);

          // Mark delivery success
          await this.db.query(
            `UPDATE ops.outbox_deliveries
             SET status = 'DELIVERED',
                 delivered_at = now()
             WHERE delivery_id = $1;`,
            [deliveryId]
          );
        } catch (err: any) {
          allDelivered = false;
          failedCount++;
          const errorMsg = err.message || String(err);

          await this.db.query(
            `UPDATE ops.outbox_deliveries
             SET status = 'FAILED',
                 last_error = $1
             WHERE delivery_id = $2;`,
            [errorMsg, deliveryId]
          );
        }
      }

      if (allDelivered) {
        await this.markEventDelivered(event.event_id);
        deliveredCount++;
      } else {
        await this.db.query(
          `UPDATE ops.outbox_events
           SET status = 'FAILED'
           WHERE event_id = $1;`,
          [event.event_id]
        );
      }
    }

    return { processedCount, deliveredCount, failedCount };
  }

  private async markEventDelivered(eventId: string): Promise<void> {
    await this.db.query(
      `UPDATE ops.outbox_events
       SET status = 'DELIVERED',
           published_at = now()
       WHERE event_id = $1;`,
      [eventId]
    );
  }
}
