/**
 * Workers & Jobs Boundary (PF-02 / PF-08)
 * Contracts and stubs for asynchronous jobs and background processing.
 */

export type JobStatus = 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED';

export interface BackgroundJob<TPayload = unknown, TResult = unknown> {
  jobId: string;
  type: string;
  status: JobStatus;
  payload: TPayload;
  result?: TResult;
  error?: string;
  createdAt: string;
  updatedAt: string;
}

export interface IJobQueue {
  enqueue<T>(type: string, payload: T): Promise<BackgroundJob<T>>;
  getJob(jobId: string): Promise<BackgroundJob | null>;
}

export class MemoryJobQueue implements IJobQueue {
  private jobs: Map<string, BackgroundJob> = new Map();

  async enqueue<T>(type: string, payload: T): Promise<BackgroundJob<T>> {
    const job: BackgroundJob<T> = {
      jobId: `job_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`,
      type,
      status: 'PENDING',
      payload,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    this.jobs.set(job.jobId, job as unknown as BackgroundJob);
    return job;
  }

  async getJob(jobId: string): Promise<BackgroundJob | null> {
    return this.jobs.get(jobId) || null;
  }
}
