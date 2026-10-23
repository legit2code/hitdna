/**
 * Architecture V2.0.1: Email Sender Abstraction
 * Decouples email delivery from core business logic so enterprise providers
 * (e.g. AWS SES, SendGrid, Postmark, Resend) can be configured without changing calling code.
 */

import crypto from 'crypto';

export interface SendEmailOptions {
  to: string;
  subject: string;
  html: string;
  text: string;
  from?: string;
}

export interface EmailSenderResult {
  messageId: string;
  success: boolean;
  timestamp: string;
  recipient: string;
}

export interface EmailSender {
  sendEmail(options: SendEmailOptions): Promise<EmailSenderResult>;
}

/**
 * Stub implementation of EmailSender for testing and development.
 * Captures outgoing emails in an in-memory ledger for audit and verification.
 */
export class StubEmailSender implements EmailSender {
  private sentEmails: Array<SendEmailOptions & { timestamp: string; messageId: string }> = [];

  public async sendEmail(options: SendEmailOptions): Promise<EmailSenderResult> {
    const messageId = `msg_${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;
    const record = {
      ...options,
      timestamp: new Date().toISOString(),
      messageId,
    };
    this.sentEmails.push(record);
    console.log(`[EmailSender Stub] Dispatched email to ${options.to}: "${options.subject}" (messageId: ${messageId})`);
    return {
      messageId,
      success: true,
      timestamp: record.timestamp,
      recipient: options.to,
    };
  }

  public getSentEmails(): Array<SendEmailOptions & { timestamp: string; messageId: string }> {
    return [...this.sentEmails];
  }

  public getLastSentEmail(): (SendEmailOptions & { timestamp: string; messageId: string }) | undefined {
    return this.sentEmails[this.sentEmails.length - 1];
  }

  public findEmailsTo(email: string): Array<SendEmailOptions & { timestamp: string; messageId: string }> {
    const normalized = email.trim().toLowerCase();
    return this.sentEmails.filter(e => e.to.trim().toLowerCase() === normalized);
  }

  public clear(): void {
    this.sentEmails = [];
  }
}

export const InMemoryEmailSender = StubEmailSender;
export type InMemoryEmailSender = StubEmailSender;

const defaultEmailSender = new StubEmailSender();

export function getDefaultEmailSender(): StubEmailSender {
  return defaultEmailSender;
}

export function getStubEmailSender(): StubEmailSender {
  return defaultEmailSender;
}

export function resetEmailSender(): void {
  defaultEmailSender.clear();
}
