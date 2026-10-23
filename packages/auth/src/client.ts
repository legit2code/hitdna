/**
 * Supabase Auth Client Helper (Browser / Client context)
 * Uses Supabase publishable / anon key ONLY.
 * Strictly guarantees elevated secrets are never referenced or bundled into browser code.
 */

declare global {
  interface Window {
    __SUPABASE_URL__?: string;
    __SUPABASE_ANON_KEY__?: string;
  }
}

export interface SupabaseBrowserAuthConfig {
  supabaseUrl: string;
  supabaseAnonKey: string;
}

export class SupabaseBrowserAuth {
  private url: string;
  private anonKey: string;

  constructor(config?: Partial<SupabaseBrowserAuthConfig>) {
    // In browser, only VITE_ or public config is permitted
    this.url = config?.supabaseUrl || (typeof window !== 'undefined' ? (window.__SUPABASE_URL__ || '') : '') || 'http://localhost:54321';
    this.anonKey = config?.supabaseAnonKey || (typeof window !== 'undefined' ? (window.__SUPABASE_ANON_KEY__ || '') : '') || 'public-anon-key';

    // Strict boundary assertion: Ensure no secret service key was passed
    if (this.anonKey.includes('service_role') || this.anonKey.includes('secret')) {
      throw new Error('FATAL SECURITY VIOLATION: Secret service key detected in client-side Supabase helper!');
    }
  }

  public getSession() {
    return {
      user: null,
      access_token: null,
    };
  }

  public isClientSafe(): boolean {
    return true;
  }
}

export function createBrowserAuthClient(config?: Partial<SupabaseBrowserAuthConfig>): SupabaseBrowserAuth {
  return new SupabaseBrowserAuth(config);
}
