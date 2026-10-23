import { describe, it, expect } from 'vitest';
import { 
  MultimodalIOCapabilityEngine, 
  MultimodalChannelDefinition 
} from '../workers/decision/capabilities/multimodal-io.ts';

describe('E40: Multimodal I/O Capability Engine', () => {
  const engine = new MultimodalIOCapabilityEngine();

  it('detects unvalidated mime-types, unbounded payloads, and missing visual injection filters', () => {
    const channels: MultimodalChannelDefinition[] = [
      {
        channelId: 'vision_ocr_input',
        modality: 'IMAGE',
        direction: 'INGESTION',
        supportedMimeTypes: ['image/png', 'image/jpeg'],
        maxPayloadSizeBytes: 100 * 1024 * 1024, // 100MB exceeds 50MB safe boundary
        hasMimeTypeValidation: false, // Unvalidated binary upload
        hasPayloadSizeLimit: false,
        hasVisualPromptInjectionFilter: false, // Visual injection vulnerability
        hasAudioTranscriptionSafetyFilter: false
      },
      {
        channelId: 'audio_listener',
        modality: 'AUDIO',
        direction: 'BIDIRECTIONAL',
        supportedMimeTypes: ['audio/wav'],
        maxPayloadSizeBytes: 10 * 1024 * 1024,
        hasMimeTypeValidation: true,
        hasPayloadSizeLimit: true,
        hasVisualPromptInjectionFilter: false,
        hasAudioTranscriptionSafetyFilter: false // Unfiltered audio egress
      }
    ];

    const report = engine.analyzeChannels('run-e40-001', channels);

    expect(report.findings.some(f => f.riskType === 'MISSING_MIME_TYPE_VALIDATION')).toBe(true);
    expect(report.findings.some(f => f.riskType === 'UNBOUNDED_PAYLOAD_BUFFER_DOS')).toBe(true);
    expect(report.findings.some(f => f.riskType === 'UNFILTERED_VISUAL_PROMPT_INJECTION')).toBe(true);
    expect(report.flaggedChannels).toContain('vision_ocr_input');
    expect(report.hasHighRiskVulnerability).toBe(true);
  });

  it('validates compliant, bounded, safe multimodal pipeline', () => {
    const channels: MultimodalChannelDefinition[] = [
      {
        channelId: 'safe_document_scanner',
        modality: 'DOCUMENT_PDF',
        direction: 'INGESTION',
        supportedMimeTypes: ['application/pdf'],
        maxPayloadSizeBytes: 15 * 1024 * 1024,
        hasMimeTypeValidation: true,
        hasPayloadSizeLimit: true,
        hasVisualPromptInjectionFilter: true,
        hasAudioTranscriptionSafetyFilter: true
      }
    ];

    const report = engine.analyzeChannels('run-e40-002', channels);

    expect(report.findings.length).toBe(0);
    expect(report.safeChannels).toContain('safe_document_scanner');
    expect(report.multimodalSafetyScore).toBe(1.0);
    expect(report.hasHighRiskVulnerability).toBe(false);
  });
});
