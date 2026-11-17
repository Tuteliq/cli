import { beforeEach, describe, expect, it, vi } from 'vitest';
import { runCli } from './helpers.js';

const { client, store } = vi.hoisted(() => ({
  client: {} as Record<string, ReturnType<typeof vi.fn>>,
  store: new Map<string, unknown>(),
}));

vi.mock('@tuteliq/sdk', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@tuteliq/sdk')>();
  return {
    ...actual,
    Tuteliq: class {
      constructor() {
        return client;
      }
    },
  };
});

vi.mock('conf', () => ({
  default: class {
    path = '/invented/config.json';
    get(key: string) {
      return store.get(key);
    }
    set(key: string, value: unknown) {
      store.set(key, value);
    }
    delete(key: string) {
      store.delete(key);
    }
  },
}));

function stub(method: string, value: unknown) {
  client[method] = vi.fn().mockResolvedValue(value);
  return client[method];
}

beforeEach(() => {
  for (const key of Object.keys(client)) delete client[key];
  store.clear();
  store.set('apiKey', 'tq_invented_key_0000');
});

describe('severity and risk formatting', () => {
  it('prints N/A when a multi-endpoint result has no level, instead of crashing', async () => {
    stub('analyseMulti', {
      summary: { total_endpoints: 1, detected_count: 0, highest_risk: null, overall_risk_level: 'none' },
      results: [
        {
          endpoint: 'romance-scam',
          detected: false,
          severity: 0,
          confidence: 0.9,
          risk_score: 0.05,
          categories: [],
          recommended_action: 'none',
        },
      ],
    });

    const r = await runCli(['analyse-multi', 'invented text', '-e', 'romance-scam']);

    expect(r.exitCode).toBeUndefined();
    expect(r.stdout).toContain('Level: N/A');
  });

  it('shows the level of each multi-endpoint result when present', async () => {
    stub('analyseMulti', {
      summary: { total_endpoints: 1, detected_count: 1, highest_risk: { endpoint: 'grooming', risk_score: 0.8 }, overall_risk_level: 'high' },
      results: [
        {
          endpoint: 'grooming',
          detected: true,
          severity: 0.7,
          confidence: 0.9,
          risk_score: 0.8,
          level: 'high',
          categories: [{ tag: 'TRUST_BUILDING', label: 'Trust building', confidence: 0.8 }],
          evidence: [{ text: 'invented excerpt', tactic: 'TRUST_BUILDING', weight: 0.6 }],
          recommended_action: 'review',
        },
      ],
    });

    const r = await runCli(['multi', 'invented text', '-e', 'grooming']);

    expect(r.stdout).toContain('Level: HIGH');
    expect(r.stdout).toContain('Categories:  Trust building');
    expect(r.stdout).toContain('invented excerpt (TRUST_BUILDING)');
  });

  it('renders a detection result with numeric severity, category labels and evidence objects', async () => {
    const detect = stub('detectSocialEngineering', {
      endpoint: 'social_engineering',
      detected: true,
      severity: 0.6,
      confidence: 0.85,
      risk_score: 0.7,
      level: 'medium',
      categories: [{ tag: 'URGENCY_FABRICATION', label: 'Urgency fabrication', confidence: 0.8 }],
      evidence: [{ text: 'invented quote', tactic: 'URGENCY_FABRICATION', weight: 0.5 }],
      recommended_action: 'review',
      rationale: 'Invented rationale.',
      language: 'en',
      language_status: 'stable',
    });

    const r = await runCli([
      'social-engineering', 'invented text',
      '--external-id', 'ext-1', '--customer-id', 'cust-1', '--age-group', '13-15',
    ]);

    expect(r.exitCode).toBeUndefined();
    expect(r.stdout).toContain('SOCIAL ENGINEERING DETECTED');
    expect(r.stdout).toContain('Severity:    60%');
    expect(r.stdout).toContain('Level:       MEDIUM');
    expect(r.stdout).toContain('Categories:  Urgency fabrication');
    expect(r.stdout).toContain('invented quote (URGENCY_FABRICATION)');
    expect(r.stdout).not.toContain('[object Object]');
    expect(detect).toHaveBeenCalledWith({
      content: 'invented text',
      includeEvidence: false,
      context: { ageGroup: '13-15' },
      external_id: 'ext-1',
      customer_id: 'cust-1',
    });
  });
});

describe('detect-distress-signals', () => {
  it('calls the distress signals detector and renders the result', async () => {
    const detect = stub('detectDistressSignals', {
      endpoint: 'distress_signals',
      detected: false,
      severity: 0,
      confidence: 0.9,
      risk_score: 0.02,
      level: 'none',
      categories: [],
      recommended_action: 'none',
      language: 'en',
      language_status: 'stable',
    });

    const r = await runCli(['distress-signals', 'invented text']);

    expect(detect).toHaveBeenCalledWith(expect.objectContaining({ content: 'invented text' }));
    expect(r.stdout).toContain('No distress signals detected');
    expect(r.stdout).toContain('Level:       NONE');
  });
});

describe('detect-synthetic-text', () => {
  it('shows the classification', async () => {
    stub('detectSyntheticText', {
      endpoint: 'synthetic_text',
      detected: true,
      severity: 0.5,
      level: 'medium',
      classification: 'ai_generated',
      confidence: 0.8,
      risk_score: 0.6,
      categories: [],
      recommended_action: 'review',
      rationale: 'Invented rationale.',
    });

    const r = await runCli(['synthetic-text', 'invented text']);

    expect(r.stdout).toContain('SYNTHETIC TEXT DETECTED');
    expect(r.stdout).toContain('Classification: ai_generated');
  });
});

describe('verify session', () => {
  it('creates a session with every option passed through', async () => {
    const create = stub('createVerificationSession', {
      session_id: 'sess_invented_1',
      url: 'https://verify.example.test/s/sess_invented_1',
      expires_at: Date.UTC(2026, 0, 1, 12, 0, 0),
      mode: 'identity',
      chip_policy: 'required',
      auto_capture: false,
    });

    const r = await runCli([
      'verify', 'session', 'create',
      '--mode', 'identity', '--document-type', 'passport',
      '--chip-policy', 'required', '--no-auto-capture',
    ]);

    expect(r.exitCode).toBeUndefined();
    expect(create).toHaveBeenCalledWith({
      mode: 'identity',
      document_type: 'passport',
      chip_policy: 'required',
      auto_capture: false,
    });
    expect(r.stdout).toContain('sess_invented_1');
    expect(r.stdout).toContain('https://verify.example.test/s/sess_invented_1');
    expect(r.stdout).toContain('2026-01-01T12:00:00.000Z');
    expect(r.stdout).toContain('Auto Capture: No');
  });

  it('defaults to an age session and leaves auto capture to the API', async () => {
    const create = stub('createVerificationSession', {
      session_id: 'sess_invented_2',
      url: 'https://verify.example.test/s/sess_invented_2',
      expires_at: Date.UTC(2026, 0, 1),
      mode: 'age',
    });

    await runCli(['verify', 'session', 'create']);

    expect(create).toHaveBeenCalledWith({ mode: 'age' });
  });

  it('rejects an unknown chip policy before calling the API', async () => {
    const create = stub('createVerificationSession', {});

    const r = await runCli(['verify', 'session', 'create', '--chip-policy', 'sometimes']);

    expect(r.exitCode).toBe(1);
    expect(r.stderr).toContain('sometimes');
    expect(create).not.toHaveBeenCalled();
  });

  it('shows a session waiting for a document photo', async () => {
    stub('getVerificationSession', {
      session_id: 'sess_invented_3',
      status: 'document_required',
      step_progress: 'uploading',
      result: null,
    });

    const r = await runCli(['verify', 'session', 'get', 'sess_invented_3']);

    expect(r.stdout).toContain('Status:     DOCUMENT_REQUIRED');
    expect(r.stdout).toContain('waiting for the user to add a document photo');
    expect(r.stdout).toContain('Step:       uploading');
  });

  it('shows the result with the face match score', async () => {
    stub('getVerificationSession', {
      session_id: 'sess_invented_4',
      status: 'completed',
      verification_mode: 'full',
      document_evidence: 'photo_and_chip',
      result: {
        status: 'verified',
        age: 34,
        is_minor: false,
        document: null,
        face_match: { matched: true, confidence: 0.61, match_score: 0.93 },
        liveness: { valid: true },
        failure_reasons: [],
      },
    });

    const r = await runCli(['verify', 'session', 'get', 'sess_invented_4']);

    expect(r.stdout).toContain('Result:     VERIFIED');
    expect(r.stdout).toContain('Age:        34');
    expect(r.stdout).toContain('Minor:      No');
    expect(r.stdout).toContain('Face Match: Yes (score 93%)');
    expect(r.stdout).toContain('Liveness:   Passed');
    expect(r.stdout).toContain('Evidence:   photo_and_chip');
  });

  it('falls back to the face match decision when the score is absent', async () => {
    stub('getVerificationSession', {
      session_id: 'sess_invented_5',
      status: 'failed',
      result: {
        status: 'failed',
        age: null,
        is_minor: null,
        document: null,
        face_match: { matched: false, confidence: 0.2 },
        liveness: { valid: false },
        failure_reasons: ['Invented reason'],
      },
    });

    const r = await runCli(['verify', 'session', 'get', 'sess_invented_5']);

    expect(r.stdout).toContain('Face Match: No');
    expect(r.stdout).not.toContain('score');
    expect(r.stdout).toContain('Age:        Unknown');
    expect(r.stdout).toContain('Invented reason');
  });

  it('shows the fields released only on the first read', async () => {
    stub('getVerificationSession', {
      session_id: 'sess_invented_8',
      status: 'completed',
      result: {
        status: 'verified',
        age: 30,
        is_minor: false,
        date_of_birth: '1996-01-01',
        document: { ocr_confidence: 0.9, document_type: 'passport', country_code: 'XX', chip_verified: true },
        face_match: { matched: true, confidence: 0.6, match_score: 0.9 },
        liveness: { valid: true },
      },
    });

    const r = await runCli(['verify', 'session', 'get', 'sess_invented_8']);

    expect(r.stdout).toContain('Released once');
    expect(r.stdout).toContain('Date of Birth:  1996-01-01');
    expect(r.stdout).toContain('Document Type:  passport');
    expect(r.stdout).toContain('Chip Verified:  Yes');
  });

  it('prints the raw response with --json', async () => {
    const body = { session_id: 'sess_invented_6', status: 'pending', result: null };
    stub('getVerificationSession', body);

    const r = await runCli(['verify', 'session', 'get', 'sess_invented_6', '--json']);

    expect(JSON.parse(r.stdout)).toEqual(body);
  });

  it('cancels a session', async () => {
    const cancel = stub('cancelVerificationSession', undefined);

    const r = await runCli(['verify', 'session', 'cancel', 'sess_invented_7']);

    expect(cancel).toHaveBeenCalledWith('sess_invented_7');
    expect(r.stdout).toContain('Session cancelled');
  });

  it('exits with an error when the API call fails', async () => {
    client.getVerificationSession = vi.fn().mockRejectedValue(new Error('Session not found'));

    const r = await runCli(['verify', 'session', 'get', 'sess_missing']);

    expect(r.exitCode).toBe(1);
    expect(r.stderr).toContain('Session not found');
  });
});

const incidentRow = {
  id: 'inc_invented_1',
  risk_category: 'bullying',
  risk_level: 'moderate',
  confidence_score: 0.8,
  detected_patterns: ['exclusion'],
  recommended_actions: ['review'],
  platform: 'InventedApp',
  language: 'en',
  source: 'text',
  file_id: null,
  status: 'new',
  policy_action: null,
  recommended_status: null,
  escalation_capped: null,
  escalation_capped_reason: null,
  speaker_stance: null,
  action_capped: null,
  action_capped_reason: null,
  is_test: false,
  external_id: 'ext-1',
  customer_id: null,
  created_at: '2026-01-02T03:04:05.000Z',
};

describe('incidents', () => {
  it('lists incidents with filters mapped to the SDK input', async () => {
    const list = stub('listIncidents', { incidents: [incidentRow], next_cursor: 'cur_next', total_returned: 1 });

    const r = await runCli([
      'incidents', 'list',
      '--category', 'bullying', '--severity', 'moderate', '--status', 'new', '--source', 'text',
      '--from', '2026-01-01T00:00:00Z', '--to', '2026-02-01T00:00:00Z',
      '--platform', 'InventedApp', '--external-id', 'ext-1', '--customer-id', 'cust-1',
      '--limit', '10', '--cursor', 'cur_prev', '--include-summary',
    ]);

    expect(list).toHaveBeenCalledWith({
      category: 'bullying',
      severity: 'moderate',
      status: 'new',
      source: 'text',
      from: '2026-01-01T00:00:00Z',
      to: '2026-02-01T00:00:00Z',
      platform: 'InventedApp',
      externalId: 'ext-1',
      customerId: 'cust-1',
      limit: 10,
      cursor: 'cur_prev',
      includeSummary: true,
    });
    expect(r.stdout).toContain('MODERATE');
    expect(r.stdout).toContain('bullying');
    expect(r.stdout).toContain('inc_invented_1');
    expect(r.stdout).toContain('--cursor cur_next');
  });

  it('says so when there are no incidents', async () => {
    stub('listIncidents', { incidents: [], next_cursor: null, total_returned: 0 });

    const r = await runCli(['incidents', 'list']);

    expect(r.stdout).toContain('No incidents found.');
  });

  it('rejects an invalid limit', async () => {
    const list = stub('listIncidents', { incidents: [], next_cursor: null, total_returned: 0 });

    const r = await runCli(['incidents', 'list', '--limit', 'ten']);

    expect(r.exitCode).toBe(1);
    expect(r.stderr).toContain('--limit');
    expect(list).not.toHaveBeenCalled();
  });

  it('gets one incident', async () => {
    stub('getIncident', { ...incidentRow, summary: 'Invented summary.', message_analysis: null });

    const r = await runCli(['incidents', 'get', 'inc_invented_1']);

    expect(client.getIncident).toHaveBeenCalledWith('inc_invented_1');
    expect(r.stdout).toContain('Category:   bullying');
    expect(r.stdout).toContain('Status:     new');
    expect(r.stdout).toContain('Patterns:   exclusion');
    expect(r.stdout).toContain('Invented summary.');
  });

  it('shows the overview', async () => {
    const overview = stub('getIncidentsOverview', {
      timeframe: { from: '2026-01-01T00:00:00Z', to: '2026-01-31T00:00:00Z' },
      total_incidents: 42,
      requires_review_count: 3,
      last_24h_count: 1,
      last_7d_count: 9,
      last_30d_count: 42,
      counts_by_category: { bullying: 30, grooming: 12 },
      counts_by_severity: { high: 5 },
      counts_by_source: { text: 42 },
      counts_by_status: { new: 40, resolved: 2 },
      top_platforms: [{ platform: 'InventedApp', count: 42 }],
    });

    const r = await runCli(['incidents', 'overview', '--from', '2026-01-01T00:00:00Z']);

    expect(overview).toHaveBeenCalledWith({ from: '2026-01-01T00:00:00Z', to: undefined });
    expect(r.stdout).toContain('Total:          42');
    expect(r.stdout).toContain('Needs Review:   3');
    expect(r.stdout).toContain('grooming');
    expect(r.stdout).toContain('InventedApp');
  });

  it('shows trends', async () => {
    const trends = stub('getIncidentTrends', {
      bucket_size: 'week',
      timeframe: { from: '2026-01-01T00:00:00Z', to: '2026-01-31T00:00:00Z' },
      series: [{ bucket_start: '2026-01-05T00:00:00Z', total: 7, by_severity: { high: 2, low: 5 } }],
    });

    const r = await runCli(['incidents', 'trends', '--bucket', 'week']);

    expect(trends).toHaveBeenCalledWith({ bucket: 'week', from: undefined, to: undefined });
    expect(r.stdout).toContain('2026-01-05T00:00:00Z');
    expect(r.stdout).toContain('high: 2');
  });

  it('reviews an incident', async () => {
    const review = stub('reviewIncident', {
      incident_id: 'inc_invented_1',
      original: { risk_category: 'bullying', risk_level: 'moderate' },
      revised: { risk_category: 'bullying', risk_level: 'low' },
      audit_receipt: { request_id: 'req_invented', timestamp: '2026-01-02T00:00:00Z', signature: 'sig' },
    });

    const r = await runCli([
      'incidents', 'review', 'inc_invented_1',
      '--action', 'downgrade', '--reason', 'insufficient_severity',
      '--moderator', 'moderator-7', '--new-level', 'low', '--comment', 'Invented comment',
    ]);

    expect(review).toHaveBeenCalledWith('inc_invented_1', {
      action: 'downgrade',
      reason_code: 'insufficient_severity',
      moderator_external_id: 'moderator-7',
      reason_comment: 'Invented comment',
      new_risk_level: 'low',
    });
    expect(r.stdout).toContain('bullying/moderate -> bullying/low');
    expect(r.stdout).toContain('req_invented');
  });

  it('requires a moderator for a review', async () => {
    const review = stub('reviewIncident', {});

    const r = await runCli(['incidents', 'review', 'inc_invented_1', '--action', 'dismiss', '--reason', 'false_positive']);

    expect(r.exitCode).toBe(1);
    expect(r.stderr).toContain('--moderator');
    expect(review).not.toHaveBeenCalled();
  });

  it('batch reviews incidents and lists failures', async () => {
    const batch = stub('batchReviewIncidents', {
      total: 2,
      succeeded: 1,
      failed: 1,
      results: [
        { incident_id: 'inc_a', ok: true },
        { incident_id: 'inc_b', ok: false, error: 'not_found' },
      ],
    });

    const r = await runCli([
      'incidents', 'batch-review', 'inc_a', 'inc_b',
      '--action', 'dismiss', '--reason', 'false_positive', '--moderator', 'moderator-7',
    ]);

    expect(batch).toHaveBeenCalledWith({
      incident_ids: ['inc_a', 'inc_b'],
      action: 'dismiss',
      reason_code: 'false_positive',
      moderator_external_id: 'moderator-7',
    });
    expect(r.stdout).toContain('1/2 reviewed');
    expect(r.stdout).toContain('inc_b');
    expect(r.stdout).toContain('not_found');
  });
});

describe('breach commands', () => {
  it('are labelled as admin only in help', async () => {
    const { program } = await import('../src/program.js');
    const breach = program.commands.find((c) => c.name() === 'breach');
    expect(breach?.description()).toMatch(/admin/i);
  });
});

describe('version', () => {
  it('reports the package version', async () => {
    const { program } = await import('../src/program.js');
    const { createRequire } = await import('node:module');
    const pkg = createRequire(import.meta.url)('../package.json') as { version: string };
    expect(program.version()).toBe(pkg.version);
  });
});

describe('whoami', () => {
  it('says a key is saved without printing any part of it', async () => {
    const { stdout } = await runCli(['whoami']);
    expect(stdout).toContain('Logged in');
    for (const part of ['tq_invented', 'invented_key', '0000']) expect(stdout).not.toContain(part);
  });

  it('says how to log in when no key is saved', async () => {
    store.clear();
    const { stdout } = await runCli(['whoami']);
    expect(stdout).toContain('Not logged in');
  });
});
