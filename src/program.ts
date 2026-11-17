import { createRequire } from 'node:module';
import { Command, InvalidArgumentError, Option } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import Conf from 'conf';
import { Tuteliq, ChipPolicy, Detection, DocumentType, VerificationMode } from '@tuteliq/sdk';
import type {
  DetectionInput,
  DetectionName,
  DetectionResult,
  IncidentSeverity,
  IncidentSource,
  IncidentSummaryRow,
  IncidentCategory,
  ModeratorAction,
  ModeratorReasonCode,
  RetentionClass,
  VerificationSessionResult,
} from '@tuteliq/sdk';

const config = new Conf({ projectName: 'tuteliq' });
const { version: VERSION } = createRequire(import.meta.url)('../package.json') as { version: string };

function getClient(): Tuteliq {
  const apiKey = config.get('apiKey') as string;
  if (!apiKey) {
    console.error(chalk.red('Not logged in. Run: tuteliq login <api-key>'));
    process.exit(1);
  }
  return new Tuteliq(apiKey);
}

const LEVEL_COLORS: Record<string, (s: string) => string> = {
  none: chalk.green,
  safe: chalk.green,
  low: chalk.yellow,
  medium: chalk.hex('#FFA500'),
  moderate: chalk.hex('#FFA500'),
  high: chalk.red,
  critical: chalk.bgRed.white,
};

/** Colours a level label. A missing level prints as N/A rather than failing the command. */
function formatLevel(level: string | null | undefined): string {
  if (!level) return chalk.dim('N/A');
  return (LEVEL_COLORS[level] || chalk.white)(level.toUpperCase());
}

const formatSeverity = formatLevel;
const formatRisk = formatLevel;

function formatPercent(value: number): string {
  return chalk.cyan((value * 100).toFixed(0) + '%');
}

function parsePositiveInt(value: string): number {
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1) {
    throw new InvalidArgumentError('Must be a positive whole number.');
  }
  return n;
}

function fail(spinner: { stop(): unknown }, error: unknown): never {
  spinner.stop();
  console.error(chalk.red('Error:'), error instanceof Error ? error.message : error);
  process.exit(1);
}

const program = new Command();

program
  .name('tuteliq')
  .description('Tuteliq CLI - AI-powered child safety analysis')
  .version(VERSION);

// Login command
program
  .command('login <api-key>')
  .description('Save your API key')
  .action((apiKey: string) => {
    config.set('apiKey', apiKey);
    console.log(chalk.green('✓ API key saved successfully!'));
    console.log(chalk.dim('Your key is stored locally at: ' + config.path));
  });

// Logout command
program
  .command('logout')
  .description('Remove saved API key')
  .action(() => {
    config.delete('apiKey');
    console.log(chalk.green('✓ Logged out successfully!'));
  });

// Whoami command
program
  .command('whoami')
  .description('Show current login status')
  .action(() => {
    const apiKey = config.get('apiKey') as string;
    if (apiKey) {
      const masked = apiKey.slice(0, 8) + '...' + apiKey.slice(-4);
      console.log(chalk.green('✓ Logged in'));
      console.log(chalk.dim('API Key: ' + masked));
    } else {
      console.log(chalk.yellow('Not logged in'));
      console.log(chalk.dim('Run: tuteliq login <api-key>'));
    }
  });

// Detect bullying
program
  .command('detect-bullying <text>')
  .alias('bullying')
  .description('Analyze text for bullying or harassment')
  .action(async (text: string) => {
    const spinner = ora('Analyzing...').start();
    try {
      const client = getClient();
      const result = await client.detectBullying({ content: text });
      spinner.stop();

      console.log();
      if (result.is_bullying) {
        console.log(chalk.red.bold('⚠ BULLYING DETECTED'));
      } else {
        console.log(chalk.green.bold('✓ No bullying detected'));
      }
      console.log();
      console.log(`Severity:    ${formatSeverity(result.severity)}`);
      console.log(`Confidence:  ${chalk.cyan((result.confidence * 100).toFixed(0) + '%')}`);
      console.log(`Risk Score:  ${chalk.cyan((result.risk_score * 100).toFixed(0) + '%')}`);
      if (result.bullying_type?.length > 0) {
        console.log(`Types:       ${result.bullying_type.join(', ')}`);
      }
      if (result.rationale) {
        console.log();
        console.log(chalk.dim('Rationale:'));
        console.log(result.rationale);
      }
      console.log();
      console.log(`Action: ${chalk.yellow(result.recommended_action)}`);
    } catch (error) {
      spinner.stop();
      console.error(chalk.red('Error:'), error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

// Detect grooming
program
  .command('detect-grooming')
  .alias('grooming')
  .description('Analyze conversation for grooming patterns')
  .requiredOption('-m, --messages <json>', 'Messages as JSON array: [{"role":"adult","content":"..."}]')
  .option('-a, --age <number>', 'Child age')
  .action(async (options) => {
    const spinner = ora('Analyzing...').start();
    try {
      const client = getClient();
      const messages = JSON.parse(options.messages);
      const result = await client.detectGrooming({
        messages,
        childAge: options.age ? parseInt(options.age) : undefined,
      });
      spinner.stop();

      console.log();
      if (result.grooming_risk !== 'none') {
        console.log(chalk.red.bold('⚠ GROOMING RISK DETECTED'));
      } else {
        console.log(chalk.green.bold('✓ No grooming detected'));
      }
      console.log();
      console.log(`Risk Level:  ${formatRisk(result.grooming_risk)}`);
      console.log(`Confidence:  ${chalk.cyan((result.confidence * 100).toFixed(0) + '%')}`);
      console.log(`Risk Score:  ${chalk.cyan((result.risk_score * 100).toFixed(0) + '%')}`);
      if (result.flags?.length > 0) {
        console.log();
        console.log(chalk.dim('Warning Flags:'));
        result.flags.forEach((flag: string) => console.log(chalk.yellow(`  • ${flag}`)));
      }
      if (result.rationale) {
        console.log();
        console.log(chalk.dim('Rationale:'));
        console.log(result.rationale);
      }
      console.log();
      console.log(`Action: ${chalk.yellow(result.recommended_action)}`);
    } catch (error) {
      spinner.stop();
      console.error(chalk.red('Error:'), error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

// Detect unsafe content
program
  .command('detect-unsafe <text>')
  .alias('unsafe')
  .description('Detect self-harm, violence, or other unsafe content')
  .action(async (text: string) => {
    const spinner = ora('Analyzing...').start();
    try {
      const client = getClient();
      const result = await client.detectUnsafe({ content: text });
      spinner.stop();

      console.log();
      if (result.unsafe) {
        console.log(chalk.red.bold('⚠ UNSAFE CONTENT DETECTED'));
      } else {
        console.log(chalk.green.bold('✓ Content is safe'));
      }
      console.log();
      console.log(`Severity:    ${formatSeverity(result.severity)}`);
      console.log(`Confidence:  ${chalk.cyan((result.confidence * 100).toFixed(0) + '%')}`);
      console.log(`Risk Score:  ${chalk.cyan((result.risk_score * 100).toFixed(0) + '%')}`);
      if (result.categories?.length > 0) {
        console.log(`Categories:  ${result.categories.join(', ')}`);
      }
      if (result.rationale) {
        console.log();
        console.log(chalk.dim('Rationale:'));
        console.log(result.rationale);
      }
      console.log();
      console.log(`Action: ${chalk.yellow(result.recommended_action)}`);
    } catch (error) {
      spinner.stop();
      console.error(chalk.red('Error:'), error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

// Quick analyze
program
  .command('analyze <text>')
  .description('Quick safety analysis (bullying + unsafe)')
  .action(async (text: string) => {
    const spinner = ora('Analyzing...').start();
    try {
      const client = getClient();
      const result = await client.analyze({ content: text });
      spinner.stop();

      console.log();
      if (result.risk_level === 'safe') {
        console.log(chalk.green.bold('✓ Content appears safe'));
      } else {
        console.log(chalk.red.bold('⚠ SAFETY CONCERNS DETECTED'));
      }
      console.log();
      console.log(`Risk Level:  ${formatRisk(result.risk_level)}`);
      console.log(`Risk Score:  ${chalk.cyan((result.risk_score * 100).toFixed(0) + '%')}`);
      console.log();
      console.log(chalk.dim('Summary:'));
      console.log(result.summary);
      console.log();
      console.log(`Action: ${chalk.yellow(result.recommended_action)}`);
    } catch (error) {
      spinner.stop();
      console.error(chalk.red('Error:'), error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

// Analyze emotions
program
  .command('emotions <text>')
  .description('Analyze emotional content')
  .action(async (text: string) => {
    const spinner = ora('Analyzing...').start();
    try {
      const client = getClient();
      const result = await client.analyzeEmotions({ content: text });
      spinner.stop();

      const trendEmoji: Record<string, string> = {
        improving: '📈',
        stable: '➡️',
        worsening: '📉',
      };

      console.log();
      console.log(chalk.bold('Emotion Analysis'));
      console.log();
      console.log(`Dominant:  ${chalk.cyan(result.dominant_emotions.join(', '))}`);
      console.log(`Trend:     ${trendEmoji[result.trend] || ''} ${result.trend}`);
      console.log();
      console.log(chalk.dim('Summary:'));
      console.log(result.summary);
      console.log();
      console.log(chalk.dim('Recommended Follow-up:'));
      console.log(result.recommended_followup);
    } catch (error) {
      spinner.stop();
      console.error(chalk.red('Error:'), error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

// Get action plan
program
  .command('action-plan <situation>')
  .alias('plan')
  .description('Get guidance for handling a situation')
  .option('-a, --age <number>', 'Child age')
  .option('-t, --audience <type>', 'Audience: child, parent, educator, platform', 'parent')
  .option('-s, --severity <level>', 'Severity: low, medium, high, critical')
  .action(async (situation: string, options) => {
    const spinner = ora('Generating action plan...').start();
    try {
      const client = getClient();
      const result = await client.getActionPlan({
        situation,
        childAge: options.age ? parseInt(options.age) : undefined,
        audience: options.audience,
        severity: options.severity,
      });
      spinner.stop();

      console.log();
      console.log(chalk.bold('Action Plan'));
      console.log(chalk.dim(`For: ${result.audience} | Tone: ${result.tone}`));
      console.log();
      console.log(chalk.dim('Steps:'));
      result.steps.forEach((step: string, i: number) => {
        console.log(chalk.cyan(`  ${i + 1}. `) + step);
      });
    } catch (error) {
      spinner.stop();
      console.error(chalk.red('Error:'), error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

// Account management (GDPR)
const account = program
  .command('account')
  .description('Account data management (GDPR compliance)');

account
  .command('delete')
  .description('Delete all account data (GDPR Article 17 — Right to Erasure)')
  .option('--confirm', 'Skip confirmation prompt')
  .action(async (options) => {
    if (!options.confirm) {
      console.log(chalk.red.bold('⚠ WARNING: This will permanently delete ALL your account data.'));
      console.log(chalk.dim('Run with --confirm to proceed.'));
      process.exit(0);
    }

    const spinner = ora('Deleting account data...').start();
    try {
      const client = getClient();
      const result = await client.deleteAccountData();
      spinner.stop();

      console.log();
      console.log(chalk.green.bold('✓ Account data deleted'));
      console.log(`Deleted records: ${chalk.cyan(String(result.deleted_count))}`);
    } catch (error) {
      spinner.stop();
      console.error(chalk.red('Error:'), error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

account
  .command('export')
  .description('Export all account data as JSON (GDPR Article 20 — Right to Data Portability)')
  .option('-o, --output <file>', 'Output file path (default: stdout)')
  .action(async (options) => {
    const spinner = ora('Exporting account data...').start();
    try {
      const client = getClient();
      const result = await client.exportAccountData();
      spinner.stop();

      const json = JSON.stringify(result, null, 2);

      if (options.output) {
        const fs = await import('fs');
        fs.writeFileSync(options.output, json);
        console.log(chalk.green.bold('✓ Data exported to ' + options.output));
      } else {
        console.log(json);
      }
    } catch (error) {
      spinner.stop();
      console.error(chalk.red('Error:'), error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

account
  .command('consent-record')
  .description('Record consent (GDPR Article 7)')
  .requiredOption('-t, --type <type>', 'Consent type (data_processing, analytics, marketing, third_party_sharing, child_safety_monitoring)')
  .requiredOption('-v, --version <version>', 'Policy version')
  .action(async (options) => {
    const spinner = ora('Recording consent...').start();
    try {
      const client = getClient();
      const result = await client.recordConsent({
        consent_type: options.type,
        version: options.version,
      });
      spinner.stop();

      console.log();
      console.log(chalk.green.bold('✓ Consent recorded'));
      console.log(`Type: ${chalk.cyan(result.consent.consent_type)}`);
      console.log(`Status: ${chalk.cyan(result.consent.status)}`);
      console.log(`Version: ${chalk.cyan(result.consent.version)}`);
    } catch (error) {
      spinner.stop();
      console.error(chalk.red('Error:'), error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

account
  .command('consent-status')
  .description('Get consent status (GDPR Article 7)')
  .option('-t, --type <type>', 'Filter by consent type')
  .action(async (options) => {
    const spinner = ora('Fetching consent status...').start();
    try {
      const client = getClient();
      const result = await client.getConsentStatus(options.type);
      spinner.stop();

      if (result.consents.length === 0) {
        console.log(chalk.dim('No consent records found.'));
        return;
      }

      console.log();
      for (const consent of result.consents) {
        const statusColor = consent.status === 'granted' ? chalk.green : chalk.red;
        console.log(`${chalk.bold(consent.consent_type)}: ${statusColor(consent.status)} (v${consent.version})`);
      }
    } catch (error) {
      spinner.stop();
      console.error(chalk.red('Error:'), error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

account
  .command('consent-withdraw')
  .description('Withdraw consent (GDPR Article 7.3)')
  .requiredOption('-t, --type <type>', 'Consent type to withdraw')
  .action(async (options) => {
    const spinner = ora('Withdrawing consent...').start();
    try {
      const client = getClient();
      const result = await client.withdrawConsent(options.type);
      spinner.stop();

      console.log();
      console.log(chalk.yellow.bold('✓ Consent withdrawn'));
      console.log(`Type: ${chalk.cyan(result.consent.consent_type)}`);
    } catch (error) {
      spinner.stop();
      console.error(chalk.red('Error:'), error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

account
  .command('audit-logs')
  .description('Get audit trail (GDPR Article 15)')
  .option('-a, --action <action>', 'Filter by action type')
  .option('-l, --limit <limit>', 'Maximum number of results')
  .action(async (options) => {
    const spinner = ora('Fetching audit logs...').start();
    try {
      const client = getClient();
      const result = await client.getAuditLogs({
        action: options.action,
        limit: options.limit ? parseInt(options.limit, 10) : undefined,
      });
      spinner.stop();

      if (result.audit_logs.length === 0) {
        console.log(chalk.dim('No audit logs found.'));
        return;
      }

      console.log();
      for (const log of result.audit_logs) {
        console.log(`${chalk.dim(log.created_at)} ${chalk.bold(log.action)} ${chalk.dim(`(${log.id})`)}`);
      }
    } catch (error) {
      spinner.stop();
      console.error(chalk.red('Error:'), error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

// Breach management
// Admin only: the breach register sits behind the API's admin authentication,
// so ordinary API keys receive 403. Kept for operators with an admin key.
const breach = program
  .command('breach')
  .description('[Admin only] Data breach register (GDPR Article 33/34). Requires an admin key; ordinary API keys receive 403');

breach
  .command('log')
  .description('Log a new data breach')
  .requiredOption('-t, --title <title>', 'Breach title')
  .requiredOption('-d, --description <description>', 'Breach description')
  .requiredOption('-s, --severity <severity>', 'Severity: low, medium, high, critical')
  .requiredOption('-u, --users <ids>', 'Affected user IDs (comma-separated)')
  .requiredOption('-c, --categories <categories>', 'Data categories (comma-separated)')
  .requiredOption('-r, --reported-by <reporter>', 'Who reported the breach')
  .action(async (options) => {
    const spinner = ora('Logging breach...').start();
    try {
      const client = getClient();
      const result = await client.logBreach({
        title: options.title,
        description: options.description,
        severity: options.severity,
        affected_user_ids: options.users.split(',').map((s: string) => s.trim()),
        data_categories: options.categories.split(',').map((s: string) => s.trim()),
        reported_by: options.reportedBy,
      });
      spinner.stop();

      console.log();
      console.log(chalk.red.bold('⚠ Breach logged'));
      console.log(`ID:       ${chalk.cyan(result.breach.id)}`);
      console.log(`Title:    ${result.breach.title}`);
      console.log(`Severity: ${formatSeverity(result.breach.severity)}`);
      console.log(`Status:   ${chalk.yellow(result.breach.status)}`);
      console.log(`Deadline: ${chalk.dim(result.breach.notification_deadline)}`);
    } catch (error) {
      spinner.stop();
      console.error(chalk.red('Error:'), error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

breach
  .command('list')
  .description('List data breaches')
  .option('-s, --status <status>', 'Filter by status: detected, investigating, contained, reported, resolved')
  .option('-l, --limit <limit>', 'Maximum number of results')
  .action(async (options) => {
    const spinner = ora('Fetching breaches...').start();
    try {
      const client = getClient();
      const result = await client.listBreaches({
        status: options.status,
        limit: options.limit ? parseInt(options.limit, 10) : undefined,
      });
      spinner.stop();

      if (result.breaches.length === 0) {
        console.log(chalk.dim('No breaches found.'));
        return;
      }

      console.log();
      for (const b of result.breaches) {
        console.log(`${formatSeverity(b.severity)} ${chalk.bold(b.title)} ${chalk.dim(`(${b.id})`)}`);
        console.log(`  Status: ${chalk.yellow(b.status)} | Notification: ${chalk.yellow(b.notification_status)} | ${chalk.dim(b.created_at)}`);
      }
    } catch (error) {
      spinner.stop();
      console.error(chalk.red('Error:'), error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

breach
  .command('get <id>')
  .description('Get a single breach by ID')
  .action(async (id: string) => {
    const spinner = ora('Fetching breach...').start();
    try {
      const client = getClient();
      const result = await client.getBreach(id);
      spinner.stop();

      const b = result.breach;
      console.log();
      console.log(chalk.bold(b.title));
      console.log();
      console.log(`ID:            ${chalk.cyan(b.id)}`);
      console.log(`Severity:      ${formatSeverity(b.severity)}`);
      console.log(`Status:        ${chalk.yellow(b.status)}`);
      console.log(`Notification:  ${chalk.yellow(b.notification_status)}`);
      console.log(`Reported By:   ${b.reported_by}`);
      console.log(`Deadline:      ${chalk.dim(b.notification_deadline)}`);
      console.log(`Created:       ${chalk.dim(b.created_at)}`);
      console.log(`Updated:       ${chalk.dim(b.updated_at)}`);
      console.log();
      console.log(chalk.dim('Description:'));
      console.log(b.description);
      console.log();
      console.log(`Affected Users:   ${b.affected_user_ids.join(', ')}`);
      console.log(`Data Categories:  ${b.data_categories.join(', ')}`);
    } catch (error) {
      spinner.stop();
      console.error(chalk.red('Error:'), error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

breach
  .command('update <id>')
  .description('Update a breach status')
  .requiredOption('-s, --status <status>', 'New status: detected, investigating, contained, reported, resolved')
  .option('-n, --notification <status>', 'Notification status: pending, users_notified, dpa_notified, completed')
  .option('--notes <notes>', 'Additional notes')
  .action(async (id: string, options) => {
    const spinner = ora('Updating breach...').start();
    try {
      const client = getClient();
      const result = await client.updateBreachStatus(id, {
        status: options.status,
        notification_status: options.notification,
        notes: options.notes,
      });
      spinner.stop();

      console.log();
      console.log(chalk.green.bold('✓ Breach updated'));
      console.log(`Status:        ${chalk.yellow(result.breach.status)}`);
      console.log(`Notification:  ${chalk.yellow(result.breach.notification_status)}`);
    } catch (error) {
      spinner.stop();
      console.error(chalk.red('Error:'), error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

// Voice analysis
program
  .command('voice <file>')
  .description('Analyze an audio file for safety concerns')
  .option('-t, --type <type>', 'Analysis type: bullying, unsafe, grooming, emotions, all', 'all')
  .option('-l, --language <lang>', 'Language hint (e.g., en, es)')
  .option('-a, --age <number>', 'Child age (for grooming analysis)')
  .action(async (file: string, options) => {
    const spinner = ora('Analyzing audio...').start();
    try {
      const client = getClient();
      const fs = await import('fs');
      const path = await import('path');
      const buffer = fs.readFileSync(file);
      const filename = path.basename(file);
      const result = await client.analyzeVoice({
        file: buffer,
        filename,
        analysisType: options.type,
        language: options.language,
        childAge: options.age ? parseInt(options.age) : undefined,
      });
      spinner.stop();

      console.log();
      console.log(chalk.bold('Voice Analysis'));
      console.log();
      console.log(`Severity:    ${formatSeverity(result.overall_severity)}`);
      console.log(`Risk Score:  ${chalk.cyan((result.overall_risk_score * 100).toFixed(0) + '%')}`);
      console.log(`Language:    ${chalk.cyan(result.transcription.language)}`);
      console.log(`Duration:    ${chalk.cyan(result.transcription.duration.toFixed(1) + 's')}`);
      console.log();
      console.log(chalk.dim('Transcript:'));
      console.log(result.transcription.text);
      if (result.analysis.bullying) {
        console.log();
        console.log(`Bullying: ${result.analysis.bullying.is_bullying ? chalk.red('DETECTED') : chalk.green('Clear')}`);
      }
      if (result.analysis.unsafe) {
        console.log(`Unsafe:   ${result.analysis.unsafe.unsafe ? chalk.red('DETECTED') : chalk.green('Clear')}`);
      }
      if (result.analysis.grooming) {
        console.log(`Grooming: ${result.analysis.grooming.grooming_risk !== 'none' ? chalk.red(result.analysis.grooming.grooming_risk.toUpperCase()) : chalk.green('Clear')}`);
      }
      if (result.analysis.emotions) {
        console.log(`Emotions: ${chalk.cyan(result.analysis.emotions.dominant_emotions.join(', '))}`);
      }
    } catch (error) {
      spinner.stop();
      console.error(chalk.red('Error:'), error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

// Image analysis
program
  .command('image <file>')
  .description('Analyze an image for safety concerns')
  .option('-t, --type <type>', 'Analysis type: bullying, unsafe, emotions, all', 'all')
  .action(async (file: string, options) => {
    const spinner = ora('Analyzing image...').start();
    try {
      const client = getClient();
      const fs = await import('fs');
      const path = await import('path');
      const buffer = fs.readFileSync(file);
      const filename = path.basename(file);
      const result = await client.analyzeImage({
        file: buffer,
        filename,
        analysisType: options.type,
      });
      spinner.stop();

      console.log();
      console.log(chalk.bold('Image Analysis'));
      console.log();
      console.log(`Severity:    ${formatSeverity(result.overall_severity)}`);
      console.log(`Risk Score:  ${chalk.cyan((result.overall_risk_score * 100).toFixed(0) + '%')}`);
      console.log();
      console.log(chalk.dim('Vision:'));
      console.log(`Description:  ${result.vision.visual_description}`);
      console.log(`Visual Sev.:  ${formatSeverity(result.vision.visual_severity)}`);
      console.log(`Has Text:     ${result.vision.contains_text ? 'Yes' : 'No'}`);
      console.log(`Has Faces:    ${result.vision.contains_faces ? 'Yes' : 'No'}`);
      if (result.vision.extracted_text) {
        console.log();
        console.log(chalk.dim('Extracted Text:'));
        console.log(result.vision.extracted_text);
      }
      if (result.text_analysis?.bullying) {
        console.log();
        console.log(`Bullying: ${result.text_analysis.bullying.is_bullying ? chalk.red('DETECTED') : chalk.green('Clear')}`);
      }
      if (result.text_analysis?.unsafe) {
        console.log(`Unsafe:   ${result.text_analysis.unsafe.unsafe ? chalk.red('DETECTED') : chalk.green('Clear')}`);
      }
    } catch (error) {
      spinner.stop();
      console.error(chalk.red('Error:'), error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

// Webhook management
const webhook = program
  .command('webhook')
  .description('Webhook management');

webhook
  .command('list')
  .description('List all webhooks')
  .action(async () => {
    const spinner = ora('Fetching webhooks...').start();
    try {
      const client = getClient();
      const result = await client.listWebhooks();
      spinner.stop();

      if (result.webhooks.length === 0) {
        console.log(chalk.dim('No webhooks configured.'));
        return;
      }

      console.log();
      for (const w of result.webhooks) {
        const status = w.is_active ? chalk.green('active') : chalk.dim('inactive');
        console.log(`${chalk.bold(w.name)} ${status} ${chalk.dim(`(${w.id})`)}`);
        console.log(`  URL:    ${chalk.cyan(w.url)}`);
        console.log(`  Events: ${w.events.join(', ')}`);
      }
    } catch (error) {
      spinner.stop();
      console.error(chalk.red('Error:'), error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

webhook
  .command('create')
  .description('Create a new webhook')
  .requiredOption('-n, --name <name>', 'Webhook name')
  .requiredOption('-u, --url <url>', 'Webhook URL')
  .requiredOption('-e, --events <events>', 'Events (comma-separated)')
  .action(async (options) => {
    const spinner = ora('Creating webhook...').start();
    try {
      const client = getClient();
      const result = await client.createWebhook({
        name: options.name,
        url: options.url,
        events: options.events.split(',').map((s: string) => s.trim()),
      });
      spinner.stop();

      console.log();
      console.log(chalk.green.bold('✓ Webhook created'));
      console.log(`ID:   ${chalk.cyan(result.id)}`);
      console.log(`Name: ${result.name}`);
      console.log();
      console.log(chalk.yellow.bold('Secret (save this — shown only once):'));
      console.log(chalk.yellow(result.secret));
    } catch (error) {
      spinner.stop();
      console.error(chalk.red('Error:'), error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

webhook
  .command('update <id>')
  .description('Update a webhook')
  .option('-n, --name <name>', 'New name')
  .option('-u, --url <url>', 'New URL')
  .option('-e, --events <events>', 'New events (comma-separated)')
  .option('--enable', 'Enable the webhook')
  .option('--disable', 'Disable the webhook')
  .action(async (id: string, options) => {
    const spinner = ora('Updating webhook...').start();
    try {
      const client = getClient();
      const result = await client.updateWebhook(id, {
        name: options.name,
        url: options.url,
        events: options.events ? options.events.split(',').map((s: string) => s.trim()) : undefined,
        isActive: options.enable ? true : options.disable ? false : undefined,
      });
      spinner.stop();

      console.log();
      console.log(chalk.green.bold('✓ Webhook updated'));
      console.log(`Name:   ${result.name}`);
      console.log(`Active: ${result.is_active ? chalk.green('Yes') : chalk.dim('No')}`);
    } catch (error) {
      spinner.stop();
      console.error(chalk.red('Error:'), error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

webhook
  .command('delete <id>')
  .description('Delete a webhook')
  .action(async (id: string) => {
    const spinner = ora('Deleting webhook...').start();
    try {
      const client = getClient();
      await client.deleteWebhook(id);
      spinner.stop();
      console.log(chalk.green.bold('✓ Webhook deleted'));
    } catch (error) {
      spinner.stop();
      console.error(chalk.red('Error:'), error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

webhook
  .command('test <id>')
  .description('Test a webhook')
  .action(async (id: string) => {
    const spinner = ora('Testing webhook...').start();
    try {
      const client = getClient();
      const result = await client.testWebhook(id);
      spinner.stop();

      console.log();
      if (result.success) {
        console.log(chalk.green.bold('✓ Webhook test passed'));
      } else {
        console.log(chalk.red.bold('✗ Webhook test failed'));
      }
      console.log(`Status:  ${chalk.cyan(String(result.status_code))}`);
      console.log(`Latency: ${chalk.cyan(result.latency_ms + 'ms')}`);
      if (result.error) {
        console.log(`Error:   ${chalk.red(result.error)}`);
      }
    } catch (error) {
      spinner.stop();
      console.error(chalk.red('Error:'), error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

webhook
  .command('regenerate-secret <id>')
  .description('Regenerate webhook signing secret')
  .action(async (id: string) => {
    const spinner = ora('Regenerating secret...').start();
    try {
      const client = getClient();
      const result = await client.regenerateWebhookSecret(id);
      spinner.stop();

      console.log();
      console.log(chalk.green.bold('✓ Secret regenerated'));
      console.log(chalk.yellow.bold('New Secret (save this — shown only once):'));
      console.log(chalk.yellow(result.secret));
    } catch (error) {
      spinner.stop();
      console.error(chalk.red('Error:'), error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

// Pricing
program
  .command('pricing')
  .description('Show pricing plans')
  .option('-d, --details', 'Show detailed pricing')
  .action(async (options) => {
    const spinner = ora('Fetching pricing...').start();
    try {
      const client = getClient();
      if (options.details) {
        const result = await client.getPricingDetails();
        spinner.stop();
        console.log();
        for (const p of result.plans) {
          console.log(chalk.bold(p.name));
          console.log(`  Monthly: ${chalk.cyan(p.price_monthly + '/mo')} | Yearly: ${chalk.cyan(p.price_yearly + '/mo')}`);
          console.log(`  API Calls: ${chalk.cyan(String(p.api_calls_per_month) + '/mo')} | Rate Limit: ${chalk.cyan(String(p.rate_limit) + '/min')}`);
          p.features.forEach((f: string) => console.log(`  - ${f}`));
          console.log();
        }
      } else {
        const result = await client.getPricing();
        spinner.stop();
        console.log();
        for (const p of result.plans) {
          console.log(`${chalk.bold(p.name)} — ${chalk.cyan(p.price)}`);
          p.features.forEach((f: string) => console.log(`  - ${f}`));
          console.log();
        }
      }
    } catch (error) {
      spinner.stop();
      console.error(chalk.red('Error:'), error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

// Usage and billing
const usage = program
  .command('usage')
  .description('Usage and billing information');

usage
  .command('monthly')
  .description('Show monthly usage summary')
  .action(async () => {
    const spinner = ora('Fetching usage...').start();
    try {
      const client = getClient();
      const result = await client.getUsageMonthly();
      spinner.stop();

      console.log();
      console.log(chalk.bold(`${result.tier_display_name} Plan`));
      console.log();
      console.log(`Used:       ${chalk.cyan(String(result.usage.used))} / ${result.usage.limit} (${result.usage.percent_used.toFixed(1)}%)`);
      console.log(`Remaining:  ${chalk.cyan(String(result.usage.remaining))}`);
      console.log(`Rate Limit: ${chalk.cyan(result.rate_limit.requests_per_minute + '/min')}`);
      console.log(`Period:     ${chalk.dim(result.billing.current_period_start + ' → ' + result.billing.current_period_end)}`);
      console.log(`Days Left:  ${chalk.cyan(String(result.billing.days_remaining))}`);
      if (result.recommendations?.should_upgrade) {
        console.log();
        console.log(chalk.yellow(`Recommendation: ${result.recommendations.reason}`));
        console.log(chalk.yellow(`Suggested: ${result.recommendations.suggested_tier}`));
      }
    } catch (error) {
      spinner.stop();
      console.error(chalk.red('Error:'), error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

usage
  .command('history')
  .description('Show daily usage history')
  .option('-d, --days <number>', 'Number of days (1-30)', '7')
  .action(async (options) => {
    const spinner = ora('Fetching history...').start();
    try {
      const client = getClient();
      const result = await client.getUsageHistory(parseInt(options.days));
      spinner.stop();

      if (result.days.length === 0) {
        console.log(chalk.dim('No usage data available.'));
        return;
      }

      console.log();
      console.log(chalk.bold('Date          Total  Success  Errors'));
      console.log(chalk.dim('─'.repeat(45)));
      for (const d of result.days) {
        console.log(`${d.date}  ${String(d.total_requests).padStart(5)}  ${String(d.success_requests).padStart(7)}  ${String(d.error_requests).padStart(6)}`);
      }
    } catch (error) {
      spinner.stop();
      console.error(chalk.red('Error:'), error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

usage
  .command('by-tool')
  .description('Show usage by tool/endpoint')
  .option('-d, --date <date>', 'Date (YYYY-MM-DD, default: today)')
  .action(async (options) => {
    const spinner = ora('Fetching usage...').start();
    try {
      const client = getClient();
      const result = await client.getUsageByTool(options.date);
      spinner.stop();

      console.log();
      console.log(chalk.bold(`Usage by Tool — ${result.date}`));
      console.log();
      if (Object.keys(result.tools).length > 0) {
        for (const [tool, count] of Object.entries(result.tools)) {
          console.log(`  ${tool.padEnd(25)} ${chalk.cyan(String(count))}`);
        }
      } else {
        console.log(chalk.dim('  No data for this date.'));
      }
    } catch (error) {
      spinner.stop();
      console.error(chalk.red('Error:'), error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

// ─── Detection Commands ──────────────────────────────────────────────────────

type DetectionView = Pick<
  DetectionResult,
  'detected' | 'risk_score' | 'severity' | 'confidence' | 'level' | 'categories' | 'evidence' | 'rationale' | 'message_analysis' | 'recommended_action'
> & {
  /** Synthetic content detectors only. */
  classification?: string;
};

function formatDetectionResult(result: DetectionView, label: string): void {
  console.log();
  if (result.detected) {
    console.log(chalk.red.bold(`⚠ ${label} DETECTED`));
  } else {
    console.log(chalk.green.bold(`✓ No ${label.toLowerCase()} detected`));
  }
  console.log();
  console.log(`Risk Score:  ${formatPercent(result.risk_score)}`);
  console.log(`Severity:    ${formatPercent(result.severity)}`);
  console.log(`Confidence:  ${formatPercent(result.confidence)}`);
  console.log(`Level:       ${formatRisk(result.level)}`);
  if (result.classification) {
    console.log(`Classification: ${chalk.cyan(result.classification)}`);
  }
  if (result.categories?.length > 0) {
    console.log(`Categories:  ${result.categories.map((c) => c.label || c.tag).join(', ')}`);
  }
  if (result.rationale) {
    console.log();
    console.log(chalk.dim('Rationale:'));
    console.log(result.rationale);
  }
  if (result.evidence && result.evidence.length > 0) {
    console.log();
    console.log(chalk.dim('Evidence:'));
    result.evidence.forEach((e) => console.log(chalk.yellow(`  • ${e.text}`) + chalk.dim(` (${e.tactic})`)));
  }
  if (result.message_analysis && result.message_analysis.length > 0) {
    console.log();
    console.log(chalk.dim('Message Analysis:'));
    result.message_analysis.forEach((m) => {
      console.log(chalk.cyan(`  [${m.message_index}]`) + ` Risk: ${(m.risk_score * 100).toFixed(0)}% — ${m.summary}${m.flags?.length > 0 ? chalk.yellow(` [${m.flags.join(', ')}]`) : ''}`);
    });
  }
  console.log();
  console.log(`Action: ${chalk.yellow(result.recommended_action)}`);
}

interface DetectionCliOptions {
  includeEvidence?: boolean;
  ageGroup?: string;
  externalId?: string;
  customerId?: string;
}

function addDetectionOptions(cmd: Command): Command {
  return cmd
    .option('--include-evidence', 'Include evidence in response')
    .option('--age-group <group>', 'Age group context')
    .option('--external-id <id>', 'External reference ID')
    .option('--customer-id <id>', 'Customer ID');
}

function extractDetectionOptions(options: DetectionCliOptions) {
  return {
    includeEvidence: options.includeEvidence || false,
    context: options.ageGroup ? { ageGroup: options.ageGroup } : undefined,
    external_id: options.externalId,
    customer_id: options.customerId,
  };
}

interface DetectionCommand {
  name: string;
  alias: string;
  description: string;
  label: string;
  run: (client: Tuteliq, input: DetectionInput) => Promise<DetectionView>;
}

const DETECTION_COMMANDS: DetectionCommand[] = [
  // Fraud detection
  {
    name: 'detect-social-engineering',
    alias: 'social-engineering',
    description: 'Detect social engineering attempts targeting minors',
    label: 'SOCIAL ENGINEERING',
    run: (c, input) => c.detectSocialEngineering(input),
  },
  {
    name: 'detect-app-fraud',
    alias: 'app-fraud',
    description: 'Detect in-app purchase fraud or scams targeting children',
    label: 'APP FRAUD',
    run: (c, input) => c.detectAppFraud(input),
  },
  {
    name: 'detect-romance-scam',
    alias: 'romance-scam',
    description: 'Detect romance scam patterns in conversations',
    label: 'ROMANCE SCAM',
    run: (c, input) => c.detectRomanceScam(input),
  },
  {
    name: 'detect-mule-recruitment',
    alias: 'mule-recruitment',
    description: 'Detect money mule recruitment targeting young people',
    label: 'MULE RECRUITMENT',
    run: (c, input) => c.detectMuleRecruitment(input),
  },
  // Extended safety
  {
    name: 'detect-gambling-harm',
    alias: 'gambling-harm',
    description: 'Detect gambling-related harm indicators',
    label: 'GAMBLING HARM',
    run: (c, input) => c.detectGamblingHarm(input),
  },
  {
    name: 'detect-coercive-control',
    alias: 'coercive-control',
    description: 'Detect coercive control patterns in communications',
    label: 'COERCIVE CONTROL',
    run: (c, input) => c.detectCoerciveControl(input),
  },
  {
    name: 'detect-vulnerability-exploitation',
    alias: 'vulnerability-exploitation',
    description: 'Detect exploitation of vulnerable individuals',
    label: 'VULNERABILITY EXPLOITATION',
    run: (c, input) => c.detectVulnerabilityExploitation(input),
  },
  {
    name: 'detect-radicalisation',
    alias: 'radicalisation',
    description: 'Detect radicalisation indicators in content',
    label: 'RADICALISATION',
    run: (c, input) => c.detectRadicalisation(input),
  },
  {
    name: 'detect-distress-signals',
    alias: 'distress-signals',
    description: 'Detect signs that someone is in distress and may need support',
    label: 'DISTRESS SIGNALS',
    run: (c, input) => c.detectDistressSignals(input),
  },
  {
    name: 'detect-synthetic-text',
    alias: 'synthetic-text',
    description: 'Detect AI-generated text',
    label: 'SYNTHETIC TEXT',
    run: (c, input) => c.detectSyntheticText(input),
  },
];

for (const def of DETECTION_COMMANDS) {
  addDetectionOptions(
    program
      .command(`${def.name} <text>`)
      .alias(def.alias)
      .description(def.description)
  ).action(async (text: string, options: DetectionCliOptions) => {
    const spinner = ora('Analyzing...').start();
    try {
      const client = getClient();
      const result = await def.run(client, { content: text, ...extractDetectionOptions(options) });
      spinner.stop();
      formatDetectionResult(result, def.label);
    } catch (error) {
      fail(spinner, error);
    }
  });
}

// ─── Multi-Endpoint Analysis ─────────────────────────────────────────────────

const DETECTION_NAMES: readonly string[] = Object.values(Detection);

function isDetectionName(name: string): name is DetectionName {
  return DETECTION_NAMES.includes(name);
}

function parseDetectionNames(value: string): DetectionName[] {
  const names = value.split(',').map((s) => s.trim()).filter(Boolean);
  const unknown = names.filter((n) => !isDetectionName(n));
  if (unknown.length > 0) {
    throw new InvalidArgumentError(`Unknown endpoint(s): ${unknown.join(', ')}. Allowed: ${DETECTION_NAMES.join(', ')}.`);
  }
  return names.filter(isDetectionName);
}

addDetectionOptions(
  program
    .command('analyse-multi <text>')
    .alias('multi')
    .description('Run multiple detection endpoints in a single request')
    .requiredOption('-e, --endpoints <list>', 'Comma-separated list of endpoints (e.g., grooming,social-engineering,romance-scam)', parseDetectionNames)
).action(async (text: string, options: DetectionCliOptions & { endpoints: DetectionName[] }) => {
  const spinner = ora('Analyzing across endpoints...').start();
  try {
    const client = getClient();
    const result = await client.analyseMulti({
      content: text,
      detections: options.endpoints,
      ...extractDetectionOptions(options),
    });
    spinner.stop();

    // Summary
    console.log();
    console.log(chalk.bold('Multi-Endpoint Analysis Summary'));
    console.log(chalk.dim('─'.repeat(50)));
    console.log(`Overall Risk:   ${formatRisk(result.summary.overall_risk_level)}`);
    console.log(`Detected:       ${chalk.cyan(String(result.summary.detected_count))} / ${result.summary.total_endpoints}`);
    console.log(`Highest Risk:   ${result.summary.highest_risk ? chalk.red(`${result.summary.highest_risk.endpoint} (${(result.summary.highest_risk.risk_score * 100).toFixed(0)}%)`) : chalk.green('none')}`);
    console.log();

    // Individual results
    console.log(chalk.bold('Endpoint Results'));
    console.log(chalk.dim('─'.repeat(50)));
    for (const r of result.results) {
      const status = r.detected ? chalk.red('DETECTED') : chalk.green('CLEAR');
      console.log();
      console.log(`${chalk.bold(r.endpoint)}: ${status}`);
      console.log(`  Risk Score:  ${formatPercent(r.risk_score)}  |  Level: ${formatRisk(r.level)}  |  Confidence: ${formatPercent(r.confidence)}`);
      if (r.categories?.length > 0) {
        console.log(`  Categories:  ${r.categories.map((c) => c.label || c.tag).join(', ')}`);
      }
      if (r.rationale) {
        console.log(`  ${chalk.dim(r.rationale)}`);
      }
      if (r.evidence && r.evidence.length > 0) {
        r.evidence.forEach((e) => console.log(chalk.yellow(`    • ${e.text}`) + chalk.dim(` (${e.tactic})`)));
      }
    }
  } catch (error) {
    fail(spinner, error);
  }
});

// ─── Video Analysis ──────────────────────────────────────────────────────────

program
  .command('analyze-video <file>')
  .alias('video')
  .description('Analyze a video file for safety concerns')
  .option('--age-group <group>', 'Age group context')
  .option('--external-id <id>', 'External reference ID')
  .option('--customer-id <id>', 'Customer ID')
  .action(async (file: string, options: { ageGroup?: string; externalId?: string; customerId?: string }) => {
    const spinner = ora('Analyzing video...').start();
    try {
      const client = getClient();
      const fs = await import('fs');
      const path = await import('path');
      const buffer = fs.readFileSync(file);
      const filename = path.basename(file);
      const result = await client.analyzeVideo({
        file: buffer,
        filename,
        ageGroup: options.ageGroup,
        external_id: options.externalId,
        customer_id: options.customerId,
      });
      spinner.stop();

      console.log();
      console.log(chalk.bold('Video Analysis'));
      console.log();
      console.log(`Frames Analyzed:   ${chalk.cyan(String(result.frames_analyzed))}`);
      console.log(`Overall Risk:      ${chalk.cyan((result.overall_risk_score * 100).toFixed(0) + '%')}`);
      console.log(`Overall Severity:  ${formatSeverity(result.overall_severity)}`);

      if (result.categories?.length > 0) {
        console.log(`Categories:        ${result.categories.join(', ')}`);
      }

      if (result.flagged_timestamps?.length > 0) {
        console.log();
        console.log(chalk.bold('Flagged Timestamps'));
        console.log(chalk.dim('─'.repeat(50)));
        for (const flag of result.flagged_timestamps) {
          const ts = chalk.dim(`[${flag.timestamp_s}s]`);
          const sev = formatSeverity(flag.severity);
          console.log();
          console.log(`${ts} ${sev} — ${flag.reason}`);
        }
      } else {
        console.log();
        console.log(chalk.green('No safety concerns found in video.'));
      }
    } catch (error) {
      spinner.stop();
      console.error(chalk.red('Error:'), error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

// ─── Choice helpers ──────────────────────────────────────────────────────────

function choiceOption(flags: string, description: string, choices: readonly string[]): Option {
  return new Option(flags, description).choices(choices);
}

/** Narrows a validated option value to its choice type. */
function asChoice<T extends string>(value: string | undefined, choices: readonly T[]): T | undefined {
  if (value === undefined) return undefined;
  const match = choices.find((c) => c === value);
  if (match === undefined) {
    throw new InvalidArgumentError(`'${value}' is not one of: ${choices.join(', ')}.`);
  }
  return match;
}

function formatYesNo(value: boolean | null | undefined): string {
  if (value === null || value === undefined) return chalk.dim('Unknown');
  return value ? 'Yes' : 'No';
}

// ─── Verification Sessions ───────────────────────────────────────────────────

const VERIFICATION_MODES = Object.values(VerificationMode);
const DOCUMENT_TYPES = [...new Set(Object.values(DocumentType))];
const CHIP_POLICIES = Object.values(ChipPolicy);

const SESSION_STATUS_COLORS: Record<string, (s: string) => string> = {
  completed: chalk.green,
  failed: chalk.red,
  expired: chalk.dim,
};

const RESULT_STATUS_COLORS: Record<string, (s: string) => string> = {
  verified: chalk.green,
  failed: chalk.red,
  needs_review: chalk.yellow,
};

function formatStatus(status: string, colors: Record<string, (s: string) => string>): string {
  return (colors[status] || chalk.yellow)(status.toUpperCase());
}

function formatFaceMatch(faceMatch: { matched: boolean; match_score?: number } | null): string {
  if (!faceMatch) return chalk.dim('N/A');
  const decision = faceMatch.matched ? chalk.green('Yes') : chalk.red('No');
  return faceMatch.match_score === undefined
    ? decision
    : `${decision} (score ${(faceMatch.match_score * 100).toFixed(0)}%)`;
}

function printVerificationSession(session: VerificationSessionResult): void {
  console.log();
  console.log(`Session:    ${chalk.cyan(session.session_id)}`);
  console.log(`Status:     ${formatStatus(session.status, SESSION_STATUS_COLORS)}`);
  if (session.status === 'document_required') {
    console.log(chalk.yellow('            Not final: waiting for the user to add a document photo.'));
  }
  if (session.step_progress) {
    console.log(`Step:       ${session.step_progress}`);
  }
  if (session.verification_mode) {
    console.log(`Check:      ${session.verification_mode}`);
  }
  if (session.chip_policy) {
    console.log(`Chip:       ${session.chip_policy}`);
  }
  if (session.expires_at !== undefined) {
    console.log(`Expires:    ${chalk.dim(new Date(session.expires_at).toISOString())}`);
  }

  const result = session.result;
  if (!result) return;

  const evidence = result.document_evidence ?? session.document_evidence;
  console.log();
  console.log(`Result:     ${formatStatus(result.status, RESULT_STATUS_COLORS)}`);
  console.log(`Age:        ${result.age === null ? chalk.dim('Unknown') : chalk.cyan(String(result.age))}`);
  if (result.age_range) {
    console.log(`Age Range:  ${result.age_range.low}-${result.age_range.high}`);
  }
  console.log(`Minor:      ${formatYesNo(result.is_minor)}`);
  console.log(`Face Match: ${formatFaceMatch(result.face_match)}`);
  console.log(`Liveness:   ${result.liveness.valid ? chalk.green('Passed') : chalk.red('Failed')}`);
  if (evidence) {
    console.log(`Evidence:   ${evidence}`);
  }
  if (result.failure_reasons && result.failure_reasons.length > 0) {
    console.log();
    console.log(chalk.dim('Failure Reasons:'));
    result.failure_reasons.forEach((r) => console.log(chalk.yellow(`  • ${r}`)));
  }

  const doc = result.document;
  if (result.date_of_birth || doc) {
    console.log();
    console.log(chalk.yellow.bold('Released once (later reads return the decision only):'));
    if (result.date_of_birth) console.log(`  Date of Birth:  ${result.date_of_birth}`);
    if (doc?.name_extracted) console.log(`  Name:           ${doc.name_extracted}`);
    if (doc?.document_type) console.log(`  Document Type:  ${doc.document_type}`);
    if (doc?.document_number) console.log(`  Number:         ${doc.document_number}`);
    if (doc?.country_name || doc?.country_code) console.log(`  Country:        ${doc.country_name ?? doc.country_code}`);
    if (doc?.expiration_date) console.log(`  Expires:        ${doc.expiration_date}${doc.expired ? chalk.red(' (expired)') : ''}`);
    if (doc?.chip_verified !== undefined) console.log(`  Chip Verified:  ${formatYesNo(doc.chip_verified)}`);
    console.log(chalk.dim('  Use --json to print the complete response.'));
  }
}

const verify = program
  .command('verify')
  .description('Age and identity verification');

const verifySession = verify
  .command('session')
  .description('Hosted verification sessions: create one, send the user its URL, then poll it');

verifySession
  .command('create')
  .description('Create a verification session and print the URL for the user')
  .addOption(choiceOption('-m, --mode <mode>', 'Verification mode', VERIFICATION_MODES).default('age'))
  .addOption(choiceOption('-d, --document-type <type>', 'Preferred document type', DOCUMENT_TYPES))
  .addOption(choiceOption('-c, --chip-policy <policy>', 'How a passport or ID card chip read counts as evidence (API default: optional)', CHIP_POLICIES))
  .option('--auto-capture', 'Take the document photo automatically once it is framed and sharp (API default)')
  .option('--no-auto-capture', 'Let the user tap Capture instead')
  .action(async (options: { mode: string; documentType?: string; chipPolicy?: string; autoCapture?: boolean }) => {
    const spinner = ora('Creating session...').start();
    try {
      const client = getClient();
      const documentType = asChoice(options.documentType, DOCUMENT_TYPES);
      const chipPolicy = asChoice(options.chipPolicy, CHIP_POLICIES);
      const session = await client.createVerificationSession({
        mode: asChoice(options.mode, VERIFICATION_MODES) ?? VerificationMode.AGE,
        ...(documentType && { document_type: documentType }),
        ...(chipPolicy && { chip_policy: chipPolicy }),
        ...(options.autoCapture !== undefined && { auto_capture: options.autoCapture }),
      });
      spinner.stop();

      console.log();
      console.log(chalk.green.bold('✓ Verification session created'));
      console.log();
      console.log(`Session:      ${chalk.cyan(session.session_id)}`);
      console.log(`URL:          ${chalk.cyan(session.url)}`);
      console.log(`Mode:         ${session.mode}`);
      console.log(`Expires:      ${chalk.dim(new Date(session.expires_at).toISOString())}`);
      if (session.chip_policy) {
        console.log(`Chip Policy:  ${session.chip_policy}`);
      }
      if (session.auto_capture !== undefined) {
        console.log(`Auto Capture: ${formatYesNo(session.auto_capture)}`);
      }
      console.log();
      console.log(chalk.dim(`Send the URL to the user, then run: tuteliq verify session get ${session.session_id}`));
    } catch (error) {
      fail(spinner, error);
    }
  });

verifySession
  .command('get <id>')
  .description('Show a session\'s status and result')
  .option('--json', 'Print the raw response, including fields released only on the first read after completion')
  .action(async (id: string, options: { json?: boolean }) => {
    const spinner = ora('Fetching session...').start();
    try {
      const client = getClient();
      const session = await client.getVerificationSession(id);
      spinner.stop();

      if (options.json) {
        console.log(JSON.stringify(session, null, 2));
        return;
      }
      printVerificationSession(session);
    } catch (error) {
      fail(spinner, error);
    }
  });

verifySession
  .command('cancel <id>')
  .description('Cancel a session')
  .action(async (id: string) => {
    const spinner = ora('Cancelling session...').start();
    try {
      const client = getClient();
      await client.cancelVerificationSession(id);
      spinner.stop();
      console.log(chalk.green.bold('✓ Session cancelled'));
    } catch (error) {
      fail(spinner, error);
    }
  });

// ─── Incidents ───────────────────────────────────────────────────────────────

const INCIDENT_SEVERITIES = ['low', 'moderate', 'high', 'critical'] as const satisfies readonly IncidentSeverity[];
const INCIDENT_SEVERITY_FILTERS = [...INCIDENT_SEVERITIES, 'medium'] as const;
const INCIDENT_STATUSES = ['new', 'reviewed', 'escalated', 'resolved', 'dismissed'] as const satisfies readonly IncidentSummaryRow['status'][];
const INCIDENT_SOURCES = ['text', 'voice', 'image', 'video', 'video_stream'] as const satisfies readonly IncidentSource[];
const INCIDENT_CATEGORIES = [
  'bullying', 'grooming', 'unsafe', 'self_harm', 'other', 'social_engineering', 'app_fraud',
  'romance_scam', 'mule_recruitment', 'gambling_harm', 'coercive_control',
  'vulnerability_exploitation', 'radicalisation', 'distress_signals', 'tfgbv', 'synthetic_content',
] as const satisfies readonly IncidentCategory[];
const TREND_BUCKETS = ['hour', 'day', 'week'] as const;
const MODERATOR_ACTIONS = [
  'confirm', 'downgrade', 'escalate', 'reclassify', 'dismiss', 'resolve', 'reopen',
] as const satisfies readonly ModeratorAction[];
const MODERATOR_REASON_CODES = [
  'confirmed_accurate', 'false_positive', 'out_of_context', 'insufficient_severity',
  'incorrect_category', 'requires_law_enforcement', 'parent_notified', 'other',
] as const satisfies readonly ModeratorReasonCode[];
const RETENTION_CLASSES = [
  'biometric-high-risk', 'safety-high-risk', 'limited-risk', 'minimal-risk',
] as const satisfies readonly RetentionClass[];

interface ReviewCliOptions {
  action: string;
  reason: string;
  moderator: string;
  comment?: string;
  newLevel?: string;
  newCategory?: string;
  retentionClass?: string;
}

function addReviewOptions(cmd: Command): Command {
  return cmd
    .addOption(choiceOption('-a, --action <action>', 'Moderator action', MODERATOR_ACTIONS).makeOptionMandatory())
    .addOption(choiceOption('-r, --reason <code>', 'Reason code', MODERATOR_REASON_CODES).makeOptionMandatory())
    .requiredOption('-m, --moderator <id>', 'Stable identifier of the moderator making the decision')
    .option('-c, --comment <text>', 'Free-form comment')
    .addOption(choiceOption('--new-level <level>', 'New risk level (downgrade, escalate)', INCIDENT_SEVERITIES))
    .addOption(choiceOption('--new-category <category>', 'New risk category (reclassify)', INCIDENT_CATEGORIES))
    .addOption(choiceOption('--retention-class <class>', 'Retention class for the audit receipt', RETENTION_CLASSES));
}

function extractReview(options: ReviewCliOptions) {
  const action = asChoice(options.action, MODERATOR_ACTIONS);
  const reasonCode = asChoice(options.reason, MODERATOR_REASON_CODES);
  if (!action || !reasonCode) {
    throw new InvalidArgumentError('--action and --reason are required.');
  }
  const newLevel = asChoice(options.newLevel, INCIDENT_SEVERITIES);
  const newCategory = asChoice(options.newCategory, INCIDENT_CATEGORIES);
  const retentionClass = asChoice(options.retentionClass, RETENTION_CLASSES);
  return {
    action,
    reason_code: reasonCode,
    moderator_external_id: options.moderator,
    ...(options.comment && { reason_comment: options.comment }),
    ...(newLevel && { new_risk_level: newLevel }),
    ...(newCategory && { new_risk_category: newCategory }),
    ...(retentionClass && { retention_class: retentionClass }),
  };
}

function formatCounts(counts: Record<string, number>): string {
  const entries = Object.entries(counts);
  if (entries.length === 0) return chalk.dim('none');
  return entries.map(([k, v]) => `${k}: ${v}`).join(', ');
}

const incidents = program
  .command('incidents')
  .description('Review and action incidents recorded for your account');

incidents
  .command('list')
  .description('List incidents, newest first')
  .option('--category <category>', 'Filter by risk category (e.g. bullying, grooming)')
  .addOption(choiceOption('--severity <level>', 'Filter by risk level', INCIDENT_SEVERITY_FILTERS))
  .addOption(choiceOption('--status <status>', 'Filter by moderation status', INCIDENT_STATUSES))
  .addOption(choiceOption('--source <source>', 'Filter by source', INCIDENT_SOURCES))
  .option('--from <iso>', 'Created at or after (ISO 8601)')
  .option('--to <iso>', 'Created before (ISO 8601)')
  .option('--platform <name>', 'Filter by platform')
  .option('--external-id <id>', 'Filter by your external ID')
  .option('--customer-id <id>', 'Filter by your customer ID')
  .option('-l, --limit <number>', 'Rows per page (1-100, default 25)', parsePositiveInt)
  .option('--cursor <cursor>', 'Cursor from the previous page')
  .option('--include-summary', 'Include each incident\'s summary (one extra credit per row)')
  .action(async (options: {
    category?: string; severity?: string; status?: string; source?: string; from?: string; to?: string;
    platform?: string; externalId?: string; customerId?: string; limit?: number; cursor?: string; includeSummary?: boolean;
  }) => {
    const spinner = ora('Fetching incidents...').start();
    try {
      const client = getClient();
      const result = await client.listIncidents({
        category: options.category,
        severity: asChoice(options.severity, INCIDENT_SEVERITY_FILTERS),
        status: asChoice(options.status, INCIDENT_STATUSES),
        source: asChoice(options.source, INCIDENT_SOURCES),
        from: options.from,
        to: options.to,
        platform: options.platform,
        externalId: options.externalId,
        customerId: options.customerId,
        limit: options.limit,
        cursor: options.cursor,
        includeSummary: options.includeSummary,
      });
      spinner.stop();

      if (result.incidents.length === 0) {
        console.log(chalk.dim('No incidents found.'));
        return;
      }

      console.log();
      for (const inc of result.incidents) {
        console.log(`${formatSeverity(inc.risk_level)} ${chalk.bold(inc.risk_category)} ${chalk.dim(`(${inc.id})`)}`);
        console.log(`  Status: ${chalk.yellow(inc.status)} | Source: ${inc.source} | ${chalk.dim(inc.created_at)}`);
        if (typeof inc.summary === 'string' && inc.summary) {
          console.log(`  ${chalk.dim(inc.summary)}`);
        }
      }
      if (result.next_cursor) {
        console.log();
        console.log(chalk.dim(`More results: add --cursor ${result.next_cursor}`));
      }
    } catch (error) {
      fail(spinner, error);
    }
  });

incidents
  .command('get <id>')
  .description('Show one incident')
  .action(async (id: string) => {
    const spinner = ora('Fetching incident...').start();
    try {
      const client = getClient();
      const inc = await client.getIncident(id);
      spinner.stop();

      console.log();
      console.log(`ID:         ${chalk.cyan(inc.id)}`);
      console.log(`Category:   ${inc.risk_category}`);
      console.log(`Level:      ${formatSeverity(inc.risk_level)}`);
      console.log(`Status:     ${inc.status}`);
      if (inc.recommended_status) {
        console.log(`Suggested:  ${inc.recommended_status}`);
      }
      console.log(`Source:     ${inc.source}`);
      if (inc.confidence_score !== null) {
        console.log(`Confidence: ${formatPercent(inc.confidence_score)}`);
      }
      if (inc.detected_patterns.length > 0) {
        console.log(`Patterns:   ${inc.detected_patterns.join(', ')}`);
      }
      if (inc.recommended_actions.length > 0) {
        console.log(`Actions:    ${inc.recommended_actions.join(', ')}`);
      }
      if (inc.platform) console.log(`Platform:   ${inc.platform}`);
      if (inc.external_id) console.log(`External:   ${inc.external_id}`);
      if (inc.customer_id) console.log(`Customer:   ${inc.customer_id}`);
      if (inc.is_test) console.log(`Test:       ${chalk.dim('Yes (non-production key)')}`);
      console.log(`Created:    ${chalk.dim(inc.created_at)}`);
      if (inc.summary) {
        console.log();
        console.log(chalk.dim('Summary:'));
        console.log(typeof inc.summary === 'string' ? inc.summary : JSON.stringify(inc.summary, null, 2));
      }
      if (inc._e2e_envelope_fields && inc._e2e_envelope_fields.length > 0) {
        console.log();
        console.log(chalk.dim(`Encrypted with your key (decrypt locally): ${inc._e2e_envelope_fields.join(', ')}`));
      }
    } catch (error) {
      fail(spinner, error);
    }
  });

incidents
  .command('overview')
  .description('Incident totals and breakdowns (default: last 30 days)')
  .option('--from <iso>', 'Window start (ISO 8601)')
  .option('--to <iso>', 'Window end (ISO 8601)')
  .action(async (options: { from?: string; to?: string }) => {
    const spinner = ora('Fetching overview...').start();
    try {
      const client = getClient();
      const ov = await client.getIncidentsOverview({ from: options.from, to: options.to });
      spinner.stop();

      console.log();
      console.log(chalk.bold('Incidents Overview'));
      console.log(chalk.dim(`${ov.timeframe.from} → ${ov.timeframe.to}`));
      console.log();
      console.log(`Total:          ${chalk.cyan(String(ov.total_incidents))}`);
      console.log(`Needs Review:   ${chalk.yellow(String(ov.requires_review_count))}`);
      console.log(`Last 24h/7d/30d: ${ov.last_24h_count} / ${ov.last_7d_count} / ${ov.last_30d_count}`);
      console.log();
      console.log(`By Category:  ${formatCounts(ov.counts_by_category)}`);
      console.log(`By Severity:  ${formatCounts(ov.counts_by_severity)}`);
      console.log(`By Source:    ${formatCounts(ov.counts_by_source)}`);
      console.log(`By Status:    ${formatCounts(ov.counts_by_status)}`);
      if (ov.top_platforms.length > 0) {
        console.log(`Top Platforms: ${ov.top_platforms.map((p) => `${p.platform} (${p.count})`).join(', ')}`);
      }
    } catch (error) {
      fail(spinner, error);
    }
  });

incidents
  .command('trends')
  .description('Incident counts over time (default: daily, last 30 days)')
  .addOption(choiceOption('-b, --bucket <size>', 'Bucket size', TREND_BUCKETS))
  .option('--from <iso>', 'Window start (ISO 8601)')
  .option('--to <iso>', 'Window end (ISO 8601)')
  .action(async (options: { bucket?: string; from?: string; to?: string }) => {
    const spinner = ora('Fetching trends...').start();
    try {
      const client = getClient();
      const trends = await client.getIncidentTrends({
        bucket: asChoice(options.bucket, TREND_BUCKETS),
        from: options.from,
        to: options.to,
      });
      spinner.stop();

      if (trends.series.length === 0) {
        console.log(chalk.dim('No incidents in this window.'));
        return;
      }

      console.log();
      console.log(chalk.bold(`Incidents per ${trends.bucket_size}`));
      console.log(chalk.dim('─'.repeat(50)));
      for (const b of trends.series) {
        console.log(`${b.bucket_start}  ${String(b.total).padStart(5)}  ${chalk.dim(formatCounts(b.by_severity))}`);
      }
    } catch (error) {
      fail(spinner, error);
    }
  });

addReviewOptions(
  incidents
    .command('review <id>')
    .description('Record a moderator decision on an incident (writes a signed audit receipt)')
).action(async (id: string, options: ReviewCliOptions) => {
  const spinner = ora('Submitting review...').start();
  try {
    const client = getClient();
    const result = await client.reviewIncident(id, extractReview(options));
    spinner.stop();

    console.log();
    console.log(chalk.green.bold('✓ Review recorded'));
    console.log(`Incident: ${chalk.cyan(result.incident_id)}`);
    console.log(`Change:   ${result.original.risk_category}/${result.original.risk_level} -> ${result.revised.risk_category}/${result.revised.risk_level}`);
    console.log(`Receipt:  ${result.audit_receipt ? chalk.cyan(result.audit_receipt.request_id) : chalk.yellow('not written')}`);
  } catch (error) {
    fail(spinner, error);
  }
});

addReviewOptions(
  incidents
    .command('batch-review <ids...>')
    .description('Apply the same moderator decision to up to 100 incidents')
).action(async (ids: string[], options: ReviewCliOptions) => {
  const spinner = ora('Submitting reviews...').start();
  try {
    const client = getClient();
    const result = await client.batchReviewIncidents({ incident_ids: ids, ...extractReview(options) });
    spinner.stop();

    console.log();
    const summary = `${result.succeeded}/${result.total} reviewed`;
    console.log(result.failed === 0 ? chalk.green.bold(`✓ ${summary}`) : chalk.yellow.bold(`⚠ ${summary}`));
    for (const item of result.results.filter((r) => !r.ok)) {
      console.log(chalk.red(`  ✗ ${item.incident_id}: ${item.error ?? 'failed'}`));
    }
  } catch (error) {
    fail(spinner, error);
  }
});

export { program };
