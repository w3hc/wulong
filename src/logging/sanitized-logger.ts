import { LoggerService } from '@nestjs/common';

const REDACTED = '[REDACTED]';

// Shapes key material takes here: PEM private keys, hex keys and signatures,
// base64 keys and ciphertexts
const SECRET_PATTERNS = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)/g,
  /\b(0x)?[0-9a-fA-F]{64,}\b/g,
  /[A-Za-z0-9+/]{64,}={0,2}/g,
];

const SECRET_ENV_NAME = /(KEY|SECRET|TOKEN|PASSWORD|MNEMONIC|SEED)$/i;
const MIN_SECRET_LENGTH = 8;

/**
 * Sanitized logger for use in TEE environments.
 *
 * In production (TEE), only emit framework-level structural messages.
 * Never emit request bodies, user data, stack traces, or secret values.
 * Whatever is emitted has known secret values and key-shaped strings redacted.
 *
 * This prevents sensitive data from leaking through logs that might be
 * observable by the host operator or external monitoring systems.
 */
export class SanitizedLogger implements LoggerService {
  private readonly SAFE_PREFIXES = [
    'NestFactory',
    'InstanceLoader',
    'RoutesResolver',
    'RouterExplorer',
    'NestApplication',
  ];

  private readonly secrets: string[];

  /**
   * @param env Environment whose secret-named values are redacted wherever they appear
   */
  constructor(env: NodeJS.ProcessEnv = process.env) {
    this.secrets = Object.entries(env)
      .filter(([name]) => SECRET_ENV_NAME.test(name))
      .map(([, value]) => value)
      .filter(
        (value): value is string => (value?.length ?? 0) >= MIN_SECRET_LENGTH,
      )
      .sort((a, b) => b.length - a.length);
  }

  /**
   * Logs informational messages, but only if they come from safe contexts.
   * @param message The log message
   * @param context The context (usually the class name)
   */
  log(message: string, context?: string): void {
    if (this.isSafe(context)) {
      process.stdout.write(`[LOG] ${context}: ${this.redact(message)}\n`);
    }
  }

  /**
   * Logs error messages without stack traces to prevent data leakage.
   * Stack traces can contain variable values and internal state.
   * @param message The error message
   * @param _trace The stack trace (ignored for security)
   * @param context The context (usually the class name)
   */
  error(message: string, _trace?: string, context?: string): void {
    // Never emit stack traces — they can contain variable values
    process.stdout.write(
      `[ERR] ${context ?? 'App'}: ${this.redact(message).split('\n')[0]}\n`,
    );
  }

  /**
   * Logs warning messages, but only if they come from safe contexts.
   * @param message The warning message
   * @param context The context (usually the class name)
   */
  warn(message: string, context?: string): void {
    if (this.isSafe(context)) {
      process.stdout.write(`[WARN] ${context}: ${this.redact(message)}\n`);
    }
  }

  /**
   * Debug logging is completely suppressed in production TEE environments.
   */
  debug(): void {
    /* suppress in production */
  }

  /**
   * Verbose logging is completely suppressed in production TEE environments.
   */
  verbose(): void {
    /* suppress in production */
  }

  /**
   * Masks known secret values and anything shaped like key material.
   * @param message The log message
   * @returns The message with secrets replaced by [REDACTED]
   */
  private redact(message: unknown): string {
    let text = String(message);
    for (const secret of this.secrets) {
      text = text.split(secret).join(REDACTED);
    }
    for (const pattern of SECRET_PATTERNS) {
      text = text.replace(pattern, REDACTED);
    }
    return text;
  }

  /**
   * Determines if a log context is safe to emit.
   * Only framework-level contexts are considered safe.
   * @param context The log context to check
   * @returns True if the context is safe to log
   */
  private isSafe(context?: string): boolean {
    return this.SAFE_PREFIXES.some((p) => context?.startsWith(p));
  }
}
