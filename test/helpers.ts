import { vi } from 'vitest';
import type { Command } from 'commander';

/** Thrown by the stubbed process.exit so a command's exit path ends the test run. */
export class ExitError extends Error {
  constructor(public readonly code: number | undefined) {
    super(`process.exit(${code})`);
  }
}

const ANSI = /\u001b\[[0-9;]*m/g;

export interface RunResult {
  stdout: string;
  stderr: string;
  exitCode: number | undefined;
}

/**
 * Imports a fresh copy of the CLI program and runs one command line against it,
 * capturing console output. The SDK and the config store are mocked by the
 * calling test file.
 */
export async function runCli(args: string[]): Promise<RunResult> {
  vi.resetModules();
  const { program } = (await import('../src/program.js')) as { program: Command };

  const out: string[] = [];
  const err: string[] = [];
  const log = vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => {
    out.push(a.map(String).join(' '));
  });
  const error = vi.spyOn(console, 'error').mockImplementation((...a: unknown[]) => {
    err.push(a.map(String).join(' '));
  });
  // Commander prints usage errors straight to stderr.
  const stderrWrite = vi.spyOn(process.stderr, 'write').mockImplementation(((chunk: string | Uint8Array) => {
    err.push(String(chunk));
    return true;
  }) as never);
  const exit = vi.spyOn(process, 'exit').mockImplementation(((code?: number) => {
    throw new ExitError(code);
  }) as never);

  let exitCode: number | undefined;
  try {
    await program.parseAsync(args, { from: 'user' });
  } catch (e) {
    if (e instanceof ExitError) exitCode = e.code;
    else throw e;
  } finally {
    log.mockRestore();
    error.mockRestore();
    stderrWrite.mockRestore();
    exit.mockRestore();
  }

  return {
    stdout: out.join('\n').replace(ANSI, ''),
    stderr: err.join('\n').replace(ANSI, ''),
    exitCode,
  };
}
