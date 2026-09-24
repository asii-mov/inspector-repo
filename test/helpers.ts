import { parsePatch } from '../src/diff/parse.js';
import type { ChangedFile } from '../src/diff/types.js';
import { parsePolicy } from '../src/policy/load.js';
import type { Policy } from '../src/policy/schema.js';

export function policyFrom(yaml: string): Policy {
  return parsePolicy(yaml, 'test-policy.yml');
}

/** Builds a changed file from added/removed lines. */
export function file(filename: string, lines: { added?: string[]; removed?: string[] } = {}, extra: Partial<ChangedFile> = {}): ChangedFile {
  const removed = lines.removed ?? [];
  const added = lines.added ?? [];
  const patch = [`@@ -1,${removed.length + 1} +1,${added.length + 1} @@`, ' // context', ...removed.map((line) => `-${line}`), ...added.map((line) => `+${line}`)].join('\n');
  return {
    filename,
    status: 'modified',
    additions: added.length,
    deletions: removed.length,
    hunks: parsePatch(patch),
    patchAvailable: true,
    ...extra,
  };
}
