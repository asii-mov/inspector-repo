import { describe, expect, it } from 'vitest';
import { parseGitDiff, parsePatch } from '../src/diff/parse.js';

describe('parsePatch', () => {
  it('tracks old and new line numbers across hunks', () => {
    const hunks = parsePatch(
      ['@@ -10,3 +10,4 @@ function login()', ' const a = 1;', '-const b = 2;', '+const b = 3;', '+const c = 4;', ' return a;', '@@ -40,1 +41,1 @@', '-old', '+new'].join('\n'),
    );
    expect(hunks).toHaveLength(2);
    expect(hunks[0]!.lines).toEqual([
      { type: 'context', content: 'const a = 1;', oldLine: 10, newLine: 10 },
      { type: 'removed', content: 'const b = 2;', oldLine: 11 },
      { type: 'added', content: 'const b = 3;', newLine: 11 },
      { type: 'added', content: 'const c = 4;', newLine: 12 },
      { type: 'context', content: 'return a;', oldLine: 12, newLine: 13 },
    ]);
    expect(hunks[1]!.lines).toEqual([
      { type: 'removed', content: 'old', oldLine: 40 },
      { type: 'added', content: 'new', newLine: 41 },
    ]);
  });

  it('ignores "no newline" markers and a trailing newline', () => {
    const hunks = parsePatch('@@ -1 +1 @@\n-a\n\\ No newline at end of file\n+b\n');
    expect(hunks[0]!.lines.map((line) => line.type)).toEqual(['removed', 'added']);
  });
});

describe('parseGitDiff', () => {
  const diff = [
    'diff --git a/src/auth/login.ts b/src/auth/login.ts',
    'index 1111111..2222222 100644',
    '--- a/src/auth/login.ts',
    '+++ b/src/auth/login.ts',
    '@@ -1,2 +1,2 @@',
    ' import bcrypt from "bcrypt";',
    '-const rounds = 12;',
    '+const rounds = 4;',
    'diff --git a/src/new file.ts b/src/new file.ts',
    'new file mode 100644',
    'index 0000000..3333333',
    '--- /dev/null',
    '+++ b/src/new file.ts',
    '@@ -0,0 +1 @@',
    '+export const x = 1;',
    'diff --git a/old/name.ts b/new/name.ts',
    'similarity index 100%',
    'rename from old/name.ts',
    'rename to new/name.ts',
    'diff --git a/gone.ts b/gone.ts',
    'deleted file mode 100644',
    '--- a/gone.ts',
    '+++ /dev/null',
    '@@ -1 +0,0 @@',
    '-bye',
    'diff --git a/logo.png b/logo.png',
    'index 4444444..5555555 100644',
    'Binary files a/logo.png and b/logo.png differ',
    '',
  ].join('\n');

  it('parses statuses, paths and counts', () => {
    const files = parseGitDiff(diff);
    expect(files.map((f) => [f.filename, f.status, f.additions, f.deletions, f.previousFilename, f.patchAvailable])).toEqual([
      ['src/auth/login.ts', 'modified', 1, 1, undefined, true],
      ['src/new file.ts', 'added', 1, 0, undefined, true],
      ['new/name.ts', 'renamed', 0, 0, 'old/name.ts', true],
      ['gone.ts', 'removed', 0, 1, undefined, true],
      ['logo.png', 'modified', 0, 0, undefined, false],
    ]);
  });

  it('unquotes paths with special characters', () => {
    const files = parseGitDiff(['diff --git "a/caf\\303\\251.ts" "b/caf\\303\\251.ts"', '--- "a/caf\\303\\251.ts"', '+++ "b/caf\\303\\251.ts"', '@@ -1 +1 @@', '-a', '+b', ''].join('\n'));
    expect(files[0]!.filename).toBe('café.ts');
  });
});
