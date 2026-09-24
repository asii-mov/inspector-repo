import type { ChangedFile, DiffLine, FileStatus, Hunk } from './types.js';

const HUNK_HEADER = /^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/;

/** Parses the hunks of a single file's patch, as returned by GitHub's "list pull request files" API. */
export function parsePatch(patch: string): Hunk[] {
  const hunks: Hunk[] = [];
  let current: Hunk | undefined;
  let oldLine = 0;
  let newLine = 0;

  const body = patch.endsWith('\n') ? patch.slice(0, -1) : patch;
  for (const raw of body.split('\n')) {
    const line = raw.endsWith('\r') ? raw.slice(0, -1) : raw;
    const header = HUNK_HEADER.exec(line);
    if (header) {
      oldLine = Number(header[1]);
      newLine = Number(header[2]);
      current = { header: line, oldStart: oldLine, newStart: newLine, lines: [] };
      hunks.push(current);
      continue;
    }
    if (!current) continue;

    const marker = line[0];
    const content = line.slice(1);
    let diffLine: DiffLine | undefined;
    if (marker === '+') {
      diffLine = { type: 'added', content, newLine: newLine++ };
    } else if (marker === '-') {
      diffLine = { type: 'removed', content, oldLine: oldLine++ };
    } else if (marker === ' ' || (marker === undefined && line === '')) {
      diffLine = { type: 'context', content, oldLine: oldLine++, newLine: newLine++ };
    }
    // "\ No newline at end of file" and anything unexpected is ignored.
    if (diffLine) current.lines.push(diffLine);
  }

  return hunks;
}

function countChanges(hunks: Hunk[]): { additions: number; deletions: number } {
  let additions = 0;
  let deletions = 0;
  for (const hunk of hunks) {
    for (const line of hunk.lines) {
      if (line.type === 'added') additions++;
      else if (line.type === 'removed') deletions++;
    }
  }
  return { additions, deletions };
}

/** Removes git's C-style quoting from a path, e.g. `"a/caf\303\251.txt"`. */
function unquotePath(path: string): string {
  if (!path.startsWith('"') || !path.endsWith('"')) return path;
  const inner = path.slice(1, -1);
  const bytes: number[] = [];
  for (let i = 0; i < inner.length; i++) {
    const char = inner[i]!;
    if (char !== '\\') {
      bytes.push(...Buffer.from(char, 'utf8'));
      continue;
    }
    const next = inner[++i];
    if (next === undefined) break;
    if (/[0-7]/.test(next)) {
      bytes.push(parseInt(inner.slice(i, i + 3), 8));
      i += 2;
    } else {
      const escapes: Record<string, string> = { n: '\n', t: '\t', '"': '"', '\\': '\\', r: '\r', a: '\x07', b: '\b', f: '\f', v: '\v' };
      bytes.push(...Buffer.from(escapes[next] ?? next, 'utf8'));
    }
  }
  return Buffer.from(bytes).toString('utf8');
}

function stripPrefix(path: string): string {
  const unquoted = unquotePath(path.trim());
  return unquoted.replace(/^[ab]\//, '');
}

/**
 * Parses the output of `git diff` (multiple files) into changed files.
 * Used by the CLI; the GitHub Action uses {@link parsePatch} with the API's per-file data.
 */
export function parseGitDiff(diff: string): ChangedFile[] {
  const files: ChangedFile[] = [];
  const sections = diff.split(/^(?=diff --git )/m).filter((section) => section.startsWith('diff --git '));

  for (const section of sections) {
    const newlineIndex = section.indexOf('\n');
    const headerLine = newlineIndex === -1 ? section : section.slice(0, newlineIndex);
    const body = newlineIndex === -1 ? '' : section.slice(newlineIndex + 1);
    const hunkStart = body.search(/^@@ /m);
    const meta = (hunkStart === -1 ? body : body.slice(0, hunkStart)).split('\n');

    let status: FileStatus = 'modified';
    let oldPath: string | undefined;
    let newPath: string | undefined;
    let binary = false;

    for (const line of meta) {
      if (line.startsWith('new file mode')) status = 'added';
      else if (line.startsWith('deleted file mode')) status = 'removed';
      else if (line.startsWith('rename from ')) {
        status = 'renamed';
        oldPath = unquotePath(line.slice('rename from '.length));
      } else if (line.startsWith('rename to ')) newPath = unquotePath(line.slice('rename to '.length));
      else if (line.startsWith('copy from ')) {
        status = 'copied';
        oldPath = unquotePath(line.slice('copy from '.length));
      } else if (line.startsWith('copy to ')) newPath = unquotePath(line.slice('copy to '.length));
      else if (line.startsWith('--- ') && !line.startsWith('--- /dev/null')) oldPath ??= stripPrefix(line.slice(4));
      else if (line.startsWith('+++ ') && !line.startsWith('+++ /dev/null')) newPath ??= stripPrefix(line.slice(4));
      else if (line.startsWith('Binary files ') || line.startsWith('GIT binary patch')) binary = true;
    }

    if (!oldPath && !newPath) {
      // Binary or mode-only change: fall back to the header, which is `a/<path> b/<path>`.
      const rest = headerLine.slice('diff --git '.length);
      const quoted = /^("(?:[^"\\]|\\.)*")\s+("(?:[^"\\]|\\.)*")$/.exec(rest);
      if (quoted) {
        oldPath = stripPrefix(quoted[1]!);
        newPath = stripPrefix(quoted[2]!);
      } else {
        const half = rest.slice(0, Math.floor((rest.length - 1) / 2));
        newPath = oldPath = stripPrefix(half);
      }
    }

    const filename = status === 'removed' ? (oldPath ?? newPath)! : (newPath ?? oldPath)!;
    const hunks = hunkStart === -1 ? [] : parsePatch(body.slice(hunkStart));
    const { additions, deletions } = countChanges(hunks);
    files.push({
      filename,
      previousFilename: status === 'renamed' || status === 'copied' ? oldPath : undefined,
      status,
      additions,
      deletions,
      hunks,
      patchAvailable: !binary,
    });
  }
  return files;
}
