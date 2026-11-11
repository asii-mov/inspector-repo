import { execFileSync, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { build } from 'esbuild';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

/** Runs the bundled CLI end to end: against diff files, stdin and real git repositories. */

const POLICY = `
settings:
  blockOn: high
  when: { baseBranches: [main] }
priorityRepositories:
  - { name: payments, repositories: ["acme/payments"], blockOn: low }
rules:
  - id: auth
    name: Authentication
    severity: critical
    match: any
    paths: ["src/auth/**"]
    fileContent: ['from "passport"']
  - id: docs
    name: Documentation
    severity: low
    paths: ["docs/**"]
`;

const AUTH_DIFF = [
  'diff --git a/src/auth/login.ts b/src/auth/login.ts',
  '--- a/src/auth/login.ts',
  '+++ b/src/auth/login.ts',
  '@@ -1 +1 @@',
  '-return bcrypt.compare(pw, hash);',
  '+return pw === hash;',
  '',
].join('\n');

const UI_DIFF = ['diff --git a/src/ui/a.css b/src/ui/a.css', '--- a/src/ui/a.css', '+++ b/src/ui/a.css', '@@ -1 +1 @@', '-a', '+b', ''].join('\n');

let root: string;
let cli: string;

const write = (path: string, text: string) => {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, text);
};

/** Git without the user's global config, hooks or signing. */
const gitEnv = { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1', GIT_AUTHOR_NAME: 'Test', GIT_AUTHOR_EMAIL: 'test@example.com', GIT_COMMITTER_NAME: 'Test', GIT_COMMITTER_EMAIL: 'test@example.com' };
const git = (cwd: string, ...args: string[]) => execFileSync('git', args, { cwd, env: gitEnv, stdio: ['ignore', 'pipe', 'pipe'] }).toString();

function run(args: string[], options: { cwd?: string; input?: string } = {}) {
  const result = spawnSync(process.execPath, [cli, ...args], { cwd: options.cwd ?? root, input: options.input, env: gitEnv, encoding: 'utf8' });
  return { code: result.status, stdout: result.stdout, stderr: result.stderr };
}

/** A repository whose `feature` branch changes the given files on top of `main`. */
function repository(name: string, base: Record<string, string>, changes: Record<string, string>): string {
  const dir = join(root, name);
  mkdirSync(dir);
  git(dir, 'init', '--quiet', '--initial-branch=main');
  for (const [path, text] of Object.entries(base)) write(join(dir, path), text);
  git(dir, 'add', '-A');
  git(dir, 'commit', '--quiet', '-m', 'base');
  git(dir, 'checkout', '--quiet', '-b', 'feature');
  for (const [path, text] of Object.entries(changes)) write(join(dir, path), text);
  git(dir, 'add', '-A');
  git(dir, 'commit', '--quiet', '--allow-empty', '-m', 'change');
  return dir;
}

beforeAll(async () => {
  root = mkdtempSync(join(tmpdir(), 'inspector-cli-'));
  cli = join(root, 'cli.mjs');
  const requireShim = "import { createRequire as __createRequire } from 'node:module'; const require = __createRequire(import.meta.url);";
  await build({ entryPoints: ['src/cli.ts'], outfile: cli, bundle: true, platform: 'node', format: 'esm', target: 'node20', banner: { js: requireShim }, logLevel: 'silent' });
  write(join(root, 'policy.yml'), POLICY);
  write(join(root, 'auth.diff'), AUTH_DIFF);
  write(join(root, 'ui.diff'), UI_DIFF);
}, 30_000);

afterAll(() => rmSync(root, { recursive: true, force: true }));

describe('CLI usage', () => {
  it('prints usage, and exits 2 for missing or unknown commands', () => {
    expect(run(['--help'])).toMatchObject({ code: 0, stdout: expect.stringContaining('Usage:') });
    expect(run([])).toMatchObject({ code: 2, stdout: expect.stringContaining('Usage:') });
    expect(run(['frobnicate'])).toMatchObject({ code: 2, stderr: expect.stringContaining('Unknown command "frobnicate"') });
  });

  it('exits 2 for bad scan options', () => {
    expect(run(['scan', '--diff', 'auth.diff'])).toMatchObject({ code: 2, stderr: expect.stringContaining('missing --policy') });
    expect(run(['scan', '--policy', 'policy.yml', '--diff', 'auth.diff', '--format', 'xml'])).toMatchObject({ code: 2, stderr: expect.stringContaining('unknown format "xml"') });
    expect(run(['scan', '--policy', 'missing.yml', '--diff', 'auth.diff']).code).toBe(2);
  });
});

describe('CLI validate', () => {
  it('summarises a valid policy', () => {
    expect(run(['validate', 'policy.yml'])).toMatchObject({ code: 0, stdout: expect.stringContaining('is valid: 2 rule(s), 1 priority group(s), review required from "high" severity') });
  });

  it('reports invalid policies with the failing path', () => {
    write(join(root, 'bad.yml'), 'settings: { blockOn: severe }');
    expect(run(['validate', 'bad.yml'])).toMatchObject({ code: 2, stderr: expect.stringContaining('settings.blockOn') });
  });

  it('warns about local files that try to change settings or central rules', () => {
    write(join(root, 'local.yml'), 'settings: { blockOn: critical }\nrules:\n  - { id: auth, name: Weak, paths: [x] }\n  - { id: tenant, name: Tenant, paths: ["db/**"] }');
    const result = run(['validate', 'policy.yml', '--local', 'local.yml']);
    expect(result).toMatchObject({ code: 0, stdout: expect.stringContaining('3 rule(s)') });
    expect(result.stderr).toContain('"settings" is ignored');
    expect(result.stderr).toContain('rule "auth" is already defined');
  });

  it('validates the example policy', () => {
    expect(run(['validate', join(process.cwd(), 'examples/security-inspector-policy.yml')]).code).toBe(0);
  });
});

describe('CLI scan of a diff', () => {
  it('exits 1 and explains when security review is required', () => {
    const result = run(['scan', '--policy', 'policy.yml', '--repo', 'acme/web', '--diff', 'auth.diff']);
    expect(result.code).toBe(1);
    expect(result.stdout).toContain('BLOCKED: Security review required: Authentication (0/1 approvals)');
    expect(result.stdout).toContain('[critical, blocking] Authentication (auth)');
    expect(result.stdout).toContain('path matches src/auth/**');
  });

  it('exits 0 for changes outside watched components', () => {
    expect(run(['scan', '--policy', 'policy.yml', '--repo', 'acme/web', '--diff', 'ui.diff'])).toMatchObject({ code: 0, stdout: expect.stringContaining('CLEAR') });
  });

  it('reads the diff from stdin', () => {
    expect(run(['scan', '--policy', 'policy.yml', '--repo', 'acme/web', '--diff', '-'], { input: AUTH_DIFF }).code).toBe(1);
  });

  it('produces machine-readable JSON', () => {
    const result = run(['scan', '--policy', 'policy.yml', '--repo', 'acme/web', '--diff', 'auth.diff', '--format', 'json']);
    expect(JSON.parse(result.stdout)).toEqual({
      repository: 'acme/web',
      priority: false,
      decision: 'blocked',
      description: 'Security review required: Authentication (0/1 approvals)',
      findings: [
        {
          rule: 'auth',
          name: 'Authentication',
          severity: 'critical',
          blocking: true,
          files: [{ filename: 'src/auth/login.ts', status: 'modified', additions: 1, deletions: 1, pathPatterns: ['src/auth/**'], matchedLines: [] }],
        },
      ],
    });
  });

  it('renders the pull request report as markdown', () => {
    const result = run(['scan', '--policy', 'policy.yml', '--repo', 'acme/web', '--diff', 'auth.diff', '--format', 'markdown']);
    expect(result.stdout).toContain('Authentication');
    expect(result.stdout).toContain('+return pw === hash;');
  });

  it('applies priority repository settings from --repo', () => {
    write(join(root, 'docs.diff'), AUTH_DIFF.replaceAll('src/auth/login.ts', 'docs/intro.md'));
    expect(run(['scan', '--policy', 'policy.yml', '--repo', 'acme/web', '--diff', 'docs.diff']).code).toBe(0);
    const priority = run(['scan', '--policy', 'policy.yml', '--repo', 'acme/payments', '--diff', 'docs.diff', '--format', 'json']);
    expect(priority.code).toBe(1);
    expect(JSON.parse(priority.stdout)).toMatchObject({ priority: true, decision: 'blocked' });
  });

  it('honours when conditions given by --target-branch, and ignores them without branch context', () => {
    const into = (branch: string) => run(['scan', '--policy', 'policy.yml', '--repo', 'acme/web', '--diff', 'auth.diff', '--target-branch', branch, '--source-branch', 'feature']);
    expect(into('dev')).toMatchObject({ code: 0, stdout: expect.stringContaining('SKIPPED: Not applicable') });
    expect(into('main').code).toBe(1);
  });

  it('flags the local rules file itself via the integrity rule', () => {
    write(join(root, 'local-rules.yml'), 'rules: []');
    write(join(root, 'local.diff'), UI_DIFF.replaceAll('src/ui/a.css', 'local-rules.yml'));
    const result = run(['scan', '--policy', 'policy.yml', '--local', 'local-rules.yml', '--repo', 'acme/web', '--diff', 'local.diff']);
    expect(result).toMatchObject({ code: 1, stdout: expect.stringContaining('security-inspector-integrity') });
  });
});

describe('CLI scan of a git repository', () => {
  it('diffs the branch against its base and reads changed files at the head commit', () => {
    const dir = repository(
      'marker',
      { 'src/session.ts': 'export const ttl = 60;\n', 'src/ui/a.css': 'a {}\n' },
      { 'src/session.ts': 'import passport from "passport";\nexport const ttl = 600;\n', 'src/ui/a.css': 'b {}\n' },
    );
    const result = run(['scan', '--policy', join(root, 'policy.yml'), '--repo', 'acme/web', '--base', 'main', '--format', 'json'], { cwd: dir });
    expect(result.code).toBe(1);
    const output = JSON.parse(result.stdout);
    expect(output.findings.map((finding: { rule: string; files: { filename: string }[] }) => [finding.rule, finding.files.map((f) => f.filename)])).toEqual([['auth', ['src/session.ts']]]);
  });

  it('flags a change that removes the marker, by reading the base version of deleted files', () => {
    const dir = repository('deleted', { 'src/strategy.ts': 'import passport from "passport";\n' }, {});
    git(dir, 'rm', '--quiet', 'src/strategy.ts');
    git(dir, 'commit', '--quiet', '-m', 'remove');
    expect(run(['scan', '--policy', join(root, 'policy.yml'), '--repo', 'acme/web', '--base', 'main'], { cwd: dir }).code).toBe(1);
  });

  it('ignores uncommitted changes and uses the branch names for conditions', () => {
    const dir = repository('clean', { 'src/ui/a.css': 'a {}\n' }, { 'src/ui/a.css': 'b {}\n' });
    write(join(dir, 'src/auth/wip.ts'), 'uncommitted\n');
    expect(run(['scan', '--policy', join(root, 'policy.yml'), '--repo', 'acme/web', '--base', 'main'], { cwd: dir }).code).toBe(0);
  });

  it('derives the repository name from the origin remote', () => {
    const dir = repository('remote', { 'docs/a.md': 'a\n' }, { 'docs/a.md': 'b\n' });
    git(dir, 'remote', 'add', 'origin', 'git@github.com:acme/payments.git');
    const result = run(['scan', '--policy', join(root, 'policy.yml'), '--base', 'main', '--format', 'json'], { cwd: dir });
    expect(JSON.parse(result.stdout)).toMatchObject({ repository: 'acme/payments', priority: true, decision: 'blocked' });
  });

  it('exits 2 when no base ref can be found', () => {
    const dir = join(root, 'orphan');
    mkdirSync(dir);
    git(dir, 'init', '--quiet', '--initial-branch=trunk');
    git(dir, 'commit', '--quiet', '--allow-empty', '-m', 'x');
    expect(run(['scan', '--policy', join(root, 'policy.yml')], { cwd: dir })).toMatchObject({ code: 2, stderr: expect.stringContaining('pass --base') });
  });
});
