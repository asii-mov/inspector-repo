import { describe, expect, it } from 'vitest';
import { resolveRepositoryProfile } from '../src/engine/priority.js';
import { evaluate } from '../src/engine/evaluate.js';
import { blockingKeys, contentRequests, INTEGRITY_RULE_ID, scan } from '../src/engine/scan.js';
import { file, policyFrom } from './helpers.js';

const policy = policyFrom(`
settings:
  blockOn: high
  ignorePaths: ["vendor/**"]
priorityRepositories:
  - name: payments
    reason: PCI
    repositories: ["acme/payments-*"]
    blockOn: medium
    severityBoost: 1
    requiredApprovals: 2
    allowBypass: false
rules:
  - id: auth
    name: Authentication
    severity: critical
    match: any
    paths: ["**/auth/**"]
    excludePaths: ["**/*.test.ts"]
    content:
      - pattern: 'bcrypt|jwt\\.sign'
  - id: crypto
    name: Cryptography
    severity: high
    paths: ["src/**"]
    content:
      - { pattern: 'createhash', flags: i }
    contentScope: added
  - id: ui
    name: Styling
    severity: low
    paths: ["**/*.css"]
  - id: deps
    name: Dependencies
    severity: medium
    priorityOnly: true
    paths: ["package.json"]
  - id: only-api
    name: API gateway
    severity: high
    repositories: ["acme/api-*"]
    paths: ["gateway/**"]
`);

const profile = (repo = 'acme/web') => resolveRepositoryProfile(policy, repo);

describe('scan', () => {
  it('does not flag UI-only changes as blocking', () => {
    const result = scan(policy, profile(), [file('src/styles/button.css', { added: ['color: red;'] })]);
    expect(result.blocking).toHaveLength(0);
    expect(result.nonBlocking.map((finding) => finding.rule.id)).toEqual(['ui']);
  });

  it('flags a file by path', () => {
    const result = scan(policy, profile(), [file('src/auth/session.ts', { added: ['const x = 1;'] })]);
    expect(result.blocking.map((finding) => finding.rule.id)).toEqual(['auth']);
    expect(result.blocking[0]!.files[0]!.pathPatterns).toEqual(['**/auth/**']);
  });

  it('flags a file by content anywhere when match is "any"', () => {
    const result = scan(policy, profile(), [file('lib/users.ts', { removed: ['const hash = bcrypt.hashSync(pw, 12);'] })]);
    const [finding] = result.blocking;
    expect(finding!.rule.id).toBe('auth');
    expect(finding!.files[0]!.matchedLines).toEqual([{ type: 'removed', line: 2, content: 'const hash = bcrypt.hashSync(pw, 12);', pattern: 'bcrypt|jwt\\.sign', matched: 'bcrypt' }]);
  });

  it('requires both path and content when match is "all"', () => {
    const outside = scan(policy, profile(), [file('scripts/hash.ts', { added: ['createHash("md5")'] })]);
    expect(outside.findings.map((finding) => finding.rule.id)).not.toContain('crypto');
    const noContent = scan(policy, profile(), [file('src/hash.ts', { added: ['const a = 1;'] })]);
    expect(noContent.findings.map((finding) => finding.rule.id)).not.toContain('crypto');
    const both = scan(policy, profile(), [file('src/hash.ts', { added: ['createHash("md5")'] })]);
    expect(both.findings.map((finding) => finding.rule.id)).toContain('crypto');
  });

  it('respects contentScope and regex flags', () => {
    const removedOnly = scan(policy, profile(), [file('src/hash.ts', { removed: ['CREATEHASH("md5")'] })]);
    expect(removedOnly.findings.map((finding) => finding.rule.id)).not.toContain('crypto');
    const added = scan(policy, profile(), [file('src/hash.ts', { added: ['CREATEHASH("md5")'] })]);
    expect(added.findings.map((finding) => finding.rule.id)).toContain('crypto');
  });

  it('honours rule excludes and global ignorePaths', () => {
    const result = scan(policy, profile(), [file('src/auth/login.test.ts', { added: ['x'] }), file('vendor/auth/lib.js', { added: ['bcrypt'] })]);
    expect(result.findings).toHaveLength(0);
  });

  it('matches renamed files by their previous path', () => {
    const result = scan(policy, profile(), [file('src/identity/login.ts', {}, { status: 'renamed', previousFilename: 'src/auth/login.ts' })]);
    expect(result.blocking.map((finding) => finding.rule.id)).toEqual(['auth']);
  });

  it('flags by path when the diff is unavailable, even if content is also required', () => {
    const result = scan(policy, profile(), [file('src/huge.ts', {}, { patchAvailable: false, additions: 5000, hunks: [] })]);
    const crypto = result.findings.find((finding) => finding.rule.id === 'crypto');
    expect(crypto?.files[0]!.contentUnavailable).toBe(true);
    expect(result.filesWithoutPatch).toEqual(['src/huge.ts']);
  });

  it('applies priority repository settings', () => {
    const files = [file('src/styles/button.css', { added: ['x'] }), file('package.json', { added: ['"left-pad": "1.0.0"'] })];
    const normal = scan(policy, profile('acme/web'), files);
    expect(normal.findings.map((finding) => finding.rule.id)).toEqual(['ui']);

    const priority = scan(policy, profile('acme/payments-api'), files);
    expect(priority.profile).toMatchObject({ priority: true, blockOn: 'medium', requiredApprovals: 2, allowBypass: false });
    const deps = priority.findings.find((finding) => finding.rule.id === 'deps')!;
    expect(deps).toMatchObject({ baseSeverity: 'medium', severity: 'high', blocking: true });
    const ui = priority.findings.find((finding) => finding.rule.id === 'ui')!;
    expect(ui).toMatchObject({ severity: 'medium', blocking: true });
  });

  it('scopes rules to repositories', () => {
    const files = [file('gateway/routes.ts', { added: ['x'] })];
    expect(scan(policy, profile('acme/web'), files).findings).toHaveLength(0);
    expect(scan(policy, profile('acme/api-edge'), files).blocking.map((finding) => finding.rule.id)).toEqual(['only-api']);
    expect(scan(policy, profile('ACME/API-edge'), files).blocking).toHaveLength(1);
  });

  it('protects its own configuration with the integrity rule', () => {
    const result = scan(policy, profile(), [file('.github/security-inspector.yml', { removed: ['- id: auth'] })], {
      integrityPaths: ['.github/security-inspector.yml'],
    });
    expect(result.blocking.map((finding) => finding.rule.id)).toEqual([INTEGRITY_RULE_ID]);
    expect(result.blocking[0]!.severity).toBe('critical');
  });

  it('sorts findings by severity and produces stable keys', () => {
    const result = scan(policy, profile(), [file('src/hash.ts', { added: ['createHash()'] }), file('src/auth/a.ts', { added: ['x'] })]);
    expect(result.blocking.map((finding) => finding.rule.id)).toEqual(['auth', 'crypto']);
    expect(blockingKeys(result)).toEqual(['auth:src/auth/a.ts', 'crypto:src/hash.ts']);
  });

  it('builds excerpts around matched lines with context', () => {
    const lines = Array.from({ length: 30 }, (_, i) => `line ${i}`);
    lines[15] = 'jwt.sign(payload, secret)';
    const result = scan(policy, profile(), [file('lib/token.ts', { added: lines })]);
    const [chunk] = result.blocking[0]!.files[0]!.excerpt;
    expect(chunk!.lines.map((line) => line.content)).toEqual(['line 13', 'line 14', 'jwt.sign(payload, secret)', 'line 16', 'line 17']);
    expect(chunk!.newStart).toBe(15);
  });

  it('caps excerpts at maxSnippetLines', () => {
    const result = scan(policy, profile(), [file('src/auth/big.ts', { added: Array.from({ length: 100 }, (_, i) => `l${i}`) })], { maxSnippetLines: 10 });
    const match = result.blocking[0]!.files[0]!;
    expect(match.excerpt.flatMap((chunk) => chunk.lines)).toHaveLength(10);
    expect(match.excerptTruncated).toBe(true);
  });
});

describe('fileContent rules', () => {
  const contentPolicy = policyFrom(`
rules:
  - id: auth
    name: Authentication
    severity: critical
    match: any
    paths: ["src/auth/**"]
    excludePaths: ["**/*.test.ts"]
    fileContent:
      - 'from "passport"'
      - pattern: '^def login'
  - id: strict
    name: Strict
    match: all
    paths: ["src/secure/**"]
    fileContent: ['SECURE_MARKER']
`);
  const profile = resolveRepositoryProfile(contentPolicy, 'acme/web');
  const ids = (files: ReturnType<typeof file>[]) => scan(contentPolicy, profile, files).blocking.map((finding) => finding.rule.id);

  it('flags any change to a file containing a marker', () => {
    const routes = 'import passport from "passport";\nrouter.get("/profile", handler);\n';
    expect(ids([file('src/server/routes.ts', { removed: ['router.get("/profile", handler);'], added: ['router.get("/me", handler);'] }, { content: routes })])).toEqual(['auth']);
  });

  it('anchors ^ and $ to lines within the file', () => {
    expect(ids([file('app/views.py', { added: ['x = 1'] }, { content: 'import os\n\ndef login(request):\n    pass\n' })])).toEqual(['auth']);
  });

  it('flags a change that removes the marker', () => {
    expect(ids([file('src/server/routes.ts', { removed: ['import passport from "passport";'] }, { content: 'router.get("/", h);\n' })])).toEqual(['auth']);
  });

  it('does not flag files without a marker', () => {
    expect(ids([file('src/server/health.ts', { added: ['x'] }, { content: 'export const ok = true;\n' })])).toEqual([]);
  });

  it('checks deleted files through their removed lines, without reading them', () => {
    const deleted = file('src/server/old.ts', { removed: ['import passport from "passport";', 'export {}'] }, { status: 'removed' });
    expect(contentRequests(contentPolicy, profile, [deleted])).toEqual([]);
    expect(ids([deleted])).toEqual(['auth']);
  });

  it('reports files it could not read, and is conservative with match: all', () => {
    const unread = file('src/secure/a.ts', { added: ['x'] });
    const result = scan(contentPolicy, profile, [unread, file('src/other.ts', { added: ['y'] })]);
    expect(result.blocking.map((finding) => finding.rule.id)).toEqual(['strict']);
    expect(result.blocking[0]!.files[0]!.contentUnavailable).toBe(true);
    expect(result.filesWithoutContent.sort()).toEqual(['src/other.ts', 'src/secure/a.ts']);
  });

  it('ignores binary content', () => {
    expect(ids([file('assets/blob.bin', { added: ['x'] }, { content: 'from "passport"\0\0' })])).toEqual([]);
  });

  it('requests content only for files a fileContent rule could flag, within the limit', () => {
    const files = [file('src/a.ts'), file('src/auth/b.test.ts'), file('src/c.ts')];
    expect(contentRequests(contentPolicy, profile, files).map((request) => request.file.filename)).toEqual(['src/a.ts', 'src/c.ts']);
    const limited = policyFrom(`
settings: { fileContentLimit: 1 }
rules:
  - { id: a, name: A, fileContent: ['x'] }
`);
    expect(contentRequests(limited, resolveRepositoryProfile(limited, 'a/b'), files)).toHaveLength(1);
  });
});

describe('when conditions', () => {
  const conditional = policyFrom(`
rules:
  - id: auth
    name: Authentication
    severity: critical
    paths: ["src/auth/**"]
  - id: deps
    name: Dependencies
    severity: high
    paths: ["package.json"]
    when:
      baseBranches: [main]
      excludeHeadBranches: ["renovate/**"]
`);
  const profile = resolveRepositoryProfile(conditional, 'acme/web');
  const files = [file('src/auth/login.ts', { added: ['x'] }), file('package.json', { added: ['y'] })];
  const ids = (baseBranch: string, headBranch: string) =>
    scan(conditional, profile, files, { pullRequest: { baseBranch, headBranch } }).blocking.map((finding) => finding.rule.id);

  it('applies a rule only to matching pull requests', () => {
    expect(ids('main', 'feature/x')).toEqual(['auth', 'deps']);
    expect(ids('develop', 'feature/x')).toEqual(['auth']);
    expect(ids('main', 'renovate/lodash-4.x')).toEqual(['auth']);
  });

  it('applies every rule when there is no pull request context', () => {
    expect(scan(conditional, profile, files).blocking).toHaveLength(2);
  });

  it('skips the whole policy for pull requests it does not cover', () => {
    const scoped = policyFrom(`
settings:
  when: { baseBranches: [main, "release/*"] }
rules:
  - { id: auth, name: Authentication, severity: critical, paths: ["src/auth/**"] }
`);
    const into = (baseBranch: string) => scan(scoped, resolveRepositoryProfile(scoped, 'a/b'), files, { pullRequest: { baseBranch, headBranch: 'feature' } });
    expect(into('release/1.2').blocking).toHaveLength(1);
    const skipped = into('develop');
    expect(skipped).toMatchObject({ skipped: expect.stringContaining('`develop`'), findings: [], rulesEvaluated: 0 });
    expect(evaluate({ scan: skipped, approvals: [], changesRequestedBy: [] })).toMatchObject({ state: 'skipped', description: expect.stringContaining('Not applicable') });
  });
});
