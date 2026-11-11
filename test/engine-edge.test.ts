import { describe, expect, it } from 'vitest';
import { decodeBypassRecord, encodeBypassRecord, parseCommand, validateReason, type BypassRecord } from '../src/engine/bypass.js';
import { checkConditions } from '../src/engine/conditions.js';
import { evaluate } from '../src/engine/evaluate.js';
import { resolveRepositoryProfile } from '../src/engine/priority.js';
import { contentRequests, INTEGRITY_RULE_ID, MAX_FILE_CONTENT_BYTES, scan } from '../src/engine/scan.js';
import { bypassPrincipals, checkBypassCommand, collectApprovals, findBypass, type AuthorizationCheck, type CommentData, type StalenessCheck } from '../src/engine/signoff.js';
import { conditionsSchema, boostSeverity, type Principals } from '../src/policy/schema.js';
import { file, policyFrom } from './helpers.js';

const when = (value: Record<string, string[]>) => conditionsSchema.parse(value);
const pr = (baseBranch: string, headBranch = 'feature/x') => ({ baseBranch, headBranch });

describe('checkConditions', () => {
  it('is met without conditions or without pull request context', () => {
    expect(checkConditions(undefined, pr('dev'))).toEqual({ met: true });
    expect(checkConditions(when({ baseBranches: ['main'] }), undefined)).toEqual({ met: true });
    expect(checkConditions(when({}), pr('anything'))).toEqual({ met: true });
  });

  it('matches base branches by glob, without crossing "/"', () => {
    const release = when({ baseBranches: ['main', 'release/*'] });
    expect(checkConditions(release, pr('main')).met).toBe(true);
    expect(checkConditions(release, pr('release/1.2')).met).toBe(true);
    expect(checkConditions(release, pr('release/1/hotfix')).met).toBe(false);
    expect(checkConditions(release, pr('dev'))).toEqual({ met: false, reason: expect.stringContaining('targets `dev`') });
  });

  it('applies base and head branch exclusions', () => {
    expect(checkConditions(when({ excludeBaseBranches: ['sandbox/**'] }), pr('sandbox/a/b'))).toEqual({ met: false, reason: expect.stringContaining('excluded') });
    expect(checkConditions(when({ excludeHeadBranches: ['renovate/**'] }), pr('main', 'renovate/npm/lodash')).met).toBe(false);
    expect(checkConditions(when({ excludeHeadBranches: ['renovate/**'] }), pr('main', 'feature/renovate')).met).toBe(true);
  });

  it('restricts head branches', () => {
    const hotfix = when({ headBranches: ['hotfix/*'] });
    expect(checkConditions(hotfix, pr('main', 'hotfix/cve')).met).toBe(true);
    expect(checkConditions(hotfix, pr('main', 'feature/a'))).toEqual({ met: false, reason: expect.stringContaining('`feature/a` is not inspected') });
  });

  it('lets an exclusion win over an inclusion', () => {
    const conditions = when({ baseBranches: ['release/*'], excludeBaseBranches: ['release/legacy'] });
    expect(checkConditions(conditions, pr('release/2.0')).met).toBe(true);
    expect(checkConditions(conditions, pr('release/legacy')).met).toBe(false);
  });
});

describe('boostSeverity', () => {
  it('raises severity and caps it at critical', () => {
    expect(boostSeverity('low', 0)).toBe('low');
    expect(boostSeverity('low', 2)).toBe('high');
    expect(boostSeverity('high', 3)).toBe('critical');
    expect(boostSeverity('critical', 1)).toBe('critical');
  });
});

describe('resolveRepositoryProfile', () => {
  const policy = policyFrom(`
settings:
  blockOn: medium
  requiredApprovals: 2
priorityRepositories:
  - { name: pci, repositories: ["acme/pay-*"], blockOn: low, severityBoost: 1, requiredApprovals: 1 }
  - { name: identity, repositories: ["acme/pay-identity"], blockOn: critical, severityBoost: 2, requiredApprovals: 3, allowBypass: false }
rules: []
`);

  it('returns the base settings for ordinary repositories', () => {
    expect(resolveRepositoryProfile(policy, 'acme/web')).toMatchObject({ priority: false, groups: [], blockOn: 'medium', severityBoost: 0, requiredApprovals: 2, allowBypass: true });
  });

  it('takes the strictest value of each setting across matching groups', () => {
    const profile = resolveRepositoryProfile(policy, 'acme/pay-identity');
    expect(profile.groups.map((group) => group.name)).toEqual(['pci', 'identity']);
    expect(profile).toMatchObject({ priority: true, blockOn: 'low', severityBoost: 2, requiredApprovals: 3, allowBypass: false });
  });

  it('never relaxes the base settings', () => {
    // pci asks for 1 approval, identity for a "critical" threshold: both looser than settings.
    expect(resolveRepositoryProfile(policy, 'acme/pay-api')).toMatchObject({ blockOn: 'low', requiredApprovals: 2 });
    const loose = policyFrom('settings: { blockOn: medium }\npriorityRepositories:\n  - { name: x, repositories: ["a/b"], blockOn: critical }');
    expect(resolveRepositoryProfile(loose, 'a/b').blockOn).toBe('medium');
  });

  it('matches repositories case-insensitively', () => {
    expect(resolveRepositoryProfile(policy, 'ACME/Pay-API').priority).toBe(true);
  });

  it('disables bypass everywhere when the policy disables it', () => {
    const off = policyFrom('settings: { bypass: { enabled: false } }');
    expect(resolveRepositoryProfile(off, 'a/b').allowBypass).toBe(false);
  });
});

describe('scan edge cases', () => {
  const policy = policyFrom(`
settings:
  ignorePaths: ["vendor/**", ".github/**"]
rules:
  - id: auth
    name: Authentication
    severity: critical
    paths: ["src/auth/**"]
    excludePaths: ["**/*.test.ts"]
  - id: removed-checks
    name: Removed permission checks
    severity: high
    content: ['requirePermission\\(']
    contentScope: removed
  - id: markers
    name: Marked files
    severity: high
    fileContent: ['@security-critical']
`);
  const profile = resolveRepositoryProfile(policy, 'acme/web');
  const ids = (result: ReturnType<typeof scan>) => result.findings.map((finding) => finding.rule.id);

  it('still flags configuration tampering inside ignored paths', () => {
    const result = scan(policy, profile, [file('.github/CODEOWNERS', { removed: ['* @acme/security'] })]);
    expect(ids(result)).toEqual([INTEGRITY_RULE_ID]);
  });

  it('does not add the integrity rule when it is disabled', () => {
    const off = policyFrom('settings: { integrityRule: false }\nrules:\n  - { id: x, name: X, paths: [nothing] }');
    expect(scan(off, resolveRepositoryProfile(off, 'a/b'), [file('CODEOWNERS', { added: ['*'] })]).findings).toEqual([]);
  });

  it('only matches the configured content scope', () => {
    expect(ids(scan(policy, profile, [file('src/api.ts', { removed: ['requirePermission("admin");'] })]))).toEqual(['removed-checks']);
    expect(ids(scan(policy, profile, [file('src/api.ts', { added: ['requirePermission("admin");'] })]))).toEqual([]);
  });

  it('flags a rename out of an excluded name into a watched one', () => {
    const renamed = file('src/auth/login.ts', { added: ['x'] }, { status: 'renamed', previousFilename: 'src/auth/login.test.ts' });
    expect(ids(scan(policy, profile, [renamed]))).toEqual(['auth']);
  });

  it('flags moving watched code into an ignored path', () => {
    const moved = file('vendor/login.ts', { added: ['x'] }, { status: 'renamed', previousFilename: 'src/auth/login.ts' });
    expect(ids(scan(policy, profile, [moved]))).toEqual(['auth']);
  });

  it('still ignores renames within ignored paths', () => {
    const moved = file('vendor/b/login.ts', { added: ['x'] }, { status: 'renamed', previousFilename: 'vendor/a/login.ts', content: '@security-critical' });
    expect(ids(scan(policy, profile, [moved]))).toEqual([]);
  });

  it('does not search files larger than the content limit, and reports them', () => {
    const huge = file('src/big.ts', { added: ['x'] }, { content: `// @security-critical\n${'a'.repeat(MAX_FILE_CONTENT_BYTES)}` });
    const result = scan(policy, profile, [huge]);
    expect(ids(result)).toEqual([]);
    expect(result.filesWithoutContent).toEqual(['src/big.ts']);
  });

  it('reports where the file marker was found', () => {
    const result = scan(policy, profile, [file('src/x.ts', { added: ['y'] }, { content: 'a\nb\n/* @security-critical */\n' })]);
    expect(result.findings[0]!.files[0]!.fileMarker).toEqual({ pattern: '@security-critical', matched: '@security-critical', line: 3, version: 'head' });
  });

  it('does not request content for ignored or excluded files, or when no rule needs it', () => {
    const files = [file('vendor/a.ts'), file('src/auth/a.test.ts'), file('src/b.ts')];
    expect(contentRequests(policy, profile, files).map((request) => request.file.filename)).toEqual(['src/auth/a.test.ts', 'src/b.ts']);
    const pathOnly = policyFrom('rules:\n  - { id: x, name: X, paths: ["**"] }');
    expect(contentRequests(pathOnly, resolveRepositoryProfile(pathOnly, 'a/b'), files)).toEqual([]);
  });

  it('inspects nothing when the policy does not apply to the pull request', () => {
    const scoped = policyFrom('settings: { when: { baseBranches: [main] } }\nrules:\n  - { id: x, name: X, paths: ["**"] }');
    const result = scan(scoped, resolveRepositoryProfile(scoped, 'a/b'), [file('CODEOWNERS', { added: ['*'] })], { pullRequest: pr('dev') });
    expect(result).toMatchObject({ findings: [], filesScanned: 0, rulesEvaluated: 0, skipped: expect.stringContaining('dev') });
    expect(contentRequests(scoped, resolveRepositoryProfile(scoped, 'a/b'), [file('a.ts')], { pullRequest: pr('dev') })).toEqual([]);
  });
});

/** Shared fixtures for decisions and sign-off. */
const policy = policyFrom(`
settings:
  blockOn: high
  securityTeam: { teams: [acme/security], users: [] }
  bypass: { teams: [acme/leads], minReasonLength: 10 }
  when: { baseBranches: [main] }
priorityRepositories:
  - { name: payments, repositories: ["acme/payments"], allowBypass: false }
rules:
  - { id: auth, name: Authentication, severity: critical, paths: ["src/auth/**"] }
  - { id: docs, name: Docs, severity: low, paths: ["docs/**"] }
`);
const intoMain = { pullRequest: pr('main') };
const flagged = (repo = 'acme/web') => scan(policy, resolveRepositoryProfile(policy, repo), [file('src/auth/login.ts', { added: ['x'] })], intoMain);
const lowOnly = () => scan(policy, resolveRepositoryProfile(policy, 'acme/web'), [file('docs/readme.md', { added: ['x'] })], intoMain);

const record = (overrides: Partial<BypassRecord> = {}): BypassRecord => ({
  v: 1,
  commentId: 1,
  user: 'lena',
  reason: 'false positive here',
  sha: 'head',
  keys: ['auth:src/auth/login.ts'],
  at: '2026-01-01T10:00:00Z',
  ...overrides,
});

describe('evaluate decisions', () => {
  const none = { approvals: [], changesRequestedBy: [] };

  it('skips pull requests the policy does not cover, without backticks in the status', () => {
    const result = scan(policy, resolveRepositoryProfile(policy, 'acme/web'), [file('src/auth/login.ts', { added: ['x'] })], { pullRequest: pr('dev') });
    const decision = evaluate({ scan: result, ...none });
    expect(decision.state).toBe('skipped');
    expect(decision.description).toMatch(/^Not applicable: /);
    expect(decision.description).not.toContain('`');
  });

  it('clears pull requests that only have non-blocking findings, and says so', () => {
    expect(evaluate({ scan: lowOnly(), ...none })).toMatchObject({ state: 'clear', description: '1 low-risk finding(s); security review not required' });
  });

  it('separates valid and stale approvals', () => {
    const approvals = [
      { user: 'alice', commitId: 'old', valid: false },
      { user: 'bob', commitId: 'head', valid: true },
    ];
    const decision = evaluate({ scan: flagged(), approvals, changesRequestedBy: [] });
    expect(decision).toMatchObject({ state: 'approved', description: 'Security review approved by @bob' });
    expect(decision.staleApprovals.map((approval) => approval.user)).toEqual(['alice']);
  });

  it('prefers an approval over a bypass', () => {
    const decision = evaluate({ scan: flagged(), approvals: [{ user: 'alice', commitId: 'head', valid: true }], changesRequestedBy: [], bypass: { record: record(), valid: true } });
    expect(decision.state).toBe('approved');
  });

  it('ignores invalid bypasses', () => {
    const decision = evaluate({ scan: flagged(), ...none, bypass: { record: record(), valid: false, invalidReason: 'new commits' } });
    expect(decision.state).toBe('blocked');
  });

  it('collapses whitespace in the bypass reason', () => {
    const decision = evaluate({ scan: flagged(), ...none, bypass: { record: record({ reason: 'only\n  a   rename' }), valid: true } });
    expect(decision).toMatchObject({ state: 'bypassed', description: 'Bypassed by @lena: only a rename' });
  });

  it('lists every reviewer who requested changes', () => {
    expect(evaluate({ scan: flagged(), approvals: [], changesRequestedBy: ['alice', 'bob'] }).description).toBe('Security changes requested by @alice, @bob');
  });
});

describe('bypass helpers', () => {
  it('validates the justification length', () => {
    expect(validateReason('', 0)).toBeUndefined();
    expect(validateReason('', 1)).toBe('A justification is required.');
    expect(validateReason('short', 10)).toBe('A justification of at least 10 characters is required.');
    expect(validateReason('long enough!', 10)).toBeUndefined();
  });

  it('parses custom commands and multi-line justifications', () => {
    expect(parseCommand('  /skip-sec  reason\nmore detail ', '/skip-sec')).toBe('reason\nmore detail');
    expect(parseCommand('/skip-sec\treason', '/skip-sec')).toBe('reason');
    expect(parseCommand('/security-bypass reason', '/skip-sec')).toBeUndefined();
  });

  it('rejects records with missing or mistyped fields', () => {
    const encode = (value: unknown) => `<!-- security-inspector:bypass ${Buffer.from(JSON.stringify(value)).toString('base64')} -->`;
    expect(decodeBypassRecord(encode(record()))).toEqual(record());
    expect(decodeBypassRecord(encode({ ...record(), v: 2 }))).toBeUndefined();
    expect(decodeBypassRecord(encode({ ...record(), commentId: '1' }))).toBeUndefined();
    expect(decodeBypassRecord(encode({ ...record(), keys: 'auth:x' }))).toBeUndefined();
    expect(decodeBypassRecord(encode({ ...record(), at: undefined }))).toBeUndefined();
  });

  it('keeps an encoded record inside a single HTML comment', () => {
    const encoded = encodeBypassRecord(record({ reason: 'x --> <!-- y' }));
    expect(encoded.match(/-->/g)).toHaveLength(1);
  });
});

/** Pretend team membership: `acme/security` = alice, `acme/leads` = lena. */
const authorizer: AuthorizationCheck = {
  async isAuthorized(user: string, principals: Principals) {
    const teams: Record<string, string[]> = { 'acme/security': ['alice'], 'acme/leads': ['lena'] };
    const login = user.toLowerCase();
    return principals.users.some((candidate) => candidate.toLowerCase() === login) || principals.teams.some((team) => teams[team]?.includes(login));
  },
};
const fresh: StalenessCheck = { unchangedSince: async (sha) => (sha === 'head' ? { ok: true } : { ok: false, reason: 'new commits were pushed' }) };
const comment = (id: number, user: string, body: string, at = '2026-01-01T10:00:00Z', updatedAt = at): CommentData => ({ id, user, body, createdAt: at, updatedAt });

describe('sign-off edge cases', () => {
  it('works out who may bypass', () => {
    expect(bypassPrincipals(policy.settings)).toEqual({ teams: ['acme/leads', 'acme/security'], users: [] });
    const leadsOnly = policyFrom('settings: { securityTeam: { users: [sam] }, bypass: { users: [lena], includeSecurityTeam: false } }');
    expect(bypassPrincipals(leadsOnly.settings)).toEqual({ teams: [], users: ['lena'] });
  });

  it('treats reviewer logins case-insensitively and ignores self-approval by a security member', async () => {
    const { approvals, changesRequestedBy } = await collectApprovals({
      reviews: [
        { user: 'Alice', state: 'APPROVED', commitId: 'head' },
        { user: 'alice', state: 'CHANGES_REQUESTED', commitId: 'head' },
      ],
      author: 'dev',
      securityTeam: policy.settings.securityTeam,
      authorizer,
      staleness: fresh,
    });
    expect(approvals).toEqual([]);
    expect(changesRequestedBy).toEqual(['alice']);

    const own = await collectApprovals({
      reviews: [{ user: 'alice', state: 'APPROVED', commitId: 'head' }],
      author: 'ALICE',
      securityTeam: policy.settings.securityTeam,
      authorizer,
      staleness: fresh,
    });
    expect(own.approvals).toEqual([]);
  });

  it('lets authors bypass their own pull request only when allowed', async () => {
    const allow = policyFrom('settings: { bypass: { users: [lena], allowAuthor: true, minReasonLength: 0 } }\nrules:\n  - { id: auth, name: A, paths: ["src/auth/**"] }');
    const scanResult = scan(allow, resolveRepositoryProfile(allow, 'a/b'), [file('src/auth/x.ts', { added: ['x'] })]);
    const result = await checkBypassCommand({ comment: comment(3, 'lena', '/security-bypass'), settings: allow.settings, scan: scanResult, author: 'lena', headSha: 'head', authorizer });
    expect(result).toMatchObject({ accepted: true, record: { user: 'lena', reason: '' } });
  });

  it('explains why bypass is disabled outside priority repositories', async () => {
    const off = policyFrom('settings: { bypass: { enabled: false } }\nrules:\n  - { id: auth, name: A, paths: ["src/auth/**"] }');
    const scanResult = scan(off, resolveRepositoryProfile(off, 'a/b'), [file('src/auth/x.ts', { added: ['x'] })]);
    const result = await checkBypassCommand({ comment: comment(3, 'alice', '/security-bypass reason long enough'), settings: off.settings, scan: scanResult, author: 'dev', headSha: 'head', authorizer });
    expect(result).toEqual({ accepted: false, message: 'Bypass is disabled by the security policy.' });
  });

  it('answers plain comments with "not a bypass command"', async () => {
    const result = await checkBypassCommand({ comment: comment(3, 'alice', 'LGTM'), settings: policy.settings, scan: flagged(), author: 'dev', headSha: 'head', authorizer });
    expect(result).toEqual({ accepted: false, message: 'Not a bypass command.' });
  });

  describe('findBypass', () => {
    const bot = 'github-actions[bot]';
    const find = (comments: CommentData[], author = 'dev') =>
      findBypass({ comments, botLogin: bot, settings: policy.settings, scan: flagged(), author, authorizer, staleness: fresh });

    it('lets the most recent genuine record decide', async () => {
      const comments = [
        comment(1, 'lena', '/security-bypass first justification', '2026-01-01T09:00:00Z'),
        comment(2, bot, encodeBypassRecord(record({ commentId: 1, sha: 'old' })), '2026-01-01T09:01:00Z'),
        comment(3, 'alice', '/security-bypass second justification', '2026-01-01T10:00:00Z'),
        comment(4, bot, encodeBypassRecord(record({ commentId: 3, user: 'alice', sha: 'head' })), '2026-01-01T10:01:00Z'),
      ];
      expect(await find(comments)).toMatchObject({ valid: true, record: { user: 'alice', commentId: 3 } });
    });

    it('skips forged records whose command was written by someone else', async () => {
      const comments = [
        comment(1, 'lena', '/security-bypass genuine justification', '2026-01-01T09:00:00Z'),
        comment(2, bot, encodeBypassRecord(record({ commentId: 1 })), '2026-01-01T09:01:00Z'),
        comment(3, 'mallory', 'not a command at all', '2026-01-01T10:00:00Z'),
        comment(4, bot, encodeBypassRecord(record({ commentId: 3, user: 'alice' })), '2026-01-01T10:01:00Z'),
      ];
      expect(await find(comments)).toMatchObject({ valid: true, record: { user: 'lena', commentId: 1 } });
    });

    it('skips records whose command comment no longer contains the command', async () => {
      const comments = [comment(1, 'lena', 'never mind', '2026-01-01T09:00:00Z'), comment(2, bot, encodeBypassRecord(record()), '2026-01-01T09:01:00Z')];
      expect(await find(comments)).toBeUndefined();
    });

    it('ignores a bypass by the author recorded before authors were disallowed', async () => {
      const comments = [comment(1, 'lena', '/security-bypass genuine justification', '2026-01-01T09:00:00Z'), comment(2, bot, encodeBypassRecord(record()), '2026-01-01T09:01:00Z')];
      expect(await find(comments, 'lena')).toBeUndefined();
    });

    it('matches the bot login case-insensitively', async () => {
      const comments = [comment(1, 'lena', '/security-bypass genuine justification', '2026-01-01T09:00:00Z'), comment(2, 'GitHub-Actions[bot]', encodeBypassRecord(record()), '2026-01-01T09:01:00Z')];
      expect(await find(comments)).toMatchObject({ valid: true });
    });
  });
});
