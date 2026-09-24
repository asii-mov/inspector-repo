import { describe, expect, it } from 'vitest';
import { decodeBypassRecord, encodeBypassRecord, parseCommand } from '../src/engine/bypass.js';
import { evaluate } from '../src/engine/evaluate.js';
import { resolveRepositoryProfile } from '../src/engine/priority.js';
import { scan } from '../src/engine/scan.js';
import { checkBypassCommand, collectApprovals, findBypass, type AuthorizationCheck, type CommentData, type StalenessCheck } from '../src/engine/signoff.js';
import type { Principals } from '../src/policy/schema.js';
import { file, policyFrom } from './helpers.js';

const policy = policyFrom(`
settings:
  securityTeam: { teams: [acme/security], users: [sec-lead] }
  bypass:
    teams: [acme/leads]
    minReasonLength: 10
priorityRepositories:
  - name: payments
    repositories: ["acme/payments"]
    allowBypass: false
    requiredApprovals: 2
rules:
  - id: auth
    name: Authentication
    severity: critical
    paths: ["src/auth/**"]
`);
const settings = policy.settings;

/** Pretend team membership: `acme/security` = alice, `acme/leads` = lena. */
const authorizer: AuthorizationCheck = {
  async isAuthorized(user: string, principals: Principals) {
    const teams: Record<string, string[]> = { 'acme/security': ['alice'], 'acme/leads': ['lena'] };
    if (principals.users.includes(user)) return true;
    return principals.teams.some((team) => teams[team]?.includes(user));
  },
};

/** Commits "old-*" are before a flagged file changed. */
const staleness: StalenessCheck = {
  async unchangedSince(sha: string) {
    return sha.startsWith('old') ? { ok: false, reason: 'flagged files changed afterwards (src/auth/login.ts)' } : { ok: true };
  },
};

const flagged = (repo = 'acme/web') => scan(policy, resolveRepositoryProfile(policy, repo), [file('src/auth/login.ts', { added: ['x'] })]);
const clean = () => scan(policy, resolveRepositoryProfile(policy, 'acme/web'), [file('src/ui/button.tsx', { added: ['x'] })]);

const comment = (id: number, user: string, body: string, at = '2026-01-01T10:00:00Z', updatedAt = at): CommentData => ({ id, user, body, createdAt: at, updatedAt });

describe('parseCommand', () => {
  it('extracts the justification', () => {
    expect(parseCommand('/security-bypass  only renamed a variable \n', '/security-bypass')).toBe('only renamed a variable');
    expect(parseCommand('/Security-Bypass', '/security-bypass')).toBe('');
    expect(parseCommand('/security-bypassed nope', '/security-bypass')).toBeUndefined();
    expect(parseCommand('please /security-bypass', '/security-bypass')).toBeUndefined();
  });
});

describe('bypass records', () => {
  it('round-trips and rejects garbage', () => {
    const record = { v: 1 as const, commentId: 5, user: 'alice', reason: 'x --> y', sha: 'abc', keys: ['auth:a'], at: '2026-01-01T00:00:00Z' };
    expect(decodeBypassRecord(`hello\n${encodeBypassRecord(record)}`)).toEqual(record);
    expect(decodeBypassRecord('<!-- security-inspector:bypass bm9wZQ== -->')).toBeUndefined();
    expect(decodeBypassRecord('no marker')).toBeUndefined();
  });
});

describe('collectApprovals', () => {
  it('uses the latest review per security reviewer and ignores others', async () => {
    const { approvals, changesRequestedBy } = await collectApprovals({
      reviews: [
        { user: 'alice', state: 'CHANGES_REQUESTED', commitId: 'head' },
        { user: 'alice', state: 'COMMENTED', commitId: 'head' },
        { user: 'alice', state: 'APPROVED', commitId: 'head' },
        { user: 'sec-lead', state: 'APPROVED', commitId: 'old-1' },
        { user: 'random-dev', state: 'APPROVED', commitId: 'head' },
        { user: 'author', state: 'APPROVED', commitId: 'head' },
      ],
      author: 'author',
      securityTeam: settings.securityTeam,
      authorizer,
      staleness,
    });
    expect(approvals).toEqual([
      { user: 'alice', commitId: 'head', valid: true },
      { user: 'sec-lead', commitId: 'old-1', valid: false },
    ]);
    expect(changesRequestedBy).toEqual([]);
  });

  it('reports changes requested and drops dismissed reviews', async () => {
    const { approvals, changesRequestedBy } = await collectApprovals({
      reviews: [
        { user: 'alice', state: 'APPROVED', commitId: 'head' },
        { user: 'alice', state: 'DISMISSED', commitId: 'head' },
        { user: 'sec-lead', state: 'CHANGES_REQUESTED', commitId: 'head' },
      ],
      author: 'author',
      securityTeam: settings.securityTeam,
      authorizer,
      staleness,
    });
    expect(approvals).toEqual([]);
    expect(changesRequestedBy).toEqual(['sec-lead']);
  });
});

describe('checkBypassCommand', () => {
  const base = { settings, author: 'dev', headSha: 'head', authorizer, now: new Date('2026-01-01T10:00:00Z') };

  it('accepts an authorised bypass with a justification', async () => {
    const result = await checkBypassCommand({ ...base, scan: flagged(), comment: comment(7, 'lena', '/security-bypass renamed a constant only') });
    expect(result).toEqual({
      accepted: true,
      record: { v: 1, commentId: 7, user: 'lena', reason: 'renamed a constant only', sha: 'head', keys: ['auth:src/auth/login.ts'], at: '2026-01-01T10:00:00.000Z' },
    });
  });

  it.each([
    ['unauthorised users', 'mallory', '/security-bypass this is totally fine', 'not authorised'],
    ['the pull request author', 'dev', '/security-bypass this is totally fine', 'authors cannot bypass'],
    ['a missing justification', 'alice', '/security-bypass', 'justification'],
  ])('rejects %s', async (_, user, body, message) => {
    const result = await checkBypassCommand({ ...base, scan: flagged(), comment: comment(1, user, body) });
    expect(result.accepted).toBe(false);
    expect(result.accepted === false && result.message).toContain(message);
  });

  it('rejects bypass in priority repositories that disallow it', async () => {
    const result = await checkBypassCommand({ ...base, scan: flagged('acme/payments'), comment: comment(1, 'alice', '/security-bypass it is a false positive') });
    expect(result.accepted === false && result.message).toContain('disabled for priority repositories (payments)');
  });

  it('rejects when there is nothing to bypass', async () => {
    const result = await checkBypassCommand({ ...base, scan: clean(), comment: comment(1, 'alice', '/security-bypass it is a false positive') });
    expect(result.accepted === false && result.message).toContain('nothing to bypass');
  });
});

describe('findBypass', () => {
  const record = (overrides: Record<string, unknown> = {}) =>
    encodeBypassRecord({ v: 1, commentId: 1, user: 'lena', reason: 'false positive here', sha: 'head', keys: ['auth:src/auth/login.ts'], at: '2026-01-01T10:00:00Z', ...overrides });
  const command = comment(1, 'lena', '/security-bypass false positive here', '2026-01-01T09:59:00Z');
  const ack = (body = record(), at = '2026-01-01T10:00:00Z', updatedAt = at) => comment(2, 'github-actions[bot]', body, at, updatedAt);
  const find = (comments: CommentData[], scanResult = flagged()) =>
    findBypass({ comments, botLogin: 'github-actions[bot]', settings, scan: scanResult, author: 'dev', authorizer, staleness });

  it('accepts a genuine, current bypass', async () => {
    expect(await find([command, ack()])).toMatchObject({ valid: true, record: { user: 'lena' } });
  });

  it('ignores records not posted by the inspector, or edited afterwards', async () => {
    expect(await find([command, { ...ack(), user: 'mallory' }])).toBeUndefined();
    expect(await find([command, ack(record(), '2026-01-01T10:00:00Z', '2026-01-02T00:00:00Z')])).toBeUndefined();
  });

  it('is revoked when the command comment is deleted or edited', async () => {
    expect(await find([ack()])).toBeUndefined();
    expect(await find([{ ...command, updatedAt: '2026-01-03T00:00:00Z' }, ack()])).toBeUndefined();
  });

  it('ignores records whose author is no longer authorised', async () => {
    expect(await find([{ ...command, user: 'mallory' }, ack(record({ user: 'mallory' }))])).toBeUndefined();
  });

  it('is invalidated by new flagged files or changes to flagged files', async () => {
    const more = scan(policy, resolveRepositoryProfile(policy, 'acme/web'), [file('src/auth/login.ts', { added: ['x'] }), file('src/auth/new.ts', { added: ['y'] })]);
    expect(await find([command, ack()], more)).toMatchObject({ valid: false, invalidReason: expect.stringContaining('src/auth/new.ts') });
    expect(await find([command, ack(record({ sha: 'old-1' }))])).toMatchObject({ valid: false, invalidReason: expect.stringContaining('changed afterwards') });
  });
});

describe('evaluate', () => {
  it('clears pull requests without blocking findings', () => {
    expect(evaluate({ scan: clean(), approvals: [], changesRequestedBy: [] })).toMatchObject({ state: 'clear' });
  });

  it('blocks until enough valid approvals', () => {
    const scanResult = flagged();
    const blocked = evaluate({ scan: scanResult, approvals: [{ user: 'alice', commitId: 'old', valid: false }], changesRequestedBy: [] });
    expect(blocked).toMatchObject({ state: 'blocked', description: 'Security review required: Authentication (0/1 approvals)' });
    expect(evaluate({ scan: scanResult, approvals: [{ user: 'alice', commitId: 'head', valid: true }], changesRequestedBy: [] })).toMatchObject({ state: 'approved' });
  });

  it('requires more approvals in priority repositories', () => {
    const decision = evaluate({ scan: flagged('acme/payments'), approvals: [{ user: 'alice', commitId: 'head', valid: true }], changesRequestedBy: [] });
    expect(decision).toMatchObject({ state: 'blocked', requiredApprovals: 2 });
  });

  it('keeps blocking when security requested changes, even with a bypass', () => {
    const bypass = { valid: true, record: { v: 1 as const, commentId: 1, user: 'lena', reason: 'fp', sha: 'head', keys: [], at: '' } };
    expect(evaluate({ scan: flagged(), approvals: [], changesRequestedBy: ['alice'], bypass })).toMatchObject({ state: 'blocked' });
    expect(evaluate({ scan: flagged(), approvals: [], changesRequestedBy: [], bypass })).toMatchObject({ state: 'bypassed' });
    expect(evaluate({ scan: flagged('acme/payments'), approvals: [], changesRequestedBy: [], bypass })).toMatchObject({ state: 'blocked' });
  });

  it('keeps status descriptions within 140 characters', () => {
    const many = policyFrom(`
rules:
${Array.from({ length: 20 }, (_, i) => `  - { id: r${i}, name: "A rather long component name ${i}", paths: ["f${i}"] }`).join('\n')}
`);
    const result = scan(many, resolveRepositoryProfile(many, 'a/b'), Array.from({ length: 20 }, (_, i) => file(`f${i}`, { added: ['x'] })));
    expect(evaluate({ scan: result, approvals: [], changesRequestedBy: [] }).description.length).toBeLessThanOrEqual(140);
  });
});
