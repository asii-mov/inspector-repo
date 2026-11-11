import { describe, expect, it, vi } from 'vitest';
import { Authorizer, ChangeTracker, listPullRequestFiles, mentions, parseTeam, readFileContents, readRepositoryFile, type Octokit } from '../src/github/api.js';
import { loadPolicy } from '../src/github/policy.js';
import { PolicyError } from '../src/policy/load.js';
import { file } from './helpers.js';

const httpError = (status: number) => Object.assign(new Error(`HTTP ${status}`), { status });
const base64 = (text: string) => Buffer.from(text, 'utf8').toString('base64');

/** A fake Octokit exposing only the endpoints a test needs. */
const fakeOctokit = (rest: Record<string, Record<string, (...args: never[]) => unknown>>, paginate?: (...args: never[]) => unknown) =>
  ({ rest, paginate }) as unknown as Octokit;

/** Fake contents API: `files` maps `owner/repo:path@ref` (or without `@ref`) to text. */
function contentsOctokit(files: Record<string, string | Error>) {
  const getContent = vi.fn(async ({ owner, repo, path, ref }: { owner: string; repo: string; path: string; ref?: string }) => {
    const value = files[`${owner}/${repo}:${path}@${ref}`] ?? files[`${owner}/${repo}:${path}`];
    if (value === undefined) throw httpError(404);
    if (value instanceof Error) throw value;
    return { data: { type: 'file', encoding: 'base64', content: base64(value) } };
  });
  return { octokit: fakeOctokit({ repos: { getContent } }), getContent };
}

describe('readRepositoryFile', () => {
  it('decodes files and treats 404 as missing', async () => {
    const { octokit } = contentsOctokit({ 'a/b:x.yml': 'hello' });
    expect(await readRepositoryFile(octokit, { owner: 'a', repo: 'b' }, 'x.yml')).toBe('hello');
    expect(await readRepositoryFile(octokit, { owner: 'a', repo: 'b' }, 'missing.yml')).toBeUndefined();
  });

  it('rejects directories and propagates other errors', async () => {
    const dir = fakeOctokit({ repos: { getContent: async () => ({ data: [] }) } });
    await expect(readRepositoryFile(dir, { owner: 'a', repo: 'b' }, 'src')).rejects.toThrow('is not a file');
    const { octokit } = contentsOctokit({ 'a/b:x.yml': httpError(403) });
    await expect(readRepositoryFile(octokit, { owner: 'a', repo: 'b' }, 'x.yml')).rejects.toMatchObject({ status: 403 });
  });
});

describe('loadPolicy', () => {
  const repository = { owner: 'acme', repo: 'web' };
  const baseSha = 'base0000000';
  const location = { policyRepository: 'acme/security-policies', policyPath: 'policy.yml', localConfigPath: '.github/security-inspector.yml' };
  const central = 'rules:\n  - { id: auth, name: Auth, paths: ["auth/**"] }';
  const local = 'settings: { blockOn: critical }\nrules:\n  - { id: tenant, name: Tenant, paths: ["db/**"] }';

  const load = (files: Record<string, string | Error>, overrides: Partial<typeof location> & { policyRef?: string } = {}) => {
    const { octokit, getContent } = contentsOctokit(files);
    return { getContent, result: loadPolicy({ location: { ...location, ...overrides }, policyOctokit: octokit, repoOctokit: octokit, repository, baseSha }) };
  };

  it('adds local rules from the base commit on top of the central policy', async () => {
    const { result, getContent } = load({ 'acme/security-policies:policy.yml': central, [`acme/web:.github/security-inspector.yml@${baseSha}`]: local });
    const loaded = await result;
    expect(loaded.policy.rules.map((rule) => rule.id)).toEqual(['auth', 'tenant']);
    expect(loaded.policy.settings.blockOn).toBe('high');
    expect(loaded.warnings).toEqual([expect.stringContaining('"settings" is ignored')]);
    expect(loaded.source).toBe('acme/security-policies:policy.yml + .github/security-inspector.yml');
    // The local file is read from the base commit, never the head.
    expect(getContent).toHaveBeenCalledWith(expect.objectContaining({ owner: 'acme', repo: 'web', ref: baseSha }));
  });

  it('reads the central policy at the configured ref', async () => {
    const { result, getContent } = load({ 'acme/security-policies:policy.yml@v2': central }, { policyRef: 'v2' });
    expect((await result).source).toBe('acme/security-policies@v2:policy.yml');
    expect(getContent).toHaveBeenCalledWith(expect.objectContaining({ repo: 'security-policies', ref: 'v2' }));
  });

  it('uses the local file as the whole policy without a central repository', async () => {
    const { result } = load({ 'acme/web:.github/security-inspector.yml': local }, { policyRepository: undefined });
    const loaded = await result;
    expect(loaded.policy.settings.blockOn).toBe('critical');
    expect(loaded.source).toBe('acme/web@base000:.github/security-inspector.yml');
  });

  it('fails clearly when no policy can be found or read', async () => {
    await expect(load({}, { policyRepository: undefined }).result).rejects.toThrow(/no policy found/);
    await expect(load({}).result).rejects.toThrow(/central policy not found/);
    await expect(load({ 'acme/security-policies:policy.yml': httpError(403) }).result).rejects.toThrow(/could not read the central policy/);
    await expect(load({}, { policyRepository: 'not-a-repo' }).result).rejects.toThrow(PolicyError);
    await expect(load({}, { policyRepository: 'a/b/c' }).result).rejects.toThrow(/expected "owner\/repo"/);
  });

  it('rejects an invalid central policy', async () => {
    await expect(load({ 'acme/security-policies:policy.yml': 'settings: { blockOn: severe }' }).result).rejects.toThrow(/settings\.blockOn/);
  });
});

describe('listPullRequestFiles', () => {
  it('parses patches and marks files without a patch', async () => {
    const octokit = fakeOctokit({ pulls: { listFiles: () => undefined } }, async () => [
      { filename: 'a.ts', status: 'modified', additions: 1, deletions: 0, sha: 's1', patch: '@@ -1 +1,2 @@\n x\n+y' },
      { filename: 'logo.png', status: 'modified', additions: 0, deletions: 0, sha: 's2' },
      { filename: 'huge.js', status: 'modified', additions: 9000, deletions: 0, sha: 's3' },
      { filename: 'new.ts', previous_filename: 'old.ts', status: 'renamed', additions: 0, deletions: 0, sha: null },
    ]);
    const files = await listPullRequestFiles(octokit, { owner: 'a', repo: 'b' }, 1);
    expect(files.map((f) => [f.filename, f.patchAvailable, f.hunks.length, f.previousFilename, f.sha])).toEqual([
      ['a.ts', true, 1, undefined, 's1'],
      ['logo.png', true, 0, undefined, 's2'],
      ['huge.js', false, 0, undefined, 's3'],
      ['new.ts', true, 0, 'old.ts', undefined],
    ]);
  });
});

describe('readFileContents', () => {
  it('reads head and base versions, and leaves unreadable files empty', async () => {
    const { octokit } = contentsOctokit({ 'a/b:a.ts@head': 'A', 'a/b:old.ts@base': 'OLD', 'a/b:err.ts@head': httpError(500) });
    const files = [file('a.ts'), file('gone.ts', {}, { status: 'removed', previousFilename: 'old.ts' }), file('err.ts')];
    const debug = vi.fn();
    await readFileContents(octokit, { owner: 'a', repo: 'b' }, [
      { file: files[0]!, version: 'head' },
      { file: files[1]!, version: 'base' },
      { file: files[2]!, version: 'head' },
    ], { head: 'head', base: 'base' }, debug, 2);
    expect(files.map((f) => f.content)).toEqual(['A', 'OLD', undefined]);
    expect(debug).toHaveBeenCalledWith(expect.stringContaining('Could not read err.ts@head'));
  });
});

describe('teams', () => {
  it('parses team references with or without an organisation', () => {
    expect(parseTeam('security', 'acme')).toEqual({ org: 'acme', slug: 'security' });
    expect(parseTeam('@other/sec', 'acme')).toEqual({ org: 'other', slug: 'sec' });
  });

  it('formats mentions without notifying anyone from code spans', () => {
    expect(mentions({ teams: ['security'], users: ['@alice', 'bob'] }, 'acme')).toEqual(['`@acme/security`', '`@alice`', '`@bob`']);
  });
});

describe('Authorizer', () => {
  const membership = (members: Record<string, string>, error?: Error) => {
    const getMembershipForUserInOrg = vi.fn(async ({ org, team_slug, username }: { org: string; team_slug: string; username: string }) => {
      if (error) throw error;
      const state = members[`${org}/${team_slug}:${username}`];
      if (!state) throw httpError(404);
      return { data: { state } };
    });
    return { octokit: fakeOctokit({ teams: { getMembershipForUserInOrg } }), getMembershipForUserInOrg };
  };

  it('accepts listed users case-insensitively without API calls', async () => {
    const { octokit, getMembershipForUserInOrg } = membership({});
    const authorizer = new Authorizer(octokit, 'acme', vi.fn());
    expect(await authorizer.isAuthorized('Alice', { teams: [], users: ['@alice'] })).toBe(true);
    expect(getMembershipForUserInOrg).not.toHaveBeenCalled();
  });

  it('only counts active team members, and caches lookups', async () => {
    const { octokit, getMembershipForUserInOrg } = membership({ 'acme/security:alice': 'active', 'acme/security:pat': 'pending' });
    const authorizer = new Authorizer(octokit, 'acme', vi.fn());
    const principals = { teams: ['security'], users: [] };
    expect(await authorizer.isAuthorized('alice', principals)).toBe(true);
    expect(await authorizer.isAuthorized('alice', principals)).toBe(true);
    expect(await authorizer.isAuthorized('pat', principals)).toBe(false);
    expect(await authorizer.isAuthorized('mallory', principals)).toBe(false);
    expect(getMembershipForUserInOrg).toHaveBeenCalledTimes(3);
  });

  it('denies and warns once when membership cannot be checked', async () => {
    const warn = vi.fn();
    const authorizer = new Authorizer(membership({}, httpError(403)).octokit, 'acme', warn);
    expect(await authorizer.isAuthorized('alice', { teams: ['security', 'leads'], users: [] })).toBe(false);
    expect(await authorizer.isAuthorized('bob', { teams: ['security'], users: [] })).toBe(false);
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('org-token'));
  });
});

describe('ChangeTracker', () => {
  const ref = { owner: 'a', repo: 'b' };
  const compare = (data: unknown, error?: Error) => {
    const compareCommitsWithBasehead = vi.fn(async () => {
      if (error) throw error;
      return { data };
    });
    return { octokit: fakeOctokit({ repos: { compareCommitsWithBasehead } }), compareCommitsWithBasehead };
  };
  const tracker = (octokit: Octokit, mode: 'flagged-changes' | 'any-change' = 'flagged-changes') =>
    new ChangeTracker(octokit, ref, 'head', new Set(['src/auth/login.ts', 'src/auth/old.ts']), mode);

  it('accepts the head commit without an API call', async () => {
    const { octokit, compareCommitsWithBasehead } = compare({});
    expect(await tracker(octokit).unchangedSince('head')).toEqual({ ok: true });
    expect(compareCommitsWithBasehead).not.toHaveBeenCalled();
  });

  it('invalidates on any new commit in any-change mode', async () => {
    expect(await tracker(compare({}).octokit, 'any-change').unchangedSince('old')).toEqual({ ok: false, reason: 'new commits were pushed' });
  });

  it('stays valid when only unflagged files changed, and caches the comparison', async () => {
    const { octokit, compareCommitsWithBasehead } = compare({ status: 'ahead', files: [{ filename: 'src/ui/a.tsx' }] });
    const changes = tracker(octokit);
    expect(await changes.unchangedSince('old')).toEqual({ ok: true });
    await changes.unchangedSince('old');
    expect(compareCommitsWithBasehead).toHaveBeenCalledTimes(1);
    expect(compareCommitsWithBasehead).toHaveBeenCalledWith(expect.objectContaining({ basehead: 'old...head' }));
  });

  it('is invalidated by changes to flagged files, including renames away from them', async () => {
    const changed = await tracker(compare({ status: 'ahead', files: [{ filename: 'src/auth/login.ts' }] }).octokit).unchangedSince('old');
    expect(changed).toEqual({ ok: false, reason: 'flagged files changed afterwards (src/auth/login.ts)' });
    const renamed = await tracker(compare({ status: 'ahead', files: [{ filename: 'src/ui/x.ts', previous_filename: 'src/auth/old.ts' }] }).octokit).unchangedSince('old');
    expect(renamed.ok).toBe(false);
  });

  it('fails closed on rewritten history, oversized comparisons and API errors', async () => {
    expect(await tracker(compare({ status: 'diverged', files: [] }).octokit).unchangedSince('old')).toEqual({ ok: false, reason: 'the branch history was rewritten' });
    const many = Array.from({ length: 300 }, (_, i) => ({ filename: `f${i}` }));
    expect(await tracker(compare({ status: 'ahead', files: many }).octokit).unchangedSince('old')).toEqual({ ok: false, reason: 'too many files changed to verify' });
    expect(await tracker(compare({}, httpError(404)).octokit).unchangedSince('old')).toEqual({ ok: false, reason: 'could not compare commits (HTTP 404)' });
  });
});
