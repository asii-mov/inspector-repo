import type * as github from '@actions/github';
import { parsePatch } from '../diff/parse.js';
import type { ChangedFile, FileStatus } from '../diff/types.js';
import type { Principals } from '../policy/schema.js';

export type Octokit = ReturnType<typeof github.getOctokit>;

export interface RepoRef {
  owner: string;
  repo: string;
}

export function httpStatus(error: unknown): number | undefined {
  return typeof error === 'object' && error !== null && 'status' in error && typeof error.status === 'number' ? error.status : undefined;
}

/** GitHub caps the "list pull request files" endpoint at 3000 files. */
export const MAX_PULL_REQUEST_FILES = 3000;

export async function listPullRequestFiles(octokit: Octokit, ref: RepoRef, pullNumber: number): Promise<ChangedFile[]> {
  const files = await octokit.paginate(octokit.rest.pulls.listFiles, { ...ref, pull_number: pullNumber, per_page: 100 });
  return files.map((file) => {
    const hasChanges = file.additions + file.deletions > 0;
    return {
      filename: file.filename,
      previousFilename: file.previous_filename,
      status: file.status as FileStatus,
      additions: file.additions,
      deletions: file.deletions,
      sha: file.sha ?? undefined,
      hunks: file.patch ? parsePatch(file.patch) : [],
      // GitHub omits the patch for binary files and very large diffs.
      patchAvailable: file.patch !== undefined || !hasChanges,
    };
  });
}

/**
 * Reads the full content of changed files for `fileContent` rules and stores it on each file.
 * Files that cannot be read (too large, binary, errors) are left without content; the scanner
 * reports them.
 */
export async function readFileContents(
  octokit: Octokit,
  ref: RepoRef,
  requests: { file: ChangedFile; version: 'head' | 'base' }[],
  shas: { head: string; base: string },
  debug: (message: string) => void,
  concurrency = 8,
): Promise<void> {
  let next = 0;
  const worker = async () => {
    while (next < requests.length) {
      const { file, version } = requests[next++]!;
      const path = version === 'base' ? (file.previousFilename ?? file.filename) : file.filename;
      try {
        file.content = await readRepositoryFile(octokit, ref, path, shas[version]);
      } catch (error) {
        debug(`Could not read ${path}@${version}: ${(error as Error).message}`);
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, requests.length) }, worker));
}

/** Reads a text file from a repository, or returns undefined if it does not exist. */
export async function readRepositoryFile(octokit: Octokit, ref: RepoRef, path: string, gitRef?: string): Promise<string | undefined> {
  try {
    const { data } = await octokit.rest.repos.getContent({ ...ref, path, ref: gitRef || undefined });
    if (Array.isArray(data) || data.type !== 'file') throw new Error(`${ref.owner}/${ref.repo}:${path} is not a file`);
    if ('content' in data && typeof data.content === 'string' && data.encoding === 'base64') {
      return Buffer.from(data.content, 'base64').toString('utf8');
    }
    throw new Error(`${ref.owner}/${ref.repo}:${path} could not be decoded`);
  } catch (error) {
    if (httpStatus(error) === 404) return undefined;
    throw error;
  }
}

/** Checks whether users belong to a set of teams/users, caching team membership lookups. */
export class Authorizer {
  private readonly cache = new Map<string, Promise<boolean>>();
  private warnedAboutPermissions = false;

  constructor(
    private readonly octokit: Octokit,
    private readonly defaultOrg: string,
    private readonly warn: (message: string) => void,
  ) {}

  async isAuthorized(user: string, principals: Principals): Promise<boolean> {
    const login = user.toLowerCase();
    if (principals.users.some((candidate) => candidate.replace(/^@/, '').toLowerCase() === login)) return true;
    for (const team of principals.teams) {
      if (await this.isTeamMember(team, user)) return true;
    }
    return false;
  }

  private isTeamMember(team: string, user: string): Promise<boolean> {
    const { org, slug } = parseTeam(team, this.defaultOrg);
    const key = `${org}/${slug}:${user}`.toLowerCase();
    let result = this.cache.get(key);
    if (!result) {
      result = this.lookup(org, slug, user);
      this.cache.set(key, result);
    }
    return result;
  }

  private async lookup(org: string, slug: string, user: string): Promise<boolean> {
    try {
      const { data } = await this.octokit.rest.teams.getMembershipForUserInOrg({ org, team_slug: slug, username: user });
      return data.state === 'active';
    } catch (error) {
      const status = httpStatus(error);
      if (status === 404) return false;
      if (!this.warnedAboutPermissions) {
        this.warnedAboutPermissions = true;
        this.warn(
          `Could not check membership of team ${org}/${slug} (HTTP ${status ?? 'error'}). ` +
            'The default GITHUB_TOKEN cannot read team membership: pass an `org-token` with "Members: read" organisation permission, or list users explicitly.',
        );
      }
      return false;
    }
  }
}

export function parseTeam(team: string, defaultOrg: string): { org: string; slug: string } {
  const cleaned = team.replace(/^@/, '');
  const slash = cleaned.indexOf('/');
  return slash === -1 ? { org: defaultOrg, slug: cleaned } : { org: cleaned.slice(0, slash), slug: cleaned.slice(slash + 1) };
}

export function mentions(principals: Principals, defaultOrg: string): string[] {
  const teams = principals.teams.map((team) => {
    const { org, slug } = parseTeam(team, defaultOrg);
    return `\`@${org}/${slug}\``;
  });
  const users = principals.users.map((user) => `\`@${user.replace(/^@/, '')}\``);
  return [...teams, ...users];
}

export type StalenessMode = 'flagged-changes' | 'any-change';

/**
 * Decides whether an approval or bypass given at an older commit still applies to the head:
 * it does unless a flagged file changed in between (or, in `any-change` mode, anything did).
 */
export class ChangeTracker {
  private readonly cache = new Map<string, Promise<{ ok: boolean; reason?: string }>>();

  constructor(
    private readonly octokit: Octokit,
    private readonly ref: RepoRef,
    private readonly headSha: string,
    private readonly flaggedPaths: Set<string>,
    private readonly mode: StalenessMode,
  ) {}

  unchangedSince(sha: string): Promise<{ ok: boolean; reason?: string }> {
    let result = this.cache.get(sha);
    if (!result) {
      result = this.compare(sha);
      this.cache.set(sha, result);
    }
    return result;
  }

  private async compare(sha: string): Promise<{ ok: boolean; reason?: string }> {
    if (sha === this.headSha) return { ok: true };
    if (this.mode === 'any-change') return { ok: false, reason: 'new commits were pushed' };
    try {
      const { data } = await this.octokit.rest.repos.compareCommitsWithBasehead({ ...this.ref, basehead: `${sha}...${this.headSha}`, per_page: 300 });
      if (data.status !== 'ahead' && data.status !== 'identical') return { ok: false, reason: 'the branch history was rewritten' };
      const files = data.files ?? [];
      if (files.length >= 300) return { ok: false, reason: 'too many files changed to verify' };
      const touched = files
        .filter((file) => this.flaggedPaths.has(file.filename) || (file.previous_filename && this.flaggedPaths.has(file.previous_filename)))
        .map((file) => file.filename);
      return touched.length === 0 ? { ok: true } : { ok: false, reason: `flagged files changed afterwards (${touched.slice(0, 3).join(', ')}${touched.length > 3 ? ', …' : ''})` };
    } catch (error) {
      return { ok: false, reason: `could not compare commits (HTTP ${httpStatus(error) ?? 'error'})` };
    }
  }
}
