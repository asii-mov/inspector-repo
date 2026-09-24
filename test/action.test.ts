import { execFile } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { build } from 'esbuild';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

/**
 * Runs the bundled action against an in-memory fake of the GitHub REST API and checks the whole
 * flow: flagging, the report comment, the commit status, labels, review requests, bypass and approval.
 */

const HEAD = 'headsha0000000000000000000000000000000001';
const BASE = 'basesha0000000000000000000000000000000001';

const POLICY = `
settings:
  securityTeam: { teams: [security], users: [] }
  bypass: { teams: [leads], minReasonLength: 10 }
  when: { baseBranches: [main] }
rules:
  - id: auth
    name: Authentication
    severity: critical
    guidance: Check the password comparison.
    match: any
    paths: ["src/auth/**"]
    fileContent: ['from "passport"']
`;

interface Comment {
  id: number;
  user: { login: string };
  body: string;
  created_at: string;
  updated_at: string;
}

class FakeGitHub {
  comments: Comment[] = [];
  reviews: { id: number; user: { login: string }; state: string; commit_id: string }[] = [];
  labels: string[] = [];
  statuses: { state: string; description: string; context: string; sha: string }[] = [];
  requestedReviewers: unknown[] = [];
  reactions: string[] = [];
  files = [
    { filename: 'src/auth/login.ts', status: 'modified', additions: 1, deletions: 1, sha: 'blob1', patch: '@@ -1,2 +1,2 @@\n export function check(pw, hash) {\n-  return bcrypt.compare(pw, hash);\n+  return pw === hash;' },
    { filename: 'src/ui/Button.tsx', status: 'modified', additions: 1, deletions: 1, sha: 'blob2', patch: '@@ -1 +1 @@\n-<b>Save</b>\n+<i>Save</i>' },
  ];
  teams: Record<string, string[]> = { security: ['sec-alice'], leads: ['lead-lena'] };
  baseRef = 'main';
  /** Files served by the contents API at the head commit. */
  headContents: Record<string, string> = { 'src/ui/Button.tsx': 'export const Button = () => <i>Save</i>;\n' };
  contentReads: string[] = [];
  private nextId = 100;
  private clock = Date.parse('2026-01-01T10:00:00Z');

  now(): string {
    this.clock += 60_000;
    return new Date(this.clock).toISOString();
  }

  addComment(user: string, body: string): Comment {
    const at = this.now();
    const comment = { id: this.nextId++, user: { login: user }, body, created_at: at, updated_at: at, html_url: `https://github.test/c/${this.nextId}` };
    this.comments.push(comment);
    return comment;
  }

  handle(method: string, path: string, body: any): [number, unknown] {
    const url = new URL(path, 'http://x');
    const route = `${method} ${decodeURIComponent(url.pathname)}`;
    let m: RegExpMatchArray | null;
    if (route === 'GET /repos/acme/web/pulls/1') {
      return [200, { number: 1, state: 'open', html_url: 'https://github.test/acme/web/pull/1', changed_files: this.files.length, user: { login: 'dev' }, head: { sha: HEAD, ref: 'feature' }, base: { sha: BASE, ref: this.baseRef }, labels: this.labels.map((name) => ({ name })), requested_reviewers: [], requested_teams: [] }];
    }
    if (route === 'GET /repos/acme/web/contents/.github/security-inspector.yml') {
      if (url.searchParams.get('ref') !== BASE) return [500, { message: 'policy must be read from the base commit' }];
      return [200, { type: 'file', encoding: 'base64', content: Buffer.from(POLICY).toString('base64') }];
    }
    if ((m = route.match(/^GET \/repos\/acme\/web\/contents\/(.+)$/))) {
      const path = m[1]!;
      this.contentReads.push(`${path}@${url.searchParams.get('ref')}`);
      const content = url.searchParams.get('ref') === HEAD ? this.headContents[path] : undefined;
      return content === undefined ? [404, { message: 'Not Found' }] : [200, { type: 'file', encoding: 'base64', content: Buffer.from(content).toString('base64') }];
    }
    if (route === 'GET /repos/acme/web/pulls/1/files') return [200, this.files];
    if (route === 'GET /repos/acme/web/issues/1/comments') return [200, this.comments];
    if (route === 'GET /repos/acme/web/pulls/1/reviews') return [200, this.reviews];
    if (route === 'POST /repos/acme/web/issues/1/comments') return [201, this.addComment('github-actions[bot]', body.body)];
    if ((m = route.match(/^PATCH \/repos\/acme\/web\/issues\/comments\/(\d+)$/))) {
      const comment = this.comments.find((c) => c.id === Number(m![1]))!;
      comment.body = body.body;
      comment.updated_at = this.now();
      return [200, comment];
    }
    if ((m = route.match(/^POST \/repos\/acme\/web\/statuses\/(\w+)$/))) {
      this.statuses.push({ ...body, sha: m[1] });
      return [201, {}];
    }
    if (route === 'POST /repos/acme/web/issues/1/labels') {
      this.labels.push(...body.labels);
      return [200, []];
    }
    if ((m = route.match(/^DELETE \/repos\/acme\/web\/issues\/1\/labels\/(.+)$/))) {
      this.labels = this.labels.filter((label) => label !== decodeURIComponent(m![1]!));
      return [200, []];
    }
    if (route === 'POST /repos/acme/web/pulls/1/requested_reviewers') {
      this.requestedReviewers.push(body);
      return [201, {}];
    }
    if ((m = route.match(/^GET \/orgs\/acme\/teams\/(\w+)\/memberships\/(.+)$/))) {
      return this.teams[m[1]!]?.includes(m[2]!) ? [200, { state: 'active' }] : [404, { message: 'Not Found' }];
    }
    if ((m = route.match(/^POST \/repos\/acme\/web\/issues\/comments\/(\d+)\/reactions$/))) {
      this.reactions.push(body.content);
      return [201, {}];
    }
    return [404, { message: `unhandled ${route}` }];
  }
}

let server: Server;
let fake: FakeGitHub;
let apiUrl: string;
let workdir: string;
let bundle: string;

beforeAll(async () => {
  workdir = mkdtempSync(join(tmpdir(), 'security-inspector-'));
  bundle = join(workdir, 'index.mjs');
  await build({
    entryPoints: ['src/action/main.ts'],
    bundle: true,
    platform: 'node',
    format: 'esm',
    outfile: bundle,
    logLevel: 'silent',
    banner: { js: "import { createRequire as __cr } from 'node:module'; const require = __cr(import.meta.url);" },
  });
  server = createServer((req: IncomingMessage, res: ServerResponse) => {
    let raw = '';
    req.on('data', (chunk) => (raw += chunk));
    req.on('end', () => {
      const [status, payload] = fake.handle(req.method!, req.url!, raw ? JSON.parse(raw) : undefined);
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(JSON.stringify(payload));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  apiUrl = `http://127.0.0.1:${typeof address === 'object' && address ? address.port : 0}`;
});

afterAll(() => server?.close());
beforeEach(() => {
  fake = new FakeGitHub();
});

async function runAction(eventName: string, payload: object): Promise<{ stdout: string; outputs: string }> {
  const eventPath = join(workdir, `event-${Date.now()}.json`);
  const outputPath = join(workdir, `output-${Date.now()}`);
  const summaryPath = join(workdir, `summary-${Date.now()}`);
  writeFileSync(eventPath, JSON.stringify(payload));
  writeFileSync(outputPath, '');
  writeFileSync(summaryPath, '');
  const env = {
    PATH: process.env.PATH,
    GITHUB_API_URL: apiUrl,
    GITHUB_SERVER_URL: 'https://github.test',
    GITHUB_REPOSITORY: 'acme/web',
    GITHUB_EVENT_NAME: eventName,
    GITHUB_EVENT_PATH: eventPath,
    GITHUB_OUTPUT: outputPath,
    GITHUB_STEP_SUMMARY: summaryPath,
    GITHUB_RUN_ID: '42',
    GITHUB_WORKFLOW_REF: 'acme/web/.github/workflows/security.yml@refs/heads/main',
    'INPUT_GITHUB-TOKEN': 'test-token',
    'INPUT_FAIL-ON-BLOCK': 'false',
    NO_PROXY: '127.0.0.1',
    no_proxy: '127.0.0.1',
  };
  const stdout = await new Promise<string>((resolve, reject) => {
    execFile(process.execPath, [bundle], { env }, (error, out, err) => (error ? reject(new Error(`${error.message}\n${out}\n${err}`)) : resolve(out)));
  });
  return { stdout, outputs: readFileSync(outputPath, 'utf8') };
}

const prEvent = { action: 'opened', pull_request: { number: 1 } };
const commentEvent = (comment: Comment) => ({ action: 'created', issue: { number: 1, pull_request: {} }, comment });

describe('GitHub Action', () => {
  it('blocks a pull request that changes authentication and explains why', async () => {
    const { outputs } = await runAction('pull_request_target', prEvent);

    expect(fake.statuses.at(-1)).toMatchObject({ sha: HEAD, state: 'failure', context: 'Security Inspector', description: 'Security review required: Authentication (0/1 approvals)' });
    expect(fake.labels).toEqual(['security-review-required']);
    expect(fake.requestedReviewers).toEqual([{ reviewers: [], team_reviewers: ['security'] }]);
    const report = fake.comments.find((c) => c.body.startsWith('<!-- security-inspector:report -->'))!;
    expect(report.body).toContain('src/auth/login.ts');
    expect(report.body).not.toContain('Button.tsx');
    expect(report.body).toContain('+  return pw === hash;');
    expect(outputs).toContain('blocked');
  });

  it('passes UI-only pull requests without commenting', async () => {
    fake.files = fake.files.filter((f) => f.filename.startsWith('src/ui'));
    await runAction('pull_request_target', prEvent);
    expect(fake.statuses.at(-1)).toMatchObject({ state: 'success', description: 'No security-critical components modified' });
    expect(fake.comments).toEqual([]);
  });

  it('records an authorised bypass, and ignores unauthorised ones', async () => {
    await runAction('pull_request_target', prEvent);

    const denied = fake.addComment('dev', '/security-bypass trust me, it is fine');
    await runAction('issue_comment', commentEvent(denied));
    expect(fake.statuses.at(-1)!.state).toBe('failure');
    expect(fake.comments.at(-1)!.body).toContain('authors cannot bypass');

    const command = fake.addComment('lead-lena', '/security-bypass false positive, only a rename');
    await runAction('issue_comment', commentEvent(command));
    expect(fake.comments.at(-1)!.body).toContain('Security review bypassed** by @lead-lena');
    expect(fake.statuses.at(-1)).toMatchObject({ state: 'success', description: 'Bypassed by @lead-lena: false positive, only a rename' });
    expect(fake.labels).toEqual(['security-bypassed']);
    expect(fake.reactions).toEqual(['-1', '+1']);

    // The bypass is remembered on the next push, as long as the flagged files are unchanged.
    await runAction('pull_request_target', { action: 'synchronize', pull_request: { number: 1 } });
    expect(fake.statuses.at(-1)!.state).toBe('success');

    // Deleting the command comment revokes the bypass.
    fake.comments = fake.comments.filter((c) => c.id !== command.id);
    await runAction('pull_request_target', { action: 'synchronize', pull_request: { number: 1 } });
    expect(fake.statuses.at(-1)!.state).toBe('failure');
  });

  it('passes once a security team member approves', async () => {
    await runAction('pull_request_target', prEvent);
    fake.reviews.push({ id: 1, user: { login: 'random-dev' }, state: 'APPROVED', commit_id: HEAD });
    await runAction('pull_request_review', { action: 'submitted', pull_request: { number: 1 } });
    expect(fake.statuses.at(-1)!.state).toBe('failure');

    fake.reviews.push({ id: 2, user: { login: 'sec-alice' }, state: 'APPROVED', commit_id: HEAD });
    await runAction('pull_request_review', { action: 'submitted', pull_request: { number: 1 } });
    expect(fake.statuses.at(-1)).toMatchObject({ state: 'success', description: 'Security review approved by @sec-alice' });
    expect(fake.labels).toEqual(['security-approved']);
    const report = fake.comments.find((c) => c.body.startsWith('<!-- security-inspector:report -->'))!;
    expect(report.body).toContain('security review approved');
    expect(fake.comments.filter((c) => c.body.startsWith('<!-- security-inspector:report -->'))).toHaveLength(1);
  });

  it('flags any change to a file that is authentication code, reading it at the head commit', async () => {
    fake.files = [{ filename: 'src/server/routes.ts', status: 'modified', additions: 1, deletions: 1, sha: 'blob3', patch: '@@ -2 +2 @@\n-router.get("/profile", h);\n+router.get("/me", h);' }];
    fake.headContents['src/server/routes.ts'] = 'import passport from "passport";\nrouter.get("/me", h);\n';
    await runAction('pull_request_target', prEvent);
    expect(fake.contentReads).toEqual([`src/server/routes.ts@${HEAD}`]);
    expect(fake.statuses.at(-1)).toMatchObject({ state: 'failure', description: 'Security review required: Authentication (0/1 approvals)' });
    const report = fake.comments.find((c) => c.body.startsWith('<!-- security-inspector:report -->'))!;
    expect(report.body).toContain('file contains `from "passport"` (line 1)');
  });

  it('only inspects pull requests into the configured branches, and re-checks when retargeted', async () => {
    fake.baseRef = 'dev';
    await runAction('pull_request_target', prEvent);
    expect(fake.statuses.at(-1)).toMatchObject({ state: 'success', description: expect.stringContaining('Not applicable: the pull request targets dev') });
    expect(fake.comments).toEqual([]);

    // Retargeting the pull request to main makes the policy apply.
    fake.baseRef = 'main';
    await runAction('pull_request_target', { action: 'edited', changes: { base: { ref: { from: 'dev' } } }, pull_request: { number: 1 } });
    expect(fake.statuses.at(-1)!.state).toBe('failure');
    expect(fake.labels).toEqual(['security-review-required']);

    // And back to dev: status passes, the label goes and the report says why.
    fake.baseRef = 'dev';
    await runAction('pull_request_target', { action: 'edited', changes: { base: { ref: { from: 'main' } } }, pull_request: { number: 1 } });
    expect(fake.statuses.at(-1)!.state).toBe('success');
    expect(fake.labels).toEqual([]);
    expect(fake.comments.find((c) => c.body.startsWith('<!-- security-inspector:report -->'))!.body).toContain('not applicable to this pull request');
  });

  it('ignores comments that are not commands', async () => {
    const chatter = fake.addComment('dev', 'LGTM');
    const { stdout } = await runAction('issue_comment', commentEvent(chatter));
    expect(stdout).toContain('Nothing to do');
    expect(fake.statuses).toEqual([]);
  });
});
