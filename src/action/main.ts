import * as core from '@actions/core';
import * as github from '@actions/github';
import { encodeBypassRecord, parseCommand, REPORT_MARKER } from '../engine/bypass.js';
import { evaluate, type Decision } from '../engine/evaluate.js';
import { resolveRepositoryProfile } from '../engine/priority.js';
import { blockingPaths, contentRequests, scan, type ScanOptions, type ScanResult } from '../engine/scan.js';
import { bypassPrincipals, checkBypassCommand, collectApprovals, findBypass, type CommentData } from '../engine/signoff.js';
import { PolicyError } from '../policy/load.js';
import type { Settings } from '../policy/schema.js';
import { renderReport } from '../report/markdown.js';
import {
  Authorizer,
  ChangeTracker,
  httpStatus,
  listPullRequestFiles,
  MAX_PULL_REQUEST_FILES,
  readFileContents,
  mentions,
  parseTeam,
  type Octokit,
  type RepoRef,
} from '../github/api.js';
import { loadPolicy } from '../github/policy.js';

interface Inputs {
  githubToken: string;
  orgToken: string;
  policyRepository: string;
  policyRef: string;
  policyPath: string;
  localConfigPath: string;
  statusContext: string;
  botLogin: string;
  blockedState: 'failure' | 'pending';
  failOnBlock: boolean;
  pullRequestNumber: string;
}

function readInputs(): Inputs {
  const blockedState = core.getInput('blocked-state') || 'failure';
  if (blockedState !== 'failure' && blockedState !== 'pending') throw new Error('`blocked-state` must be "failure" or "pending"');
  return {
    githubToken: core.getInput('github-token', { required: true }),
    orgToken: core.getInput('org-token'),
    policyRepository: core.getInput('policy-repository'),
    policyRef: core.getInput('policy-ref'),
    policyPath: core.getInput('policy-path') || 'security-inspector-policy.yml',
    localConfigPath: core.getInput('local-config-path') || '.github/security-inspector.yml',
    statusContext: core.getInput('status-context') || 'Security Inspector',
    botLogin: core.getInput('bot-login') || 'github-actions[bot]',
    blockedState,
    failOnBlock: core.getBooleanInput('fail-on-block'),
    pullRequestNumber: core.getInput('pull-request-number'),
  };
}

interface Trigger {
  pullNumber: number;
  /** Set when the run was triggered by a pull request comment. */
  comment?: CommentData;
  /** True for events where the PR's contents changed, so reviewers may be requested. */
  contentChanged: boolean;
}

function resolveTrigger(inputs: Inputs): Trigger | undefined {
  const { context } = github;
  const payload = context.payload;
  if (inputs.pullRequestNumber) {
    return { pullNumber: Number(inputs.pullRequestNumber), contentChanged: false };
  }
  switch (context.eventName) {
    case 'pull_request':
    case 'pull_request_target':
      if (!payload.pull_request) return undefined;
      // `edited` matters when the base branch changes: the diff and any `when` conditions change with it.
      return {
        pullNumber: payload.pull_request.number,
        contentChanged: ['opened', 'reopened', 'synchronize', 'ready_for_review', 'edited'].includes(payload.action ?? ''),
      };
    case 'pull_request_review':
      if (!payload.pull_request) return undefined;
      return { pullNumber: payload.pull_request.number, contentChanged: false };
    case 'issue_comment': {
      const comment = payload.comment;
      if (!payload.issue?.pull_request || !comment || payload.action !== 'created') return undefined;
      const body = String(comment.body ?? '');
      if (!body.trim().startsWith('/')) return undefined;
      return {
        pullNumber: payload.issue.number,
        contentChanged: false,
        comment: { id: comment.id, user: comment.user.login, body, createdAt: comment.created_at, updatedAt: comment.updated_at },
      };
    }
    default:
      return undefined;
  }
}

/** Path of the workflow file running this action, so the integrity rule can protect it. */
function currentWorkflowPath(ref: RepoRef): string | undefined {
  const workflowRef = process.env.GITHUB_WORKFLOW_REF;
  const prefix = `${ref.owner}/${ref.repo}/`;
  if (!workflowRef?.toLowerCase().startsWith(prefix.toLowerCase())) return undefined;
  return workflowRef.slice(prefix.length).split('@')[0];
}

function toComment(comment: { id: number; user: { login: string } | null; body?: string; created_at: string; updated_at: string }): CommentData {
  return { id: comment.id, user: comment.user?.login ?? '', body: comment.body ?? '', createdAt: comment.created_at, updatedAt: comment.updated_at };
}

async function react(octokit: Octokit, ref: RepoRef, commentId: number, content: '+1' | '-1' | 'eyes'): Promise<void> {
  try {
    await octokit.rest.reactions.createForIssueComment({ ...ref, comment_id: commentId, content });
  } catch (error) {
    core.debug(`Could not react to comment ${commentId}: ${(error as Error).message}`);
  }
}

async function setStatus(octokit: Octokit, ref: RepoRef, sha: string, inputs: Inputs, state: 'success' | 'failure' | 'pending' | 'error', description: string, targetUrl?: string) {
  await octokit.rest.repos.createCommitStatus({
    ...ref,
    sha,
    state,
    context: inputs.statusContext,
    description: description.slice(0, 140),
    target_url: targetUrl,
  });
}

async function upsertReport(
  octokit: Octokit,
  ref: RepoRef,
  pull: { number: number; html_url: string },
  comments: CommentData[],
  inputs: Inputs,
  body: string,
  shouldCreate: boolean,
): Promise<string | undefined> {
  const existing = comments.find((comment) => comment.user.toLowerCase() === inputs.botLogin.toLowerCase() && comment.body.startsWith(REPORT_MARKER));
  if (existing) {
    if (existing.body !== body) await octokit.rest.issues.updateComment({ ...ref, comment_id: existing.id, body });
    return `${pull.html_url}#issuecomment-${existing.id}`;
  }
  if (!shouldCreate) return undefined;
  const { data } = await octokit.rest.issues.createComment({ ...ref, issue_number: pull.number, body });
  return data.html_url;
}

async function syncLabels(octokit: Octokit, ref: RepoRef, pullNumber: number, current: string[], settings: Settings, decision: Decision) {
  const { reviewRequired, approved, bypassed } = settings.labels;
  const wanted = new Map<string | false, boolean>([
    [reviewRequired, decision.state === 'blocked'],
    [approved, decision.state === 'approved'],
    [bypassed, decision.state === 'bypassed'],
  ]);
  const add: string[] = [];
  for (const [label, want] of wanted) {
    if (label === false) continue;
    const has = current.includes(label);
    if (want && !has) add.push(label);
    if (!want && has) await octokit.rest.issues.removeLabel({ ...ref, issue_number: pullNumber, name: label });
  }
  if (add.length > 0) await octokit.rest.issues.addLabels({ ...ref, issue_number: pullNumber, labels: add });
}

async function requestSecurityReview(
  octokit: Octokit,
  ref: RepoRef,
  pull: { number: number; user: { login: string } | null; requested_reviewers?: ({ login: string } | null)[] | null; requested_teams?: ({ slug: string } | null)[] | null },
  settings: Settings,
  decision: Decision,
) {
  const author = pull.user?.login.toLowerCase();
  const approvedBy = new Set(decision.validApprovals.map((approval) => approval.user.toLowerCase()));
  const alreadyUsers = new Set((pull.requested_reviewers ?? []).map((user) => user?.login.toLowerCase()));
  const alreadyTeams = new Set((pull.requested_teams ?? []).map((team) => team?.slug.toLowerCase()));

  const reviewers = settings.securityTeam.users
    .map((user) => user.replace(/^@/, ''))
    .filter((user) => user.toLowerCase() !== author && !approvedBy.has(user.toLowerCase()) && !alreadyUsers.has(user.toLowerCase()));
  const teamReviewers = settings.securityTeam.teams
    .map((team) => parseTeam(team, ref.owner))
    .filter(({ org, slug }) => org.toLowerCase() === ref.owner.toLowerCase() && !alreadyTeams.has(slug.toLowerCase()))
    .map(({ slug }) => slug);
  if (reviewers.length === 0 && teamReviewers.length === 0) return;
  await octokit.rest.pulls.requestReviewers({ ...ref, pull_number: pull.number, reviewers, team_reviewers: teamReviewers });
}

function bypassAcknowledgement(scanResult: ScanResult, recordMarker: string, user: string, reason: string, sha: string): string {
  const components = scanResult.blocking.map((finding) => `**${finding.rule.name}**`).join(', ');
  return [
    `⚠️ **Security review bypassed** by @${user} for commit \`${sha.slice(0, 7)}\`.`,
    '',
    `> ${reason.replace(/\r?\n/g, '\n> ')}`,
    '',
    `Covered components: ${components}. The bypass stops applying if the flagged files change. Delete the command comment to revoke it.`,
    '',
    recordMarker,
  ].join('\n');
}

async function tryWrite(what: string, action: () => Promise<unknown>): Promise<boolean> {
  try {
    await action();
    return true;
  } catch (error) {
    const status = httpStatus(error);
    const hint = status === 403 ? ' The token lacks write access (pull requests from forks get a read-only token with `pull_request`; use `pull_request_target`).' : '';
    core.warning(`Could not ${what}: ${(error as Error).message}.${hint}`);
    return false;
  }
}

async function run(): Promise<void> {
  const inputs = readInputs();
  const trigger = resolveTrigger(inputs);
  if (!trigger) {
    core.info(`Nothing to do for event "${github.context.eventName}".`);
    return;
  }

  const ref: RepoRef = github.context.repo;
  const repository = `${ref.owner}/${ref.repo}`;
  const octokit = github.getOctokit(inputs.githubToken);
  const orgOctokit = inputs.orgToken ? github.getOctokit(inputs.orgToken) : octokit;

  if (trigger.comment && trigger.comment.user.toLowerCase() === inputs.botLogin.toLowerCase()) return;

  const { data: pull } = await octokit.rest.pulls.get({ ...ref, pull_number: trigger.pullNumber });
  if (pull.state !== 'open') {
    core.info(`Pull request #${pull.number} is ${pull.state}; skipping.`);
    return;
  }
  const headSha = pull.head.sha;
  const author = pull.user?.login ?? '';

  let loaded;
  try {
    loaded = await loadPolicy({
      location: {
        policyRepository: inputs.policyRepository || undefined,
        policyRef: inputs.policyRef || undefined,
        policyPath: inputs.policyPath,
        localConfigPath: inputs.localConfigPath,
      },
      policyOctokit: orgOctokit,
      repoOctokit: octokit,
      repository: ref,
      baseSha: pull.base.sha,
    });
  } catch (error) {
    if (error instanceof PolicyError) {
      await tryWrite('set commit status', () => setStatus(octokit, ref, headSha, inputs, 'error', 'Security policy could not be loaded; see workflow logs'));
    }
    throw error;
  }
  const { policy } = loaded;
  const settings = policy.settings;
  loaded.warnings.forEach((warning) => core.warning(warning));

  // A comment that is not one of our commands needs no work.
  const isBypass = trigger.comment && parseCommand(trigger.comment.body, settings.bypass.command) !== undefined;
  const isRecheck = trigger.comment && parseCommand(trigger.comment.body, settings.recheckCommand) !== undefined;
  if (trigger.comment && !isBypass && !isRecheck) {
    core.info('Comment is not a Security Inspector command; skipping.');
    return;
  }

  const profile = resolveRepositoryProfile(policy, repository);
  const files = await listPullRequestFiles(octokit, ref, pull.number);
  if (pull.changed_files > MAX_PULL_REQUEST_FILES) {
    core.warning(`This pull request changes ${pull.changed_files} files; GitHub only lists the first ${MAX_PULL_REQUEST_FILES}, the rest were not inspected.`);
  }
  const scanOptions: ScanOptions = {
    integrityPaths: [inputs.localConfigPath, currentWorkflowPath(ref)].filter((path): path is string => Boolean(path)),
    pullRequest: { baseBranch: pull.base.ref, headBranch: pull.head.ref },
  };
  const requests = contentRequests(policy, profile, files, scanOptions);
  if (requests.length > 0) {
    await readFileContents(octokit, ref, requests, { head: headSha, base: pull.base.sha }, (message) => core.debug(message));
  }
  const scanResult = scan(policy, profile, files, scanOptions);
  if (scanResult.skipped) core.info(`Policy does not apply: ${scanResult.skipped}`);

  const authorizer = new Authorizer(orgOctokit, ref.owner, (message) => core.warning(message));
  const comments = (await octokit.paginate(octokit.rest.issues.listComments, { ...ref, issue_number: pull.number, per_page: 100 })).map(toComment);

  if (trigger.comment && isBypass) {
    const result = await checkBypassCommand({ comment: trigger.comment, settings, scan: scanResult, author, headSha, authorizer });
    if (result.accepted) {
      const body = bypassAcknowledgement(scanResult, encodeBypassRecord(result.record), result.record.user, result.record.reason, headSha);
      const { data } = await octokit.rest.issues.createComment({ ...ref, issue_number: pull.number, body });
      comments.push(toComment(data));
      await react(octokit, ref, trigger.comment.id, '+1');
      core.info(`Bypass recorded for @${result.record.user}.`);
    } else {
      await react(octokit, ref, trigger.comment.id, '-1');
      await octokit.rest.issues.createComment({ ...ref, issue_number: pull.number, body: `@${trigger.comment.user} ${result.message}` });
      core.info(`Bypass rejected: ${result.message}`);
    }
  } else if (trigger.comment && isRecheck) {
    await react(octokit, ref, trigger.comment.id, 'eyes');
  }

  const staleness = new ChangeTracker(octokit, ref, headSha, blockingPaths(scanResult), settings.staleApprovals);
  const reviews = await octokit.paginate(octokit.rest.pulls.listReviews, { ...ref, pull_number: pull.number, per_page: 100 });
  const { approvals, changesRequestedBy } = await collectApprovals({
    reviews: reviews.map((review) => ({ user: review.user?.login ?? '', state: review.state, commitId: review.commit_id ?? '' })),
    author,
    securityTeam: settings.securityTeam,
    authorizer,
    staleness,
  });
  const bypass = await findBypass({ comments, botLogin: inputs.botLogin, settings, scan: scanResult, author, authorizer, staleness });
  const decision = evaluate({ scan: scanResult, approvals, changesRequestedBy, bypass });

  const report = renderReport(scanResult, decision, {
    settings,
    policySource: loaded.source,
    headSha,
    reviewers: mentions(settings.securityTeam, ref.owner),
    bypassers: mentions(bypassPrincipals(settings), ref.owner),
  });

  const shouldComment = scanResult.blocking.length > 0 || (scanResult.nonBlocking.length > 0 && settings.report.commentOnNonBlocking);
  let reportUrl: string | undefined;
  await tryWrite('update the report comment', async () => {
    reportUrl = await upsertReport(octokit, ref, pull, comments, inputs, report, shouldComment);
  });
  const statusState = decision.state === 'blocked' ? inputs.blockedState : 'success';
  const targetUrl = reportUrl ?? `${github.context.serverUrl}/${repository}/actions/runs/${github.context.runId}`;
  await tryWrite('set commit status', () => setStatus(octokit, ref, headSha, inputs, statusState, decision.description, targetUrl));
  await tryWrite('update labels', () => syncLabels(octokit, ref, pull.number, pull.labels.map((label) => label.name), settings, decision));
  if (decision.state === 'blocked' && settings.requestReview && trigger.contentChanged) {
    await tryWrite('request security review', () => requestSecurityReview(octokit, ref, pull, settings, decision));
  }

  await core.summary.addRaw(report).write();
  core.setOutput('decision', decision.state);
  core.setOutput('blocking-count', scanResult.blocking.length);
  core.setOutput('finding-count', scanResult.findings.length);
  core.setOutput('components', scanResult.blocking.map((finding) => finding.rule.id).join(','));
  core.setOutput('priority', String(profile.priority));

  core.info(`${decision.state}: ${decision.description}`);
  if (decision.state === 'blocked' && inputs.failOnBlock) core.setFailed(decision.description);
}

run().catch((error: unknown) => {
  core.setFailed(error instanceof Error ? error.message : String(error));
});
