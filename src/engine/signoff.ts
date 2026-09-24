import type { Principals, Settings } from '../policy/schema.js';
import { decodeBypassRecord, parseCommand, validateReason, type BypassRecord } from './bypass.js';
import type { Approval, BypassStatus } from './evaluate.js';
import { blockingKeys, type ScanResult } from './scan.js';

/**
 * Security sign-off: approvals from security reviewers and bypasses recorded by the inspector.
 * I/O is injected so the rules can be tested without GitHub.
 */

export interface AuthorizationCheck {
  isAuthorized(user: string, principals: Principals): Promise<boolean>;
}

export interface StalenessCheck {
  unchangedSince(sha: string): Promise<{ ok: boolean; reason?: string }>;
}

export interface ReviewData {
  user: string;
  state: string;
  commitId: string;
}

export interface CommentData {
  id: number;
  user: string;
  body: string;
  createdAt: string;
  updatedAt: string;
}

const sameUser = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();

/** Who may run the bypass command. */
export function bypassPrincipals(settings: Settings): Principals {
  const { bypass, securityTeam } = settings;
  return {
    teams: [...bypass.teams, ...(bypass.includeSecurityTeam ? securityTeam.teams : [])],
    users: [...bypass.users, ...(bypass.includeSecurityTeam ? securityTeam.users : [])],
  };
}

/** Reads the latest review state of each security reviewer. Reviews must be in chronological order. */
export async function collectApprovals(options: {
  reviews: ReviewData[];
  author: string;
  securityTeam: Principals;
  authorizer: AuthorizationCheck;
  staleness: StalenessCheck;
}): Promise<{ approvals: Approval[]; changesRequestedBy: string[] }> {
  const latest = new Map<string, ReviewData>();
  for (const review of options.reviews) {
    // Plain comments do not change a reviewer's verdict.
    if (review.state === 'APPROVED' || review.state === 'CHANGES_REQUESTED' || review.state === 'DISMISSED') {
      latest.set(review.user.toLowerCase(), review);
    }
  }

  const approvals: Approval[] = [];
  const changesRequestedBy: string[] = [];
  for (const review of latest.values()) {
    if (review.state === 'DISMISSED' || sameUser(review.user, options.author)) continue;
    if (!(await options.authorizer.isAuthorized(review.user, options.securityTeam))) continue;
    if (review.state === 'CHANGES_REQUESTED') {
      changesRequestedBy.push(review.user);
    } else {
      const { ok } = await options.staleness.unchangedSince(review.commitId);
      approvals.push({ user: review.user, commitId: review.commitId, valid: ok });
    }
  }
  return { approvals, changesRequestedBy };
}

export type BypassCommandResult =
  | { accepted: true; record: BypassRecord }
  | { accepted: false; message: string };

/** Validates a bypass command. On success returns the record the inspector should publish. */
export async function checkBypassCommand(options: {
  comment: CommentData;
  settings: Settings;
  scan: ScanResult;
  author: string;
  headSha: string;
  authorizer: AuthorizationCheck;
  now?: Date;
}): Promise<BypassCommandResult> {
  const { comment, settings, scan } = options;
  const reason = parseCommand(comment.body, settings.bypass.command);
  if (reason === undefined) return { accepted: false, message: 'Not a bypass command.' };

  if (!scan.profile.allowBypass) {
    const groups = scan.profile.groups.map((group) => group.name).join(', ');
    return {
      accepted: false,
      message: groups ? `Bypass is disabled for priority repositories (${groups}). A security approval is required.` : 'Bypass is disabled by the security policy.',
    };
  }
  if (sameUser(comment.user, options.author) && !settings.bypass.allowAuthor) {
    return { accepted: false, message: 'Pull request authors cannot bypass the security review of their own pull request.' };
  }
  if (!(await options.authorizer.isAuthorized(comment.user, bypassPrincipals(settings)))) {
    return { accepted: false, message: `@${comment.user} is not authorised to bypass the security review.` };
  }
  const reasonError = validateReason(reason, settings.bypass.minReasonLength);
  if (reasonError) return { accepted: false, message: `${reasonError} Usage: \`${settings.bypass.command} <justification>\`` };
  if (scan.blocking.length === 0) return { accepted: false, message: 'There is nothing to bypass: no blocking security findings.' };

  return {
    accepted: true,
    record: {
      v: 1,
      commentId: comment.id,
      user: comment.user,
      reason,
      sha: options.headSha,
      keys: blockingKeys(scan),
      at: (options.now ?? new Date()).toISOString(),
    },
  };
}

/**
 * Finds the most recent bypass recorded by the inspector and decides whether it still applies.
 *
 * A record only counts if it was posted by the inspector's own account and not edited since, and
 * the command comment it references still exists, is unedited since the record, and was written
 * by someone who is (still) authorised. Deleting the command comment therefore revokes a bypass.
 */
export async function findBypass(options: {
  comments: CommentData[];
  botLogin: string;
  settings: Settings;
  scan: ScanResult;
  author: string;
  authorizer: AuthorizationCheck;
  staleness: StalenessCheck;
}): Promise<BypassStatus | undefined> {
  const { settings } = options;
  const byId = new Map(options.comments.map((comment) => [comment.id, comment]));
  const records = options.comments
    .filter((comment) => sameUser(comment.user, options.botLogin) && comment.updatedAt === comment.createdAt)
    .map((comment) => ({ comment, record: decodeBypassRecord(comment.body) }))
    .filter((entry): entry is { comment: CommentData; record: BypassRecord } => entry.record !== undefined)
    .sort((a, b) => b.comment.createdAt.localeCompare(a.comment.createdAt));

  for (const { comment: ack, record } of records) {
    const command = byId.get(record.commentId);
    if (!command || !sameUser(command.user, record.user)) continue;
    if (command.updatedAt > ack.createdAt) continue;
    if (parseCommand(command.body, settings.bypass.command) === undefined) continue;
    if (sameUser(record.user, options.author) && !settings.bypass.allowAuthor) continue;
    if (!(await options.authorizer.isAuthorized(record.user, bypassPrincipals(settings)))) continue;

    // The most recent genuine record decides.
    const covered = new Set(record.keys);
    const uncovered = blockingKeys(options.scan).filter((key) => !covered.has(key));
    if (uncovered.length > 0) {
      const files = uncovered.map((key) => key.slice(key.indexOf(':') + 1));
      return { record, valid: false, invalidReason: `new flagged changes were added (${[...new Set(files)].slice(0, 3).join(', ')})` };
    }
    const { ok, reason } = await options.staleness.unchangedSince(record.sha);
    return ok ? { record, valid: true } : { record, valid: false, invalidReason: reason };
  }
  return undefined;
}
