import type { BypassRecord } from './bypass.js';
import type { ScanResult } from './scan.js';

export type DecisionState = 'clear' | 'approved' | 'bypassed' | 'blocked';

export interface Approval {
  user: string;
  commitId: string;
  /** False when flagged files changed after the approval (see `settings.staleApprovals`). */
  valid: boolean;
}

export interface BypassStatus {
  record: BypassRecord;
  valid: boolean;
  /** Why a recorded bypass no longer applies. */
  invalidReason?: string;
}

export interface EvaluationInput {
  scan: ScanResult;
  /** Latest approving review of each security reviewer. */
  approvals: Approval[];
  /** Security reviewers whose latest review requests changes. */
  changesRequestedBy: string[];
  /** Most recent bypass recorded on the pull request, if any. */
  bypass?: BypassStatus;
}

export interface Decision {
  state: DecisionState;
  requiredApprovals: number;
  validApprovals: Approval[];
  staleApprovals: Approval[];
  changesRequestedBy: string[];
  bypass?: BypassStatus;
  /** One-line summary, suitable for a commit status (max 140 characters). */
  description: string;
}

const STATUS_DESCRIPTION_LIMIT = 140;

function truncate(text: string, limit: number): string {
  return text.length <= limit ? text : `${text.slice(0, limit - 1)}…`;
}

function componentList(scan: ScanResult): string {
  return scan.blocking.map((finding) => finding.rule.name).join(', ');
}

/** Decides whether the pull request may be merged. Pure: no I/O. */
export function evaluate(input: EvaluationInput): Decision {
  const { scan } = input;
  const requiredApprovals = scan.profile.requiredApprovals;
  const validApprovals = input.approvals.filter((approval) => approval.valid);
  const staleApprovals = input.approvals.filter((approval) => !approval.valid);
  const base = { requiredApprovals, validApprovals, staleApprovals, changesRequestedBy: input.changesRequestedBy, bypass: input.bypass };

  if (scan.blocking.length === 0) {
    const description =
      scan.nonBlocking.length === 0
        ? 'No security-critical components modified'
        : `${scan.nonBlocking.length} low-risk finding(s); security review not required`;
    return { ...base, state: 'clear', description };
  }

  if (input.changesRequestedBy.length > 0) {
    const users = input.changesRequestedBy.map((user) => `@${user}`).join(', ');
    return { ...base, state: 'blocked', description: truncate(`Security changes requested by ${users}`, STATUS_DESCRIPTION_LIMIT) };
  }

  if (validApprovals.length >= requiredApprovals) {
    const users = validApprovals.map((approval) => `@${approval.user}`).join(', ');
    return { ...base, state: 'approved', description: truncate(`Security review approved by ${users}`, STATUS_DESCRIPTION_LIMIT) };
  }

  if (input.bypass?.valid && scan.profile.allowBypass) {
    const { user, reason } = input.bypass.record;
    return { ...base, state: 'bypassed', description: truncate(`Bypassed by @${user}: ${reason.replace(/\s+/g, ' ')}`, STATUS_DESCRIPTION_LIMIT) };
  }

  const progress = `${validApprovals.length}/${requiredApprovals} approvals`;
  const prefix = 'Security review required: ';
  const suffix = ` (${progress})`;
  const components = truncate(componentList(scan), STATUS_DESCRIPTION_LIMIT - prefix.length - suffix.length);
  return { ...base, state: 'blocked', description: `${prefix}${components}${suffix}` };
}
