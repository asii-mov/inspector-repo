import picomatch from 'picomatch';
import type { Conditions } from '../policy/schema.js';

export interface PullRequestContext {
  /** Branch the pull request merges into, e.g. `main`. */
  baseBranch: string;
  /** Branch the pull request comes from. */
  headBranch: string;
}

const matches = (globs: string[], branch: string) => globs.length > 0 && picomatch.isMatch(branch, globs, { dot: true });

/**
 * Checks pull request conditions. Without pull request context (e.g. a CLI run on a bare diff)
 * conditions are treated as met, so nothing is skipped by accident.
 */
export function checkConditions(when: Conditions | undefined, pr: PullRequestContext | undefined): { met: boolean; reason?: string } {
  if (!when || !pr) return { met: true };
  if (when.baseBranches.length > 0 && !matches(when.baseBranches, pr.baseBranch)) {
    return { met: false, reason: `the pull request targets \`${pr.baseBranch}\` (only ${when.baseBranches.map((b) => `\`${b}\``).join(', ')} are inspected)` };
  }
  if (matches(when.excludeBaseBranches, pr.baseBranch)) {
    return { met: false, reason: `pull requests into \`${pr.baseBranch}\` are excluded` };
  }
  if (when.headBranches.length > 0 && !matches(when.headBranches, pr.headBranch)) {
    return { met: false, reason: `the source branch \`${pr.headBranch}\` is not inspected (only ${when.headBranches.map((b) => `\`${b}\``).join(', ')})` };
  }
  if (matches(when.excludeHeadBranches, pr.headBranch)) {
    return { met: false, reason: `pull requests from \`${pr.headBranch}\` are excluded` };
  }
  return { met: true };
}
