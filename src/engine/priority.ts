import picomatch from 'picomatch';
import { severityRank, type Policy, type PriorityGroup, type Severity } from '../policy/schema.js';

export function matchesRepository(patterns: string[], repository: string): boolean {
  if (patterns.length === 0) return false;
  return picomatch.isMatch(repository.toLowerCase(), patterns.map((pattern) => pattern.toLowerCase()), { dot: true });
}

/** Effective settings for one repository, after applying every matching priority group. */
export interface RepositoryProfile {
  repository: string;
  priority: boolean;
  groups: PriorityGroup[];
  blockOn: Severity;
  severityBoost: number;
  requiredApprovals: number;
  allowBypass: boolean;
}

/** Resolves the strictest combination of settings that apply to a repository. */
export function resolveRepositoryProfile(policy: Policy, repository: string): RepositoryProfile {
  const groups = policy.priorityRepositories.filter((group) => matchesRepository(group.repositories, repository));
  let blockOn = policy.settings.blockOn;
  let severityBoost = 0;
  let requiredApprovals = policy.settings.requiredApprovals;
  let allowBypass = policy.settings.bypass.enabled;

  for (const group of groups) {
    if (group.blockOn && severityRank(group.blockOn) < severityRank(blockOn)) blockOn = group.blockOn;
    severityBoost = Math.max(severityBoost, group.severityBoost);
    requiredApprovals = Math.max(requiredApprovals, group.requiredApprovals ?? 0);
    allowBypass = allowBypass && group.allowBypass;
  }

  return { repository, priority: groups.length > 0, groups, blockOn, severityBoost, requiredApprovals, allowBypass };
}
