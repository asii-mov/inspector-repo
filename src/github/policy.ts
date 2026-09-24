import { mergeLocalRules, parseLocalRules, parsePolicy, PolicyError } from '../policy/load.js';
import type { Policy } from '../policy/schema.js';
import { readRepositoryFile, type Octokit, type RepoRef } from './api.js';

export interface PolicyLocation {
  /** Central policy repository (`owner/repo`), maintained by the security team. */
  policyRepository?: string;
  policyRef?: string;
  policyPath: string;
  /** Repository-local configuration path, read from the pull request's base commit. */
  localConfigPath: string;
}

export interface LoadedPolicy {
  policy: Policy;
  source: string;
  warnings: string[];
}

function parseRepository(value: string): RepoRef {
  const [owner, repo, ...rest] = value.split('/');
  if (!owner || !repo || rest.length > 0) throw new PolicyError('expected "owner/repo"', `policy-repository "${value}"`);
  return { owner, repo };
}

/**
 * Loads the effective policy.
 *
 * The repository-local file is always read from the pull request's *base* commit, never from its
 * head, so a pull request cannot weaken the policy it is being checked against.
 */
export async function loadPolicy(options: {
  location: PolicyLocation;
  /** Client able to read the central policy repository. */
  policyOctokit: Octokit;
  /** Client for the repository under review. */
  repoOctokit: Octokit;
  repository: RepoRef;
  baseSha: string;
}): Promise<LoadedPolicy> {
  const { location, repository, baseSha } = options;
  const localSource = `${repository.owner}/${repository.repo}@${baseSha.slice(0, 7)}:${location.localConfigPath}`;
  const localText = await readRepositoryFile(options.repoOctokit, repository, location.localConfigPath, baseSha);

  if (!location.policyRepository) {
    if (localText === undefined) {
      throw new PolicyError(
        'no policy found. Configure `policy-repository` to use a central policy, or add a policy file to the default branch.',
        localSource,
      );
    }
    return { policy: parsePolicy(localText, localSource), source: localSource, warnings: [] };
  }

  const central = parseRepository(location.policyRepository);
  const centralSource = `${location.policyRepository}${location.policyRef ? `@${location.policyRef}` : ''}:${location.policyPath}`;
  let centralText: string | undefined;
  try {
    centralText = await readRepositoryFile(options.policyOctokit, central, location.policyPath, location.policyRef);
  } catch (error) {
    throw new PolicyError(`could not read the central policy: ${(error as Error).message}`, centralSource);
  }
  if (centralText === undefined) {
    throw new PolicyError(
      'central policy not found. Check the path, and that `org-token` can read the policy repository (the default GITHUB_TOKEN cannot read other private repositories).',
      centralSource,
    );
  }

  const policy = parsePolicy(centralText, centralSource);
  if (localText === undefined) return { policy, source: centralSource, warnings: [] };

  const local = parseLocalRules(localText, localSource);
  const merged = mergeLocalRules(policy, local.rules, localSource);
  const source = local.rules.length > 0 ? `${centralSource} + ${location.localConfigPath}` : centralSource;
  return { policy: merged.policy, source, warnings: [...local.warnings, ...merged.warnings] };
}
