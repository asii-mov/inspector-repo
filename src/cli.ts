import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { parseGitDiff } from './diff/parse.js';
import { evaluate } from './engine/evaluate.js';
import { resolveRepositoryProfile } from './engine/priority.js';
import { contentRequests, MAX_FILE_CONTENT_BYTES, scan, type ScanOptions } from './engine/scan.js';
import { mergeLocalRules, parseLocalRules, parsePolicy, PolicyError } from './policy/load.js';
import { renderReport, renderText } from './report/markdown.js';

const USAGE = `Security Inspector: flag changes to security-critical components.

Usage:
  security-inspector validate <policy.yml> [--local <file>]
  security-inspector scan --policy <policy.yml> [options]

Scan options:
  --policy <file>     Policy file (required)
  --local <file>      Repository-local rules to add on top of the policy
  --repo <owner/repo> Repository name, used for priority repositories and rule scoping
                      (default: derived from the "origin" remote)
  --base <ref>        Base ref to diff against (default: origin/HEAD, then main)
  --head <ref>        Head ref (default: HEAD)
  --diff <file>       Read a unified diff from a file ("-" for stdin) instead of running git.
                      File contents for fileContent rules are then read from the working tree.
  --target-branch <b> Branch the pull request would merge into, for \`when\` conditions
                      (default: derived from --base, e.g. origin/main -> main)
  --source-branch <b> Branch the pull request comes from (default: current branch or --head)
  --format <fmt>      text | markdown | json (default: text)

Exit codes: 0 no review needed, 1 security review required, 2 usage or policy error.
`;

function git(args: string[]): string {
  return execFileSync('git', args, { encoding: 'utf8', maxBuffer: 256 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] });
}

function tryGit(args: string[]): string | undefined {
  try {
    return git(args).trim();
  } catch {
    return undefined;
  }
}

function repositoryFromRemote(): string {
  const url = tryGit(['remote', 'get-url', 'origin']);
  const match = url && /[/:]([^/:]+\/[^/]+?)(?:\.git)?\/?$/.exec(url);
  return match ? match[1]! : 'local/repository';
}

function defaultBase(): string {
  const originHead = tryGit(['symbolic-ref', '--quiet', '--short', 'refs/remotes/origin/HEAD']);
  if (originHead) return originHead;
  for (const candidate of ['origin/main', 'origin/master', 'main', 'master']) {
    if (tryGit(['rev-parse', '--verify', '--quiet', candidate])) return candidate;
  }
  throw new PolicyError('could not determine a base ref; pass --base', 'git');
}

function branchName(ref: string): string {
  return ref.replace(/^refs\/(heads|remotes)\//, '').replace(/^origin\//, '');
}

/** Reads a file at a git revision (or from the working tree when `revision` is undefined). */
function readFileAt(path: string, revision: string | undefined): string | undefined {
  try {
    if (revision === undefined) return existsSync(path) ? readFileSync(path, 'utf8') : undefined;
    const content = execFileSync('git', ['show', `${revision}:${path}`], { encoding: 'utf8', maxBuffer: MAX_FILE_CONTENT_BYTES * 4, stdio: ['ignore', 'pipe', 'ignore'] });
    return content;
  } catch {
    return undefined;
  }
}

function loadPolicyFiles(policyPath: string, localPath?: string) {
  const policy = parsePolicy(readFileSync(policyPath, 'utf8'), policyPath);
  if (!localPath) return { policy, warnings: [] as string[] };
  const local = parseLocalRules(readFileSync(localPath, 'utf8'), localPath);
  const merged = mergeLocalRules(policy, local.rules, localPath);
  return { policy: merged.policy, warnings: [...local.warnings, ...merged.warnings] };
}

function main(argv: string[]): number {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      policy: { type: 'string' },
      local: { type: 'string' },
      repo: { type: 'string' },
      base: { type: 'string' },
      head: { type: 'string' },
      diff: { type: 'string' },
      'target-branch': { type: 'string' },
      'source-branch': { type: 'string' },
      format: { type: 'string', default: 'text' },
      help: { type: 'boolean', short: 'h' },
    },
  });
  const [command, ...rest] = positionals;

  if (values.help || !command) {
    process.stdout.write(USAGE);
    return values.help ? 0 : 2;
  }

  if (command === 'validate') {
    const path = rest[0] ?? values.policy;
    if (!path) throw new PolicyError('missing policy file', 'validate');
    const { policy, warnings } = loadPolicyFiles(path, values.local);
    warnings.forEach((warning) => process.stderr.write(`warning: ${warning}\n`));
    process.stdout.write(
      `✔ ${path} is valid: ${policy.rules.length} rule(s), ${policy.priorityRepositories.length} priority group(s), review required from "${policy.settings.blockOn}" severity.\n`,
    );
    return 0;
  }

  if (command !== 'scan') {
    process.stderr.write(`Unknown command "${command}".\n\n${USAGE}`);
    return 2;
  }
  if (!values.policy) throw new PolicyError('missing --policy', 'scan');
  if (!['text', 'markdown', 'json'].includes(values.format!)) throw new PolicyError(`unknown format "${values.format}"`, 'scan');

  const { policy, warnings } = loadPolicyFiles(values.policy, values.local);
  warnings.forEach((warning) => process.stderr.write(`warning: ${warning}\n`));

  let diffText: string;
  let revisions: { head?: string; base?: string } = {};
  let baseRef = values.base;
  let headRef = values.head;
  if (values.diff) {
    diffText = readFileSync(values.diff === '-' ? 0 : values.diff, 'utf8');
  } else {
    const base = (baseRef ??= defaultBase());
    const head = (headRef ??= 'HEAD');
    diffText = git(['diff', '--no-color', '--no-ext-diff', '--find-renames', '-U3', `${base}...${head}`]);
    revisions = { head, base: git(['merge-base', base, head]).trim() };
  }

  const targetBranch = values['target-branch'] ?? (baseRef ? branchName(baseRef) : undefined);
  const sourceBranch = values['source-branch'] ?? (headRef && headRef !== 'HEAD' ? branchName(headRef) : tryGit(['rev-parse', '--abbrev-ref', 'HEAD']));
  const options: ScanOptions = {
    integrityPaths: values.local ? [values.local] : [],
    pullRequest: targetBranch && sourceBranch ? { baseBranch: targetBranch, headBranch: sourceBranch } : undefined,
  };

  const repository = values.repo ?? repositoryFromRemote();
  const profile = resolveRepositoryProfile(policy, repository);
  const files = parseGitDiff(diffText);
  for (const { file, version } of contentRequests(policy, profile, files, options)) {
    const path = version === 'base' ? (file.previousFilename ?? file.filename) : file.filename;
    // With --diff there are no revisions: read the working tree (head) and skip base versions.
    if (values.diff && version === 'base') continue;
    file.content = readFileAt(path, values.diff ? undefined : revisions[version]);
  }
  const result = scan(policy, profile, files, options);
  const decision = evaluate({ scan: result, approvals: [], changesRequestedBy: [] });

  if (values.format === 'json') {
    const findings = result.findings.map((finding) => ({
      rule: finding.rule.id,
      name: finding.rule.name,
      severity: finding.severity,
      blocking: finding.blocking,
      files: finding.files.map((file) => ({
        filename: file.filename,
        status: file.status,
        additions: file.additions,
        deletions: file.deletions,
        pathPatterns: file.pathPatterns,
        matchedLines: file.matchedLines,
      })),
    }));
    process.stdout.write(`${JSON.stringify({ repository, priority: profile.priority, decision: decision.state, description: decision.description, findings }, null, 2)}\n`);
  } else if (values.format === 'markdown') {
    process.stdout.write(
      `${renderReport(result, decision, { settings: policy.settings, policySource: values.policy, reviewers: [], bypassers: [], interactive: false })}\n`,
    );
  } else {
    process.stdout.write(`${renderText(result, decision)}\n`);
  }
  return decision.state === 'blocked' ? 1 : 0;
}

try {
  process.exitCode = main(process.argv.slice(2));
} catch (error) {
  process.stderr.write(`error: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 2;
}
