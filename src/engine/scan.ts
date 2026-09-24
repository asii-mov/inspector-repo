import picomatch from 'picomatch';
import type { ChangedFile, DiffLine, FileStatus, Hunk } from '../diff/types.js';
import { boostSeverity, severityRank, type Policy, type Rule, type Severity } from '../policy/schema.js';
import { matchesRepository, type RepositoryProfile } from './priority.js';

export const INTEGRITY_RULE_ID = 'security-inspector-integrity';

/** Lines longer than this are truncated before regex matching (minified bundles etc.). */
const MAX_MATCH_LINE_LENGTH = 2000;
/** Context lines shown around a matched line in excerpts. */
const EXCERPT_CONTEXT = 2;

export interface MatchedLine {
  type: 'added' | 'removed';
  line: number;
  content: string;
  /** Source of the pattern that matched. */
  pattern: string;
  /** The text the pattern matched, e.g. `bcrypt`. */
  matched: string;
}

export interface ExcerptChunk {
  oldStart: number;
  newStart: number;
  lines: DiffLine[];
}

export interface FileMatch {
  filename: string;
  previousFilename?: string;
  status: FileStatus;
  additions: number;
  deletions: number;
  sha?: string;
  /** Path globs of the rule that matched this file. */
  pathPatterns: string[];
  /** Changed lines that matched the rule's content patterns. */
  matchedLines: MatchedLine[];
  /** True when the file was flagged by path but GitHub returned no diff (binary or too large). */
  contentUnavailable: boolean;
  excerpt: ExcerptChunk[];
  excerptTruncated: boolean;
}

export interface Finding {
  rule: Rule;
  /** Severity after priority-repository boosts. */
  severity: Severity;
  baseSeverity: Severity;
  blocking: boolean;
  files: FileMatch[];
  additions: number;
  deletions: number;
}

export interface ScanResult {
  profile: RepositoryProfile;
  findings: Finding[];
  blocking: Finding[];
  nonBlocking: Finding[];
  filesScanned: number;
  /** Files whose content could not be inspected (only path rules applied). */
  filesWithoutPatch: string[];
  rulesEvaluated: number;
}

export interface ScanOptions {
  /** Extra paths protected by the built-in integrity rule (e.g. the running workflow file). */
  integrityPaths?: string[];
  maxSnippetLines?: number;
}

interface CompiledRule {
  rule: Rule;
  pathMatchers: { glob: string; test: (path: string) => boolean }[];
  isExcluded: (path: string) => boolean;
  patterns: { source: string; regex: RegExp }[];
  honoursIgnorePaths: boolean;
}

export function integrityRule(paths: string[]): Rule {
  return {
    id: INTEGRITY_RULE_ID,
    name: 'Security Inspector configuration',
    description:
      'Changes to the inspector configuration, the workflow that runs it, or CODEOWNERS could weaken or disable the security review gate.',
    guidance: 'Confirm the change does not remove rules, relax thresholds, skip the inspector workflow or change who can approve.',
    severity: 'critical',
    paths: [...new Set(['.github/CODEOWNERS', 'CODEOWNERS', 'docs/CODEOWNERS', ...paths])],
    excludePaths: [],
    content: [],
    contentScope: 'both',
    match: 'all',
    repositories: [],
    excludeRepositories: [],
    priorityOnly: false,
  };
}

function compileRule(rule: Rule, honoursIgnorePaths: boolean): CompiledRule {
  const options = { dot: true };
  const exclude = rule.excludePaths.length > 0 ? picomatch(rule.excludePaths, options) : () => false;
  return {
    rule,
    pathMatchers: rule.paths.map((glob) => ({ glob, test: picomatch(glob, options) })),
    isExcluded: exclude,
    patterns: rule.content.map((pattern) => {
      const { pattern: source, flags = '' } = typeof pattern === 'string' ? { pattern } : pattern;
      return { source, regex: new RegExp(source, flags.replace(/[gy]/g, '')) };
    }),
    honoursIgnorePaths,
  };
}

function ruleApplies(rule: Rule, profile: RepositoryProfile): boolean {
  if (rule.priorityOnly && !profile.priority) return false;
  if (rule.repositories.length > 0 && !matchesRepository(rule.repositories, profile.repository)) return false;
  if (matchesRepository(rule.excludeRepositories, profile.repository)) return false;
  return true;
}

function matchLines(compiled: CompiledRule, hunks: Hunk[]): MatchedLine[] {
  if (compiled.patterns.length === 0) return [];
  const scope = compiled.rule.contentScope;
  const matches: MatchedLine[] = [];
  for (const hunk of hunks) {
    for (const line of hunk.lines) {
      if (line.type === 'context') continue;
      if (scope !== 'both' && line.type !== scope) continue;
      const text = line.content.length > MAX_MATCH_LINE_LENGTH ? line.content.slice(0, MAX_MATCH_LINE_LENGTH) : line.content;
      for (const { source, regex } of compiled.patterns) {
        const hit = regex.exec(text);
        if (!hit) continue;
        matches.push({
          type: line.type,
          line: (line.type === 'added' ? line.newLine : line.oldLine) ?? 0,
          content: line.content,
          pattern: source,
          matched: hit[0].trim().slice(0, 60) || source,
        });
        break;
      }
    }
  }
  return matches;
}

/**
 * Builds a compact diff excerpt around the lines that matter: the matched lines when the rule
 * matched on content, otherwise every changed line.
 */
export function buildExcerpt(hunks: Hunk[], isInteresting: (line: DiffLine) => boolean, maxLines: number): { chunks: ExcerptChunk[]; truncated: boolean } {
  const chunks: ExcerptChunk[] = [];
  let budget = maxLines;
  let truncated = false;

  for (const hunk of hunks) {
    const keep = new Array<boolean>(hunk.lines.length).fill(false);
    hunk.lines.forEach((line, index) => {
      if (!isInteresting(line)) return;
      for (let i = Math.max(0, index - EXCERPT_CONTEXT); i <= Math.min(hunk.lines.length - 1, index + EXCERPT_CONTEXT); i++) keep[i] = true;
    });

    let current: ExcerptChunk | undefined;
    for (let index = 0; index < hunk.lines.length; index++) {
      if (!keep[index]) {
        current = undefined;
        continue;
      }
      if (budget <= 0) {
        truncated = true;
        break;
      }
      const line = hunk.lines[index]!;
      if (!current) {
        current = { oldStart: firstNumber(hunk.lines, index, 'oldLine') ?? hunk.oldStart, newStart: firstNumber(hunk.lines, index, 'newLine') ?? hunk.newStart, lines: [] };
        chunks.push(current);
      }
      current.lines.push(line);
      budget--;
    }
    if (truncated) break;
  }
  return { chunks, truncated };
}

function firstNumber(lines: DiffLine[], from: number, key: 'oldLine' | 'newLine'): number | undefined {
  for (let i = from; i < lines.length; i++) {
    const value = lines[i]![key];
    if (value !== undefined) return value;
  }
  return undefined;
}

function matchFile(compiled: CompiledRule, file: ChangedFile, maxSnippetLines: number): FileMatch | undefined {
  const { rule } = compiled;
  const candidates = [file.filename, file.previousFilename].filter((path): path is string => Boolean(path));
  if (candidates.every((path) => compiled.isExcluded(path))) return undefined;

  const pathPatterns = compiled.pathMatchers.filter((matcher) => candidates.some((path) => matcher.test(path))).map((matcher) => matcher.glob);
  const pathHit = pathPatterns.length > 0;
  const matchedLines = matchLines(compiled, file.hunks);
  const contentHit = matchedLines.length > 0;
  const hasPaths = rule.paths.length > 0;
  const hasContent = rule.content.length > 0;
  // Content cannot be checked when GitHub has no diff for the file; a path match is then enough.
  const contentUnknown = hasContent && !file.patchAvailable;

  let matched: boolean;
  if (rule.match === 'any') {
    matched = pathHit || contentHit;
  } else {
    const pathOk = !hasPaths || pathHit;
    const contentOk = !hasContent || contentHit || (contentUnknown && pathHit);
    matched = pathOk && contentOk;
  }
  if (!matched) return undefined;

  // Files flagged by path show all their changes; files flagged by content focus on the matches.
  const matchedKeys = new Set(matchedLines.map((match) => `${match.type}:${match.line}`));
  const interesting = contentHit && !pathHit
    ? (line: DiffLine) => line.type !== 'context' && matchedKeys.has(`${line.type}:${line.type === 'added' ? line.newLine : line.oldLine}`)
    : (line: DiffLine) => line.type !== 'context';
  const { chunks, truncated } = buildExcerpt(file.hunks, interesting, maxSnippetLines);

  return {
    filename: file.filename,
    previousFilename: file.previousFilename,
    status: file.status,
    additions: file.additions,
    deletions: file.deletions,
    sha: file.sha,
    pathPatterns,
    matchedLines,
    contentUnavailable: !file.patchAvailable && pathHit,
    excerpt: chunks,
    excerptTruncated: truncated,
  };
}

/** Scans the changed files of a pull request against the policy. Pure: no I/O. */
export function scan(policy: Policy, profile: RepositoryProfile, files: ChangedFile[], options: ScanOptions = {}): ScanResult {
  const maxSnippetLines = options.maxSnippetLines ?? policy.settings.report.maxSnippetLines;
  const ignored = policy.settings.ignorePaths.length > 0 ? picomatch(policy.settings.ignorePaths, { dot: true }) : () => false;

  const compiled: CompiledRule[] = [];
  if (policy.settings.integrityRule) compiled.push(compileRule(integrityRule(options.integrityPaths ?? []), false));
  for (const rule of policy.rules) {
    if (ruleApplies(rule, profile)) compiled.push(compileRule(rule, true));
  }

  const findings: Finding[] = [];
  for (const rule of compiled) {
    const matches: FileMatch[] = [];
    for (const file of files) {
      if (rule.honoursIgnorePaths && ignored(file.filename)) continue;
      const match = matchFile(rule, file, maxSnippetLines);
      if (match) matches.push(match);
    }
    if (matches.length === 0) continue;

    const severity = boostSeverity(rule.rule.severity, profile.severityBoost);
    findings.push({
      rule: rule.rule,
      severity,
      baseSeverity: rule.rule.severity,
      blocking: severityRank(severity) >= severityRank(profile.blockOn),
      files: matches,
      additions: matches.reduce((sum, match) => sum + match.additions, 0),
      deletions: matches.reduce((sum, match) => sum + match.deletions, 0),
    });
  }

  findings.sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || a.rule.name.localeCompare(b.rule.name));
  return {
    profile,
    findings,
    blocking: findings.filter((finding) => finding.blocking),
    nonBlocking: findings.filter((finding) => !finding.blocking),
    filesScanned: files.length,
    filesWithoutPatch: files.filter((file) => !file.patchAvailable).map((file) => file.filename),
    rulesEvaluated: compiled.length,
  };
}

/** Stable keys identifying what a bypass covered: one per blocking (rule, file) pair. */
export function blockingKeys(result: ScanResult): string[] {
  return result.blocking.flatMap((finding) => finding.files.map((file) => `${finding.rule.id}:${file.filename}`)).sort();
}

/** Every file path (current and previous) involved in a blocking finding. */
export function blockingPaths(result: ScanResult): Set<string> {
  const paths = new Set<string>();
  for (const finding of result.blocking) {
    for (const file of finding.files) {
      paths.add(file.filename);
      if (file.previousFilename) paths.add(file.previousFilename);
    }
  }
  return paths;
}
