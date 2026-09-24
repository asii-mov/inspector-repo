import picomatch from 'picomatch';
import type { ChangedFile, DiffLine, FileStatus, Hunk } from '../diff/types.js';
import { boostSeverity, severityRank, type Policy, type Rule, type Severity } from '../policy/schema.js';
import { checkConditions, type PullRequestContext } from './conditions.js';
import { matchesRepository, type RepositoryProfile } from './priority.js';

export const INTEGRITY_RULE_ID = 'security-inspector-integrity';

/** Lines longer than this are truncated before regex matching (minified bundles etc.). */
const MAX_MATCH_LINE_LENGTH = 2000;
/** Context lines shown around a matched line in excerpts. */
const EXCERPT_CONTEXT = 2;
/** Files larger than this are not searched by `fileContent` rules. */
export const MAX_FILE_CONTENT_BYTES = 1_000_000;

export interface MatchedLine {
  type: 'added' | 'removed';
  line: number;
  content: string;
  /** Source of the pattern that matched. */
  pattern: string;
  /** The text the pattern matched, e.g. `bcrypt`. */
  matched: string;
}

/** Where a `fileContent` pattern matched: the file is part of the component. */
export interface FileMarker {
  pattern: string;
  matched: string;
  line: number;
  /** `head`: the file contains the marker; `base`: the change removed it. */
  version: 'head' | 'base';
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
  /** Marker that identified the file as part of the component (`fileContent` rules). */
  fileMarker?: FileMarker;
  /** Changed lines that matched the rule's content patterns. */
  matchedLines: MatchedLine[];
  /** True when the file was flagged but its diff or content could not be inspected. */
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
  /** Set when `settings.when` excludes this pull request; nothing was inspected. */
  skipped?: string;
  findings: Finding[];
  blocking: Finding[];
  nonBlocking: Finding[];
  filesScanned: number;
  /** Files whose content could not be inspected (only path rules applied). */
  filesWithoutPatch: string[];
  /** Files `fileContent` rules could not read (too large, over the limit or unavailable). */
  filesWithoutContent: string[];
  rulesEvaluated: number;
}

export interface ScanOptions {
  /** Extra paths protected by the built-in integrity rule (e.g. the running workflow file). */
  integrityPaths?: string[];
  maxSnippetLines?: number;
  /** Branches of the pull request, for `when` conditions. */
  pullRequest?: PullRequestContext;
}

interface Pattern {
  source: string;
  regex: RegExp;
}

interface CompiledRule {
  rule: Rule;
  pathMatchers: { glob: string; test: (path: string) => boolean }[];
  isExcluded: (path: string) => boolean;
  filePatterns: Pattern[];
  patterns: Pattern[];
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
    fileContent: [],
    content: [],
    contentScope: 'both',
    match: 'all',
    repositories: [],
    excludeRepositories: [],
    priorityOnly: false,
  };
}

function compilePatterns(patterns: Rule['content'], extraFlags = ''): Pattern[] {
  return patterns.map((pattern) => {
    const { pattern: source, flags = '' } = typeof pattern === 'string' ? { pattern } : pattern;
    const combined = [...new Set(`${flags.replace(/[gy]/g, '')}${extraFlags}`)].join('');
    return { source, regex: new RegExp(source, combined) };
  });
}

function compileRule(rule: Rule, honoursIgnorePaths: boolean): CompiledRule {
  // Case-insensitive: `**/*password*` must also catch `ResetPassword.ts`.
  const options = { dot: true, nocase: true };
  const exclude = rule.excludePaths.length > 0 ? picomatch(rule.excludePaths, options) : () => false;
  return {
    rule,
    pathMatchers: rule.paths.map((glob) => ({ glob, test: picomatch(glob, options) })),
    isExcluded: exclude,
    // `m` so that ^ and $ anchor to lines within the whole file.
    filePatterns: compilePatterns(rule.fileContent, 'm'),
    patterns: compilePatterns(rule.content),
    honoursIgnorePaths,
  };
}

function ruleApplies(rule: Rule, profile: RepositoryProfile, pullRequest: PullRequestContext | undefined): boolean {
  if (rule.priorityOnly && !profile.priority) return false;
  if (rule.repositories.length > 0 && !matchesRepository(rule.repositories, profile.repository)) return false;
  if (matchesRepository(rule.excludeRepositories, profile.repository)) return false;
  return checkConditions(rule.when, pullRequest).met;
}

/** The rules that apply to this pull request, or the reason the whole policy does not apply. */
function applicableRules(policy: Policy, profile: RepositoryProfile, options: ScanOptions): { rules: CompiledRule[]; skipped?: string } {
  const policyConditions = checkConditions(policy.settings.when, options.pullRequest);
  if (!policyConditions.met) return { rules: [], skipped: policyConditions.reason };

  const rules: CompiledRule[] = [];
  if (policy.settings.integrityRule) rules.push(compileRule(integrityRule(options.integrityPaths ?? []), false));
  for (const rule of policy.rules) {
    if (ruleApplies(rule, profile, options.pullRequest)) rules.push(compileRule(rule, true));
  }
  return { rules };
}

function ignoreMatcher(policy: Policy): (path: string) => boolean {
  return policy.settings.ignorePaths.length > 0 ? picomatch(policy.settings.ignorePaths, { dot: true, nocase: true }) : () => false;
}

function isExcludedFrom(rule: CompiledRule, file: ChangedFile, ignored: (path: string) => boolean): boolean {
  if (rule.honoursIgnorePaths && ignored(file.filename)) return true;
  const candidates = [file.filename, file.previousFilename].filter((path): path is string => Boolean(path));
  return candidates.every((path) => rule.isExcluded(path));
}

/** A file needs its full content when a `fileContent` rule could apply and the diff alone is not enough. */
function needsContent(file: ChangedFile): boolean {
  // A deleted file's whole content is already in the diff as removed lines.
  return !(file.status === 'removed' && file.patchAvailable);
}

/**
 * Lists the files whose full content `fileContent` rules need, most relevant first, capped at
 * `settings.fileContentLimit`. The caller reads them and sets {@link ChangedFile.content}.
 */
export function contentRequests(policy: Policy, profile: RepositoryProfile, files: ChangedFile[], options: ScanOptions = {}): { file: ChangedFile; version: 'head' | 'base' }[] {
  const { rules } = applicableRules(policy, profile, options);
  const contentRules = rules.filter((rule) => rule.filePatterns.length > 0);
  if (contentRules.length === 0) return [];
  const ignored = ignoreMatcher(policy);
  const couldFlag = (rule: CompiledRule, file: ChangedFile) => {
    if (isExcludedFrom(rule, file, ignored)) return false;
    // With `match: all`, the file content only matters if the path matches too.
    if (rule.rule.match === 'all' && rule.pathMatchers.length > 0) {
      return [file.filename, file.previousFilename].some((path) => path && rule.pathMatchers.some((matcher) => matcher.test(path)));
    }
    return true;
  };
  return files
    .filter((file) => needsContent(file) && contentRules.some((rule) => couldFlag(rule, file)))
    .slice(0, policy.settings.fileContentLimit)
    .map((file) => ({ file, version: file.status === 'removed' ? 'base' : 'head' }));
}

function lineNumberAt(text: string, index: number): number {
  let line = 1;
  for (let i = text.indexOf('\n'); i !== -1 && i < index; i = text.indexOf('\n', i + 1)) line++;
  return line;
}

/** Finds a `fileContent` marker in the file, or in lines this change removed from it. */
function matchFileContent(compiled: CompiledRule, file: ChangedFile): { marker?: FileMarker; unknown: boolean } {
  if (compiled.filePatterns.length === 0) return { unknown: false };

  const content = file.content;
  const readable = content !== undefined && content.length <= MAX_FILE_CONTENT_BYTES && !content.includes('\0');
  if (readable) {
    for (const { source, regex } of compiled.filePatterns) {
      const hit = regex.exec(content);
      if (hit) {
        const version = file.status === 'removed' ? 'base' : 'head';
        return { marker: { pattern: source, matched: hit[0].trim().slice(0, 60) || source, line: lineNumberAt(content, hit.index), version }, unknown: false };
      }
    }
  }
  // If the change removed the marker, the file was part of the component before this change.
  for (const hunk of file.hunks) {
    for (const line of hunk.lines) {
      if (line.type !== 'removed') continue;
      const text = line.content.slice(0, MAX_MATCH_LINE_LENGTH);
      for (const { source, regex } of compiled.filePatterns) {
        const hit = regex.exec(text);
        if (hit) return { marker: { pattern: source, matched: hit[0].trim().slice(0, 60) || source, line: line.oldLine ?? 0, version: 'base' }, unknown: false };
      }
    }
  }
  return { unknown: !readable && needsContent(file) };
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

interface FileMatchResult {
  match?: FileMatch;
  /** A `fileContent` criterion could not be evaluated because the file could not be read. */
  contentUnknown: boolean;
}

function matchFile(compiled: CompiledRule, file: ChangedFile, maxSnippetLines: number): FileMatchResult {
  const { rule } = compiled;
  const candidates = [file.filename, file.previousFilename].filter((path): path is string => Boolean(path));

  const pathPatterns = compiled.pathMatchers.filter((matcher) => candidates.some((path) => matcher.test(path))).map((matcher) => matcher.glob);
  const pathHit = pathPatterns.length > 0;
  const fileContent = matchFileContent(compiled, file);
  const fileHit = fileContent.marker !== undefined;
  const matchedLines = matchLines(compiled, file.hunks);
  const contentHit = matchedLines.length > 0;

  // Criteria the rule defines. `unknown` means the file could not be inspected for it.
  const criteria = [
    { defined: rule.paths.length > 0, hit: pathHit, unknown: false },
    { defined: rule.fileContent.length > 0, hit: fileHit, unknown: fileContent.unknown },
    { defined: rule.content.length > 0, hit: contentHit, unknown: !file.patchAvailable },
  ].filter((criterion) => criterion.defined);

  const anyHit = criteria.some((criterion) => criterion.hit);
  // With `all`, a criterion that could not be checked is assumed to match (conservative), as long
  // as at least one criterion really matched.
  const matched = rule.match === 'any' ? anyHit : anyHit && criteria.every((criterion) => criterion.hit || criterion.unknown);
  if (!matched) return { contentUnknown: fileContent.unknown };

  // Files that belong to the component (by path or file content) show all their changes; files
  // flagged only by changed lines focus on those lines.
  const matchedKeys = new Set(matchedLines.map((match) => `${match.type}:${match.line}`));
  const interesting = contentHit && !pathHit && !fileHit
    ? (line: DiffLine) => line.type !== 'context' && matchedKeys.has(`${line.type}:${line.type === 'added' ? line.newLine : line.oldLine}`)
    : (line: DiffLine) => line.type !== 'context';
  const { chunks, truncated } = buildExcerpt(file.hunks, interesting, maxSnippetLines);

  return {
    contentUnknown: fileContent.unknown,
    match: {
      filename: file.filename,
      previousFilename: file.previousFilename,
      status: file.status,
      additions: file.additions,
      deletions: file.deletions,
      sha: file.sha,
      pathPatterns,
      fileMarker: fileContent.marker,
      matchedLines,
      contentUnavailable: criteria.some((criterion) => criterion.unknown && !criterion.hit),
      excerpt: chunks,
      excerptTruncated: truncated,
    },
  };
}

/** Scans the changed files of a pull request against the policy. Pure: no I/O. */
export function scan(policy: Policy, profile: RepositoryProfile, files: ChangedFile[], options: ScanOptions = {}): ScanResult {
  const maxSnippetLines = options.maxSnippetLines ?? policy.settings.report.maxSnippetLines;
  const ignored = ignoreMatcher(policy);
  const { rules: compiled, skipped } = applicableRules(policy, profile, options);

  const findings: Finding[] = [];
  const withoutContent = new Set<string>();
  for (const rule of compiled) {
    const matches: FileMatch[] = [];
    for (const file of files) {
      if (isExcludedFrom(rule, file, ignored)) continue;
      const { match, contentUnknown } = matchFile(rule, file, maxSnippetLines);
      if (contentUnknown) withoutContent.add(file.filename);
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
    skipped,
    findings,
    blocking: findings.filter((finding) => finding.blocking),
    nonBlocking: findings.filter((finding) => !finding.blocking),
    filesScanned: skipped ? 0 : files.length,
    filesWithoutPatch: skipped ? [] : files.filter((file) => !file.patchAvailable).map((file) => file.filename),
    filesWithoutContent: [...withoutContent],
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
