import type { Severity, Settings } from '../policy/schema.js';
import { REPORT_MARKER } from '../engine/bypass.js';
import type { Decision } from '../engine/evaluate.js';
import type { ExcerptChunk, FileMatch, Finding, ScanResult } from '../engine/scan.js';

const MAX_COMMENT_LENGTH = 60_000;

const SEVERITY_BADGE: Record<Severity, string> = {
  critical: '🔴 Critical',
  high: '🟠 High',
  medium: '🟡 Medium',
  low: '🔵 Low',
};

export interface ReportContext {
  settings: Settings;
  /** Where the policy was loaded from, e.g. `acme/security-policies@main:policy.yml`. */
  policySource: string;
  headSha?: string;
  /** Mentions of who can approve, e.g. `@acme/security`. */
  reviewers: string[];
  /** Mentions of who can bypass. */
  bypassers: string[];
  /** Whether the report is rendered for GitHub (commands and checklists) or a terminal. */
  interactive?: boolean;
}

/** Escapes text for use inside a markdown table cell or inline text. */
function escapeInline(text: string): string {
  return text.replace(/[\\`*_[\]<>|]/g, (char) => `\\${char}`).replace(/\r?\n/g, ' ');
}

function code(text: string): string {
  const longest = Math.max(0, ...(text.match(/`+/g) ?? []).map((run) => run.length));
  const fence = '`'.repeat(longest + 1);
  const pad = text.startsWith('`') || text.endsWith('`') ? ' ' : '';
  return `${fence}${pad}${text.replace(/\|/g, '\\|')}${pad}${fence}`;
}

function fenced(body: string, language: string): string {
  const longest = Math.max(2, ...(body.match(/`{3,}/g) ?? []).map((run) => run.length));
  const fence = '`'.repeat(longest + 1);
  return `${fence}${language}\n${body}\n${fence}`;
}

function changes(additions: number, deletions: number): string {
  return `+${additions} −${deletions}`;
}

function renderExcerpt(chunks: ExcerptChunk[]): string {
  const lines: string[] = [];
  for (const chunk of chunks) {
    lines.push(`@@ -${chunk.oldStart} +${chunk.newStart} @@`);
    for (const line of chunk.lines) {
      const marker = line.type === 'added' ? '+' : line.type === 'removed' ? '-' : ' ';
      lines.push(`${marker}${line.content}`);
    }
  }
  return lines.join('\n');
}

function triggerDescription(file: FileMatch): string {
  const parts: string[] = [];
  if (file.pathPatterns.length > 0) parts.push(`path ${file.pathPatterns.map(code).join(', ')}`);
  if (file.matchedLines.length > 0) {
    const terms = [...new Set(file.matchedLines.map((line) => line.matched))];
    const lineCount = file.matchedLines.length;
    parts.push(`content ${terms.slice(0, 3).map(code).join(', ')}${terms.length > 3 ? ', …' : ''} (${lineCount} line${lineCount === 1 ? '' : 's'})`);
  }
  if (file.contentUnavailable) parts.push('_diff not available_');
  return parts.join('; ');
}

function fileLabel(file: FileMatch): string {
  return file.previousFilename && file.previousFilename !== file.filename
    ? `${code(file.previousFilename)} → ${code(file.filename)}`
    : code(file.filename);
}

function renderFinding(finding: Finding, context: ReportContext, withExcerpts: boolean): string {
  const { rule } = finding;
  const out: string[] = [];
  const boosted = finding.severity !== finding.baseSeverity ? ` _(raised from ${finding.baseSeverity}: priority repository)_` : '';
  out.push(`#### ${escapeInline(rule.name)} — ${SEVERITY_BADGE[finding.severity]}${boosted}`);
  out.push('');
  if (rule.description) out.push(`**Why this matters:** ${rule.description.trim()}`, '');
  if (rule.guidance) out.push(`**Reviewer guidance:** ${rule.guidance.trim()}`, '');

  const max = context.settings.report.maxFilesPerComponent;
  out.push('| File | Status | Changes | Flagged by |', '|---|---|---|---|');
  for (const file of finding.files.slice(0, max)) {
    out.push(`| ${fileLabel(file)} | ${file.status} | ${changes(file.additions, file.deletions)} | ${triggerDescription(file)} |`);
  }
  if (finding.files.length > max) out.push(`| _…and ${finding.files.length - max} more file(s)_ | | | |`);
  out.push('');

  if (withExcerpts) {
    for (const file of finding.files.slice(0, max)) {
      if (file.excerpt.length === 0) continue;
      const truncated = file.excerptTruncated ? ' (truncated)' : '';
      out.push(`<details><summary>Changes in <code>${escapeHtml(file.filename)}</code>${truncated}</summary>`, '');
      out.push(fenced(renderExcerpt(file.excerpt), 'diff'), '', '</details>', '');
    }
  }
  return out.join('\n');
}

function escapeHtml(text: string): string {
  return text.replace(/[&<>"]/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[char]!);
}

function summaryTable(findings: Finding[]): string {
  const rows = findings.map(
    (finding) => `| ${escapeInline(finding.rule.name)} | ${SEVERITY_BADGE[finding.severity]} | ${finding.files.length} | ${changes(finding.additions, finding.deletions)} |`,
  );
  return ['| Component | Severity | Files | Changes |', '|---|---|---|---|', ...rows].join('\n');
}

function headline(decision: Decision, scan: ScanResult): string {
  const count = scan.blocking.length;
  const components = `${count} security-critical component${count === 1 ? '' : 's'}`;
  switch (decision.state) {
    case 'clear':
      return scan.findings.length === 0
        ? '### ✅ Security Inspector: no security-critical components modified'
        : '### ✅ Security Inspector: security review not required';
    case 'approved':
      return `### ✅ Security Inspector: security review approved (${components})`;
    case 'bypassed':
      return `### ⚠️ Security Inspector: review bypassed (${components})`;
    case 'blocked':
      return `### 🛑 Security Inspector: security review required (${components})`;
  }
}

function nextSteps(decision: Decision, scan: ScanResult, context: ReportContext): string[] {
  const { settings } = context;
  const out: string[] = [];
  const reviewers = context.reviewers.length > 0 ? context.reviewers.join(', ') : 'the security team';

  if (decision.state === 'approved') {
    out.push(`Approved by ${decision.validApprovals.map((approval) => `@${approval.user}`).join(', ')}.`);
  } else if (decision.state === 'bypassed' && decision.bypass) {
    const { record } = decision.bypass;
    out.push(`Bypassed by @${record.user} at commit \`${record.sha.slice(0, 7)}\`:`, '', `> ${escapeInline(record.reason)}`);
  } else if (decision.state === 'blocked') {
    out.push('**Merge is blocked until this pull request is reviewed by the security team.**', '');
    if (decision.changesRequestedBy.length > 0) {
      out.push(`- ❌ Changes requested by ${decision.changesRequestedBy.map((user) => `@${user}`).join(', ')}.`);
    }
    out.push(`- Approvals: **${decision.validApprovals.length} / ${decision.requiredApprovals}** from ${reviewers}.`);
    if (decision.staleApprovals.length > 0) {
      const which = settings.staleApprovals === 'any-change' ? 'new commits were pushed' : 'flagged files changed';
      out.push(`- Approvals from ${decision.staleApprovals.map((approval) => `@${approval.user}`).join(', ')} no longer count because ${which} afterwards.`);
    }
    if (decision.bypass && !decision.bypass.valid) {
      out.push(`- The bypass by @${decision.bypass.record.user} no longer applies: ${decision.bypass.invalidReason ?? 'the flagged changes differ'}.`);
    }
    if (context.interactive !== false) {
      if (scan.profile.allowBypass) {
        const who = context.bypassers.length > 0 ? context.bypassers.join(', ') : 'an authorised user';
        out.push(
          `- **False positive?** ${who} can comment \`${settings.bypass.command} <justification>\` to bypass. The bypass is recorded here and stops applying if the flagged files change.`,
        );
      } else {
        out.push('- Bypass is disabled for this repository; a security approval is required.');
      }
      out.push(`- Status not updating after a review? Comment \`${settings.recheckCommand}\`.`);
    }
  }
  return out;
}

export interface RenderOptions {
  /** Drop diff excerpts, used automatically when the comment would be too long. */
  excerpts?: boolean;
}

/** Renders the pull request comment / job summary. */
export function renderReport(scan: ScanResult, decision: Decision, context: ReportContext, options: RenderOptions = {}): string {
  const withExcerpts = options.excerpts ?? true;
  const out: string[] = [REPORT_MARKER, headline(decision, scan), ''];
  const { profile } = scan;

  if (profile.priority) {
    const groups = profile.groups.map((group) => `**${escapeInline(group.name)}**${group.reason ? ` (${escapeInline(group.reason)})` : ''}`).join(', ');
    out.push(
      `> [!IMPORTANT]`,
      `> This is a **priority repository**: ${groups}. Stricter rules apply: review required from ${profile.blockOn} severity, ${profile.requiredApprovals} approval(s), bypass ${profile.allowBypass ? 'allowed' : 'disabled'}.`,
      '',
    );
  }

  if (scan.blocking.length > 0) {
    out.push(summaryTable(scan.blocking), '');
    out.push(...nextSteps(decision, scan, context), '');
    out.push('<details open><summary><strong>Flagged changes</strong></summary>', '');
    for (const finding of scan.blocking) out.push(renderFinding(finding, context, withExcerpts));
    out.push('</details>', '');
  } else if (scan.findings.length === 0) {
    out.push('This pull request does not modify any component on the security team\'s watch list. No security review is needed.', '');
  } else {
    out.push(`Only low-risk findings (below **${profile.blockOn}** severity) were detected, so no security review is required.`, '');
  }

  if (scan.nonBlocking.length > 0 && context.settings.report.showNonBlocking) {
    out.push(`<details><summary>Non-blocking findings (${scan.nonBlocking.length})</summary>`, '');
    out.push(summaryTable(scan.nonBlocking), '');
    for (const finding of scan.nonBlocking) out.push(renderFinding(finding, context, withExcerpts));
    out.push('</details>', '');
  }

  if (scan.filesWithoutPatch.length > 0) {
    out.push(`<sub>${scan.filesWithoutPatch.length} file(s) had no diff available (binary or too large) and were checked by path only.</sub>`, '');
  }
  const head = context.headSha ? ` · head \`${context.headSha.slice(0, 7)}\`` : '';
  out.push(`<sub>Policy: \`${context.policySource}\` · ${scan.rulesEvaluated} rule(s) · ${scan.filesScanned} file(s) scanned${head}</sub>`);

  const report = out.join('\n');
  if (report.length > MAX_COMMENT_LENGTH && withExcerpts) return renderReport(scan, decision, context, { excerpts: false });
  if (report.length > MAX_COMMENT_LENGTH) return `${report.slice(0, MAX_COMMENT_LENGTH)}\n\n_…report truncated_`;
  return report;
}

/** Plain-text rendering for the CLI. */
export function renderText(scan: ScanResult, decision: Decision): string {
  const out: string[] = [];
  out.push(`${decision.state.toUpperCase()}: ${decision.description}`);
  if (scan.profile.priority) out.push(`Priority repository: ${scan.profile.groups.map((group) => group.name).join(', ')}`);
  for (const finding of scan.findings) {
    out.push('');
    out.push(`[${finding.severity}${finding.blocking ? ', blocking' : ''}] ${finding.rule.name} (${finding.rule.id}) ${changes(finding.additions, finding.deletions)}`);
    for (const file of finding.files) {
      out.push(`  ${file.status.padEnd(8)} ${file.filename}  ${changes(file.additions, file.deletions)}`);
      for (const line of file.matchedLines.slice(0, 5)) {
        const marker = line.type === 'added' ? '+' : '-';
        out.push(`      ${marker}${String(line.line).padStart(5)}: ${line.content.trim().slice(0, 120)}   [matched "${line.matched}"]`);
      }
      if (file.matchedLines.length > 5) out.push(`      … ${file.matchedLines.length - 5} more matching line(s)`);
    }
  }
  return out.join('\n');
}
