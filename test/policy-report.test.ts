import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { evaluate } from '../src/engine/evaluate.js';
import { resolveRepositoryProfile } from '../src/engine/priority.js';
import { scan } from '../src/engine/scan.js';
import { mergeLocalRules, parseLocalRules, parsePolicy, PolicyError } from '../src/policy/load.js';
import { renderReport } from '../src/report/markdown.js';
import { file, policyFrom } from './helpers.js';

describe('policy loading', () => {
  it('applies defaults', () => {
    const policy = parsePolicy('rules: []', 'p.yml');
    expect(policy.settings).toMatchObject({
      blockOn: 'high',
      requiredApprovals: 1,
      integrityRule: true,
      bypass: { enabled: true, command: '/security-bypass', allowAuthor: false, minReasonLength: 10 },
      labels: { reviewRequired: 'security-review-required' },
    });
  });

  it('reports every validation problem with its path', () => {
    const run = () => parsePolicy('settings: { blockOn: severe }\nrules:\n  - { id: a, name: A }\n  - { id: c, name: C, bogus: 1, paths: [y] }', 'p.yml');
    expect(run).toThrow(PolicyError);
    expect(run).toThrow(/settings\.blockOn/);
    expect(run).toThrow(/rules\.0: a rule must define at least one of `paths` or `content`/);
    expect(run).toThrow(/bogus/);
  });

  it('rejects duplicate rule ids', () => {
    expect(() => parsePolicy('rules:\n  - { id: a, name: A, paths: [x] }\n  - { id: a, name: B, paths: [y] }', 'p.yml')).toThrow(/rules\.1\.id: duplicate rule id "a"/);
  });

  it('rejects invalid regular expressions', () => {
    expect(() => parsePolicy('rules:\n  - { id: a, name: A, content: ["(unclosed"] }', 'p.yml')).toThrow(/invalid content pattern/);
  });

  it('lets repositories add rules but not override central ones or settings', () => {
    const central = policyFrom('rules:\n  - { id: auth, name: Auth, severity: critical, paths: ["auth/**"] }');
    const local = parseLocalRules('settings: { blockOn: critical }\nrules:\n  - { id: auth, name: Weak, severity: low, paths: [nothing] }\n  - { id: tenant, name: Tenant, paths: [db/**] }', 'local.yml');
    expect(local.warnings).toEqual([expect.stringContaining('"settings" is ignored')]);
    const merged = mergeLocalRules(central, local.rules, 'local.yml');
    expect(merged.policy.rules.map((rule) => [rule.id, rule.name])).toEqual([
      ['auth', 'Auth'],
      ['tenant', 'Tenant'],
    ]);
    expect(merged.warnings).toEqual([expect.stringContaining('rule "auth" is already defined')]);
  });

  it('accepts the example policy and local rules', () => {
    const policy = parsePolicy(readFileSync('examples/security-inspector-policy.yml', 'utf8'), 'example');
    expect(policy.rules.length).toBeGreaterThan(5);
    expect(() => parseLocalRules(readFileSync('examples/local-rules.yml', 'utf8'), 'local')).not.toThrow();
  });
});

describe('example policy behaviour', () => {
  const policy = parsePolicy(readFileSync('examples/security-inspector-policy.yml', 'utf8'), 'example');
  const run = (repo: string, files: ReturnType<typeof file>[]) => scan(policy, resolveRepositoryProfile(policy, repo), files);

  it('flags authentication changes and ignores UI changes', () => {
    expect(run('acme/web', [file('src/components/Button.tsx', { added: ['<button className="primary">Save</button>'] }), file('src/styles/app.css', { added: ['color: red;'] })]).findings).toEqual([]);
    const auth = run('acme/web', [file('src/server/users.ts', { removed: ['const ok = await bcrypt.compare(pw, hash);'], added: ['const ok = pw === hash;'] })]);
    expect(auth.blocking.map((finding) => finding.rule.id)).toEqual(['authentication']);
  });

  it('flags hardcoded secrets and disabled TLS verification', () => {
    const result = run('acme/web', [file('src/client.ts', { added: ['const apiKey = "sk_live_1234567890abcdef";', 'https.request({ rejectUnauthorized: false })'] })]);
    expect(result.blocking.map((finding) => finding.rule.id).sort()).toEqual(['cryptography', 'secrets']);
  });

  it('applies priority rules to payment repositories', () => {
    const result = run('acme/payments-core', [file('package.json', { added: ['"left-pad": "^1.0.0"'] })]);
    expect(result.profile.priority).toBe(true);
    expect(result.blocking.map((finding) => [finding.rule.id, finding.severity])).toEqual([['dependencies', 'high']]);
  });
});

describe('renderReport', () => {
  const policy = policyFrom(`
priorityRepositories:
  - { name: payments, reason: "PCI scope", repositories: ["acme/pay"] }
rules:
  - id: auth
    name: Authentication
    severity: critical
    description: Who a user is.
    guidance: Check token lifetimes.
    paths: ["src/auth/**"]
  - { id: ui, name: Styling, severity: low, paths: ["**/*.css"] }
`);
  const files = [file('src/auth/login.ts', { removed: ['expiresIn: "15m"'], added: ['expiresIn: "30d" // ```'] }), file('a.css', { added: ['x'] })];
  const context = { settings: policy.settings, policySource: 'acme/policies:policy.yml', headSha: 'abcdef1234', reviewers: ['`@acme/security`'], bypassers: ['`@acme/leads`'] };

  it('explains what was flagged, what changed and how to proceed', () => {
    const result = scan(policy, resolveRepositoryProfile(policy, 'acme/pay'), files);
    const report = renderReport(result, evaluate({ scan: result, approvals: [], changesRequestedBy: [] }), context);
    expect(report.startsWith('<!-- security-inspector:report -->')).toBe(true);
    expect(report).toContain('security review required (1 security-critical component)');
    expect(report).toContain('priority repository');
    expect(report).toContain('PCI scope');
    expect(report).toContain('| Authentication | 🔴 Critical | 1 | +1 −1 |');
    expect(report).toContain('**Reviewer guidance:** Check token lifetimes.');
    expect(report).toContain('-expiresIn: "15m"');
    expect(report).toContain('+expiresIn: "30d" // ```');
    expect(report).toContain('````diff'); // fence longer than the content's backticks
    expect(report).toContain('`/security-bypass <justification>`');
    expect(report).toContain('Non-blocking findings (1)');
  });

  it('drops excerpts when the comment would be too long', () => {
    const big = Array.from({ length: 400 }, (_, i) => file(`src/auth/f${i}.ts`, { added: Array.from({ length: 20 }, () => 'x'.repeat(200)) }));
    const bigPolicy = policyFrom('settings: { report: { maxFilesPerComponent: 200 } }\nrules:\n  - { id: auth, name: Authentication, paths: ["src/auth/**"] }');
    const result = scan(bigPolicy, resolveRepositoryProfile(bigPolicy, 'a/b'), big);
    const report = renderReport(result, evaluate({ scan: result, approvals: [], changesRequestedBy: [] }), { ...context, settings: bigPolicy.settings });
    expect(report.length).toBeLessThanOrEqual(61_000);
    expect(report).not.toContain('```diff');
  });
});
