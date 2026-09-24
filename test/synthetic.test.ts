import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import type { ChangedFile } from '../src/diff/types.js';
import { evaluate } from '../src/engine/evaluate.js';
import { resolveRepositoryProfile } from '../src/engine/priority.js';
import { scan } from '../src/engine/scan.js';
import { parsePolicy } from '../src/policy/load.js';
import { file } from './helpers.js';

/**
 * Synthetic pull requests against the example policy: real security changes must be caught,
 * everyday changes must pass. `acme/payments-api` is a priority repository in that policy.
 */
const policy = parsePolicy(readFileSync('examples/security-inspector-policy.yml', 'utf8'), 'example');

interface Scenario {
  name: string;
  files: ChangedFile[];
  /** Expected blocking rule ids in a normal repository and in the priority repository. */
  web: string[];
  payments: string[];
}

const scenarios: Scenario[] = [
  // Everyday changes: no review needed.
  {
    name: 'UI copy and styling',
    files: [file('src/components/Header.tsx', { removed: ['<h1>Welcome</h1>'], added: ['<h1>Welcome back!</h1>'] }), file('src/styles/app.css', { removed: ['color: #333;'], added: ['color: #1a73e8;'] })],
    web: [],
    payments: [],
  },
  { name: 'auth unit tests only', files: [file('src/auth/login.test.ts', { added: ['test("accepts good password", () => {});'] })], web: [], payments: [] },
  { name: 'auth documentation only', files: [file('docs/auth/README.md', { added: ['Tokens expire after 15 minutes.'] })], web: [], payments: [] },
  { name: 'UI variable named sessionId', files: [file('src/components/SessionBanner.tsx', { added: ['const sessionId = user.lastVisit;'] })], web: [], payments: [] },
  { name: 'regex.exec in a parser', files: [file('src/utils/parse.ts', { added: ['const m = pattern.exec(line);'] })], web: [], payments: [] },
  // Security-relevant changes: must be caught.
  {
    name: 'password check weakened',
    files: [file('src/auth/login.ts', { removed: ['const ok = await bcrypt.compare(password, user.passwordHash);'], added: ['const ok = password === user.passwordHash;'] })],
    web: ['authentication'],
    payments: ['authentication'],
  },
  {
    name: 'password check outside the auth folder',
    files: [file('src/services/legacy-sync.ts', { added: ['export const matches = (pw, hash) => bcrypt.compareSync(pw, hash) || pw === "letmein";'] })],
    web: ['authentication'],
    payments: ['authentication'],
  },
  { name: 'token lifetime extended', files: [file('src/auth/tokens.ts', { removed: ['{ expiresIn: "15m" }'], added: ['{ expiresIn: "30d" }'] })], web: ['authentication'], payments: ['authentication'] },
  { name: 'CamelCase password handler', files: [file('src/api/ResetPassword.ts', { added: ['user.hash = newHash;'] })], web: ['authentication'], payments: ['authentication'] },
  { name: 'auth module moved', files: [file('src/identity/tokens.ts', {}, { status: 'renamed', previousFilename: 'src/auth/tokens.ts' })], web: ['authentication'], payments: ['authentication'] },
  {
    name: 'admin check removed',
    files: [file('src/routes/admin.ts', { removed: ['if (!req.user.isAdmin) {', '  return res.status(403).send("forbidden");', '}'] })],
    web: ['authorization'],
    payments: ['authorization'],
  },
  {
    name: 'CORS opened to any origin',
    files: [file('src/server/app.ts', { removed: ['app.use(cors({ origin: ["https://app.acme.test"] }));'], added: ['app.use(cors({ origin: "*", credentials: true }));'] })],
    web: ['security-headers'],
    payments: ['security-headers'],
  },
  { name: 'hardcoded API key', files: [file('src/config.ts', { added: ['apiKey: "sk_live_51H8xQ2eZvKYlo2C9aB7",'] })], web: ['secrets'], payments: ['secrets'] },
  { name: 'TLS verification disabled', files: [file('src/server/http.ts', { added: ['new https.Agent({ keepAlive: true, rejectUnauthorized: false });'] })], web: ['cryptography'], payments: ['cryptography'] },
  { name: 'raw SQL with string concatenation', files: [file('src/db/users.ts', { added: ['return prisma.$queryRawUnsafe("SELECT * FROM users WHERE name LIKE %" + term + "%");'] })], web: ['injection-sinks'], payments: ['injection-sinks'] },
  { name: 'shell exec', files: [file('src/jobs/convert.ts', { added: ['exec(`convert ${input} out.png`);'] })], web: ['injection-sinks'], payments: ['injection-sinks'] },
  { name: 'security group opened to the internet', files: [file('infra/main.tf', { removed: ['cidr_blocks = ["10.0.0.0/8"]'], added: ['cidr_blocks = ["0.0.0.0/0"]'] })], web: ['infrastructure-iam'], payments: ['infrastructure-iam'] },
  // Stricter only in the priority repository.
  { name: 'CI workflow change', files: [file('.github/workflows/deploy.yml', { removed: ['runs-on: ubuntu-latest'], added: ['runs-on: ubuntu-24.04'] })], web: [], payments: ['ci-pipeline'] },
  { name: 'dependency bump', files: [file('package.json', { removed: ['"express": "^4.19.0"'], added: ['"express": "^5.1.0"'] })], web: [], payments: ['dependencies'] },
];

describe('synthetic pull requests against the example policy', () => {
  for (const repository of ['acme/web', 'acme/payments-api'] as const) {
    describe(repository, () => {
      it.each(scenarios.map((scenario) => [scenario.name, scenario] as const))('%s', (_, scenario) => {
        const result = scan(policy, resolveRepositoryProfile(policy, repository), scenario.files);
        const expected = repository === 'acme/web' ? scenario.web : scenario.payments;
        expect(result.blocking.map((finding) => finding.rule.id).sort()).toEqual([...expected].sort());
        expect(evaluate({ scan: result, approvals: [], changesRequestedBy: [] }).state).toBe(expected.length > 0 ? 'blocked' : 'clear');
      });
    });
  }
});
