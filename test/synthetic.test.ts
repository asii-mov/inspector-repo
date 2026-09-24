import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import type { ChangedFile } from '../src/diff/types.js';
import { evaluate } from '../src/engine/evaluate.js';
import type { PullRequestContext } from '../src/engine/conditions.js';
import { resolveRepositoryProfile } from '../src/engine/priority.js';
import { scan } from '../src/engine/scan.js';
import { parsePolicy } from '../src/policy/load.js';
import { file } from './helpers.js';

/**
 * Synthetic pull requests against the example policy.
 *
 * The inspector watches components, not vulnerabilities: ANY change to authentication code must be
 * flagged, however harmless it looks, while everyday changes elsewhere pass. `acme/payments-api`
 * is a priority repository, and the policy only inspects pull requests into main and release/*.
 */
const policy = parsePolicy(readFileSync('examples/security-inspector-policy.yml', 'utf8'), 'example');

// Full file contents at the head commit, as the action reads them for `fileContent` rules.
const LOGIN = 'import bcrypt from "bcrypt";\nexport async function login(email, password) {\n  const user = await findUser(email);\n  if (!user) {\n    return null;\n  }\n  return (await bcrypt.compare(password, user.hash)) ? user : null;\n}\n';
const USERS_SERVICE = 'import bcrypt from "bcrypt";\nexport async function checkCredentials(email, password) {\n  const user = await findUser(email);\n  return user;\n}\nexport const displayName = (user) => user.firstName;\n';
const ROUTES = 'import passport from "passport";\nrouter.post("/login", passport.authenticate("local"));\nrouter.get("/me", (req, res) => res.json(req.user));\n';
const APP = 'import cors from "cors";\napp.use(cors({ origin: "*", credentials: true }));\n';
const HTTP = 'import https from "https";\nexport const agent = new https.Agent({ keepAlive: true, rejectUnauthorized: false });\n';
const HEADER = 'export const Header = () => <h1>Welcome back!</h1>;\n';
const ADMIN_AFTER = 'export function deleteUser(req, res) {\n  return res.send(removeUser(req.params.id));\n}\n';

interface Scenario {
  name: string;
  files: ChangedFile[];
  /** Expected blocking rule ids for a PR into main of a normal repository / the priority repository. */
  web: string[];
  payments: string[];
}

const scenarios: Scenario[] = [
  // Everyday changes: no review needed.
  {
    name: 'UI copy and styling',
    files: [
      file('src/components/Header.tsx', { removed: ['<h1>Welcome</h1>'], added: ['<h1>Welcome back!</h1>'] }, { content: HEADER }),
      file('src/styles/app.css', { removed: ['color: #333;'], added: ['color: #1a73e8;'] }),
    ],
    web: [],
    payments: [],
  },
  { name: 'auth unit tests only', files: [file('src/auth/login.test.ts', { added: ['test("accepts good password", () => {});'] })], web: [], payments: [] },
  { name: 'auth documentation only', files: [file('docs/auth/README.md', { added: ['Tokens expire after 15 minutes.'] })], web: [], payments: [] },
  { name: 'UI variable named sessionId', files: [file('src/components/SessionBanner.tsx', { added: ['const sessionId = user.lastVisit;'] }, { content: 'const sessionId = user.lastVisit;\n' })], web: [], payments: [] },

  // Any change to authentication code, however harmless: must be reviewed.
  { name: 'auth: formatting-only refactor', files: [file('src/auth/login.ts', { removed: ['  if (!user) return null;'], added: ['  if (!user) {', '    return null;', '  }'] }, { content: LOGIN })], web: ['authentication'], payments: ['authentication'] },
  { name: 'auth: added a log line', files: [file('src/auth/login.ts', { added: ['  console.log("login attempt", email);'] }, { content: LOGIN })], web: ['authentication'], payments: ['authentication'] },
  { name: 'auth: token lifetime changed', files: [file('src/auth/tokens.ts', { removed: ['{ expiresIn: "15m" }'], added: ['{ expiresIn: "30d" }'] })], web: ['authentication'], payments: ['authentication'] },
  {
    name: 'auth code outside the auth folder, changed line has no auth keyword',
    files: [file('src/services/users.ts', { removed: ['  return ok ? user : null;'], added: ['  return user;'] }, { content: USERS_SERVICE })],
    web: ['authentication'],
    payments: ['authentication'],
  },
  {
    name: 'unrelated function in a file that is auth code',
    files: [file('src/services/users.ts', { removed: ['export const displayName = (user) => user.firstName + " " + user.lastName;'], added: ['export const displayName = (user) => user.firstName;'] }, { content: USERS_SERVICE })],
    web: ['authentication'],
    payments: ['authentication'],
  },
  { name: 'route change in a file using passport', files: [file('src/server/routes.ts', { removed: ['router.get("/profile", h);'], added: ['router.get("/me", h);'] }, { content: ROUTES })], web: ['authentication'], payments: ['authentication'] },
  { name: 'CamelCase password handler', files: [file('src/api/ResetPassword.ts', { added: ['user.hash = newHash;'] }, { content: 'user.hash = newHash;\n' })], web: ['authentication'], payments: ['authentication'] },
  { name: 'auth module moved', files: [file('src/identity/tokens.ts', {}, { status: 'renamed', previousFilename: 'src/auth/tokens.ts', content: 'export {}\n' })], web: ['authentication'], payments: ['authentication'] },

  // Other watched components.
  {
    name: 'last admin check removed from a route',
    files: [file('src/routes/users.ts', { removed: ['  if (!req.user.isAdmin) {', '    return res.status(403).send("forbidden");', '  }'] }, { content: ADMIN_AFTER })],
    web: ['authorization'],
    payments: ['authorization'],
  },
  { name: 'CORS configuration', files: [file('src/server/app.ts', { removed: ['app.use(cors({ origin: ALLOWED }));'], added: ['app.use(cors({ origin: "*", credentials: true }));'] }, { content: APP })], web: ['security-middleware'], payments: ['security-middleware'] },
  { name: 'TLS agent settings', files: [file('src/server/http.ts', { added: ['export const agent = new https.Agent({ keepAlive: true, rejectUnauthorized: false });'] }, { content: HTTP })], web: ['cryptography'], payments: ['cryptography'] },
  { name: 'security group', files: [file('infra/main.tf', { removed: ['cidr_blocks = ["10.0.0.0/8"]'], added: ['cidr_blocks = ["0.0.0.0/0"]'] })], web: ['infrastructure-iam'], payments: ['infrastructure-iam'] },

  // Stricter only in the priority repository.
  { name: 'CI workflow change', files: [file('.github/workflows/deploy.yml', { removed: ['runs-on: ubuntu-latest'], added: ['runs-on: ubuntu-24.04'] })], web: [], payments: ['ci-pipeline'] },
  { name: 'dependency bump', files: [file('package.json', { removed: ['"express": "^4.19.0"'], added: ['"express": "^5.1.0"'] })], web: [], payments: ['dependencies'] },
];

const intoMain: PullRequestContext = { baseBranch: 'main', headBranch: 'feature/change' };

describe('synthetic pull requests into main against the example policy', () => {
  for (const repository of ['acme/web', 'acme/payments-api'] as const) {
    describe(repository, () => {
      it.each(scenarios.map((scenario) => [scenario.name, scenario] as const))('%s', (_, scenario) => {
        const result = scan(policy, resolveRepositoryProfile(policy, repository), scenario.files, { pullRequest: intoMain });
        const expected = repository === 'acme/web' ? scenario.web : scenario.payments;
        expect(result.blocking.map((finding) => finding.rule.id).sort()).toEqual([...expected].sort());
        expect(evaluate({ scan: result, approvals: [], changesRequestedBy: [] }).state).toBe(expected.length > 0 ? 'blocked' : 'clear');
      });
    });
  }
});

describe('synthetic pull requests into other branches', () => {
  const authChange = scenarios.find((scenario) => scenario.name === 'auth: added a log line')!.files;

  it.each([
    ['main', 'blocked'],
    ['release/2.4', 'blocked'],
    ['dev', 'skipped'],
    ['feature/big-rewrite', 'skipped'],
  ])('a change to auth code in a PR into %s is %s', (baseBranch, state) => {
    const result = scan(policy, resolveRepositoryProfile(policy, 'acme/web'), authChange, { pullRequest: { baseBranch, headBranch: 'feature/change' } });
    expect(evaluate({ scan: result, approvals: [], changesRequestedBy: [] }).state).toBe(state);
  });

  it('checks dependency changes only on the way into main (rule-level condition)', () => {
    const bump = scenarios.find((scenario) => scenario.name === 'dependency bump')!.files;
    const into = (baseBranch: string) =>
      scan(policy, resolveRepositoryProfile(policy, 'acme/payments-api'), bump, { pullRequest: { baseBranch, headBranch: 'feature/change' } }).blocking.map((finding) => finding.rule.id);
    expect(into('main')).toEqual(['dependencies']);
    expect(into('release/2.4')).toEqual([]);
  });
});
