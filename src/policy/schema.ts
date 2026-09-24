import { z } from 'zod';

export const SEVERITIES = ['low', 'medium', 'high', 'critical'] as const;
export type Severity = (typeof SEVERITIES)[number];

export function severityRank(severity: Severity): number {
  return SEVERITIES.indexOf(severity);
}

export function boostSeverity(severity: Severity, levels: number): Severity {
  const index = Math.min(SEVERITIES.length - 1, Math.max(0, severityRank(severity) + levels));
  return SEVERITIES[index]!;
}

const principalsSchema = z
  .object({
    /** GitHub teams, as `org/team-slug` or just `team-slug` (resolved against the repository owner). */
    teams: z.array(z.string().min(1)).default([]),
    /** Individual GitHub usernames. */
    users: z.array(z.string().min(1)).default([]),
  })
  .strict();

export type Principals = z.infer<typeof principalsSchema>;

const contentPatternSchema = z.union([
  z.string().min(1),
  z
    .object({
      pattern: z.string().min(1),
      /** Regular expression flags, e.g. `i` for case-insensitive. `g`/`y` are ignored. */
      flags: z.string().regex(/^[dgimsuvy]*$/).optional(),
    })
    .strict(),
]);

export const ruleSchema = z
  .object({
    /** Stable identifier, used in reports, fingerprints and bypass records. */
    id: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_.-]*$/, 'rule ids may only contain letters, digits, ".", "_" and "-"'),
    /** Human readable component name shown to developers, e.g. "Authentication". */
    name: z.string().min(1),
    /** Why this component is security critical. */
    description: z.string().optional(),
    /** What the security reviewer should look at. */
    guidance: z.string().optional(),
    severity: z.enum(SEVERITIES).default('high'),
    /** Glob patterns (picomatch syntax) matched against changed file paths. */
    paths: z.array(z.string().min(1)).default([]),
    /** Glob patterns that exclude files from this rule (e.g. tests). */
    excludePaths: z.array(z.string().min(1)).default([]),
    /** Regular expressions matched against changed lines of the diff. */
    content: z.array(contentPatternSchema).default([]),
    /** Which changed lines `content` is matched against. */
    contentScope: z.enum(['added', 'removed', 'both']).default('both'),
    /**
     * How `paths` and `content` combine when both are set.
     * `all`: the file must match a path AND contain a matching changed line.
     * `any`: either is enough.
     */
    match: z.enum(['all', 'any']).default('all'),
    /** Restrict the rule to repositories matching these `owner/repo` globs. */
    repositories: z.array(z.string().min(1)).default([]),
    /** Never apply the rule to repositories matching these `owner/repo` globs. */
    excludeRepositories: z.array(z.string().min(1)).default([]),
    /** Only apply this rule in priority repositories. */
    priorityOnly: z.boolean().default(false),
  })
  .strict()
  .refine((rule) => rule.paths.length > 0 || rule.content.length > 0, {
    message: 'a rule must define at least one of `paths` or `content`',
  });

export type Rule = z.infer<typeof ruleSchema>;

export const priorityGroupSchema = z
  .object({
    /** Label for the group, e.g. "payments" or "pci". */
    name: z.string().min(1),
    /** `owner/repo` glob patterns, e.g. `acme/payments-*`. */
    repositories: z.array(z.string().min(1)).min(1),
    /** Why these repositories are sensitive. Shown in the report. */
    reason: z.string().optional(),
    /** Overrides `settings.blockOn` for these repositories. */
    blockOn: z.enum(SEVERITIES).optional(),
    /** Raise the severity of every finding by this many levels (capped at critical). */
    severityBoost: z.number().int().min(0).max(3).default(0),
    /** Overrides `settings.requiredApprovals` for these repositories. */
    requiredApprovals: z.number().int().min(1).max(10).optional(),
    /** Set to false to disable the bypass command for these repositories. */
    allowBypass: z.boolean().default(true),
  })
  .strict();

export type PriorityGroup = z.infer<typeof priorityGroupSchema>;

const labelSchema = z.union([z.string().min(1), z.literal(false)]);

export const settingsSchema = z
  .object({
    /** Findings at or above this severity require security review before merge. */
    blockOn: z.enum(SEVERITIES).default('high'),
    /** Approvals needed from the security team. */
    requiredApprovals: z.number().int().min(1).max(10).default(1),
    /**
     * When an approval (or bypass) stops counting after new commits.
     * `flagged-changes`: only if a flagged file changes afterwards (recommended).
     * `any-change`: any new commit invalidates it.
     */
    staleApprovals: z.enum(['flagged-changes', 'any-change']).default('flagged-changes'),
    /** Who counts as a security reviewer. */
    securityTeam: principalsSchema.default({ teams: [], users: [] }),
    /** Automatically request review from the security team when a PR is blocked. */
    requestReview: z.boolean().default(true),
    /** Paths never inspected by any rule (e.g. vendored code, lockfiles). */
    ignorePaths: z.array(z.string().min(1)).default([]),
    /**
     * Built-in rule that flags changes to the inspector's own configuration, the workflow
     * running it and CODEOWNERS, so the gate cannot be quietly weakened in a pull request.
     */
    integrityRule: z.boolean().default(true),
    bypass: z
      .object({
        enabled: z.boolean().default(true),
        command: z.string().regex(/^\/[\w-]+$/).default('/security-bypass'),
        /** Who may bypass, in addition to the security team. */
        teams: z.array(z.string().min(1)).default([]),
        users: z.array(z.string().min(1)).default([]),
        /** Whether the security team may bypass (in addition to the lists above). */
        includeSecurityTeam: z.boolean().default(true),
        /** Whether the pull request author may bypass their own pull request. */
        allowAuthor: z.boolean().default(false),
        /** Minimum length of the justification. 0 disables the requirement. */
        minReasonLength: z.number().int().min(0).default(10),
      })
      .strict()
      .prefault({}),
    recheckCommand: z.string().regex(/^\/[\w-]+$/).default('/security-recheck'),
    labels: z
      .object({
        reviewRequired: labelSchema.default('security-review-required'),
        approved: labelSchema.default('security-approved'),
        bypassed: labelSchema.default('security-bypassed'),
      })
      .strict()
      .prefault({}),
    report: z
      .object({
        /** Maximum diff lines shown per flagged file. */
        maxSnippetLines: z.number().int().min(0).max(200).default(20),
        /** Maximum files listed per component. */
        maxFilesPerComponent: z.number().int().min(1).max(200).default(25),
        /** Include findings below `blockOn` in the report. */
        showNonBlocking: z.boolean().default(true),
        /** Comment on pull requests that only have non-blocking findings. */
        commentOnNonBlocking: z.boolean().default(false),
      })
      .strict()
      .prefault({}),
  })
  .strict();

export type Settings = z.infer<typeof settingsSchema>;

export const policySchema = z
  .object({
    version: z.literal(1).default(1),
    settings: settingsSchema.prefault({}),
    priorityRepositories: z.array(priorityGroupSchema).default([]),
    rules: z.array(ruleSchema).default([]),
  })
  .strict()
  .superRefine((policy, ctx) => {
    const seen = new Set<string>();
    policy.rules.forEach((rule, index) => {
      if (seen.has(rule.id)) {
        ctx.addIssue({ code: 'custom', path: ['rules', index, 'id'], message: `duplicate rule id "${rule.id}"` });
      }
      seen.add(rule.id);
    });
  });

export type Policy = z.infer<typeof policySchema>;

/**
 * Repository-local configuration. When a central policy is configured, repositories may only
 * add rules on top of it; they cannot relax settings or remove central rules.
 */
export const localConfigSchema = z
  .object({
    version: z.literal(1).default(1),
    rules: z.array(ruleSchema).default([]),
  })
  .strict();

export type LocalConfig = z.infer<typeof localConfigSchema>;
