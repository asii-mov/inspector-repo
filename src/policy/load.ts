import { parse as parseYaml } from 'yaml';
import type { ZodError } from 'zod';
import { policySchema, ruleSchema, type Policy, type Rule } from './schema.js';

export class PolicyError extends Error {
  constructor(
    message: string,
    readonly source: string,
  ) {
    super(`${source}: ${message}`);
    this.name = 'PolicyError';
  }
}

function formatZodError(error: ZodError): string {
  return error.issues
    .map((issue) => {
      const path = issue.path.length > 0 ? issue.path.join('.') : '(root)';
      return `  - ${path}: ${issue.message}`;
    })
    .join('\n');
}

function parseDocument(text: string, source: string): unknown {
  try {
    return parseYaml(text) ?? {};
  } catch (error) {
    throw new PolicyError(`invalid YAML: ${(error as Error).message}`, source);
  }
}

/** Parses and validates a full policy document (YAML or JSON). */
export function parsePolicy(text: string, source: string): Policy {
  const result = policySchema.safeParse(parseDocument(text, source));
  if (!result.success) {
    throw new PolicyError(`invalid policy:\n${formatZodError(result.error)}`, source);
  }
  for (const rule of result.data.rules) validateRegexes(rule, source);
  return result.data;
}

export interface LocalRulesResult {
  rules: Rule[];
  warnings: string[];
}

/**
 * Parses a repository-local configuration that sits on top of a central policy.
 * Only `rules` are honoured; anything else is reported as a warning and ignored so that a
 * repository cannot relax the security team's settings.
 */
export function parseLocalRules(text: string, source: string): LocalRulesResult {
  const document = parseDocument(text, source);
  const warnings: string[] = [];
  if (document === null || typeof document !== 'object' || Array.isArray(document)) {
    throw new PolicyError('expected a mapping at the top level', source);
  }
  const record = document as Record<string, unknown>;
  for (const key of Object.keys(record)) {
    if (key !== 'rules' && key !== 'version') {
      warnings.push(`${source}: "${key}" is ignored because a central policy is configured; repositories may only add rules.`);
    }
  }
  const result = ruleSchema.array().default([]).safeParse(record.rules);
  if (!result.success) {
    throw new PolicyError(`invalid rules:\n${formatZodError(result.error)}`, source);
  }
  for (const rule of result.data) validateRegexes(rule, source);
  return { rules: result.data, warnings };
}

/** Adds repository-local rules to a policy. Local rules can never replace central ones. */
export function mergeLocalRules(policy: Policy, localRules: Rule[], source: string): { policy: Policy; warnings: string[] } {
  const warnings: string[] = [];
  const ids = new Set(policy.rules.map((rule) => rule.id));
  const added: Rule[] = [];
  for (const rule of localRules) {
    if (ids.has(rule.id)) {
      warnings.push(`${source}: rule "${rule.id}" is already defined by the central policy; the local definition is ignored.`);
      continue;
    }
    ids.add(rule.id);
    added.push(rule);
  }
  return { policy: { ...policy, rules: [...policy.rules, ...added] }, warnings };
}

function validateRegexes(rule: Rule, source: string): void {
  for (const pattern of [...rule.fileContent, ...rule.content]) {
    const { pattern: body, flags } = typeof pattern === 'string' ? { pattern, flags: '' } : pattern;
    try {
      new RegExp(body, flags);
    } catch (error) {
      throw new PolicyError(`rule "${rule.id}" has an invalid content pattern /${body}/: ${(error as Error).message}`, source);
    }
  }
}
