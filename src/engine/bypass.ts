/** A bypass recorded by the inspector after an authorised user ran the bypass command. */
export interface BypassRecord {
  v: 1;
  /** ID of the comment containing the bypass command. */
  commentId: number;
  user: string;
  reason: string;
  /** Head commit at the time of the bypass. */
  sha: string;
  /** Blocking (rule, file) keys the bypass covered. */
  keys: string[];
  at: string;
}

const RECORD_MARKER = 'security-inspector:bypass';
export const REPORT_MARKER = '<!-- security-inspector:report -->';

/** Parses a comment for a slash command. Returns the text after the command, or undefined. */
export function parseCommand(body: string, command: string): string | undefined {
  const trimmed = body.trim();
  if (!trimmed.toLowerCase().startsWith(command.toLowerCase())) return undefined;
  const rest = trimmed.slice(command.length);
  if (rest.length > 0 && !/^\s/.test(rest)) return undefined; // e.g. "/security-bypassed"
  return rest.trim();
}

export function validateReason(reason: string, minLength: number): string | undefined {
  if (reason.length < minLength) {
    return minLength === 1 ? 'A justification is required.' : `A justification of at least ${minLength} characters is required.`;
  }
  return undefined;
}

export function encodeBypassRecord(record: BypassRecord): string {
  const payload = Buffer.from(JSON.stringify(record), 'utf8').toString('base64');
  return `<!-- ${RECORD_MARKER} ${payload} -->`;
}

export function decodeBypassRecord(body: string): BypassRecord | undefined {
  const match = new RegExp(`<!-- ${RECORD_MARKER} ([A-Za-z0-9+/=]+) -->`).exec(body);
  if (!match) return undefined;
  try {
    const record = JSON.parse(Buffer.from(match[1]!, 'base64').toString('utf8')) as Partial<BypassRecord>;
    if (
      record.v !== 1 ||
      typeof record.commentId !== 'number' ||
      typeof record.user !== 'string' ||
      typeof record.reason !== 'string' ||
      typeof record.sha !== 'string' ||
      !Array.isArray(record.keys) ||
      typeof record.at !== 'string'
    ) {
      return undefined;
    }
    return record as BypassRecord;
  } catch {
    return undefined;
  }
}
