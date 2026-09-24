export type FileStatus = 'added' | 'removed' | 'modified' | 'renamed' | 'copied' | 'changed' | 'unchanged';

export interface DiffLine {
  type: 'added' | 'removed' | 'context';
  content: string;
  /** Line number in the old file (removed and context lines). */
  oldLine?: number;
  /** Line number in the new file (added and context lines). */
  newLine?: number;
}

export interface Hunk {
  header: string;
  oldStart: number;
  newStart: number;
  lines: DiffLine[];
}

export interface ChangedFile {
  filename: string;
  previousFilename?: string;
  status: FileStatus;
  additions: number;
  deletions: number;
  /** Blob SHA of the file at the head commit, when known. */
  sha?: string;
  hunks: Hunk[];
  /** False for binary files or diffs too large for GitHub to return. */
  patchAvailable: boolean;
}
