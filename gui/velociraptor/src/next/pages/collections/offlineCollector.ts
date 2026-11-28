// Builds the Server.Utils.CreateCollector request for the offline
// collector builder. Kept free of app imports so it can be unit tested.

export const COLLECTOR_ARTIFACT = 'Server.Utils.CreateCollector';

export const COLLECTOR_OS = ['Windows', 'WindowsArm64', 'Linux', 'MacOS', 'MacOSArm', 'Generic'] as const;
export type CollectorOs = typeof COLLECTOR_OS[number];

export type CollectorTarget = 'ZIP' | 'S3' | 'GCS' | 'Azure' | 'SMBShare' | 'SFTP';
export type CollectorEncryption = 'None' | 'X509' | 'Password';

export interface TargetField { key: string; label: string; secret?: boolean; multiline?: boolean; placeholder?: string; required?: boolean }

// The fields each upload target needs, as the CreateCollector artifact
// reads them from target_args.
export const TARGET_FIELDS: Record<CollectorTarget, TargetField[]> = {
  ZIP: [],
  S3: [
    { key: 'bucket', label: 'Bucket', required: true },
    { key: 'region', label: 'Region', placeholder: 'us-east-1' },
    { key: 'credentialsKey', label: 'Access key ID' },
    { key: 'credentialsSecret', label: 'Secret access key', secret: true },
    { key: 'credentialsToken', label: 'Session token', secret: true },
    { key: 'endpoint', label: 'Endpoint (for S3-compatible storage)', placeholder: 'https://…' },
    { key: 's3UploadRoot', label: 'Folder in the bucket' },
    { key: 'serverSideEncryption', label: 'Server-side encryption', placeholder: 'aws:kms or AES256' },
    { key: 'kmsEncryptionKey', label: 'KMS key ID' },
  ],
  GCS: [
    { key: 'bucket', label: 'Bucket', required: true },
    { key: 'GCSKey', label: 'Service account key (JSON)', secret: true, multiline: true, required: true },
  ],
  Azure: [
    { key: 'sas_url', label: 'Container SAS URL', secret: true, required: true, placeholder: 'https://account.blob.core.windows.net/container?sv=…' },
  ],
  SMBShare: [
    { key: 'server_address', label: 'Share', required: true, placeholder: '//server/share/folder' },
    { key: 'username', label: 'User name' },
    { key: 'password', label: 'Password', secret: true },
  ],
  SFTP: [
    { key: 'endpoint', label: 'Server and port', required: true, placeholder: 'sftp.example.com:22' },
    { key: 'user', label: 'User name', required: true },
    { key: 'path', label: 'Folder on the server' },
    { key: 'privatekey', label: 'Private key', secret: true, multiline: true, required: true },
    { key: 'hostkey', label: 'Server host key', placeholder: 'ssh-ed25519 AAAA…' },
  ],
};

export interface CollectorForm {
  os: CollectorOs;
  artifacts: string[];
  // Changed parameters only, per artifact.
  parameters: Record<string, Record<string, string>>;
  target: CollectorTarget;
  targetArgs: Record<string, string>;
  encryption: CollectorEncryption;
  publicKey: string;
  password: string;
  format: 'jsonl' | 'csv';
  filenameTemplate: string;
  collectorFilename: string;
  outputDirectory: string;
  tempdir: string;
  level: string;
  concurrency: string;
  cpuLimit: string;
  progressTimeout: string;
  timeout: string;
  prompt: boolean;
  deleteAtExit: boolean;
}

export function defaultCollectorForm(): CollectorForm {
  return {
    os: 'Windows', artifacts: [], parameters: {}, target: 'ZIP', targetArgs: {},
    encryption: 'None', publicKey: '', password: '', format: 'jsonl',
    filenameTemplate: 'Collection-%Hostname%-%TIMESTAMP%', collectorFilename: '',
    outputDirectory: '', tempdir: '', level: '5', concurrency: '2', cpuLimit: '0',
    progressTimeout: '1800', timeout: '0', prompt: false, deleteAtExit: false,
  };
}

/** What is still missing before the collector can be built. */
export function collectorProblems(f: CollectorForm): string[] {
  const out: string[] = [];
  if (!f.artifacts.length) out.push('Pick at least one artifact.');
  for (const field of TARGET_FIELDS[f.target]) {
    if (field.required && !(f.targetArgs[field.key] ?? '').trim()) out.push(`${field.label} is required.`);
  }
  if (f.encryption === 'Password' && !f.password) out.push('Enter the password that will protect the collection.');
  for (const [label, v] of [['Compression level', f.level], ['Concurrency', f.concurrency], ['CPU limit', f.cpuLimit],
    ['Progress timeout', f.progressTimeout], ['Timeout', f.timeout]] as const) {
    if (v.trim() && !/^\d+$/.test(v.trim())) out.push(`${label} must be a whole number.`);
  }
  if (f.level.trim() && Number(f.level) > 9) out.push('Compression level is 0 to 9.');
  if (f.cpuLimit.trim() && Number(f.cpuLimit) > 100) out.push('CPU limit is 0 to 100.');
  return out;
}

type Env = { key: string; value: string }[];

export function collectorRequest(f: CollectorForm): { artifacts: string[]; specs: { artifact: string; parameters: { env: Env } }[] } {
  const env: Env = [];
  const set = (key: string, value: string | undefined) => {
    if (value !== undefined && value !== '') env.push({ key, value });
  };
  const yn = (b: boolean) => (b ? 'Y' : 'N');

  // Only the fields of the chosen target, so no stray secrets are sent.
  const targetArgs: Record<string, string> = {};
  for (const field of TARGET_FIELDS[f.target]) {
    const v = (f.targetArgs[field.key] ?? '').trim();
    if (v) targetArgs[field.key] = field.multiline ? f.targetArgs[field.key] : v;
  }
  const params: Record<string, Record<string, string>> = {};
  for (const a of f.artifacts) if (f.parameters[a] && Object.keys(f.parameters[a]).length) params[a] = f.parameters[a];

  set('OS', f.os);
  set('artifacts', JSON.stringify(f.artifacts));
  set('parameters', JSON.stringify(params));
  set('target', f.target);
  set('target_args', JSON.stringify(targetArgs));
  set('encryption_scheme', f.encryption);
  set('encryption_args', JSON.stringify(
    f.encryption === 'X509' ? { public_key: f.publicKey.trim() }
      : f.encryption === 'Password' ? { password: f.password } : {}));
  set('opt_format', f.format);
  set('opt_filename_template', f.filenameTemplate.trim());
  set('opt_collector_filename', f.collectorFilename.trim());
  set('opt_output_directory', f.outputDirectory.trim());
  set('opt_tempdir', f.tempdir.trim());
  set('opt_level', f.level.trim());
  set('opt_concurrency', f.concurrency.trim());
  set('opt_cpu_limit', f.cpuLimit.trim());
  set('opt_progress_timeout', f.progressTimeout.trim());
  set('opt_timeout', f.timeout.trim());
  set('opt_prompt', yn(f.prompt));
  set('opt_delete_at_exit', yn(f.deleteAtExit));

  return { artifacts: [COLLECTOR_ARTIFACT], specs: [{ artifact: COLLECTOR_ARTIFACT, parameters: { env } }] };
}
