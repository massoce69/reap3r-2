export type V2ScriptType = 'power_shell' | 'bash' | 'python';

export type V2RunScriptPayload = {
  script_type: V2ScriptType;
  content: string;
  args: string[];
  timeout_secs: number;
  run_as?: string;
  env: Record<string, string>;
  stream_output: boolean;
  signature: null;
};

export function toV2RunScriptPayload(payloadInput: any): V2RunScriptPayload {
  const interpreter = String(payloadInput?.interpreter || '').toLowerCase();
  const script = String(payloadInput?.script || '');
  const timeoutSec = Number(payloadInput?.timeout_sec ?? payloadInput?.timeout_secs ?? 300) || 300;
  const streamOutput = Boolean(payloadInput?.stream_output);
  const args = Array.isArray(payloadInput?.args) ? payloadInput.args.map((v: any) => String(v)) : [];

  const env: Record<string, string> = {};
  if (payloadInput?.env && typeof payloadInput.env === 'object') {
    for (const [k, v] of Object.entries(payloadInput.env)) {
      if (typeof k !== 'string') continue;
      if (typeof v === 'string') env[k] = v;
      else if (typeof v === 'number' || typeof v === 'boolean') env[k] = String(v);
    }
  }

  const runAs = typeof payloadInput?.run_as === 'string' ? payloadInput.run_as : undefined;

  let scriptType: V2ScriptType = 'power_shell';
  if (interpreter === 'bash' || interpreter === 'sh') scriptType = 'bash';
  if (interpreter === 'python') scriptType = 'python';
  if (interpreter === 'cmd') {
    scriptType = 'power_shell';
  }

  return {
    script_type: scriptType,
    content: interpreter === 'cmd' ? `cmd /c ${script}` : script,
    args,
    timeout_secs: Math.max(5, Math.min(3600, Math.trunc(timeoutSec))),
    run_as: runAs,
    env,
    stream_output: streamOutput,
    signature: null,
  };
}
