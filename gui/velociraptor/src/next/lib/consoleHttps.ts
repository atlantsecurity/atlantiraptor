// Client for /api/v1/atl/https: serving the console at the customer's
// own host name with a browser-trusted certificate.
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import * as api from './api';

export type CertMode = 'certificate' | 'letsencrypt';

export interface HttpsSettings {
  enabled: boolean;
  hostname: string;
  bind_address?: string;
  port: number;
  mode: CertMode;
  redirect_http: boolean;
  email?: string;
  cert_pem?: string;
  updated?: number;
  updated_by?: string;
}

export interface CertInfo {
  subject: string;
  issuer: string;
  names: string[];
  not_before: number;
  not_after: number;
  trusted: boolean;
  trust_error?: string;
  self_signed?: boolean;
  fingerprint_sha256?: string;
  chain_length: number;
  key_algorithm: string;
}

export interface HttpsView {
  available: boolean;
  unavailable_reason?: string;
  active: HttpsSettings;
  pending?: { settings: HttpsSettings; expires: number; by: string };
  serving: '' | 'active' | 'pending';
  url?: string;
  cert: { status?: '' | 'ready' | 'issuing' | 'failed'; error?: string; info?: CertInfo };
  recovery_url: string;
  authenticator?: string;
  public_url?: string;
  last_error?: string;
  reserved_ports?: number[];
  dns?: string[];
  dns_error?: string;
}

export interface HttpsUpload {
  cert_pem?: string;
  key_pem?: string;
  pfx_base64?: string;
  pfx_password?: string;
}

export interface ApplyRequest {
  action: 'apply';
  settings: Partial<HttpsSettings>;
  upload?: HttpsUpload;
  keep_certificate?: boolean;
  confirm?: boolean;
}

type Action = ApplyRequest | { action: 'confirm' | 'revert' | 'disable' };

const KEY = ['console-https'];

export function useConsoleHttps(poll = false) {
  return useQuery({
    queryKey: KEY,
    queryFn: ({ signal }) => api.get<HttpsView>('v1/atl/https', {}, signal),
    refetchInterval: poll ? 3000 : false,
  });
}

export function useConsoleHttpsAction() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (a: Action) => api.post<{ state: HttpsView; warnings?: string[] }>('v1/atl/https', a),
    onSuccess: d => qc.setQueryData(KEY, d.state),
    onError: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}

export function checkDns(hostname: string) {
  return api.post<{ hostname: string; dns?: string[]; dns_error?: string }>('v1/atl/https', { action: 'dns', hostname });
}

// Can this browser open the new address, with a certificate it trusts?
// A no-cors request resolves whatever the server answers (even a sign-in
// page) and rejects on a network or certificate error, which is exactly
// the question. Nothing is read from the response.
export async function probe(url: string, timeoutMs = 8000): Promise<boolean> {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const u = new URL(url);
    u.search = `probe=${Date.now()}`;
    await fetch(u.href, { mode: 'no-cors', cache: 'no-store', credentials: 'omit', signal: ctl.signal });
    return true;
  } catch {
    return false;
  } finally {
    clearTimeout(t);
  }
}

export async function fileToBase64(f: File): Promise<string> {
  const buf = new Uint8Array(await f.arrayBuffer());
  let s = '';
  for (let i = 0; i < buf.length; i += 0x8000) s += String.fromCharCode(...buf.subarray(i, i + 0x8000));
  return btoa(s);
}

export const daysLeft = (notAfter: number, now = Date.now()) => Math.floor((notAfter * 1000 - now) / 86400000);

// Sign-in methods that send the browser back to GUI.public_url, so a new
// address only works for sign-in once public_url points at it.
export function redirectsToPublicUrl(authenticator?: string): boolean {
  return !!authenticator && !['basic', 'certs'].includes(authenticator);
}
