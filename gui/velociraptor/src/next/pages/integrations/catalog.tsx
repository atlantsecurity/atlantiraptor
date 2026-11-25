// What each integration needs. Credentials are never entered here: every
// integration points at a named secret managed under Admin › Secrets.
import { Mail, MessageSquare, Database, Rss } from 'lucide-react';

export interface Field {
  key: string;
  label: string;
  kind: 'text' | 'select' | 'secret';
  options?: string[];
  initial: string;
  help?: string;
  // For secret fields: which secret type, possibly depending on another field.
  secretType?: string | ((values: Record<string, string>) => string);
}

export interface Integration {
  id: string;
  title: string;
  icon: React.ReactNode;
  description: string;
  artifact: string;
  mode: 'forwarder' | 'import';
  fields: Field[];
  setup: string;
}

const LEVELS = ['critical', 'high', 'medium', 'low', 'info'];

export const INTEGRATIONS: Integration[] = [
  {
    id: 'webhook', title: 'Slack, Teams, Discord or webhook', icon: <MessageSquare />, mode: 'forwarder',
    artifact: 'Server.Alerts.Webhook',
    description: 'Posts each alert to a chat channel or any endpoint that accepts JSON.',
    setup: 'Create an HTTP Secrets secret with the webhook URL in url and method POST.',
    fields: [
      { key: 'Secret', label: 'Secret', kind: 'secret', secretType: 'HTTP Secrets', initial: '' },
      { key: 'Format', label: 'Message format', kind: 'select', options: ['slack', 'teams', 'discord', 'generic'], initial: 'slack' },
      { key: 'MinLevel', label: 'Minimum severity', kind: 'select', options: LEVELS, initial: 'medium' },
    ],
  },
  {
    id: 'email', title: 'Email', icon: <Mail />, mode: 'forwarder',
    artifact: 'Server.Alerts.Email',
    description: 'Emails alerts, at most once per alert name per period.',
    setup: 'Create an SMTP Creds secret with your mail server and login.',
    fields: [
      { key: 'Secret', label: 'Secret', kind: 'secret', secretType: 'SMTP Creds', initial: '' },
      { key: 'To', label: 'Recipients (comma separated)', kind: 'text', initial: '' },
      { key: 'MinLevel', label: 'Minimum severity', kind: 'select', options: LEVELS, initial: 'high' },
      { key: 'PeriodSeconds', label: 'Same alert at most every (seconds)', kind: 'text', initial: '600' },
      { key: 'MaxPerHour', label: 'At most this many emails per hour', kind: 'text', initial: '30' },
    ],
  },
  {
    id: 'siem', title: 'Splunk or Elastic', icon: <Database />, mode: 'forwarder',
    artifact: 'Server.Alerts.ForwardSIEM',
    description: 'Ships every alert to Splunk HEC or an Elasticsearch / OpenSearch index.',
    setup: 'Create a Splunk Creds secret (url, token, index) or an Elastic Creds secret (addresses and credentials).',
    fields: [
      { key: 'Target', label: 'Destination', kind: 'select', options: ['splunk', 'elastic'], initial: 'splunk' },
      { key: 'Secret', label: 'Secret', kind: 'secret', initial: '',
        secretType: v => (v.Target === 'elastic' ? 'Elastic Creds' : 'Splunk Creds') },
      { key: 'Index', label: 'Elastic index', kind: 'text', initial: 'atlantiraptor-alerts', help: 'Splunk uses the index in its secret.' },
    ],
  },
  {
    id: 'misp', title: 'MISP indicator feed', icon: <Rss />, mode: 'import',
    artifact: 'Server.Import.MISP',
    description: 'Pulls recent MISP indicators into an IOC sweep you can review before running.',
    setup: 'Create an HTTP Secrets secret: url https://<misp>/attributes/restSearch, method POST, and extra_headers "Authorization: <api key>".',
    fields: [
      { key: 'Secret', label: 'Secret', kind: 'secret', secretType: 'HTTP Secrets', initial: '' },
      { key: 'Days', label: 'Published in the last (days)', kind: 'text', initial: '30' },
      { key: 'OnlyIDS', label: 'Only indicators flagged for detection', kind: 'select', options: ['Y', 'N'], initial: 'Y' },
    ],
  },
];

export function secretTypeOf(f: Field, values: Record<string, string>): string {
  return typeof f.secretType === 'function' ? f.secretType(values) : f.secretType ?? '';
}
