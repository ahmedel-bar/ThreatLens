import type { Analyzer, Finding } from '../types';

type Result = Omit<Finding, 'cardId'>;
type DkimKey = { selector: string; bits: number | null };

export interface MailData {
  txtRecords?: string[][];
  spfLookups?: number;
  dmarcDomain?: string;
  dkim?: DkimKey[];
}

// Join each record's DNS chunks, keeping those that start with the given version tag
export const findRecords = (txtRecords: string[][] = [], prefix: string) =>
  txtRecords
    .map((chunks) => chunks.join(''))
    .filter((record) => record.toLowerCase().startsWith(prefix.toLowerCase()));

// Split a "tag=value; tag=value" record into an object keyed by lowercase tag
const parseTags = (record: string): Record<string, string | undefined> =>
  Object.fromEntries(
    record.split(';').map((part) => {
      const [tag, ...value] = part.split('=');
      return [tag.trim().toLowerCase(), value.join('=').trim()];
    }),
  );

// Whether mail from servers not in the SPF record fails, via -all, ~all or a redirect
const spfFailsUnlisted = (spf: string) => {
  const terms = spf.toLowerCase().split(' ');
  const all = terms.find((term) => ['all', '+all', '-all', '~all', '?all'].includes(term));
  if (all) return all === '-all' || all === '~all';
  return terms.some((term) => term.startsWith('redirect='));
};

// An SPF record of just "v=spf1 -all" says the domain sends no mail
export const sendsNoMail = (d: MailData) => {
  const spf = findRecords(d.txtRecords, 'v=spf1')[0] || '';
  return spf.toLowerCase().split(' ').filter(Boolean).join(' ') === 'v=spf1 -all';
};

const enforced = (policy = '') => ['quarantine', 'reject'].includes(policy.toLowerCase());

export const checkSpf = (d: MailData): Result => {
  const spf = findRecords(d.txtRecords, 'v=spf1');
  if (!spf.length) {
    return {
      severity: 'issue',
      title: 'No SPF record found',
      detail:
        'Publish a v=spf1 TXT record listing the servers allowed to send mail for this domain, or v=spf1 -all if it sends none',
    };
  }
  if (spf.length > 1) {
    return {
      severity: 'issue',
      title: 'Multiple SPF records found',
      detail: 'Receivers treat this as an SPF error, so merge them into a single v=spf1 record',
    };
  }
  if ((d.spfLookups ?? 0) > 10) {
    return {
      severity: 'issue',
      title: `SPF record needs ${d.spfLookups} DNS lookups, over the limit of 10`,
      detail:
        'Receivers stop at 10 and treat SPF as failed. Remove includes you no longer use, or replace some with ip4/ip6 ranges',
    };
  }
  if (!spfFailsUnlisted(spf[0])) {
    return {
      severity: 'warning',
      title: "SPF record doesn't fail unlisted senders",
      detail: 'End the record with -all or ~all so mail from servers it does not list fails SPF',
    };
  }
  return { severity: 'pass', title: 'SPF record published' };
};

export const checkDmarc = (d: MailData): Result => {
  const dmarc = findRecords(d.txtRecords, 'v=DMARC1');
  if (!dmarc.length) {
    return {
      severity: 'issue',
      title: 'No DMARC record found',
      detail:
        'Publish a v=DMARC1 TXT record on the _dmarc subdomain so receivers can act on spoofed mail',
    };
  }
  if (dmarc.length > 1) {
    return {
      severity: 'issue',
      title: 'Multiple DMARC records found',
      detail: 'Receivers ignore DMARC when there is more than one record, so merge them into one',
    };
  }
  const tags = parseTags(dmarc[0]);
  const tag = d.dmarcDomain && tags.sp ? 'sp' : 'p';
  const policy = tags[tag]?.toLowerCase();
  const from = d.dmarcDomain ? ` (from ${d.dmarcDomain})` : '';
  const percent = tags.pct ? Number(tags.pct) : 100;
  if (!enforced(policy)) {
    const next = `set ${tag}=quarantine or ${tag}=reject`;
    return {
      severity: 'warning',
      title: `DMARC policy is monitor-only${from}`,
      detail: tags.rua
        ? `Mail that fails DMARC is still delivered. Once reports show your own mail passing, ${next}`
        : `Mail that fails DMARC is still delivered, and no reports are sent. Add rua=mailto:<address> to get reports, then ${next}`,
    };
  }
  if (percent < 100) {
    return {
      severity: 'warning',
      title: `DMARC policy only applies to ${percent}% of failing mail${from}`,
      detail: 'Raise pct to 100, or remove it, so the policy applies to all failing mail',
    };
  }
  return { severity: 'pass', title: `DMARC policy: ${policy}${from}` };
};

const checkSubdomainDmarc = (d: MailData): Result | null => {
  const dmarc = findRecords(d.txtRecords, 'v=DMARC1');
  if (dmarc.length !== 1 || d.dmarcDomain) return null;
  const { p, sp } = parseTags(dmarc[0]);
  if (!sp || !enforced(p) || enforced(sp)) return null;
  return {
    severity: 'warning',
    title: "DMARC policy doesn't cover subdomains",
    detail: `sp=${sp} lets spoofed mail from subdomains through. Set sp=quarantine or sp=reject, or remove sp so subdomains follow p`,
  };
};

export const checkDkim = (d: MailData): Result => {
  const keys = d.dkim ?? [];
  const names = (list: DkimKey[]) => list.map((key) => key.selector).join(', ');
  const weak = keys.filter((key) => key.bits && key.bits < 1024);
  const short = keys.filter((key) => key.bits === 1024);
  if (!keys.length && sendsNoMail(d)) {
    return { severity: 'pass', title: "Domain sends no mail, so DKIM isn't needed" };
  }
  if (!keys.length) {
    return {
      severity: 'info',
      title: 'No DKIM key found on common selectors',
      detail:
        "DKIM can use any selector name, so it may be set up under one we don't check. " +
        'If not, publish a DKIM key so receivers can verify your mail',
    };
  }
  if (weak.length) {
    return {
      severity: 'issue',
      title: `DKIM key under 1024 bits (${names(weak)})`,
      detail: 'Receivers ignore signatures from keys this short. Replace it with a 2048-bit key',
    };
  }
  if (short.length) {
    return {
      severity: 'info',
      title: `1024-bit DKIM key (${names(short)})`,
      detail:
        '2048-bit keys are recommended. Rotate to a 2048-bit key, or ask your mail provider to',
    };
  }
  return { severity: 'pass', title: `DKIM key found (${names(keys)})` };
};

const mailConfig: Analyzer = (d) =>
  [checkSpf(d), checkDmarc(d), checkSubdomainDmarc(d), checkDkim(d)].filter((r) => r !== null);

export default mailConfig;
