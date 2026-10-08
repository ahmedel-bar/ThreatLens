import type { Analyzer } from '../types';

const ADVERTISING = ['Advertising', 'Adult Advertising'];

const names = (list: any[]): string => list.map((t) => t.name).join(', ');

// Warn on ad trackers, and note any analytics or other tracking the page reports to
const trackers: Analyzer = (d) => {
  const list: any[] = Array.isArray(d.trackers) ? d.trackers : [];
  const others: string[] = Array.isArray(d.otherTrackers) ? d.otherTrackers : [];
  const ads = list.filter((t) => ADVERTISING.includes(t.category));
  const analytics = list.filter((t) => t.category === 'Site Analytics');
  const out: ReturnType<Analyzer> = [];
  if (ads.length) {
    out.push({
      severity: 'warning',
      title: `Loads ${ads.length} advertising tracker(s)`,
      detail: names(ads),
    });
  }
  if (analytics.length) {
    out.push({
      severity: 'info',
      title: `Reports to ${analytics.length} analytics service(s)`,
      detail: names(analytics),
    });
  }
  if (others.length) {
    out.push({
      severity: 'info',
      title: `Contacts ${others.length} other tracking host(s)`,
      detail: others.join(', '),
    });
  }
  if (!out.length) out.push({ severity: 'pass', title: 'No trackers found' });
  return out;
};

export default trackers;
