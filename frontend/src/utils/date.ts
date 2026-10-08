/**
 * ThreatLens Timestamp Normalization and Formatting Utility
 * Converts Unix timestamps (seconds or milliseconds), ISO strings, and raw dates
 * into human-readable UTC date and time:
 * Example: "May 12, 2025 — 11:07 UTC"
 */

const MONTH_NAMES = [
  'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
  'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'
];

export function formatTimestamp(val: string | number | null | undefined): string {
  if (val === null || val === undefined || val === '') {
    return '—';
  }

  let date: Date;

  try {
    if (typeof val === 'number') {
      // If it's in seconds (typical Unix timestamp e.g. 1494587220), convert to ms
      if (val < 10000000000) {
        date = new Date(val * 1000);
      } else {
        date = new Date(val);
      }
    } else if (typeof val === 'string') {
      const trimmed = val.trim();
      // Check if the string is numeric digits (Unix epoch)
      if (/^\d+$/.test(trimmed)) {
        const num = parseInt(trimmed, 10);
        if (num < 10000000000) {
          date = new Date(num * 1000);
        } else {
          date = new Date(num);
        }
      } else {
        date = new Date(trimmed);
      }
    } else {
      return '—';
    }

    if (isNaN(date.getTime())) {
      return typeof val === 'string' ? val : '—';
    }

    const year = date.getUTCFullYear();
    const month = MONTH_NAMES[date.getUTCMonth()];
    const day = date.getUTCDate();
    const hours = String(date.getUTCHours()).padStart(2, '0');
    const minutes = String(date.getUTCMinutes()).padStart(2, '0');

    return `${month} ${day}, ${year} — ${hours}:${minutes} UTC`;
  } catch {
    return typeof val === 'string' ? val : '—';
  }
}

export function formatRelativeOrDate(val: string | number | null | undefined): string {
  return formatTimestamp(val);
}
