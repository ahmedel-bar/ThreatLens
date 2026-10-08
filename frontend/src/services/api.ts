import {
  IOCDetectionResult,
  InvestigationDetail,
  InvestigationSummary,
  ProviderCapability,
  IOCType,
} from '../types';

const API_BASE = '/api/v1';

export async function detectIoc(ioc: string): Promise<IOCDetectionResult> {
  const resp = await fetch(`${API_BASE}/detect`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ioc }),
  });
  if (!resp.ok) {
    throw new Error(`Detection failed: ${resp.statusText}`);
  }
  return resp.json();
}

export async function startInvestigation(
  ioc: string,
  iocType?: IOCType,
  maxDepth: number = 1
): Promise<InvestigationDetail> {
  const resp = await fetch(`${API_BASE}/investigations`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ioc, ioc_type: iocType, max_depth: maxDepth }),
  });
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({}));
    throw new Error(err.error?.message || err.detail || `Failed to start investigation`);
  }
  return resp.json();
}

export async function getInvestigation(id: string): Promise<InvestigationDetail> {
  const resp = await fetch(`${API_BASE}/investigations/${id}`);
  if (!resp.ok) {
    throw new Error(`Failed to fetch investigation ${id}`);
  }
  return resp.json();
}

export async function listInvestigations(): Promise<InvestigationSummary[]> {
  const resp = await fetch(`${API_BASE}/investigations?limit=50`);
  if (!resp.ok) {
    throw new Error(`Failed to fetch investigation history`);
  }
  return resp.json();
}

export async function pivotInvestigation(
  id: string,
  targetIoc: string,
  targetType?: IOCType
): Promise<InvestigationDetail> {
  const resp = await fetch(`${API_BASE}/investigations/${id}/pivot`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target_ioc: targetIoc, target_type: targetType, depth: 1 }),
  });
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({}));
    throw new Error(err.error?.message || err.detail || `Pivot failed`);
  }
  return resp.json();
}

export async function getProviders(): Promise<ProviderCapability[]> {
  const resp = await fetch(`${API_BASE}/providers`);
  if (!resp.ok) {
    throw new Error(`Failed to fetch providers`);
  }
  return resp.json();
}
