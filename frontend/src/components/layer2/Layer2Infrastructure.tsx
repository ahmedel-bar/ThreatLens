import React, { useState } from 'react';
import {
  Layer2Infrastructure as Layer2Type,
  ServiceInfo,
  CertInfo,
  TTPTechnique,
  PulseMetadata,
  ThreatAttribution,
  PassiveDnsRecord,
  TTPTacticNode,
  TTPTechniqueNode,
  TTPSubTechnique,
  HistoricalWhoisRecord,
} from '../../types';
import { formatTimestamp } from '../../utils/date';
import {
  Network,
  Globe2,
  Server,
  Lock,
  FileText,
  Calendar,
  ExternalLink,
  Cpu,
  Radio,
  Clock,
  Terminal,
  Copy,
  Check,
  ShieldAlert,
  ChevronDown,
  ChevronUp,
  ChevronRight,
  Crosshair,
  Activity,
  Radar,
  Eye,
  Search,
  AlertTriangle,
  History,
  FolderGit2,
  ShieldCheck,
  Layers,
  Shield,
  Mail,
  Link2,
  Compass,
  Cookie,
  Code,
  Share2,
  Zap,
} from 'lucide-react';

interface Layer2Props {
  layer2: Layer2Type;
}

const ProvenanceBadges: React.FC<{ sources?: string[] }> = ({ sources }) => {
  if (!sources || sources.length === 0) return null;

  const getBadgeStyle = (src: string) => {
    const s = src.toLowerCase();
    if (s.includes('webcheck') || s.includes('web-check')) return 'bg-violet-500/10 text-violet-400 border-violet-500/30';
    if (s.includes('shodan')) return 'bg-rose-500/10 text-rose-400 border-rose-500/30';
    if (s.includes('censys')) return 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30';
    if (s.includes('virustotal')) return 'bg-blue-500/10 text-blue-400 border-blue-500/30';
    if (s.includes('otx')) return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
    if (s.includes('threatfox')) return 'bg-orange-500/10 text-orange-400 border-orange-500/30';
    if (s.includes('malwarebazaar')) return 'bg-teal-500/10 text-teal-400 border-teal-500/30';
    if (s.includes('pulsedive')) return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
    if (s.includes('criminalip') || s.includes('criminal_ip') || s.includes('criminal ip')) return 'bg-red-500/10 text-red-400 border-red-500/30';
    if (s.includes('mnemonic') || s.includes('passivedns')) return 'bg-sky-500/10 text-sky-400 border-sky-500/30';
    if (s.includes('dns')) return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
    if (s.includes('rdap') || s.includes('whois')) return 'bg-purple-500/10 text-purple-400 border-purple-500/30';
    if (s.includes('ipinfo')) return 'bg-blue-500/10 text-blue-400 border-blue-500/30';
    if (s.includes('urlscan')) return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
    return 'bg-gray-500/10 text-gray-400 border-gray-500/30';
  };

  return (
    <div className="flex flex-wrap items-center gap-1">
      {sources.map((src, i) => (
        <span
          key={i}
          className={`text-[9px] font-mono uppercase px-1.5 py-0.5 rounded border ${getBadgeStyle(src)}`}
        >
          {src}
        </span>
      ))}
    </div>
  );
};

interface ConsolidatedAttribution extends ThreatAttribution {
  displayTitle: string;
}

const CANONICAL_MALWARE_NAMES: Record<string, string> = {
  baza: 'BazarLoader',
  bazaloader: 'BazarLoader',
  bazarloader: 'BazarLoader',
  bazloader: 'BazarLoader',
  'baza loader': 'BazarLoader',
  'bazar loader': 'BazarLoader',
  glassrat: 'GlassRAT',
  agenttesla: 'Agent Tesla',
  redline: 'RedLine Stealer',
  redlinestealer: 'RedLine Stealer',
  remcos: 'Remcos RAT',
  remcosrat: 'Remcos RAT',
  asyncrat: 'AsyncRAT',
  njrat: 'njRAT',
  cobaltstrike: 'Cobalt Strike',
  sliver: 'Sliver C2',
  emotet: 'Emotet',
  qakbot: 'QakBot',
  trickbot: 'TrickBot',
  lockbit: 'LockBit',
  wannacry: 'WannaCry',
};

function isAvSignature(name?: string): boolean {
  if (!name) return false;
  const s = name.trim();
  if (/^mal[\s/._-]*html[\s/._-]*gen/i.test(s)) return true;
  if (/^(?:win32|win64|msil|vbs|js|html|pdf)[\s/._:-]/i.test(s)) return true;
  if (/^(?:heur|troj|backdoor|generic|hacktool)[\s/._:-]/i.test(s)) return true;
  if (/^[A-Za-z0-9_-]+![A-Za-z0-9]+$/i.test(s)) return true;
  return false;
}

const isIpStr = (s?: string): boolean => {
  if (!s) return false;
  const clean = s.trim();
  if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(clean)) return true;
  if (clean.includes(':') && /^[0-9a-fA-F:]+$/.test(clean)) return true;
  return false;
};

const formatDnsRecordValue = (val: string): string => {
  if (!val) return '';
  const s = val.trim();
  if (s.startsWith('{') && s.endsWith('}')) {
    try {
      const parsed = JSON.parse(s);
      if (typeof parsed === 'object' && parsed !== null) {
        return Object.entries(parsed)
          .map(([k, v]) => `${k.replace(/_/g, ' ')}: ${v}`)
          .join(' | ');
      }
    } catch {
      // not json
    }
  }
  return s;
};

function isGenericClassification(name?: string): boolean {
  if (!name) return false;
  if (isAvSignature(name)) return true;
  const s = name.trim().toLowerCase();
  const norm = s.replace(/[\s_-]+/g, ' ').trim();
  if ([
    'generic', 'trojan generic', 'trojan generickd', 'generic detection',
    'generic malware classification', 'generic malware', 'generic threat', 'unknown', 'malicious',
    'suspicious', 'malware', 'malware download', 'malware downloading', 'malware delivery',
    'malware activity', 'malware dropper', 'malware loader', 'payload', 'payload download',
    'payload delivery', 'malicious payload', 'trojan', 'trojan activity', 'trojan downloader',
    'trojan dropper', 'trojan download', 'virus', 'worm', 'backdoor',
    'dropper', 'downloader', 'sample', 'threat', 'unclassified',
    'c2', 'c2 activity', 'c2 communication', 'botnet c2', 'command and control',
    'command & control', 'phishing', 'phishing campaign', 'malicious activity',
    'suspicious activity', 'malicious behavior', 'suspicious behavior', 'exploit', 'exploit kit'
  ].includes(norm)) {
    return true;
  }
  if (/^(?:trojan\.)?generic(?:\.[a-z0-9]+)?$/.test(s)) return true;
  if (/^generic(?:\.[a-z0-9]+)?$/.test(s)) return true;
  if (/^trojan:win(?:32|64)\/generic.*$/.test(s)) return true;
  if (/^generic\s+(?:malware|detection|classification|trojan|family|threat).*$/.test(s)) return true;
  if (/^(?:malware|trojan|virus|worm|backdoor|dropper|downloader|ransomware|infostealer|stealer|miner|botnet|payload|exploit)$/.test(s)) return true;
  if (/^(?:unknown|suspicious|malicious|sample|threat|unclassified)$/.test(s)) return true;
  if (/^heur(?:istic)?(?::|\.|\s).*$/.test(s)) return true;
  if (/^malware[\s_-]*(?:download|downloader|downloading|activity|delivery|traffic|beacon|sample|loader|dropper).*$/.test(s)) return true;
  if (/^trojan[\s_-]*(?:activity|downloader|dropper|download|generic).*$/.test(s)) return true;
  if (/^(?:botnet|c2)[\s_-]*(?:c2|activity|traffic|communication|server).*$/.test(s)) return true;
  if (/^(?:command[\s_-]*and[\s_-]*control|command[\s_-]*&[\s_-]*control)$/.test(s)) return true;
  if (/^(?:malicious|suspicious)[\s_-]*(?:activity|behavior|traffic|payload|download|domain|ip|url).*$/.test(s)) return true;
  if (/^(?:payload|payload[\s_-]*delivery|payload[\s_-]*download|exploit[\s_-]*kit|phishing|credential[\s_-]*harvesting).*$/.test(s)) return true;
  return false;
}

function isCveIdentifier(name?: string): boolean {
  if (!name) return false;
  return /^CVE-\d{4}-\d{4,8}$/i.test(name.trim());
}

function consolidateThreatAttributions(rawList: ThreatAttribution[]): ConsolidatedAttribution[] {
  if (!rawList || rawList.length === 0) return [];

  const genericTokens = new Set([
    'rat', 'trojan', 'malware', 'backdoor', 'unknown', 'virus', 'worm',
    'stealer', 'generic', 'detection', 'sample', 'threat', 'suspicious', 'malicious',
    'payload', 'download', 'downloader', 'c2', 'unclassified', 'activity', 'behavior'
  ]);

  const getTokens = (attr: ThreatAttribution): Set<string> => {
    const tokens = new Set<string>();
    const addToken = (str?: string) => {
      if (!str) return;
      const clean = str.trim().toLowerCase();
      if (clean && !genericTokens.has(clean) && !isGenericClassification(clean) && !isCveIdentifier(clean)) {
        tokens.add(clean);
        const alpha = clean.replace(/[^a-z0-9]/g, '');
        if (alpha && !genericTokens.has(alpha) && !isGenericClassification(alpha) && !isCveIdentifier(alpha)) {
          tokens.add(alpha);
          if (CANONICAL_MALWARE_NAMES[alpha]) {
            tokens.add(CANONICAL_MALWARE_NAMES[alpha].toLowerCase());
          }
        }
      }
    };

    addToken(attr.malware_family);
    addToken(attr.threat_actor);
    (attr.aliases || []).forEach(addToken);
    (attr.malware_names || []).forEach(addToken);
    return tokens;
  };

  const getClassificationKey = (attr: ThreatAttribution): string => {
    if (attr.detection_classification && !attr.malware_family && !attr.threat_actor) {
      return attr.detection_classification.trim().toLowerCase().replace(/[^a-z0-9]/g, '');
    }
    return '';
  };

  const getCveKey = (attr: ThreatAttribution): string => {
    if (attr.cves && attr.cves.length > 0 && !attr.malware_family && !attr.threat_actor && !attr.detection_classification) {
      return attr.cves[0].trim().toUpperCase();
    }
    return '';
  };

  const getToolKey = (attr: ThreatAttribution): string => {
    if (attr.entity_type === 'tool' || (attr.tool && !attr.malware_family && !attr.threat_actor)) {
      return (attr.tool || attr.canonical_name || '').trim().toLowerCase().replace(/[^a-z0-9]/g, '');
    }
    return '';
  };

  const getThreatAssocKey = (attr: ThreatAttribution): string => {
    if (attr.entity_type === 'threat_association' || (attr.threat_association && !attr.malware_family && !attr.threat_actor)) {
      return (attr.threat_association || attr.canonical_name || '').trim().toLowerCase().replace(/[^a-z0-9]/g, '');
    }
    return '';
  };

  // Preprocess items: route CVEs to cves, AV signatures to provider_detection_name, generic malware_family to detection_classification
  const normalizedList: ThreatAttribution[] = rawList.map((raw) => {
    const item = { ...raw };
    if (item.entity_type === 'tool' || item.tool) {
      item.tool = item.tool || item.canonical_name;
    }
    if (item.entity_type === 'threat_association' || item.threat_association) {
      item.threat_association = item.threat_association || item.canonical_name;
    }
    if (item.malware_family) {
      if (isCveIdentifier(item.malware_family)) {
        const cve = item.malware_family.trim().toUpperCase();
        item.cves = Array.from(new Set([...(item.cves || []), cve]));
        item.malware_family = undefined;
      } else if (isAvSignature(item.malware_family)) {
        if (!item.provider_detection_name) {
          item.provider_detection_name = item.malware_family;
        }
        item.malware_family = undefined;
      } else if (isGenericClassification(item.malware_family)) {
        if (!item.detection_classification) {
          item.detection_classification = item.malware_family;
        }
        item.malware_family = undefined;
      } else {
        const alpha = item.malware_family.trim().toLowerCase().replace(/[^a-z0-9]/g, '');
        if (CANONICAL_MALWARE_NAMES[alpha]) {
          const canon = CANONICAL_MALWARE_NAMES[alpha];
          if (item.malware_family !== canon) {
            item.aliases = [...(item.aliases || []), item.malware_family];
            item.malware_family = canon;
          }
        }
      }
    }
    if (item.threat_actor) {
      if (isCveIdentifier(item.threat_actor) || isGenericClassification(item.threat_actor)) {
        item.threat_actor = undefined;
      }
    }
    return item;
  });

  const clusters: ThreatAttribution[] = [];

  for (const item of normalizedList) {
    const itemTokens = getTokens(item);
    const itemCampaign = (item.campaign || '').trim().toLowerCase();
    const itemActor = (item.threat_actor || '').trim().toLowerCase();
    const itemClassKey = getClassificationKey(item);
    const itemCveKey = getCveKey(item);
    const itemToolKey = getToolKey(item);
    const itemThreatAssocKey = getThreatAssocKey(item);

    // Check if item matches any existing cluster
    let matchedClusterIndex = -1;
    for (let i = 0; i < clusters.length; i++) {
      const c = clusters[i];
      const cCampaign = (c.campaign || '').trim().toLowerCase();
      const cActor = (c.threat_actor || '').trim().toLowerCase();
      const cClassKey = getClassificationKey(c);
      const cCveKey = getCveKey(c);
      const cToolKey = getToolKey(c);
      const cThreatAssocKey = getThreatAssocKey(c);
      const cTokens = getTokens(c);

      // Match 0a: Both are standalone classifications with same normalized key
      if (itemClassKey && cClassKey && itemClassKey === cClassKey) {
        matchedClusterIndex = i;
        break;
      }

      // Match 0b: Both are standalone CVEs with same normalized key
      if (itemCveKey && cCveKey && itemCveKey === cCveKey) {
        matchedClusterIndex = i;
        break;
      }

      // Match 0c: Both are tools with same normalized key
      if (itemToolKey && cToolKey && itemToolKey === cToolKey) {
        matchedClusterIndex = i;
        break;
      }

      // Match 0d: Both are threat associations with same normalized key
      if (itemThreatAssocKey && cThreatAssocKey && itemThreatAssocKey === cThreatAssocKey) {
        matchedClusterIndex = i;
        break;
      }

      // Do NOT cluster a standalone generic classification, standalone CVE, tool, or threat association with anything else
      if (itemClassKey || cClassKey || itemCveKey || cCveKey || itemToolKey || cToolKey || itemThreatAssocKey || cThreatAssocKey) {
        continue;
      }

      // If both items have malware families and they are different, NEVER cluster them together
      if (item.malware_family && c.malware_family) {
        const itemFamAlpha = item.malware_family.trim().toLowerCase().replace(/[^a-z0-9]/g, '');
        const cFamAlpha = c.malware_family.trim().toLowerCase().replace(/[^a-z0-9]/g, '');
        const itemAliases = new Set((item.aliases || []).map(a => a.toLowerCase().replace(/[^a-z0-9]/g, '')));
        const cAliases = new Set((c.aliases || []).map(a => a.toLowerCase().replace(/[^a-z0-9]/g, '')));

        const isSameFamily = (itemFamAlpha === cFamAlpha) ||
          cAliases.has(itemFamAlpha) ||
          itemAliases.has(cFamAlpha) ||
          (CANONICAL_MALWARE_NAMES[itemFamAlpha] && CANONICAL_MALWARE_NAMES[itemFamAlpha] === CANONICAL_MALWARE_NAMES[cFamAlpha]);

        if (!isSameFamily) {
          continue; // Distinct malware families must never merge into each other
        }
      }

      // Match 1: Same campaign
      if (itemCampaign && cCampaign && itemCampaign === cCampaign) {
        matchedClusterIndex = i;
        break;
      }
      // Match 2: Same actor
      if (itemActor && cActor && itemActor === cActor) {
        matchedClusterIndex = i;
        break;
      }
      // Match 3: Overlapping non-generic tokens (e.g. family or alias)
      let tokenOverlap = false;
      for (const t of itemTokens) {
        if (cTokens.has(t)) {
          tokenOverlap = true;
          break;
        }
      }
      if (tokenOverlap) {
        matchedClusterIndex = i;
        break;
      }
    }

    if (matchedClusterIndex >= 0) {
      const target = clusters[matchedClusterIndex];

      // Primary malware family
      if (!target.malware_family && item.malware_family) {
        target.malware_family = item.malware_family;
      } else if (target.malware_family && item.malware_family && target.malware_family.toLowerCase() !== item.malware_family.toLowerCase()) {
        const existingFam = target.malware_family;
        const incomingFam = item.malware_family;
        const existingAlpha = existingFam.toLowerCase().replace(/[^a-z0-9]/g, '');
        const incomingAlpha = incomingFam.toLowerCase().replace(/[^a-z0-9]/g, '');

        if (CANONICAL_MALWARE_NAMES[incomingAlpha]) {
          target.malware_family = CANONICAL_MALWARE_NAMES[incomingAlpha];
          target.aliases = [...(target.aliases || []), existingFam];
        } else if (incomingFam !== incomingFam.toLowerCase() && existingFam === existingFam.toLowerCase()) {
          target.malware_family = incomingFam;
          target.aliases = [...(target.aliases || []), existingFam];
        } else {
          target.aliases = [...(target.aliases || []), incomingFam];
        }
      }

      // Threat actor
      if (!target.threat_actor && item.threat_actor) {
        target.threat_actor = item.threat_actor;
      }

      // Threat actor aliases union
      const allActorAliases = [
        ...(target.threat_actor_aliases || []),
        ...(item.threat_actor_aliases || []),
      ];
      target.threat_actor_aliases = Array.from(new Set(allActorAliases.map((a) => a.trim()).filter(Boolean)));

      // Campaign
      if (!target.campaign && item.campaign) {
        target.campaign = item.campaign;
      }

      // Tool & Threat Association
      if (!target.tool && item.tool) {
        target.tool = item.tool;
      }
      if (!target.threat_association && item.threat_association) {
        target.threat_association = item.threat_association;
      }
      if (!target.canonical_name && item.canonical_name) {
        target.canonical_name = item.canonical_name;
      }
      if (!target.entity_type && item.entity_type) {
        target.entity_type = item.entity_type;
      }
      if (!target.relationship_type && item.relationship_type) {
        target.relationship_type = item.relationship_type;
      }

      // Malware type
      if (!target.malware_type && item.malware_type) {
        target.malware_type = item.malware_type;
      }

      // Detection classification & verdict
      if (!target.detection_classification && item.detection_classification) {
        target.detection_classification = item.detection_classification;
      }
      if (!target.verdict && item.verdict) {
        target.verdict = item.verdict;
      }

      // Aliases union
      const allAliases = [
        ...(target.aliases || []),
        ...(item.aliases || []),
        ...(target.malware_names || []),
        ...(item.malware_names || []),
      ];
      target.aliases = Array.from(new Set(allAliases.map((a) => a.trim()).filter(Boolean)));

      // Threat tags union
      const allTags = [
        ...(target.threat_tags || []),
        ...(item.threat_tags || []),
      ];
      target.threat_tags = Array.from(new Set(allTags.map((t) => t.replace(/^#/, '').trim()).filter(Boolean)));

      // CVEs union
      const allCves = [
        ...(target.cves || []),
        ...(item.cves || []),
      ];
      target.cves = Array.from(new Set(allCves.map((c) => c.trim()).filter(Boolean)));

      // Sources union
      const allSources = [
        ...(target.sources || []),
        ...(item.sources || []),
      ];
      target.sources = Array.from(new Set(allSources.map((s) => s.trim()).filter(Boolean)));

      // Evidence union
      const allEvidence = [
        ...(target.evidence || []),
        ...(item.evidence || []),
      ];
      target.evidence = Array.from(new Set(allEvidence.map((e) => e.trim()).filter(Boolean)));

      if (!target.evidence_summary && item.evidence_summary) {
        target.evidence_summary = item.evidence_summary;
      } else if (item.evidence_summary && target.evidence_summary && !target.evidence_summary.includes(item.evidence_summary)) {
        target.evidence_summary = `${target.evidence_summary}; ${item.evidence_summary}`;
      }

      if (!target.provider_detection_name && item.provider_detection_name) {
        target.provider_detection_name = item.provider_detection_name;
      }
      const distinctClusterSources = new Set(target.sources.map((s) => s.toLowerCase()));
      target.is_corroborated = Boolean(target.is_corroborated || item.is_corroborated || (distinctClusterSources.size >= 2));

      // Confidence: pick highest
      const getConfVal = (conf?: string | number): number => {
        if (typeof conf === 'number') return conf <= 1 ? conf * 100 : conf;
        if (!conf) return 50;
        const c = String(conf).toLowerCase();
        if (c.includes('high')) return 85;
        if (c.includes('med')) return 60;
        if (c.includes('low')) return 30;
        const num = parseFloat(c);
        return isNaN(num) ? 50 : (num <= 1 ? num * 100 : num);
      };
      if (getConfVal(item.confidence) > getConfVal(target.confidence)) {
        target.confidence = item.confidence;
      }
    } else {
      // New cluster
      const distinctItemSources = new Set((item.sources || []).map((s) => s.toLowerCase()));
      clusters.push({
        ...item,
        tool: item.tool,
        threat_association: item.threat_association,
        canonical_name: item.canonical_name,
        entity_type: item.entity_type,
        relationship_type: item.relationship_type,
        aliases: [...(item.aliases || []), ...(item.malware_names || [])],
        threat_actor_aliases: [...(item.threat_actor_aliases || [])],
        threat_tags: (item.threat_tags || []).map((t) => t.replace(/^#/, '').trim()).filter(Boolean),
        sources: [...(item.sources || [])],
        evidence: [...(item.evidence || [])],
        provider_detection_name: item.provider_detection_name,
        is_corroborated: Boolean(item.is_corroborated || (distinctItemSources.size >= 2)),
      });
    }
  }

  return clusters.map((c) => {
    const primaryFamily = c.malware_family?.trim() || '';
    const actor = c.threat_actor?.trim() || '';
    const primaryAlpha = primaryFamily.toLowerCase().replace(/[^a-z0-9]/g, '');
    const actorAlpha = actor.toLowerCase().replace(/[^a-z0-9]/g, '');

    // Filter aliases: exclude primary family name, threat actor, and generic classifications
    const cleanAliases = (c.aliases || []).filter((alias) => {
      const a = alias.trim();
      if (!a) return false;
      if (isGenericClassification(a) || isCveIdentifier(a)) return false;
      const aAlpha = a.toLowerCase().replace(/[^a-z0-9]/g, '');
      if (primaryAlpha && aAlpha === primaryAlpha) return false;
      if (actorAlpha && aAlpha === actorAlpha) return false;
      return true;
    });

    // Filter actor aliases: exclude threat actor, family, and generic classifications
    const cleanActorAliases = (c.threat_actor_aliases || []).filter((alias) => {
      const a = alias.trim();
      if (!a) return false;
      if (isGenericClassification(a) || isCveIdentifier(a)) return false;
      const aAlpha = a.toLowerCase().replace(/[^a-z0-9]/g, '');
      if (actorAlpha && aAlpha === actorAlpha) return false;
      return true;
    });

    const seenAliases = new Set<string>();
    const deduplicatedAliases: string[] = [];
    for (const a of cleanAliases) {
      const lower = a.toLowerCase();
      if (!seenAliases.has(lower)) {
        seenAliases.add(lower);
        deduplicatedAliases.push(a);
      }
    }

    const seenActorAliases = new Set<string>();
    const deduplicatedActorAliases: string[] = [];
    for (const a of cleanActorAliases) {
      const lower = a.toLowerCase();
      if (!seenActorAliases.has(lower)) {
        seenActorAliases.add(lower);
        deduplicatedActorAliases.push(a);
      }
    }

    const seenTags = new Set<string>();
    const deduplicatedTags: string[] = [];
    for (const t of (c.threat_tags || [])) {
      const lower = t.toLowerCase();
      if (!seenTags.has(lower)) {
        seenTags.add(lower);
        deduplicatedTags.push(t);
      }
    }

    const displayTitle = primaryFamily || actor || c.tool || c.threat_association || c.canonical_name || c.detection_classification || (c.cves && c.cves.length > 0 ? c.cves[0] : '') || c.campaign || 'Security Detection';
    const distinctClusterSources = new Set((c.sources || []).map((s) => s.toLowerCase()));
    const isCorroborated = Boolean(c.is_corroborated || distinctClusterSources.size >= 2);

    return {
      ...c,
      displayTitle,
      aliases: deduplicatedAliases,
      threat_actor_aliases: deduplicatedActorAliases,
      threat_tags: deduplicatedTags,
      is_corroborated: isCorroborated,
    };
  });
}

export const Layer2Infrastructure: React.FC<Layer2Props> = ({ layer2 }) => {
  const [expandedBanners, setExpandedBanners] = useState<Record<string, boolean>>({});
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [collapsedTactics, setCollapsedTactics] = useState<Record<string, boolean>>({});
  const [expandedTechniques, setExpandedTechniques] = useState<Record<string, boolean>>({});
  const [pdnsSearch, setPdnsSearch] = useState('');
  const [pdnsFilterType, setPdnsFilterType] = useState('ALL');
  const [whoisSearch, setWhoisSearch] = useState('');
  const [expandedWhois, setExpandedWhois] = useState<Record<string, boolean>>({});
  const [expandedWebCheckSections, setExpandedWebCheckSections] = useState<Record<string, boolean>>({
    waf: true,
    headers: true,
    tech: true,
    mail: true,
    redirects: true,
    subdomains: true,
    trackers: false,
    threats: true,
  });

  const toggleWebCheckSection = (key: string) => {
    setExpandedWebCheckSections((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const infra = layer2?.aggregated_infrastructure || ({} as any);
  const webcheck = infra.extra?.webcheck || layer2?.provider_contributions?.webcheck?.extra?.webcheck;
  const hasWebCheck = Boolean(webcheck && typeof webcheck === 'object' && Object.keys(webcheck).length > 0);
  const allCookies = React.useMemo(() => {
    if (!webcheck?.cookies) return [];
    if (Array.isArray(webcheck.cookies)) return webcheck.cookies;
    const list: any[] = [];
    if (Array.isArray(webcheck.cookies.cookies)) list.push(...webcheck.cookies.cookies);
    if (Array.isArray(webcheck.cookies.headerCookies)) list.push(...webcheck.cookies.headerCookies);
    if (Array.isArray(webcheck.cookies.clientCookies)) list.push(...webcheck.cookies.clientCookies);
    return list;
  }, [webcheck?.cookies]);
  const net = infra.network;
  const geo = infra.geo;
  const dns = infra.dns;
  const whois = infra.whois;
  const http = infra.http;
  const shodan = infra.shodan_details;
  const censys = infra.censys_details;
  const temporal = infra.temporal;
  const ipScoring = infra.ip_scoring;
  const detection = infra.detection;
  const security = infra.security;
  const pulses: PulseMetadata[] = layer2?.otx_pulses && layer2.otx_pulses.length > 0
    ? layer2.otx_pulses
    : (infra.otx_pulses || []);

  const servicesDetail: ServiceInfo[] = React.useMemo(() => {
    const list: ServiceInfo[] = [...(infra.services_detail || [])];
    const existingPorts = new Set(list.map((s) => s.port));

    if (infra.services && Array.isArray(infra.services)) {
      for (const s of infra.services) {
        if (s.port && !existingPorts.has(s.port)) {
          existingPorts.add(s.port);
          list.push({
            port: s.port,
            transport: (s as any).transport || 'tcp',
            protocol: (s as any).protocol,
            service_name: s.service_name || 'open-port',
            banner: s.banner,
            cpe: [],
            sources: (s as any).sources || ['provider'],
          });
        }
      }
    }

    if (infra.open_ports && Array.isArray(infra.open_ports)) {
      for (const p of infra.open_ports) {
        const portNum = Number(p);
        if (portNum && !existingPorts.has(portNum)) {
          existingPorts.add(portNum);
          list.push({
            port: portNum,
            transport: 'tcp',
            service_name: 'open-port',
            cpe: [],
            sources: ['webcheck'],
          });
        }
      }
    }

    return list.sort((a, b) => a.port - b.port);
  }, [infra.services_detail, infra.services, infra.open_ports]);

  const certsDetail: CertInfo[] = infra.certificates_detail && infra.certificates_detail.length > 0
    ? infra.certificates_detail
    : (infra.certificates || []).map((c: any) => ({
        fingerprint_sha256: c.fingerprint,
        sans: c.names || [],
        tls_versions: [],
        ciphers: [],
        sources: ['provider'],
      }));

  const vulnsDetail = infra.vulnerabilities || [];

  const rootType = (layer2?.root_type || '').toLowerCase();
  const isHash = ['md5', 'sha1', 'sha256'].includes(rootType);
  const isIp = ['ipv4', 'ipv6'].includes(rootType);
  const isDomain = rootType === 'domain';
  const isUrl = rootType === 'url';

  const fileMeta = infra.file_metadata;
  const ttps: TTPTechnique[] = layer2?.ttps && layer2.ttps.length > 0
    ? layer2.ttps
    : (infra.ttps && infra.ttps.length > 0
      ? infra.ttps
      : (fileMeta?.ttps || []));

  const passiveDns: PassiveDnsRecord[] = (layer2?.passive_dns && layer2.passive_dns.length > 0)
    ? layer2.passive_dns
    : (infra.passive_dns && infra.passive_dns.length > 0
      ? infra.passive_dns
      : []);
  const hasPassiveDns = (isDomain || isIp) && passiveDns.length > 0;

  const ttpTree: TTPTacticNode[] = (layer2?.ttp_hierarchy && layer2.ttp_hierarchy.length > 0)
    ? layer2.ttp_hierarchy
    : (infra.ttp_hierarchy && infra.ttp_hierarchy.length > 0
      ? infra.ttp_hierarchy
      : []);

  const resolvedTtpTree: TTPTacticNode[] = React.useMemo(() => {
    if (ttpTree && ttpTree.length > 0) return ttpTree;
    if (!ttps || ttps.length === 0) return [];

    const groups: Record<string, { id: string; name: string; order: number; techniques: Record<string, TTPTechniqueNode> }> = {};

    ttps.forEach((ttp) => {
      const rawId = (ttp.technique_id || '').trim().toUpperCase();
      if (!rawId) return;
      const isSub = rawId.includes('.');
      const parentId = isSub ? rawId.split('.')[0] : rawId;
      const tacticName = ttp.tactic || 'Behavioral Execution';
      const tacticId = tacticName.toLowerCase().replace(/[^a-z0-9]/g, '') || 'ta0002';

      if (!groups[tacticId]) {
        groups[tacticId] = {
          id: tacticId,
          name: tacticName,
          order: 1,
          techniques: {},
        };
      }

      const tGroup = groups[tacticId];
      if (isSub) {
        if (!tGroup.techniques[parentId]) {
          tGroup.techniques[parentId] = {
            id: parentId,
            name: `Technique ${parentId}`,
            sources: [...(ttp.sources || [])],
            evidence: [],
            sub_techniques: [],
          };
        }
        const parent = tGroup.techniques[parentId];
        (ttp.sources || []).forEach((s) => {
          if (!parent.sources.includes(s)) parent.sources.push(s);
        });
        const subExists = parent.sub_techniques.find((st) => st.id === rawId);
        if (!subExists) {
          parent.sub_techniques.push({
            id: rawId,
            name: ttp.technique_name || rawId,
            description: ttp.description,
            severity: ttp.severity,
            sources: [...(ttp.sources || [])],
            evidence: ttp.description ? [ttp.description] : [],
          });
        }
      } else {
        if (!tGroup.techniques[rawId]) {
          tGroup.techniques[rawId] = {
            id: rawId,
            name: ttp.technique_name || rawId,
            description: ttp.description,
            severity: ttp.severity,
            sources: [...(ttp.sources || [])],
            evidence: ttp.description ? [ttp.description] : [],
            sub_techniques: [],
          };
        } else {
          const tech = tGroup.techniques[rawId];
          (ttp.sources || []).forEach((s) => {
            if (!tech.sources.includes(s)) tech.sources.push(s);
          });
          if (!tech.name && ttp.technique_name) tech.name = ttp.technique_name;
          if (!tech.description && ttp.description) tech.description = ttp.description;
          if (!tech.severity && ttp.severity) tech.severity = ttp.severity;
        }
      }
    });

    return Object.values(groups).map((g) => ({
      id: g.id,
      name: g.name,
      order: g.order,
      techniques: Object.values(g.techniques).sort((a, b) => a.id.localeCompare(b.id)),
    }));
  }, [ttpTree, ttps]);

  const hasTTPs = resolvedTtpTree.length > 0 || ttps.length > 0;
  const hasFile = isHash && Boolean(infra.file_type || infra.file_size !== undefined || fileMeta);
  const hasPulses = pulses.length > 0;

  // Network/Host/Exposure intelligence is strictly for network IOCs (IP, Domain, URL) and NEVER for Hashes
  const hasNetwork = !isHash && Boolean(net?.asn || net?.org || net?.isp || net?.cidr || net?.ptr || infra.asn || infra.org || infra.cidr || infra.ptr);
  const hasGeo = (isIp || isDomain) && Boolean(geo?.country || geo?.city || geo?.region || infra.country || infra.city || infra.region);
  const hasDns = (isDomain || isUrl || isIp) && Boolean(
    (dns?.hostnames && dns.hostnames.length > 0) ||
    (dns?.domains && dns.domains.length > 0) ||
    (dns?.records && dns.records.length > 0) ||
    Object.keys(infra.dns_records || {}).length > 0
  );
  const hasWhois = (isDomain || isUrl || isIp) && Boolean(
    whois?.registrar || whois?.creation_date || whois?.expiration_date ||
    infra.registrar || infra.whois_creation || infra.whois_expiration ||
    (infra.nameservers && infra.nameservers.length > 0)
  );

  const historicalWhois: HistoricalWhoisRecord[] = (layer2?.historical_whois && layer2.historical_whois.length > 0)
    ? layer2.historical_whois
    : (infra.historical_whois && infra.historical_whois.length > 0
      ? infra.historical_whois
      : []);
  const hasHistoricalWhois = (isDomain || isIp || isUrl) && historicalWhois.length > 0;

  const filteredHistoricalWhois = React.useMemo(() => {
    if (!historicalWhois || historicalWhois.length === 0) return [];
    if (!whoisSearch.trim()) return historicalWhois;
    const q = whoisSearch.toLowerCase();
    return historicalWhois.filter((rec) => {
      const reg = (rec.registrar || '').toLowerCase();
      const org = (rec.registrant_organization || '').toLowerCase();
      const country = (rec.registrant_country || '').toLowerCase();
      const ns = (rec.nameservers || []).join(' ').toLowerCase();
      const firstSeen = (rec.first_seen || '').toLowerCase();
      const lastUpdated = (rec.last_updated || '').toLowerCase();
      return (
        reg.includes(q) ||
        org.includes(q) ||
        country.includes(q) ||
        ns.includes(q) ||
        firstSeen.includes(q) ||
        lastUpdated.includes(q)
      );
    });
  }, [historicalWhois, whoisSearch]);

  const toggleWhois = (id: string) => {
    setExpandedWhois((prev) => ({ ...prev, [id]: !prev[id] }));
  };
  const hasServices = !isHash && (servicesDetail.length > 0 || (infra.open_ports && infra.open_ports.length > 0));
  const hasCerts = (isIp || isDomain || isUrl) && certsDetail.length > 0;
  const hasHttp = (isDomain || isUrl || isIp) && Boolean(http?.server || http?.title || http?.screenshot_url || infra.http_server || infra.http_title || infra.screenshot_url || http?.status_code != null);
  const hasVulns = !isHash && vulnsDetail.length > 0;
  const hasShodanDetails = !isHash && Boolean(shodan && (shodan.os || (shodan.tags && shodan.tags.length > 0) || shodan.total_ports > 0 || shodan.last_update));
  const hasCensysDetails = !isHash && Boolean(censys && (censys.ip || censys.hostname || censys.os || (censys.host_labels && censys.host_labels.length > 0) || (censys.web_properties && censys.web_properties.length > 0) || (censys.service_count && censys.service_count > 0) || censys.last_observed_at || censys.bgp_prefix));
  const hasTemporal = Boolean(temporal?.last_scan || temporal?.first_seen || temporal?.last_seen);
  const hasIpScoring = isIp && Boolean(ipScoring && (ipScoring.inbound_score || ipScoring.outbound_score || ipScoring.reputation_score !== undefined || ipScoring.critical_risk || (ipScoring.abuse_indicators && ipScoring.abuse_indicators.length > 0)));
  const hasDetection = isIp && Boolean(detection && (detection.is_vpn || detection.is_tor || detection.is_proxy || detection.is_hosting || detection.is_cloud || detection.is_scanner || detection.is_darkweb || detection.is_snort || detection.is_mobile || detection.is_cdn || (detection.ip_categories && detection.ip_categories.length > 0) || (detection.vpn_providers && detection.vpn_providers.length > 0) || (detection.special_issues && detection.special_issues.length > 0)));
  const hasSecurity = isIp && Boolean(security && ((security.user_search_count ?? 0) > 0 || (security.ids_alerts_count ?? 0) > 0 || (security.ids_alert_signatures && security.ids_alert_signatures.length > 0) || security.honeypot_detected || security.webcam_detected || security.admin_page_detected || security.invalid_ssl || (security.abuse_record_count ?? 0) > 0 || (security.policy_violations && security.policy_violations.length > 0)));
  const attributions: ThreatAttribution[] = (infra.threat_attributions && infra.threat_attributions.length > 0)
    ? infra.threat_attributions
    : (infra.threat_attribution ? [infra.threat_attribution] : []);
  const consolidatedAttributions = React.useMemo(() => consolidateThreatAttributions(attributions), [attributions]);
  const hasAttribution = consolidatedAttributions.length > 0;

  const canonicalMxList: Array<{ exchange: string; priority?: number }> = React.useMemo(() => {
    const list: Array<{ exchange: string; priority?: number }> = [];
    const seen = new Set<string>();

    const addMx = (ex?: string, priority?: number) => {
      if (!ex) return;
      const clean = ex.trim().replace(/\.$/, '');
      if (!clean || seen.has(clean.toLowerCase()) || isIpStr(clean)) return;
      seen.add(clean.toLowerCase());
      list.push({ exchange: clean, priority });
    };

    if (webcheck?.['mail-config']?.mx && Array.isArray(webcheck['mail-config'].mx)) {
      for (const m of webcheck['mail-config'].mx) {
        if (typeof m === 'string') {
          const parts = m.trim().split(/\s+/);
          if (parts.length >= 2 && !isNaN(Number(parts[0]))) {
            addMx(parts[1], Number(parts[0]));
          } else {
            addMx(parts[0], 10);
          }
        } else if (typeof m === 'object' && m !== null) {
          addMx(m.exchange || m.host || m.address, m.priority);
        }
      }
    }

    if (infra.dns_records?.MX && Array.isArray(infra.dns_records.MX)) {
      for (const raw of infra.dns_records.MX) {
        const parts = String(raw).trim().split(/\s+/);
        if (parts.length >= 2 && !isNaN(Number(parts[0]))) {
          addMx(parts[1], Number(parts[0]));
        } else {
          addMx(parts[0], 10);
        }
      }
    }

    if (infra.dns?.records && Array.isArray(infra.dns.records)) {
      for (const r of infra.dns.records) {
        if (r.record_type?.toUpperCase() === 'MX' && r.value) {
          const parts = String(r.value).trim().split(/\s+/);
          if (parts.length >= 2 && !isNaN(Number(parts[0]))) {
            addMx(parts[1], Number(parts[0]));
          } else {
            addMx(parts[0], 10);
          }
        }
      }
    }

    return list.sort((a, b) => (a.priority ?? 10) - (b.priority ?? 10));
  }, [webcheck, infra.dns_records, infra.dns]);

  const toggleBanner = (key: string) => {
    setExpandedBanners((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const copyToClipboard = (key: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1800);
  };

  const toggleTactic = (tacticId: string) => {
    setCollapsedTactics((prev) => ({
      ...prev,
      [tacticId]: !prev[tacticId],
    }));
  };

  const toggleTechnique = (techId: string) => {
    setExpandedTechniques((prev) => ({
      ...prev,
      [techId]: !prev[techId],
    }));
  };

  const filteredPassiveDns = React.useMemo(() => {
    if (!passiveDns || passiveDns.length === 0) return [];
    return passiveDns.filter((rec) => {
      if (pdnsFilterType !== 'ALL' && rec.rrtype?.toUpperCase() !== pdnsFilterType) {
        return false;
      }
      if (pdnsSearch.trim()) {
        const q = pdnsSearch.toLowerCase();
        const matchQuery = (rec.query || '').toLowerCase().includes(q);
        const matchAnswer = (rec.answer || '').toLowerCase().includes(q);
        const matchRrtype = (rec.rrtype || '').toLowerCase().includes(q);
        const matchSource = (rec.sources || []).some((s) => s.toLowerCase().includes(q));
        if (!matchQuery && !matchAnswer && !matchRrtype && !matchSource) {
          return false;
        }
      }
      return true;
    });
  }, [passiveDns, pdnsFilterType, pdnsSearch]);

  const uniqueRrtypes = React.useMemo(() => {
    const set = new Set<string>();
    passiveDns.forEach((r) => {
      if (r.rrtype) set.add(r.rrtype.toUpperCase());
    });
    return Array.from(set).sort();
  }, [passiveDns]);

  const totalTechniquesCount = React.useMemo(() => {
    return resolvedTtpTree.reduce((acc, t) => acc + (t.techniques?.length || 0), 0);
  }, [resolvedTtpTree]);

  const getRrtypeBadge = (rrtype?: string) => {
    const t = (rrtype || '').toUpperCase();
    switch (t) {
      case 'A':
        return 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30';
      case 'AAAA':
        return 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30';
      case 'CNAME':
        return 'bg-purple-500/15 text-purple-400 border-purple-500/30';
      case 'PTR':
        return 'bg-blue-500/15 text-blue-400 border-blue-500/30';
      case 'MX':
        return 'bg-amber-500/15 text-amber-400 border-amber-500/30';
      case 'NS':
        return 'bg-orange-500/15 text-orange-400 border-orange-500/30';
      case 'TXT':
        return 'bg-violet-500/15 text-violet-400 border-violet-500/30';
      case 'SOA':
        return 'bg-pink-500/15 text-pink-400 border-pink-500/30';
      default:
        return 'bg-theme-surface text-theme-secondary border-theme';
    }
  };

  // Extract unique active infrastructure contributors
  const rawSources: string[] = [
    ...(net?.sources || []),
    ...(geo?.sources || []),
    ...(dns?.sources || []),
    ...(passiveDns.flatMap((p) => p.sources || [])),
    ...(ipScoring?.sources || []),
    ...(detection?.sources || []),
    ...(security?.sources || []),
    ...servicesDetail.flatMap((s) => s.sources || []),
    ...certsDetail.flatMap((c) => c.sources || []),
    ...vulnsDetail.flatMap((v) => v.sources || []),
    ...attributions.flatMap((a) => a.sources || []),
    ...Object.keys(layer2.provider_contributions || {}),
  ];
  const activeSources: string[] = Array.from(new Set(rawSources.filter((s) => typeof s === 'string' && s.trim().length > 0)));

  return (
    <section className="space-y-4">
      {/* Layer 02 Header */}
      <div className="flex items-center justify-between flex-wrap gap-3 border-b border-theme pb-3">
        <div>
          <div className="flex items-center space-x-2">
            <span className="text-xs font-mono font-bold tracking-widest text-cyan-500 uppercase">Layer 02</span>
            <span className="text-theme-muted">/</span>
            <h2 className="text-lg font-bold text-theme-primary tracking-wide">
              {isHash ? 'Payload Architecture & Behavioral Intelligence' : 'Infrastructure & Host Intelligence'}
            </h2>
          </div>
          <p className="text-xs text-theme-secondary">
            {isHash
              ? 'Multi-provider static analysis telemetry: cryptographic hashes, observed filenames, PE headers, and extracted MITRE ATT&CK behavioral TTPs.'
              : 'Multi-provider host exposure telemetry: routing, services, banners, TLS certificates, software CPEs, and detected vulnerabilities.'}
          </p>
        </div>

        {/* Contributing Providers Badges */}
        {activeSources.length > 0 && (
          <div className="flex items-center space-x-2 bg-theme-surface border border-theme px-3 py-1.5 rounded-lg text-xs font-mono">
            <span className="text-theme-secondary text-[11px]">Telemetry Providers:</span>
            <div className="flex items-center space-x-1.5">
              {activeSources.map((src) => (
                <span
                  key={src}
                  className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-cyan-500/10 text-cyan-400 border border-cyan-500/30"
                >
                  {src}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {/* 0. Threat & Malware Intelligence Card */}
        {hasAttribution && (
          <div className="bg-theme-card border border-rose-500/40 rounded-xl p-4.5 space-y-3 shadow-sm md:col-span-2 lg:col-span-3">
            <div className="flex items-center justify-between pb-2 border-b border-theme flex-wrap gap-2">
              <div className="flex items-center space-x-2 text-rose-400 text-xs font-bold uppercase tracking-wider">
                <ShieldAlert className="w-4 h-4" />
                <span>Threat & Malware Intelligence ({consolidatedAttributions.length})</span>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {consolidatedAttributions.map((attr, idx) => {
                const confNum = typeof attr.confidence === 'number'
                  ? (attr.confidence <= 1.0 ? Math.round(attr.confidence * 100) : Math.round(attr.confidence))
                  : null;

                const distinctProviders = Array.from(new Set((attr.sources || []).map((s) => s.trim().toLowerCase())));
                const isCorroborated = Boolean(attr.is_corroborated || distinctProviders.length >= 2);

                const allEvidencePoints: string[] = Array.from(
                  new Set([
                    ...(attr.evidence || []),
                    ...(attr.evidence_summary ? attr.evidence_summary.split(';').map((s) => s.trim()).filter(Boolean) : []),
                  ])
                );

                return (
                  <div key={idx} className="bg-theme-inset border border-theme rounded-lg p-3 space-y-2 text-xs font-mono">
                    {/* Header */}
                    <div className="flex items-center justify-between flex-wrap gap-1 pb-1.5 border-b border-theme">
                      <div className="flex items-center space-x-1.5 max-w-[200px]">
                        <span className="font-bold text-sm text-theme-primary truncate" title={attr.displayTitle}>
                          {attr.displayTitle}
                        </span>
                        {attr.malware_type && (
                          <span className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase bg-purple-500/20 text-purple-300 border border-purple-500/30">
                            {attr.malware_type}
                          </span>
                        )}
                        {!attr.malware_type && attr.threat_actor && !attr.malware_family && (
                          <span className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase bg-rose-500/20 text-rose-300 border border-rose-500/30">
                            Threat Actor
                          </span>
                        )}
                        {(attr.entity_type === 'tool' || (attr.tool && !attr.malware_family && !attr.threat_actor)) && (
                          <span className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase bg-blue-500/20 text-blue-300 border border-blue-500/30">
                            Tool
                          </span>
                        )}
                        {(attr.entity_type === 'threat_association' || (attr.threat_association && !attr.malware_family && !attr.threat_actor)) && (
                          <span className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                            Threat Association
                          </span>
                        )}
                        {(attr.entity_type === 'campaign' || (attr.campaign && !attr.malware_family && !attr.threat_actor && !attr.tool && !attr.threat_association)) && (
                          <span className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase bg-amber-500/20 text-amber-300 border border-amber-500/30">
                            Campaign
                          </span>
                        )}
                        {!attr.malware_type && attr.cves && attr.cves.length > 0 && !attr.malware_family && !attr.threat_actor && !attr.tool && !attr.threat_association && (
                          <span className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase bg-red-500/20 text-red-300 border border-red-500/30">
                            Vulnerability
                          </span>
                        )}
                        {!attr.malware_type && attr.detection_classification && !attr.malware_family && !attr.threat_actor && (!attr.cves || attr.cves.length === 0) && !attr.tool && !attr.threat_association && (
                          <span className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase bg-amber-500/20 text-amber-300 border border-amber-500/30">
                            Detection
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-1.5">
                        {isCorroborated && (
                          <span className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                            Cross-Provider Corroborated
                          </span>
                        )}
                        {(confNum != null || attr.confidence) && (
                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase ${
                            confNum != null
                              ? (confNum >= 80 ? 'bg-red-500/20 text-red-400 border border-red-500/30' : confNum >= 50 ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30' : 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30')
                              : (String(attr.confidence).toLowerCase() === 'high' ? 'bg-red-500/20 text-red-400 border border-red-500/30' : 'bg-orange-500/20 text-orange-400 border border-orange-500/30')
                          }`}>
                            {confNum != null ? `${confNum}%` : attr.confidence} confidence
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Dedicated Fields */}
                    <div className="space-y-1 text-[11px]">
                      {attr.threat_actor && (
                        <div className="flex items-start justify-between gap-2 py-1 border-b border-theme/40">
                          <span className="text-theme-secondary font-medium">Threat Actor:</span>
                          <span className="text-rose-400 font-semibold text-right text-xs truncate max-w-[180px]" title={attr.threat_actor}>
                            {attr.threat_actor}
                          </span>
                        </div>
                      )}
                      {attr.threat_actor_aliases && attr.threat_actor_aliases.length > 0 && (
                        <div className="py-1 border-b border-theme/40 space-y-1">
                          <span className="text-theme-secondary font-medium block">Threat Actor Aliases:</span>
                          <div className="flex flex-wrap gap-1 max-h-16 overflow-y-auto">
                            {attr.threat_actor_aliases.map((alias, aIdx) => (
                              <span key={aIdx} className="px-1.5 py-0.5 rounded text-[10px] bg-rose-500/10 text-rose-300 border border-rose-500/20">
                                {alias}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                      {attr.malware_family && (
                        <div className="flex items-start justify-between gap-2 py-1 border-b border-theme/40">
                          <span className="text-theme-secondary font-medium">Malware Family:</span>
                          <span className="text-theme-primary font-semibold text-right text-xs truncate max-w-[180px]" title={attr.malware_family}>
                            {attr.malware_family}
                          </span>
                        </div>
                      )}
                      {attr.tool && (
                        <div className="flex items-start justify-between gap-2 py-1 border-b border-theme/40">
                          <span className="text-theme-secondary font-medium">Tool:</span>
                          <span className="text-blue-300 font-semibold text-right text-xs truncate max-w-[180px]" title={attr.tool}>
                            {attr.tool}
                          </span>
                        </div>
                      )}
                      {attr.threat_association && (
                        <div className="flex items-start justify-between gap-2 py-1 border-b border-theme/40">
                          <span className="text-theme-secondary font-medium">Threat Association:</span>
                          <span className="text-indigo-300 font-semibold text-right text-xs truncate max-w-[180px]" title={attr.threat_association}>
                            {attr.threat_association}
                          </span>
                        </div>
                      )}
                      {attr.relationship_type && (
                        <div className="flex items-start justify-between gap-2 py-1 border-b border-theme/40">
                          <span className="text-theme-secondary font-medium">Relationship:</span>
                          <span className="text-cyan-400 font-semibold text-right text-xs truncate max-w-[180px]" title={attr.relationship_type}>
                            {attr.relationship_type.replace(/_/g, ' ')}
                          </span>
                        </div>
                      )}
                      {attr.aliases && attr.aliases.length > 0 && (
                        <div className="py-1 border-b border-theme/40 space-y-1">
                          <span className="text-theme-secondary font-medium block">Malware Aliases / Known Names:</span>
                          <div className="flex flex-wrap gap-1 max-h-16 overflow-y-auto">
                            {attr.aliases.map((alias, aIdx) => (
                              <span key={aIdx} className="px-1.5 py-0.5 rounded text-[10px] bg-theme-surface text-theme-muted border border-theme">
                                {alias}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                      {attr.campaign && (
                        <div className="flex items-start justify-between gap-2 py-1 border-b border-theme/40">
                          <span className="text-theme-secondary font-medium">Campaign:</span>
                          <span className="text-amber-400 font-semibold text-right text-xs truncate max-w-[180px]" title={attr.campaign}>
                            {attr.campaign}
                          </span>
                        </div>
                      )}
                      {attr.cves && attr.cves.length > 0 && (
                        <div className="py-1 border-b border-theme/40 space-y-1">
                          <span className="text-theme-secondary font-medium block">Vulnerability / CVE:</span>
                          <div className="flex flex-wrap gap-1 max-h-16 overflow-y-auto">
                            {attr.cves.map((cve, cIdx) => (
                              <span key={cIdx} className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-red-500/15 text-red-400 border border-red-500/30">
                                {cve}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                      {attr.detection_classification && (
                        <div className="flex items-start justify-between gap-2 py-1 border-b border-theme/40">
                          <span className="text-theme-secondary font-medium">Provider Classification:</span>
                          <span className="text-amber-400 font-semibold text-right text-xs truncate max-w-[180px]" title={attr.detection_classification}>
                            {attr.detection_classification}
                          </span>
                        </div>
                      )}
                      {attr.provider_detection_name && (
                        <div className="flex items-start justify-between gap-2 py-1 border-b border-theme/40">
                          <span className="text-theme-secondary font-medium">Provider Signature:</span>
                          <span className="text-amber-400 font-semibold text-right text-xs truncate max-w-[180px]" title={attr.provider_detection_name}>
                            {attr.provider_detection_name}
                          </span>
                        </div>
                      )}
                      {attr.verdict && (
                        <div className="flex items-start justify-between gap-2 py-1 border-b border-theme/40">
                          <span className="text-theme-secondary font-medium">Verdict:</span>
                          <span className={`font-semibold text-right text-xs uppercase ${
                            attr.verdict.toLowerCase() === 'malicious' ? 'text-red-400' :
                            attr.verdict.toLowerCase() === 'suspicious' ? 'text-orange-400' :
                            attr.verdict.toLowerCase() === 'whitelisted' || attr.verdict.toLowerCase() === 'benign' ? 'text-emerald-400' :
                            'text-theme-muted'
                          }`} title={attr.verdict}>
                            {attr.verdict}
                          </span>
                        </div>
                      )}
                      {attr.threat_tags && attr.threat_tags.length > 0 && (
                        <div className="py-1 border-b border-theme/40 space-y-1">
                          <span className="text-theme-secondary font-medium block">Threat Tags:</span>
                          <div className="flex flex-wrap gap-1 max-h-20 overflow-y-auto">
                            {attr.threat_tags.map((tag, tIdx) => (
                              <span key={tIdx} className="px-1.5 py-0.5 rounded text-[10px] bg-rose-500/10 text-rose-300 border border-rose-500/20">
                                #{tag}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>

                    {/* Evidence */}
                    {allEvidencePoints.length > 0 && (
                      <div className="py-1.5 border-b border-theme/40 space-y-1">
                        <span className="text-theme-secondary font-medium block">Evidence:</span>
                        <ul className="space-y-1 max-h-28 overflow-y-auto list-none pl-0">
                          {allEvidencePoints.map((ev, eIdx) => (
                            <li key={eIdx} className="text-[11px] text-theme-muted flex items-start gap-1.5" title={ev}>
                              <span className="text-rose-400 font-bold">•</span>
                              <span>{ev}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {/* Sources */}
                    <div className="pt-1.5 flex justify-between items-center">
                      <span className="text-[11px] text-theme-secondary font-medium">Sources:</span>
                      <ProvenanceBadges sources={attr.sources} />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* IP Threat & Risk Scoring Card (Criminal IP) */}
        {hasIpScoring && (
          <div className="bg-theme-card border border-rose-500/30 rounded-xl p-4.5 space-y-3 shadow-sm">
            <div className="flex items-center justify-between pb-2 border-b border-theme">
              <div className="flex items-center space-x-2 text-rose-500 text-xs font-bold uppercase tracking-wider">
                <Radar className="w-4 h-4" />
                <span>IP Threat & Risk Scoring</span>
              </div>
              <ProvenanceBadges sources={ipScoring?.sources || ['criminalip']} />
            </div>

            <div className="space-y-2 text-xs font-mono">
              <div className="grid grid-cols-2 gap-2">
                {ipScoring?.inbound_score && (
                  <div className="bg-theme-surface/60 p-2.5 rounded-lg border border-theme space-y-1">
                    <span className="text-[10px] text-theme-secondary block uppercase font-semibold">Inbound Score</span>
                    <span className={`inline-block px-2 py-0.5 rounded text-xs font-bold uppercase ${
                      ['critical', 'dangerous'].includes(ipScoring.inbound_score.toLowerCase())
                        ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                        : ['moderate', 'medium'].includes(ipScoring.inbound_score.toLowerCase())
                        ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30'
                        : 'bg-green-500/20 text-green-400 border border-green-500/30'
                    }`}>
                      {ipScoring.inbound_score}
                    </span>
                  </div>
                )}
                {ipScoring?.outbound_score && (
                  <div className="bg-theme-surface/60 p-2.5 rounded-lg border border-theme space-y-1">
                    <span className="text-[10px] text-theme-secondary block uppercase font-semibold">Outbound Score</span>
                    <span className={`inline-block px-2 py-0.5 rounded text-xs font-bold uppercase ${
                      ['critical', 'dangerous'].includes(ipScoring.outbound_score.toLowerCase())
                        ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                        : ['moderate', 'medium'].includes(ipScoring.outbound_score.toLowerCase())
                        ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30'
                        : 'bg-green-500/20 text-green-400 border border-green-500/30'
                    }`}>
                      {ipScoring.outbound_score}
                    </span>
                  </div>
                )}
              </div>

              {ipScoring?.reputation_score !== undefined && (
                <div className="flex justify-between items-center bg-theme-surface/40 px-2.5 py-1.5 rounded border border-theme">
                  <span className="text-theme-secondary">Provider Reputation:</span>
                  <span className="text-theme-primary font-bold">{ipScoring.reputation_score}/100</span>
                </div>
              )}

              {ipScoring?.critical_risk && (
                <div className="flex items-center space-x-2 bg-red-500/15 border border-red-500/30 text-red-400 px-3 py-1.5 rounded-lg text-xs font-bold">
                  <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                  <span>CRITICAL RISK THREAT LEVEL</span>
                </div>
              )}

              {ipScoring?.abuse_indicators && ipScoring.abuse_indicators.length > 0 && (
                <div className="space-y-1 pt-1">
                  <span className="text-theme-secondary text-[10px] block uppercase font-semibold">Observed Abuse Indicators:</span>
                  <div className="flex flex-wrap gap-1">
                    {ipScoring.abuse_indicators.map((ind, i) => (
                      <span key={i} className="px-1.5 py-0.5 rounded text-[10px] bg-red-500/10 text-red-400 border border-red-500/20 font-semibold">
                        {ind}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Detection, Proxy & Threat Telemetry Card (Criminal IP) */}
        {hasDetection && (
          <div className="bg-theme-card border border-amber-500/30 rounded-xl p-4.5 space-y-3 shadow-sm">
            <div className="flex items-center justify-between pb-2 border-b border-theme">
              <div className="flex items-center space-x-2 text-amber-500 text-xs font-bold uppercase tracking-wider">
                <Eye className="w-4 h-4" />
                <span>Detection & Proxy Telemetry</span>
              </div>
              <ProvenanceBadges sources={detection?.sources || ['criminalip']} />
            </div>

            <div className="space-y-2.5 text-xs font-mono">
              <div className="grid grid-cols-2 gap-1.5">
                {[
                  { label: 'VPN Node', active: detection?.is_vpn || detection?.is_anonymous_vpn, color: 'text-amber-400 bg-amber-500/10 border-amber-500/30' },
                  { label: 'Tor Exit Node', active: detection?.is_tor, color: 'text-red-400 bg-red-500/10 border-red-500/30' },
                  { label: 'Proxy Node', active: detection?.is_proxy, color: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30' },
                  { label: 'Hosting / DC', active: detection?.is_hosting, color: 'text-blue-400 bg-blue-500/10 border-blue-500/30' },
                  { label: 'Cloud Provider', active: detection?.is_cloud, color: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30' },
                  { label: 'Scanner / Crawler', active: detection?.is_scanner, color: 'text-orange-400 bg-orange-500/10 border-orange-500/30' },
                  { label: 'Darkweb Presence', active: detection?.is_darkweb, color: 'text-purple-400 bg-purple-500/10 border-purple-500/30' },
                  { label: 'Snort IDS Alert', active: detection?.is_snort, color: 'text-rose-400 bg-rose-500/10 border-rose-500/30' },
                  { label: 'Mobile Gateway', active: detection?.is_mobile, color: 'text-indigo-400 bg-indigo-500/10 border-indigo-500/30' },
                  { label: 'CDN Edge', active: detection?.is_cdn, color: 'text-teal-400 bg-teal-500/10 border-teal-500/30' },
                ].map((item, idx) => (
                  <div
                    key={idx}
                    className={`flex items-center justify-between px-2 py-1 rounded border text-[11px] ${
                      item.active
                        ? item.color + ' font-bold'
                        : 'text-theme-muted bg-theme-surface/30 border-theme/50'
                    }`}
                  >
                    <span>{item.label}</span>
                    <span>{item.active ? 'YES' : 'NO'}</span>
                  </div>
                ))}
              </div>

              {detection?.vpn_providers && detection.vpn_providers.length > 0 && (
                <div className="space-y-1 pt-1">
                  <span className="text-theme-secondary text-[10px] block uppercase font-semibold">VPN Providers:</span>
                  <div className="flex flex-wrap gap-1">
                    {detection.vpn_providers.map((vpn, idx) => (
                      <span key={idx} className="px-1.5 py-0.5 rounded text-[10px] bg-amber-500/10 text-amber-400 border border-amber-500/20 font-bold">
                        {vpn}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {detection?.ip_categories && detection.ip_categories.length > 0 && (
                <div className="space-y-1 pt-1">
                  <span className="text-theme-secondary text-[10px] block uppercase font-semibold">IP Classifications:</span>
                  <div className="flex flex-wrap gap-1">
                    {detection.ip_categories.map((cat, idx) => (
                      <span key={idx} className="px-1.5 py-0.5 rounded text-[10px] bg-theme-surface text-theme-primary border border-theme uppercase">
                        {cat}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {detection?.special_issues && detection.special_issues.length > 0 && (
                <div className="space-y-1 pt-1">
                  <span className="text-theme-secondary text-[10px] block uppercase font-semibold">Special Issues:</span>
                  <div className="flex flex-wrap gap-1">
                    {detection.special_issues.map((iss, idx) => (
                      <span key={idx} className="px-1.5 py-0.5 rounded text-[10px] bg-red-500/10 text-red-400 border border-red-500/20">
                        {iss}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Host Security Indicators Card (Criminal IP) */}
        {hasSecurity && (
          <div className="bg-theme-card border border-theme rounded-xl p-4.5 space-y-3 shadow-sm">
            <div className="flex items-center justify-between pb-2 border-b border-theme">
              <div className="flex items-center space-x-2 text-indigo-400 text-xs font-bold uppercase tracking-wider">
                <Search className="w-4 h-4" />
                <span>Host Security Indicators</span>
              </div>
              <ProvenanceBadges sources={security?.sources || ['criminalip']} />
            </div>

            <div className="space-y-2 text-xs font-mono">
              {(security?.user_search_count ?? 0) > 0 && (
                <div className="flex justify-between items-center bg-theme-surface/50 p-2 rounded border border-theme">
                  <span className="text-theme-secondary">User Search Lookups:</span>
                  <span className="text-theme-primary font-bold">{security?.user_search_count} queries</span>
                </div>
              )}

              <div className="grid grid-cols-2 gap-2">
                <div className={`p-2 rounded border text-[11px] flex justify-between items-center ${
                  security?.honeypot_detected ? 'bg-red-500/10 border-red-500/30 text-red-400 font-bold' : 'bg-theme-surface/30 border-theme text-theme-muted'
                }`}>
                  <span>Honeypot:</span>
                  <span>{security?.honeypot_detected ? 'DETECTED' : 'CLEAN'}</span>
                </div>
                <div className={`p-2 rounded border text-[11px] flex justify-between items-center ${
                  security?.webcam_detected ? 'bg-orange-500/10 border-orange-500/30 text-orange-400 font-bold' : 'bg-theme-surface/30 border-theme text-theme-muted'
                }`}>
                  <span>Webcam / IoT:</span>
                  <span>{security?.webcam_detected ? 'DETECTED' : 'NONE'}</span>
                </div>
                <div className={`p-2 rounded border text-[11px] flex justify-between items-center ${
                  security?.admin_page_detected ? 'bg-yellow-500/10 border-yellow-500/30 text-yellow-400 font-bold' : 'bg-theme-surface/30 border-theme text-theme-muted'
                }`}>
                  <span>Admin Page:</span>
                  <span>{security?.admin_page_detected ? 'EXPOSED' : 'NONE'}</span>
                </div>
                <div className={`p-2 rounded border text-[11px] flex justify-between items-center ${
                  security?.invalid_ssl ? 'bg-red-500/10 border-red-500/30 text-red-400 font-bold' : 'bg-theme-surface/30 border-theme text-theme-muted'
                }`}>
                  <span>SSL Certificate:</span>
                  <span>{security?.invalid_ssl ? 'INVALID' : 'VALID'}</span>
                </div>
              </div>

              {(security?.ids_alerts_count ?? 0) > 0 && (
                <div className="space-y-1 pt-1">
                  <div className="flex justify-between items-center text-rose-400 font-bold">
                    <span>IDS Alert Signatures:</span>
                    <span>{security?.ids_alerts_count} Alerts</span>
                  </div>
                  {security?.ids_alert_signatures && security.ids_alert_signatures.length > 0 && (
                    <div className="space-y-1 max-h-24 overflow-y-auto">
                      {security.ids_alert_signatures.map((sig, idx) => (
                        <div key={idx} className="bg-rose-500/10 border border-rose-500/20 text-rose-300 p-1.5 rounded text-[10px] break-all">
                          {sig}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        )}

        {/* 1. Network & Routing Card */}
        {hasNetwork && (
          <div className="bg-theme-card border border-theme rounded-xl p-4.5 space-y-3 shadow-sm">
            <div className="flex items-center justify-between pb-2 border-b border-theme">
              <div className="flex items-center space-x-2 text-cyan-500 text-xs font-bold uppercase tracking-wider">
                <Network className="w-4 h-4" />
                <span>Network & Routing</span>
              </div>
              <ProvenanceBadges sources={net?.sources} />
            </div>
            <div className="space-y-2 text-xs font-mono">
              {(net?.ip || (layer2.root_type !== 'domain' && layer2.root_type !== 'url' && !layer2.root_type.includes('sha') && layer2.root_type !== 'md5')) && (
                <div className="flex justify-between items-center">
                  <span className="text-theme-secondary">Target IP:</span>
                  <span className="text-theme-primary font-bold">{net?.ip || layer2.root_ioc}</span>
                </div>
              )}
              {net?.ip_version && (
                <div className="flex justify-between items-center">
                  <span className="text-theme-secondary">IP Version:</span>
                  <span className="text-theme-primary">{net.ip_version}</span>
                </div>
              )}
              {(net?.asn || infra.asn) && (
                <div className="flex justify-between items-center">
                  <span className="text-theme-secondary">Autonomous System:</span>
                  <span className="text-cyan-400 font-bold">{net?.asn || infra.asn}</span>
                </div>
              )}
              {(net?.asn_name || infra.asn_name) && (
                <div className="flex justify-between items-center">
                  <span className="text-theme-secondary">AS Name:</span>
                  <span className="text-theme-primary font-semibold text-right truncate max-w-[170px]" title={net?.asn_name || infra.asn_name}>
                    {net?.asn_name || infra.asn_name}
                  </span>
                </div>
              )}
              {(net?.org || infra.org) && (
                <div className="flex justify-between items-center">
                  <span className="text-theme-secondary">Organization:</span>
                  <span className="text-theme-primary text-right truncate max-w-[170px]" title={net?.org || infra.org}>
                    {net?.org || infra.org}
                  </span>
                </div>
              )}
              {net?.isp && (
                <div className="flex justify-between items-center">
                  <span className="text-theme-secondary">ISP:</span>
                  <span className="text-theme-primary text-right truncate max-w-[170px]" title={net.isp}>
                    {net.isp}
                  </span>
                </div>
              )}
              {net?.bgp_prefix && (
                <div className="flex justify-between items-center">
                  <span className="text-theme-secondary">BGP Prefix:</span>
                  <span className="text-cyan-400 font-mono">{net.bgp_prefix}</span>
                </div>
              )}
              {(net?.cidr || infra.cidr) && (
                <div className="flex justify-between items-center">
                  <span className="text-theme-secondary">Subnet CIDR:</span>
                  <span className="text-theme-primary">{net?.cidr || infra.cidr}</span>
                </div>
              )}
              {(net?.ptr || infra.ptr) && (
                <div className="flex justify-between items-center">
                  <span className="text-theme-secondary">Reverse DNS (PTR):</span>
                  <span className="text-theme-primary truncate max-w-[170px]" title={net?.ptr || infra.ptr}>
                    {net?.ptr || infra.ptr}
                  </span>
                </div>
              )}
            </div>
          </div>
        )}

        {/* 2. Geolocation Card */}
        {hasGeo && (
          <div className="bg-theme-card border border-theme rounded-xl p-4.5 space-y-3 shadow-sm">
            <div className="flex items-center justify-between pb-2 border-b border-theme">
              <div className="flex items-center space-x-2 text-blue-500 text-xs font-bold uppercase tracking-wider">
                <Globe2 className="w-4 h-4" />
                <span>Physical Geolocation</span>
              </div>
              <ProvenanceBadges sources={geo?.sources} />
            </div>
            <div className="space-y-2 text-xs font-mono">
              <div className="text-[10px] text-theme-secondary uppercase font-semibold flex items-center justify-between pb-0.5">
                <span>Primary Observation</span>
                <span className="text-theme-muted font-normal">Self-Consistent</span>
              </div>
              {geo?.continent && (
                <div className="flex justify-between items-center">
                  <span className="text-theme-secondary">Continent:</span>
                  <span className="text-theme-primary">{geo.continent}</span>
                </div>
              )}
              {(geo?.country || infra.country) && (
                <div className="flex justify-between items-center">
                  <span className="text-theme-secondary">Country:</span>
                  <span className="text-theme-primary font-bold">
                    {geo?.country || infra.country} {geo?.country_code ? `(${geo.country_code})` : ''}
                  </span>
                </div>
              )}
              {(geo?.region || infra.region) && (
                <div className="flex justify-between items-center">
                  <span className="text-theme-secondary">Region / State:</span>
                  <span className="text-theme-primary">{geo?.region || infra.region}</span>
                </div>
              )}
              {(geo?.city || infra.city) && (
                <div className="flex justify-between items-center">
                  <span className="text-theme-secondary">City:</span>
                  <span className="text-theme-primary">{geo?.city || infra.city}</span>
                </div>
              )}
              {geo?.postal_code && (
                <div className="flex justify-between items-center">
                  <span className="text-theme-secondary">Postal Code:</span>
                  <span className="text-theme-primary">{geo.postal_code}</span>
                </div>
              )}
              {geo?.latitude != null &&
              geo?.longitude != null &&
              !isNaN(Number(geo.latitude)) &&
              !isNaN(Number(geo.longitude)) && (
                <div className="flex justify-between items-center">
                  <span className="text-theme-secondary">Coordinates:</span>
                  <span className="text-theme-primary">
                    {Number(geo.latitude).toFixed(4)}, {Number(geo.longitude).toFixed(4)}
                  </span>
                </div>
              )}
              {geo?.timezone && (
                <div className="flex justify-between items-center">
                  <span className="text-theme-secondary">Timezone:</span>
                  <span className="text-theme-primary">{geo.timezone}</span>
                </div>
              )}

              {/* Alternative Observations to preserve provider contradictions without field mixing */}
              {infra.alternative_geolocations && infra.alternative_geolocations.length > 0 && (
                <div className="pt-2 border-t border-theme/60 space-y-1.5">
                  <div className="flex items-center justify-between text-[10px] text-theme-secondary uppercase font-semibold">
                    <span>Alternative Observations ({infra.alternative_geolocations.length}):</span>
                    <span className="text-cyan-400 font-normal">Anycast / Multi-Region</span>
                  </div>
                  <div className="space-y-1 pl-1">
                    {infra.alternative_geolocations.map((altGeo, aIdx) => (
                      <div key={aIdx} className="bg-theme-surface/40 p-1.5 rounded border border-theme/50 text-[11px] space-y-0.5">
                        <div className="flex justify-between items-center">
                          <span className="font-semibold text-theme-primary">
                            {[altGeo.city, altGeo.region, altGeo.country].filter(Boolean).join(', ')}
                          </span>
                          <ProvenanceBadges sources={altGeo.sources} />
                        </div>
                        {altGeo.latitude != null && altGeo.longitude != null && (
                          <div className="text-[10px] text-theme-muted">
                            {Number(altGeo.latitude).toFixed(4)}, {Number(altGeo.longitude).toFixed(4)}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                  <p className="text-[9px] text-theme-muted italic pt-0.5">
                    Multi-region Anycast routing or CDN edge nodes may yield differing provider locations.
                  </p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* 3. DNS & Hostnames Card */}
        {hasDns && (
          <div className="bg-theme-card border border-theme rounded-xl p-4.5 space-y-3 shadow-sm">
            <div className="flex items-center justify-between pb-2 border-b border-theme">
              <div className="flex items-center space-x-2 text-amber-500 text-xs font-bold uppercase tracking-wider">
                <FileText className="w-4 h-4" />
                <span>DNS & Hostnames</span>
              </div>
              <ProvenanceBadges sources={dns?.sources} />
            </div>
            <div className="space-y-2 text-xs font-mono max-h-56 overflow-y-auto">
              {dns?.hostnames && dns.hostnames.filter((h) => !isIpStr(h)).length > 0 && (
                <div className="space-y-1">
                  <span className="text-theme-secondary text-[11px] block">Associated Hostnames:</span>
                  <div className="space-y-0.5 pl-2 border-l border-theme">
                    {dns.hostnames
                      .filter((h) => !isIpStr(h))
                      .map((h, i) => (
                        <div key={i} className="text-theme-primary truncate" title={h}>
                          {h}
                        </div>
                      ))}
                  </div>
                </div>
              )}
              {dns?.domains && dns.domains.filter((d) => !isIpStr(d)).length > 0 && (
                <div className="space-y-1 pt-1">
                  <span className="text-theme-secondary text-[11px] block">Associated Domains:</span>
                  <div className="space-y-0.5 pl-2 border-l border-theme">
                    {dns.domains
                      .filter((d) => !isIpStr(d))
                      .map((d, i) => (
                        <div key={i} className="text-amber-400 font-semibold truncate" title={d}>
                          {d}
                        </div>
                      ))}
                  </div>
                </div>
              )}
              {/* DNS Zone Records */}
              {infra.dns_records && Object.keys(infra.dns_records).length > 0 && (
                <div className="pt-1 space-y-1">
                  <span className="text-theme-secondary text-[11px] block">Zone Records:</span>
                  {Object.entries(infra.dns_records).map(([recType, values]) => (
                    <div key={recType} className="border-b border-theme pb-1 last:border-none">
                      <span className="text-amber-500 font-bold uppercase text-[10px] bg-amber-500/10 px-1 py-0.5 rounded mr-1.5 border border-amber-500/20">
                        {recType}
                      </span>
                      <span className="text-theme-primary">{values.map(formatDnsRecordValue).join(', ')}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* 4. WHOIS & Registration Card */}
        {hasWhois && (
          <div className="bg-theme-card border border-theme rounded-xl p-4.5 space-y-3 shadow-sm">
            <div className="flex items-center justify-between pb-2 border-b border-theme">
              <div className="flex items-center space-x-2 text-purple-500 text-xs font-bold uppercase tracking-wider">
                <Calendar className="w-4 h-4" />
                <span>Domain Registration</span>
              </div>
              <ProvenanceBadges sources={whois?.sources} />
            </div>
            <div className="space-y-2 text-xs font-mono">
              {(whois?.registrar || infra.registrar) && (
                <div className="flex justify-between items-center">
                  <span className="text-theme-secondary">Registrar:</span>
                  <span className="text-theme-primary font-semibold truncate max-w-[170px]" title={whois?.registrar || infra.registrar}>
                    {whois?.registrar || infra.registrar}
                  </span>
                </div>
              )}
              {(whois?.creation_date || infra.whois_creation) && (
                <div className="flex justify-between items-center">
                  <span className="text-theme-secondary">Created:</span>
                  <span className="text-theme-primary">{formatTimestamp(whois?.creation_date || infra.whois_creation)}</span>
                </div>
              )}
              {whois?.updated_date && (
                <div className="flex justify-between items-center">
                  <span className="text-theme-secondary">Updated:</span>
                  <span className="text-theme-primary">{formatTimestamp(whois.updated_date)}</span>
                </div>
              )}
              {(whois?.expiration_date || infra.whois_expiration) && (
                <div className="flex justify-between items-center">
                  <span className="text-theme-secondary">Expires:</span>
                  <span className="text-theme-primary">{formatTimestamp(whois?.expiration_date || infra.whois_expiration)}</span>
                </div>
              )}
              {whois?.registrant_org && (
                <div className="flex justify-between items-center">
                  <span className="text-theme-secondary">Registrant Org:</span>
                  <span className="text-theme-primary truncate max-w-[170px]" title={whois.registrant_org}>{whois.registrant_org}</span>
                </div>
              )}
              {whois?.registrant_country && (
                <div className="flex justify-between items-center">
                  <span className="text-theme-secondary">Registrant Country:</span>
                  <span className="text-theme-primary">{whois.registrant_country}</span>
                </div>
              )}
              {whois?.registrar_url && (
                <div className="flex justify-between items-center">
                  <span className="text-theme-secondary">Registrar URL:</span>
                  <a href={whois.registrar_url.startsWith('http') ? whois.registrar_url : `http://${whois.registrar_url}`} target="_blank" rel="noreferrer" className="text-cyan-400 hover:underline truncate max-w-[170px]">
                    {whois.registrar_url}
                  </a>
                </div>
              )}
              {whois?.registry_domain_id && (
                <div className="flex justify-between items-center">
                  <span className="text-theme-secondary">Domain ID:</span>
                  <span className="text-theme-muted font-mono text-[10px] truncate max-w-[170px]" title={whois.registry_domain_id}>{whois.registry_domain_id}</span>
                </div>
              )}
              {whois?.dnssec && (
                <div className="flex justify-between items-center">
                  <span className="text-theme-secondary">DNSSEC:</span>
                  <span className="text-theme-primary">{whois.dnssec}</span>
                </div>
              )}
              {whois?.status && whois.status.length > 0 && (
                <div className="space-y-1 pt-1">
                  <span className="text-theme-secondary block">Domain Status:</span>
                  <div className="flex flex-wrap gap-1">
                    {whois.status.slice(0, 4).map((st, i) => (
                      <span key={i} className="px-1 py-0.2 rounded text-[9px] bg-theme-surface text-theme-muted border border-theme">
                        {st}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {infra.nameservers && infra.nameservers.length > 0 && (
                <div className="space-y-1">
                  <span className="text-theme-secondary block">Nameservers:</span>
                  <div className="space-y-0.5 pl-2 border-l border-theme">
                    {infra.nameservers.slice(0, 3).map((ns, i) => (
                      <div key={i} className="text-theme-primary truncate" title={ns}>
                        {ns}
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {historicalWhois.length > 0 && (
                <div className="pt-2 border-t border-theme flex justify-between items-center">
                  <span className="text-theme-secondary">Historical Archive:</span>
                  <span className="text-[10px] font-bold text-purple-400 bg-purple-500/10 px-2 py-0.5 rounded border border-purple-500/20">
                    {historicalWhois.length} {historicalWhois.length === 1 ? 'snapshot' : 'snapshots'}
                  </span>
                </div>
              )}
            </div>
          </div>
        )}

        {/* 5. Shodan Host Intelligence Card */}
        {hasShodanDetails && shodan && (
          <div className="bg-theme-card border border-theme rounded-xl p-4.5 space-y-3 shadow-sm">
            <div className="flex items-center justify-between pb-2 border-b border-theme">
              <div className="flex items-center space-x-2 text-rose-500 text-xs font-bold uppercase tracking-wider">
                <Radio className="w-4 h-4" />
                <span>Shodan Host Intelligence</span>
              </div>
              <ProvenanceBadges sources={shodan.sources} />
            </div>
            <div className="space-y-2 text-xs font-mono">
              <div className="flex justify-between items-center">
                <span className="text-theme-secondary">Operating System:</span>
                <span className="text-theme-primary font-bold">{shodan.os || '—'}</span>
              </div>
              {shodan.device_type && (
                <div className="flex justify-between items-center">
                  <span className="text-theme-secondary">Device Type:</span>
                  <span className="text-theme-primary font-bold capitalize">{shodan.device_type}</span>
                </div>
              )}
              <div className="flex justify-between items-center">
                <span className="text-theme-secondary">Indexed Ports / Services:</span>
                <span className="text-theme-primary font-bold">
                  {shodan.total_ports || shodan.services_count || 0} {((shodan.total_ports || shodan.services_count || 0) === 1) ? 'port' : 'ports'}
                </span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-theme-secondary">Detected CVEs:</span>
                <span className={`font-bold text-[11px] ${(shodan.total_vulns || 0) > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                  {(shodan.total_vulns || 0) > 0 ? `${shodan.total_vulns} detected` : 'No vulnerabilities reported by Shodan'}
                </span>
              </div>
              {(shodan.asn || shodan.org || shodan.isp) && (
                <div className="flex justify-between items-center">
                  <span className="text-theme-secondary">Network / ASN:</span>
                  <span className="text-cyan-400 font-semibold truncate max-w-[170px]" title={[shodan.asn, shodan.org || shodan.isp].filter(Boolean).join(' - ')}>
                    {[shodan.asn, shodan.org || shodan.isp].filter(Boolean).join(' - ') || '—'}
                  </span>
                </div>
              )}
              {(shodan.city || shodan.country) && (
                <div className="flex justify-between items-center">
                  <span className="text-theme-secondary">Location:</span>
                  <span className="text-theme-primary truncate max-w-[170px]" title={[shodan.city, shodan.country].filter(Boolean).join(', ')}>
                    {[shodan.city, shodan.country].filter(Boolean).join(', ') || '—'}
                  </span>
                </div>
              )}
              {shodan.latitude != null && shodan.longitude != null && !isNaN(Number(shodan.latitude)) && (
                <div className="flex justify-between items-center text-[11px]">
                  <span className="text-theme-secondary">Coordinates:</span>
                  <span className="text-theme-muted">{Number(shodan.latitude).toFixed(4)}, {Number(shodan.longitude).toFixed(4)}</span>
                </div>
              )}
              {shodan.tags && shodan.tags.length > 0 && (
                <div className="space-y-1">
                  <span className="text-theme-secondary block">Host Tags:</span>
                  <div className="flex flex-wrap gap-1">
                    {shodan.tags.map((t, i) => (
                      <span key={i} className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-rose-500/10 text-rose-400 border border-rose-500/20">
                        {t}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {shodan.domains && shodan.domains.length > 0 && (
                <div className="space-y-1">
                  <span className="text-theme-secondary text-[11px] block">Observed Domains:</span>
                  <div className="flex flex-wrap gap-1 max-h-16 overflow-y-auto">
                    {shodan.domains.slice(0, 4).map((d, i) => (
                      <span key={i} className="text-amber-400 text-[10px] truncate max-w-[200px]" title={d}>
                        {d}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {shodan.last_update && (
                <div className="flex justify-between items-center pt-1 border-t border-theme">
                  <span className="text-theme-secondary">Last Indexed:</span>
                  <span className="text-theme-muted text-[11px]">{formatTimestamp(shodan.last_update)}</span>
                </div>
              )}
            </div>
          </div>
        )}

        {/* 5b. Censys Host & Asset Intelligence Card */}
        {hasCensysDetails && censys && (
          <div className="bg-theme-card border border-theme rounded-xl p-4.5 space-y-3 shadow-sm">
            <div className="flex items-center justify-between pb-2 border-b border-theme">
              <div className="flex items-center space-x-2 text-cyan-400 text-xs font-bold uppercase tracking-wider">
                <Radar className="w-4 h-4" />
                <span>Censys Host Intelligence</span>
              </div>
              <ProvenanceBadges sources={censys.sources || ['censys']} />
            </div>
            <div className="space-y-2 text-xs font-mono">
              {censys.ip && (
                <div className="flex justify-between items-center">
                  <span className="text-theme-secondary">Host IP:</span>
                  <span className="text-theme-primary font-bold">{censys.ip}</span>
                </div>
              )}
              {censys.os && (
                <div className="flex justify-between items-center">
                  <span className="text-theme-secondary">Operating System:</span>
                  <span className="text-theme-primary font-bold">{censys.os}</span>
                </div>
              )}
              <div className="flex justify-between items-center">
                <span className="text-theme-secondary">Indexed Services:</span>
                <span className="text-theme-primary font-bold">
                  {censys.service_count || 0} {(censys.service_count === 1) ? 'service' : 'services'}
                </span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-theme-secondary">Detected CVEs:</span>
                <span className={`font-bold text-[11px] ${(censys.total_vulns || 0) > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                  {(censys.total_vulns || 0) > 0 ? `${censys.total_vulns} detected` : 'No vulnerabilities reported by Censys'}
                </span>
              </div>
              {(censys.asn || censys.asn_name) && (
                <div className="flex justify-between items-center">
                  <span className="text-theme-secondary">Autonomous System:</span>
                  <span className="text-cyan-400 font-semibold truncate max-w-[170px]" title={[censys.asn, censys.asn_name].filter(Boolean).join(' - ')}>
                    {[censys.asn, censys.asn_name].filter(Boolean).join(' - ')}
                  </span>
                </div>
              )}
              {censys.bgp_prefix && (
                <div className="flex justify-between items-center">
                  <span className="text-theme-secondary">BGP Prefix:</span>
                  <span className="text-theme-primary font-mono">{censys.bgp_prefix}</span>
                </div>
              )}
              {(censys.city || censys.country) && (
                <div className="flex justify-between items-center">
                  <span className="text-theme-secondary">Location:</span>
                  <span className="text-theme-primary truncate max-w-[170px]" title={[censys.city, censys.country].filter(Boolean).join(', ')}>
                    {[censys.city, censys.country].filter(Boolean).join(', ')}
                  </span>
                </div>
              )}
              {censys.latitude != null && censys.longitude != null && !isNaN(Number(censys.latitude)) && (
                <div className="flex justify-between items-center text-[11px]">
                  <span className="text-theme-secondary">Coordinates:</span>
                  <span className="text-theme-muted">{Number(censys.latitude).toFixed(4)}, {Number(censys.longitude).toFixed(4)}</span>
                </div>
              )}
              {censys.host_labels && censys.host_labels.length > 0 && (
                <div className="space-y-1">
                  <span className="text-theme-secondary block">Host Labels:</span>
                  <div className="flex flex-wrap gap-1">
                    {censys.host_labels.map((lbl, i) => (
                      <span key={i} className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                        {lbl}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {censys.last_observed_at && (
                <div className="flex justify-between items-center pt-1 border-t border-theme">
                  <span className="text-theme-secondary">Last Observed:</span>
                  <span className="text-theme-muted text-[11px]">{formatTimestamp(censys.last_observed_at)}</span>
                </div>
              )}
            </div>
          </div>
        )}

        {/* 6. Web & HTTP Telemetry Card */}
        {hasHttp && (
          <div className="bg-theme-card border border-theme rounded-xl p-4.5 space-y-3 shadow-sm">
            <div className="flex items-center justify-between pb-2 border-b border-theme">
              <div className="flex items-center space-x-2 text-yellow-500 text-xs font-bold uppercase tracking-wider">
                <Server className="w-4 h-4" />
                <span>Web Telemetry</span>
              </div>
              <ProvenanceBadges sources={http?.sources} />
            </div>
            <div className="space-y-2 text-xs font-mono">
              {(http?.server || infra.http_server) && (
                <div className="flex justify-between items-center">
                  <span className="text-theme-secondary">Server Header:</span>
                  <span className="text-theme-primary font-semibold">{http?.server || infra.http_server}</span>
                </div>
              )}
              {http?.status_code != null && (
                <div className="flex justify-between items-center">
                  <span className="text-theme-secondary">HTTP Status:</span>
                  <span className={`px-1.5 py-0.2 rounded text-[10px] font-bold ${
                    http.status_code >= 200 && http.status_code < 300
                      ? 'bg-emerald-500/20 text-emerald-400'
                      : http.status_code >= 300 && http.status_code < 400
                      ? 'bg-amber-500/20 text-amber-400'
                      : 'bg-red-500/20 text-red-400'
                  }`}>
                    {http.status_code}
                  </span>
                </div>
              )}
              {(http?.title || infra.http_title) && (
                <div className="space-y-0.5">
                  <span className="text-theme-secondary block">Page Title:</span>
                  <span className="text-yellow-400 font-medium italic block break-words">
                    "{http?.title || infra.http_title}"
                  </span>
                </div>
              )}
              {http?.technologies && http.technologies.length > 0 && (
                <div className="space-y-1">
                  <span className="text-theme-secondary block">Technologies:</span>
                  <div className="flex flex-wrap gap-1">
                    {http.technologies.map((tech, i) => (
                      <span key={i} className="px-1.5 py-0.5 rounded text-[10px] bg-yellow-500/10 text-yellow-400 border border-yellow-500/20">
                        {tech}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {(http?.screenshot_url || infra.screenshot_url) && (
                <div className="pt-2">
                  <a
                    href={http?.screenshot_url || infra.screenshot_url}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center space-x-1 text-cyan-500 hover:text-cyan-400 text-xs font-semibold"
                  >
                    <span>View Captured Screenshot</span>
                    <ExternalLink className="w-3 h-3" />
                  </a>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Web-Check Intelligence & OSINT Reconnaissance */}
        {hasWebCheck && (
          <div className="bg-theme-card border border-violet-500/30 rounded-xl p-4.5 space-y-4 shadow-sm md:col-span-2 lg:col-span-3">
            <div className="flex items-center justify-between pb-2 border-b border-theme flex-wrap gap-2">
              <div className="flex items-center space-x-2 text-violet-400 text-xs font-bold uppercase tracking-wider">
                <Compass className="w-4 h-4" />
                <span>Web-Check OSINT Intelligence</span>
              </div>
              <div className="flex items-center space-x-2">
                <span className="text-[10px] font-mono text-violet-400 bg-violet-500/10 px-2 py-0.5 rounded border border-violet-500/20">
                  Lissy93 Web Intelligence
                </span>
                <ProvenanceBadges sources={['webcheck']} />
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {/* A. Web-Check Infrastructure & Server Location */}
              {(webcheck.location || webcheck['get-ip']) && (
                <div className="bg-theme-inset border border-theme rounded-lg p-3 space-y-2 text-xs font-mono md:col-span-2 lg:col-span-3">
                  <div className="flex items-center justify-between">
                    <span className="text-theme-secondary font-bold uppercase text-[10px] flex items-center space-x-1">
                      <Network className="w-3.5 h-3.5 text-violet-400" />
                      <span>Web-Check Infrastructure & Server Location</span>
                    </span>
                    <span className="text-[10px] text-theme-muted">Server Location & Network</span>
                  </div>
                  <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-2 pt-1 text-[11px]">
                    {(webcheck.location?.ip || webcheck['get-ip']?.ip) && (
                      <div className="bg-theme-surface/50 p-2 rounded border border-theme">
                        <span className="text-[10px] text-theme-muted block">IP Address</span>
                        <span className="text-theme-primary font-bold">{webcheck.location?.ip || webcheck['get-ip']?.ip}</span>
                      </div>
                    )}
                    {webcheck.location?.asn && (
                      <div className="bg-theme-surface/50 p-2 rounded border border-theme">
                        <span className="text-[10px] text-theme-muted block">Autonomous System</span>
                        <span className="text-violet-300 font-bold">{webcheck.location.asn}</span>
                      </div>
                    )}
                    {(webcheck.location?.org || webcheck.location?.isp) && (
                      <div className="bg-theme-surface/50 p-2 rounded border border-theme">
                        <span className="text-[10px] text-theme-muted block">Organization / ISP</span>
                        <span className="text-theme-primary truncate block" title={webcheck.location.org || webcheck.location.isp}>
                          {webcheck.location.org || webcheck.location.isp}
                        </span>
                      </div>
                    )}
                    {(webcheck.location?.city || webcheck.location?.country || webcheck.location?.country_name) && (
                      <div className="bg-theme-surface/50 p-2 rounded border border-theme">
                        <span className="text-[10px] text-theme-muted block">Server Location</span>
                        <span className="text-emerald-400 font-bold">
                          {[webcheck.location.city, webcheck.location.region, webcheck.location.country || webcheck.location.country_name].filter(Boolean).join(', ')}
                        </span>
                        {webcheck.location.lat != null && webcheck.location.lon != null && (
                          <span className="text-[9px] text-theme-muted block font-mono">
                            {webcheck.location.lat}, {webcheck.location.lon}
                          </span>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* B. Open Ports & Services Reconnaissance */}
              {webcheck.ports && (
                <div className="bg-theme-inset border border-theme rounded-lg p-3 space-y-2 text-xs font-mono md:col-span-2 lg:col-span-3">
                  <div className="flex items-center justify-between flex-wrap gap-1">
                    <span className="text-theme-secondary font-bold uppercase text-[10px] flex items-center space-x-1">
                      <Radio className="w-3.5 h-3.5 text-rose-400" />
                      <span>Web-Check Port Reconnaissance ({Array.isArray(webcheck.ports.openPorts) ? webcheck.ports.openPorts.length : 0} Open)</span>
                    </span>
                    <div className="flex items-center gap-1.5">
                      <span className="text-[9px] font-mono text-cyan-400 bg-cyan-500/10 px-1.5 py-0.5 rounded border border-cyan-500/20">
                        Active Probe (32 Common Ports)
                      </span>
                      {webcheck.ports.failedPorts && Array.isArray(webcheck.ports.failedPorts) && (
                        <span className="text-[10px] text-theme-muted">
                          {webcheck.ports.failedPorts.length} closed/filtered
                        </span>
                      )}
                    </div>
                  </div>
                  {webcheck.ports.openPorts && Array.isArray(webcheck.ports.openPorts) && webcheck.ports.openPorts.length > 0 ? (
                    <div className="space-y-2 pt-1">
                      <div className="flex flex-wrap gap-1.5">
                        {webcheck.ports.openPorts.map((p: any, pIdx: number) => (
                          <span
                            key={pIdx}
                            className="px-2 py-0.5 rounded text-[11px] font-bold bg-rose-500/10 text-rose-400 border border-rose-500/30 font-mono"
                          >
                            Port {p}/tcp
                          </span>
                        ))}
                      </div>
                      <div className="overflow-x-auto rounded border border-theme">
                        <table className="w-full text-left text-[11px] font-mono">
                          <thead className="bg-theme-surface/70 text-theme-secondary uppercase text-[10px]">
                            <tr>
                              <th className="px-3 py-1.5 border-b border-theme">Port</th>
                              <th className="px-3 py-1.5 border-b border-theme">Protocol</th>
                              <th className="px-3 py-1.5 border-b border-theme">Service</th>
                              <th className="px-3 py-1.5 border-b border-theme">Status</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-theme/40 bg-theme-surface/20">
                            {webcheck.ports.openPorts.map((p: any, idx: number) => {
                              const pNum = Number(p);
                              const defaultService =
                                pNum === 80 ? 'http'
                                : pNum === 443 ? 'https'
                                : pNum === 22 ? 'ssh'
                                : pNum === 21 ? 'ftp'
                                : pNum === 25 ? 'smtp'
                                : pNum === 53 ? 'dns'
                                : pNum === 8080 ? 'http-proxy'
                                : pNum === 8443 ? 'https-alt'
                                : pNum === 3306 ? 'mysql'
                                : pNum === 3389 ? 'rdp'
                                : 'open-port';
                              return (
                                <tr key={idx} className="hover:bg-theme-surface/40">
                                  <td className="px-3 py-1 text-theme-primary font-bold">{pNum}</td>
                                  <td className="px-3 py-1 text-theme-secondary">TCP</td>
                                  <td className="px-3 py-1 text-cyan-400">{defaultService}</td>
                                  <td className="px-3 py-1 text-emerald-400 font-semibold">OPEN / ACCESSIBLE</td>
                                </tr>
                              );
                            })}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  ) : (
                    <div className="flex items-center justify-between pt-1">
                      <p className="text-[11px] text-emerald-400 font-semibold flex items-center space-x-1.5">
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
                        <span>0 open ports detected</span>
                      </p>
                      {webcheck.ports.failedPorts && Array.isArray(webcheck.ports.failedPorts) && (
                        <span className="text-[10px] text-theme-muted font-mono">
                          ({webcheck.ports.failedPorts.length} common ports scanned & closed/filtered)
                        </span>
                      )}
                    </div>
                  )}
                </div>
              )}

              {/* C. DNS Records Table */}
              {webcheck.dns && typeof webcheck.dns === 'object' && (
                <div className="bg-theme-inset border border-theme rounded-lg p-3 space-y-2 text-xs font-mono md:col-span-2 lg:col-span-3">
                  <div className="flex items-center justify-between">
                    <span className="text-theme-secondary font-bold uppercase text-[10px] flex items-center space-x-1">
                      <Server className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Web-Check DNS Records Table</span>
                    </span>
                    <span className="text-[10px] text-theme-muted">Direct Resolution</span>
                  </div>
                  {Object.keys(webcheck.dns).length > 0 && Object.values(webcheck.dns).some(v => Array.isArray(v) ? v.length > 0 : Boolean(v)) ? (
                    <div className="overflow-x-auto rounded border border-theme max-h-48 overflow-y-auto">
                      <table className="w-full text-left text-[11px] font-mono">
                        <thead className="bg-theme-surface/70 text-theme-secondary uppercase text-[10px] sticky top-0">
                          <tr>
                            <th className="px-3 py-1.5 border-b border-theme w-20">Type</th>
                            <th className="px-3 py-1.5 border-b border-theme">Value</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-theme/40 bg-theme-surface/20">
                          {Object.entries(webcheck.dns).flatMap(([type, val]: [string, any]) => {
                            const items = Array.isArray(val) ? val : (val ? [val] : []);
                            return items.map((item: any, iIdx: number) => {
                              const valStr = typeof item === 'object' ? (item.value || item.address || item.exchange || JSON.stringify(item)) : String(item);
                              return (
                                <tr key={`${type}_${iIdx}`} className="hover:bg-theme-surface/40">
                                  <td className="px-3 py-1 text-cyan-400 font-bold">{type.toUpperCase()}</td>
                                  <td className="px-3 py-1 text-theme-primary break-all">{valStr}</td>
                                </tr>
                              );
                            });
                          })}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <p className="text-[10px] text-theme-muted pt-1">No DNS records detected for this target.</p>
                  )}
                </div>
              )}

              {/* D. SSL / TLS Certificate Details */}
              {(webcheck.ssl || webcheck['tls-connection'] || webcheck['tls-labs']) && (
                <div className="bg-theme-inset border border-theme rounded-lg p-3 space-y-2 text-xs font-mono">
                  <div className="flex items-center justify-between">
                    <span className="text-theme-secondary font-bold uppercase text-[10px] flex items-center space-x-1">
                      <Lock className="w-3.5 h-3.5 text-cyan-400" />
                      <span>TLS / SSL Encryption Details</span>
                    </span>
                    {webcheck['tls-labs']?.grade && (
                      <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                        Grade {webcheck['tls-labs'].grade}
                      </span>
                    )}
                  </div>
                  {(webcheck['tls-connection']?.protocol || webcheck['tls-connection']?.cipher || webcheck.ssl?.subject || webcheck.ssl?.issuer || webcheck.ssl?.valid_to) ? (
                    <div className="space-y-1 text-[11px] pt-1">
                      {webcheck['tls-connection']?.protocol && (
                        <div className="flex justify-between items-center">
                          <span className="text-theme-secondary">Protocol:</span>
                          <span className="text-cyan-300 font-bold">{webcheck['tls-connection'].protocol}</span>
                        </div>
                      )}
                      {webcheck['tls-connection']?.cipher && (
                        <div className="flex justify-between items-center">
                          <span className="text-theme-secondary">Cipher:</span>
                          <span className="text-theme-primary font-mono text-[10px] truncate max-w-[150px]">
                            {typeof webcheck['tls-connection'].cipher === 'object'
                              ? webcheck['tls-connection'].cipher.name
                              : String(webcheck['tls-connection'].cipher)}
                          </span>
                        </div>
                      )}
                      {webcheck.ssl?.subject && (
                        <div className="flex justify-between items-center">
                          <span className="text-theme-secondary">Subject:</span>
                          <span className="text-theme-primary truncate max-w-[150px]">
                            {typeof webcheck.ssl.subject === 'object' ? (webcheck.ssl.subject.CN || JSON.stringify(webcheck.ssl.subject)) : String(webcheck.ssl.subject)}
                          </span>
                        </div>
                      )}
                      {webcheck.ssl?.issuer && (
                        <div className="flex justify-between items-center">
                          <span className="text-theme-secondary">Issuer:</span>
                          <span className="text-theme-primary truncate max-w-[150px]">
                            {typeof webcheck.ssl.issuer === 'object' ? (webcheck.ssl.issuer.CN || JSON.stringify(webcheck.ssl.issuer)) : String(webcheck.ssl.issuer)}
                          </span>
                        </div>
                      )}
                      {webcheck.ssl?.valid_to && (
                        <div className="flex justify-between items-center">
                          <span className="text-theme-secondary">Expires:</span>
                          <span className="text-emerald-400">{webcheck.ssl.valid_to}</span>
                        </div>
                      )}
                    </div>
                  ) : (
                    <p className="text-[10px] text-theme-muted pt-1">No TLS/SSL certificate parameters detected (port 443 closed or unencrypted service).</p>
                  )}
                </div>
              )}

              {/* E. WHOIS Domain / IP Registration */}
              {webcheck.whois && typeof webcheck.whois === 'object' && (
                <div className="bg-theme-inset border border-theme rounded-lg p-3 space-y-2 text-xs font-mono md:col-span-2">
                  <div className="flex items-center justify-between">
                    <span className="text-theme-secondary font-bold uppercase text-[10px] flex items-center space-x-1">
                      <FileText className="w-3.5 h-3.5 text-violet-400" />
                      <span>WHOIS Registration Intelligence</span>
                    </span>
                    {webcheck.whois.registrar && (
                      <span className="text-[10px] text-theme-muted truncate max-w-[200px]">{webcheck.whois.registrar}</span>
                    )}
                  </div>
                  {(webcheck.whois.created || webcheck.whois.expires || webcheck.whois.registrant || webcheck.whois.organization || webcheck.whois.registrar) ? (
                    <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 pt-1 text-[11px]">
                      {webcheck.whois.created && (
                        <div className="bg-theme-surface/50 p-2 rounded border border-theme">
                          <span className="text-[10px] text-theme-muted block">Created</span>
                          <span className="text-theme-primary font-bold">{webcheck.whois.created}</span>
                        </div>
                      )}
                      {webcheck.whois.expires && (
                        <div className="bg-theme-surface/50 p-2 rounded border border-theme">
                          <span className="text-[10px] text-theme-muted block">Expires</span>
                          <span className="text-emerald-400 font-bold">{webcheck.whois.expires}</span>
                        </div>
                      )}
                      {(webcheck.whois.registrant || webcheck.whois.organization) && (
                        <div className="bg-theme-surface/50 p-2 rounded border border-theme">
                          <span className="text-[10px] text-theme-muted block">Registrant</span>
                          <span className="text-theme-primary truncate block">
                            {typeof webcheck.whois.registrant === 'object'
                              ? (webcheck.whois.registrant.organization || webcheck.whois.registrant.name || 'Private')
                              : (webcheck.whois.organization || String(webcheck.whois.registrant))}
                          </span>
                        </div>
                      )}
                    </div>
                  ) : (
                    <p className="text-[10px] text-theme-muted pt-1">No registration records found in WHOIS data.</p>
                  )}
                </div>
              )}

              {/* F. Data Breaches (Have I Been Pwned) */}
              {webcheck.breaches?.breaches && Array.isArray(webcheck.breaches.breaches) && webcheck.breaches.breaches.length > 0 && (
                <div className="bg-theme-inset border border-rose-500/30 rounded-lg p-3 space-y-2 text-xs font-mono md:col-span-2 lg:col-span-3">
                  <div className="flex items-center justify-between">
                    <span className="text-rose-400 font-bold uppercase text-[10px] flex items-center space-x-1">
                      <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
                      <span>Data Breaches ({webcheck.breaches.breaches.length})</span>
                    </span>
                    <span className="text-[10px] text-theme-muted">Have I Been Pwned</span>
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2 pt-1 text-[11px]">
                    {webcheck.breaches.breaches.map((b: any, bIdx: number) => (
                      <div key={bIdx} className="bg-rose-500/10 border border-rose-500/30 rounded p-2 space-y-1">
                        <div className="flex justify-between items-center">
                          <span className="text-rose-300 font-bold">{b.title || b.name}</span>
                          <span className="text-[10px] text-theme-muted">{b.date}</span>
                        </div>
                        {b.accounts != null && (
                          <div className="text-[10px] text-theme-secondary">
                            Accounts: <span className="text-theme-primary font-bold">{Number(b.accounts).toLocaleString()}</span>
                          </div>
                        )}
                        {b.exposed && Array.isArray(b.exposed) && (
                          <div className="flex flex-wrap gap-1 pt-0.5">
                            {b.exposed.slice(0, 4).map((ex: string, eIdx: number) => (
                              <span key={eIdx} className="px-1 py-0.2 rounded text-[9px] bg-theme-surface text-theme-muted border border-theme">
                                {ex}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* 1. WAF & Firewall Detection */}
              {webcheck.firewall && (
                <div className="bg-theme-inset border border-theme rounded-lg p-3 space-y-2 text-xs font-mono">
                  <div className="flex items-center justify-between">
                    <span className="text-theme-secondary font-bold uppercase text-[10px] flex items-center space-x-1">
                      <Shield className="w-3.5 h-3.5 text-violet-400" />
                      <span>WAF & Protection</span>
                    </span>
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase ${
                      webcheck.firewall.hasWaf
                        ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                        : 'bg-theme-surface text-theme-muted border border-theme'
                    }`}>
                      {webcheck.firewall.hasWaf ? 'WAF DETECTED' : 'NO WAF'}
                    </span>
                  </div>
                  {webcheck.firewall.waf ? (
                    <div className="flex justify-between items-center text-[11px] pt-1">
                      <span className="text-theme-secondary">Identified WAF:</span>
                      <span className="text-violet-300 font-bold">{webcheck.firewall.waf}</span>
                    </div>
                  ) : (
                    <p className="text-[10px] text-theme-muted pt-1">No web application firewall signatures matched.</p>
                  )}
                  {webcheck['security-txt'] && (
                    <div className="pt-2 border-t border-theme/50 flex justify-between items-center text-[11px]">
                      <span className="text-theme-secondary">security.txt:</span>
                      <span className={webcheck['security-txt'].isPresent ? 'text-emerald-400 font-bold' : 'text-theme-muted'}>
                        {webcheck['security-txt'].isPresent ? 'PRESENT' : 'NOT FOUND'}
                      </span>
                    </div>
                  )}
                </div>
              )}

              {/* 2. Security Headers Scorecard */}
              {(infra.security_headers || webcheck?.['http-security']) && (() => {
                const secHeaders = infra.security_headers;
                const canonicalSpecs = [
                  { id: 'hsts', name: 'Strict-Transport-Security', label: 'HSTS', key: 'strictTransportPolicy' },
                  { id: 'csp', name: 'Content-Security-Policy', label: 'CSP', key: 'contentSecurityPolicy' },
                  { id: 'x_frame', name: 'X-Frame-Options', label: 'X-Frame', key: 'xFrameOptions' },
                  { id: 'x_content_type', name: 'X-Content-Type-Options', label: 'X-Content-Type', key: 'xContentTypeOptions' },
                  { id: 'x_xss', name: 'X-XSS-Protection', label: 'X-XSS', key: 'xXSSProtection' },
                  { id: 'referrer_policy', name: 'Referrer-Policy', label: 'Referrer', key: 'referrerPolicy' },
                  { id: 'permissions_policy', name: 'Permissions-Policy', label: 'Permissions', key: 'permissionsPolicy' },
                  { id: 'coop', name: 'Cross-Origin-Opener-Policy', label: 'COOP', key: 'crossOriginOpenerPolicy' },
                  { id: 'corp', name: 'Cross-Origin-Resource-Policy', label: 'CORP', key: 'crossOriginResourcePolicy' },
                  { id: 'coep', name: 'Cross-Origin-Embedder-Policy', label: 'COEP', key: 'crossOriginEmbedderPolicy' },
                ];

                const headersList = secHeaders?.headers || canonicalSpecs.map((spec) => {
                  const val = webcheck?.['http-security']?.[spec.key];
                  const isPresent = Boolean(val);
                  return {
                    name: spec.name,
                    display_name: spec.label,
                    state: isPresent ? 'PRESENT' : 'MISSING',
                    value: typeof val === 'string' ? val : (isPresent ? 'configured' : undefined),
                    sources: ['webcheck'],
                  };
                });

                const activeCount = secHeaders != null ? secHeaders.active_count : headersList.filter((h: any) => h.state === 'PRESENT').length;
                const totalSupported = secHeaders != null ? secHeaders.total_supported : 10;
                const evaluatedCount = secHeaders != null ? secHeaders.evaluated_count : headersList.length;

                return (
                  <div className="bg-theme-inset border border-theme rounded-lg p-3 space-y-2 text-xs font-mono md:col-span-2">
                    <div className="flex items-center justify-between">
                      <span className="text-theme-secondary font-bold uppercase text-[10px] flex items-center space-x-1">
                        <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                        <span>HTTP Security Headers</span>
                      </span>
                      <span className="text-[10px] text-theme-muted font-bold">
                        {activeCount} / {evaluatedCount || totalSupported} Active
                      </span>
                    </div>
                    <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-1.5 pt-1">
                      {headersList.map((hdr: any) => {
                        const isPresent = hdr.state === 'PRESENT';
                        const isFailed = hdr.state === 'REQUEST_FAILED';
                        const isNotChecked = hdr.state === 'NOT_CHECKED';
                        const isUnavailable = hdr.state === 'UNAVAILABLE';

                        let badgeStyle = 'bg-theme-surface/30 border-theme text-theme-muted';
                        let icon = '✗';
                        if (isPresent) {
                          badgeStyle = 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400 font-bold';
                          icon = '✓';
                        } else if (isFailed) {
                          badgeStyle = 'bg-rose-500/10 border-rose-500/30 text-rose-400';
                          icon = '!';
                        } else if (isNotChecked) {
                          badgeStyle = 'bg-theme-surface/20 border-theme/40 text-theme-muted/60';
                          icon = '-';
                        } else if (isUnavailable) {
                          badgeStyle = 'bg-theme-surface/20 border-theme/40 text-theme-muted/60';
                          icon = '?';
                        }

                        const tooltipText = hdr.value ? `${hdr.name}: ${hdr.value}` : (hdr.evidence || hdr.name);

                        return (
                          <div
                            key={hdr.name}
                            title={tooltipText}
                            className={`p-1.5 rounded border text-[10px] flex justify-between items-center transition-colors ${badgeStyle}`}
                          >
                            <span className="truncate">{hdr.display_name || hdr.name}</span>
                            <span className="ml-1 shrink-0">{icon}</span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                );
              })()}

              {/* 3. Tech Stack (Wappalyzer) */}
              {webcheck['tech-stack']?.technologies && webcheck['tech-stack'].technologies.length > 0 && (
                <div className="bg-theme-inset border border-theme rounded-lg p-3 space-y-2 text-xs font-mono md:col-span-2 lg:col-span-3">
                  <div className="flex items-center justify-between">
                    <span className="text-theme-secondary font-bold uppercase text-[10px] flex items-center space-x-1">
                      <Code className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Detected Technologies ({webcheck['tech-stack'].technologies.length})</span>
                    </span>
                    <span className="text-[10px] text-theme-muted">Wappalyzer Engine</span>
                  </div>
                  <div className="flex flex-wrap gap-1.5 pt-1">
                    {webcheck['tech-stack'].technologies.map((t: any, idx: number) => {
                      const name = typeof t === 'string' ? t : (t.name || 'Unknown');
                      const version = typeof t === 'object' ? t.version : null;
                      const categories = typeof t === 'object' && Array.isArray(t.categories) ? t.categories : [];
                      return (
                        <span
                          key={idx}
                          className="px-2 py-1 rounded text-[11px] bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 font-semibold inline-flex items-center space-x-1"
                        >
                          <span>{name}</span>
                          {version && <span className="text-cyan-400 text-[9px] bg-cyan-950/60 px-1 py-0.2 rounded font-mono">v{version}</span>}
                          {categories.length > 0 && (
                            <span className="text-theme-muted text-[9px]">({typeof categories[0] === 'string' ? categories[0] : (categories[0]?.name || '')})</span>
                          )}
                        </span>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* 4. Mail Configuration & Domain Security */}
              {(webcheck['mail-config'] && typeof webcheck['mail-config'] === 'object' || canonicalMxList.length > 0) && (
                <div className="bg-theme-inset border border-theme rounded-lg p-3 space-y-2 text-xs font-mono md:col-span-2">
                  <div className="flex items-center justify-between">
                    <span className="text-theme-secondary font-bold uppercase text-[10px] flex items-center space-x-1">
                      <Mail className="w-3.5 h-3.5 text-indigo-400" />
                      <span>Mail Server & Anti-Spoofing Configuration</span>
                    </span>
                    <span className="text-[10px] text-theme-muted">SPF / DMARC / DKIM / MX</span>
                  </div>
                  <div className="space-y-1.5 pt-1 text-[11px]">
                    {isIp && (
                      <div className="bg-theme-surface/40 p-2 rounded border border-theme text-[10px] text-theme-muted flex items-center gap-1.5">
                        <span className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase bg-theme-surface text-theme-muted border border-theme">
                          NOT APPLICABLE
                        </span>
                        <span>Mail routing policies (SPF, DMARC, MX) apply to domain names, not raw IP addresses.</span>
                      </div>
                    )}

                    {/* SPF */}
                    <div className="bg-theme-surface/50 p-2 rounded border border-theme space-y-0.5">
                      <div className="flex justify-between items-center">
                        <span className="text-theme-secondary font-semibold">SPF (Sender Policy Framework):</span>
                        <span className={`px-1.5 py-0.2 rounded text-[10px] font-bold ${
                          webcheck['mail-config']?.spf?.record
                            ? (webcheck['mail-config'].spf?.valid ? 'bg-emerald-500/20 text-emerald-400' : 'bg-yellow-500/20 text-yellow-400')
                            : 'bg-theme-surface text-theme-muted'
                        }`}>
                          {webcheck['mail-config']?.spf?.record
                            ? (webcheck['mail-config'].spf?.valid ? 'VALID SPF' : 'SPF RECORD')
                            : isIp ? 'NOT APPLICABLE' : 'NOT DETECTED / NO RECORD'}
                        </span>
                      </div>
                      {webcheck['mail-config']?.spf?.record ? (
                        <div className="text-[10px] text-theme-muted font-mono break-all">
                          {webcheck['mail-config'].spf.record}
                        </div>
                      ) : (
                        <div className="text-[10px] text-theme-muted italic">
                          {isIp ? 'SPF records are published on domain names.' : 'No SPF anti-spoofing policy published for this host.'}
                        </div>
                      )}
                    </div>

                    {/* DMARC */}
                    <div className="bg-theme-surface/50 p-2 rounded border border-theme space-y-0.5">
                      <div className="flex justify-between items-center">
                        <span className="text-theme-secondary font-semibold">DMARC (Domain Message Authentication):</span>
                        <span className={`px-1.5 py-0.2 rounded text-[10px] font-bold ${
                          webcheck['mail-config']?.dmarc?.record
                            ? 'bg-indigo-500/20 text-indigo-300'
                            : 'bg-theme-surface text-theme-muted'
                        }`}>
                          {webcheck['mail-config']?.dmarc?.record
                            ? `Policy: ${webcheck['mail-config'].dmarc.policy || 'none'}`
                            : isIp ? 'NOT APPLICABLE' : 'NOT CONFIGURED'}
                        </span>
                      </div>
                      {webcheck['mail-config']?.dmarc?.record ? (
                        <div className="text-[10px] text-theme-muted font-mono break-all">
                          {webcheck['mail-config'].dmarc.record}
                        </div>
                      ) : (
                        <div className="text-[10px] text-theme-muted italic">
                          {isIp ? 'DMARC policies are configured on domain names.' : 'No DMARC enforcement policy record found.'}
                        </div>
                      )}
                    </div>

                    {/* DKIM */}
                    <div className="bg-theme-surface/50 p-2 rounded border border-theme space-y-0.5">
                      <div className="flex justify-between items-center">
                        <span className="text-theme-secondary font-semibold">DKIM (DomainKeys Identified Mail):</span>
                        <span className={`px-1.5 py-0.2 rounded text-[10px] font-bold ${
                          webcheck['mail-config']?.dkim?.valid || webcheck['mail-config']?.dkim?.record
                            ? 'bg-emerald-500/20 text-emerald-400'
                            : 'bg-theme-surface text-theme-muted'
                        }`}>
                          {webcheck['mail-config']?.dkim?.valid || webcheck['mail-config']?.dkim?.record ? 'DKIM DETECTED' : isIp ? 'NOT APPLICABLE' : 'NOT DETECTED / NO RECORD'}
                        </span>
                      </div>
                      {webcheck['mail-config']?.dkim?.record && (
                        <div className="text-[10px] text-theme-muted font-mono break-all">
                          {webcheck['mail-config'].dkim.record}
                        </div>
                      )}
                    </div>

                    {/* MX Records - Canonical Cross-Provider Resolution */}
                    {canonicalMxList.length > 0 ? (
                      <div className="pt-1">
                        <span className="text-[10px] text-theme-secondary uppercase font-semibold block mb-1">
                          MX Records ({canonicalMxList.length}):
                        </span>
                        <div className="flex flex-wrap gap-1">
                          {canonicalMxList.map((m, mIdx) => (
                            <span key={mIdx} className="px-1.5 py-0.5 rounded text-[10px] bg-theme-surface text-theme-primary border border-theme">
                              {m.priority != null ? `[${m.priority}] ` : ''}{m.exchange}
                            </span>
                          ))}
                        </div>
                      </div>
                    ) : isIp ? (
                      <div className="pt-1 text-[10px] text-theme-muted italic">
                        Not applicable for IP targets.
                      </div>
                    ) : (
                      <div className="pt-1 text-[10px] text-theme-muted italic">
                        No MX mail exchange servers routed to this target.
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* 5. DNS Blocklists & Threat Intel */}
              {(webcheck['block-lists'] || webcheck.threats) && (
                <div className="bg-theme-inset border border-theme rounded-lg p-3 space-y-2 text-xs font-mono">
                  <div className="flex items-center justify-between">
                    <span className="text-theme-secondary font-bold uppercase text-[10px] flex items-center space-x-1">
                      <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
                      <span>Blocklists & Reputation</span>
                    </span>
                    <span className="text-[10px] text-theme-muted">DNSBL & Intel</span>
                  </div>

                  <div className="space-y-1.5 pt-1 text-[11px]">
                    {webcheck['block-lists']?.blocklists && (
                      <div className="flex justify-between items-center bg-theme-surface/50 p-2 rounded border border-theme">
                        <span className="text-theme-secondary">DNS Blocklists:</span>
                        {(() => {
                          const bls = Array.isArray(webcheck['block-lists'].blocklists) ? webcheck['block-lists'].blocklists : [];
                          const blocked = bls.filter((b: any) => b.isBlocked);
                          return blocked.length > 0 ? (
                            <span className="text-red-400 font-bold">{blocked.length} BLOCKED</span>
                          ) : (
                            <span className="text-emerald-400 font-bold">ALL CLEAN ({bls.length} checked)</span>
                          );
                        })()}
                      </div>
                    )}

                    {webcheck.threats && (
                      <div className="space-y-1 pt-1">
                        {webcheck.threats.safeBrowsing && (
                          <div className="flex justify-between items-center text-[10px]">
                            <span className="text-theme-secondary">Google Safe Browsing:</span>
                            <span className={webcheck.threats.safeBrowsing.isFound ? 'text-red-400 font-bold' : 'text-emerald-400 font-bold'}>
                              {webcheck.threats.safeBrowsing.isFound ? 'FLAGGED' : 'CLEAN'}
                            </span>
                          </div>
                        )}
                        {webcheck.threats.urlHaus && (
                          <div className="flex justify-between items-center text-[10px]">
                            <span className="text-theme-secondary">URLhaus Threat Database:</span>
                            <span className={webcheck.threats.urlHaus.isFound ? 'text-red-400 font-bold' : 'text-emerald-400 font-bold'}>
                              {webcheck.threats.urlHaus.isFound ? 'LISTED' : 'CLEAN'}
                            </span>
                          </div>
                        )}
                        {webcheck.threats.phishTank && (
                          <div className="flex justify-between items-center text-[10px]">
                            <span className="text-theme-secondary">PhishTank Feed:</span>
                            <span className={webcheck.threats.phishTank.isFound ? 'text-red-400 font-bold' : 'text-emerald-400 font-bold'}>
                              {webcheck.threats.phishTank.isFound ? 'PHISHING' : 'CLEAN'}
                            </span>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* 6. Redirects Chain */}
              {webcheck.redirects?.redirects && Array.isArray(webcheck.redirects.redirects) && webcheck.redirects.redirects.length > 0 && (
                <div className="bg-theme-inset border border-theme rounded-lg p-3 space-y-2 text-xs font-mono md:col-span-2 lg:col-span-3">
                  <div className="flex items-center justify-between">
                    <span className="text-theme-secondary font-bold uppercase text-[10px] flex items-center space-x-1">
                      <Link2 className="w-3.5 h-3.5 text-amber-400" />
                      <span>HTTP Redirect Chain ({webcheck.redirects.redirects.length} {webcheck.redirects.redirects.length === 1 ? 'hop' : 'hops'})</span>
                    </span>
                  </div>
                  <div className="flex flex-wrap items-center gap-1.5 pt-1 text-[11px]">
                    {webcheck.redirects.redirects.map((hop: string, hIdx: number) => (
                      <React.Fragment key={hIdx}>
                        <span className="px-2 py-0.5 rounded bg-theme-surface text-amber-300 border border-amber-500/30 font-mono break-all max-w-[320px] truncate" title={hop}>
                          {hop}
                        </span>
                        {hIdx < webcheck.redirects.redirects.length - 1 && (
                          <span className="text-amber-500 font-bold">&rarr;</span>
                        )}
                      </React.Fragment>
                    ))}
                  </div>
                </div>
              )}

              {/* 7. Subdomains Discovered */}
              {webcheck.subdomains?.subdomains && Array.isArray(webcheck.subdomains.subdomains) && webcheck.subdomains.subdomains.length > 0 && (
                <div className="bg-theme-inset border border-theme rounded-lg p-3 space-y-2 text-xs font-mono md:col-span-2 lg:col-span-3">
                  <div className="flex items-center justify-between">
                    <span className="text-theme-secondary font-bold uppercase text-[10px] flex items-center space-x-1">
                      <Globe2 className="w-3.5 h-3.5 text-sky-400" />
                      <span>Discovered Subdomains ({webcheck.subdomains.subdomains.length})</span>
                    </span>
                    {webcheck.subdomains.source && (
                      <span className="text-[10px] text-theme-muted">Source: {webcheck.subdomains.source}</span>
                    )}
                  </div>
                  <div className="flex flex-wrap gap-1 max-h-32 overflow-y-auto pt-1">
                    {webcheck.subdomains.subdomains.map((sub: string, sIdx: number) => (
                      <span
                        key={sIdx}
                        className="px-1.5 py-0.5 rounded text-[10px] bg-theme-surface text-sky-300 border border-theme hover:border-sky-500/40 transition-colors"
                      >
                        {sub}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* 8. Server Status & Uptime */}
              {webcheck.status && (
                <div className="bg-theme-inset border border-theme rounded-lg p-3 space-y-2 text-xs font-mono">
                  <div className="flex items-center justify-between">
                    <span className="text-theme-secondary font-bold uppercase text-[10px] flex items-center space-x-1">
                      <Activity className="w-3.5 h-3.5 text-emerald-400" />
                      <span>Server Status & Latency</span>
                    </span>
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase ${
                      webcheck.status.isUp !== false
                        ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                        : 'bg-red-500/20 text-red-400 border border-red-500/30'
                    }`}>
                      {webcheck.status.isUp !== false ? 'ONLINE' : 'OFFLINE'}
                    </span>
                  </div>
                  <div className="space-y-1 pt-1 text-[11px]">
                    <div className="flex justify-between items-center">
                      <span className="text-theme-secondary">HTTP Response:</span>
                      <span className="text-theme-primary font-bold">
                        {webcheck.status.responseCode || webcheck.status.status || '—'}
                      </span>
                    </div>
                    {webcheck.status.responseTime != null && (
                      <div className="flex justify-between items-center">
                        <span className="text-theme-secondary">Response Latency:</span>
                        <span className="text-cyan-400 font-bold">{webcheck.status.responseTime} ms</span>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* 9. Global Site Ranking & Carbon Footprint */}
              {(webcheck.rank || webcheck.carbon || webcheck.quality) && (
                <div className="bg-theme-inset border border-theme rounded-lg p-3 space-y-2 text-xs font-mono">
                  <div className="flex items-center justify-between">
                    <span className="text-theme-secondary font-bold uppercase text-[10px] flex items-center space-x-1">
                      <Zap className="w-3.5 h-3.5 text-yellow-400" />
                      <span>Site Metrics & Rank</span>
                    </span>
                    <span className="text-[10px] text-theme-muted">Tranco & Eco</span>
                  </div>
                  <div className="space-y-1.5 pt-1 text-[11px]">
                    {webcheck.rank && (
                      <div className="flex justify-between items-center">
                        <span className="text-theme-secondary">Tranco Global Rank:</span>
                        <span className="text-yellow-400 font-bold">
                          {(() => {
                            const r = webcheck.rank.ranks?.[0]?.rank || webcheck.rank.rank;
                            return r != null ? `#${Number(r).toLocaleString()}` : (webcheck.rank.skipped || 'Unranked');
                          })()}
                        </span>
                      </div>
                    )}
                    {webcheck.carbon && (
                      <div className="flex justify-between items-center">
                        <span className="text-theme-secondary">Carbon Cleanliness:</span>
                        <span className="text-emerald-400 font-bold">
                          {webcheck.carbon.cleanerThan != null ? `Cleaner than ${webcheck.carbon.cleanerThan}% of sites` : (webcheck.carbon.green ? 'Green Host' : '—')}
                        </span>
                      </div>
                    )}
                    {webcheck.quality && typeof webcheck.quality === 'object' && webcheck.quality.categories && (
                      <div className="pt-1 flex flex-wrap gap-1">
                        {Object.entries(webcheck.quality.categories).map(([catKey, catVal]: [string, any]) => (
                          <span key={catKey} className="px-1.5 py-0.5 rounded text-[9px] bg-theme-surface text-cyan-300 border border-theme">
                            {catVal?.title || catKey}: {catVal?.score != null ? Math.round(catVal.score * 100) : '—'}%
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* 10. Wayback Machine Web Archive */}
              {webcheck.archives && (
                <div className="bg-theme-inset border border-theme rounded-lg p-3 space-y-2 text-xs font-mono">
                  <div className="flex items-center justify-between">
                    <span className="text-theme-secondary font-bold uppercase text-[10px] flex items-center space-x-1">
                      <History className="w-3.5 h-3.5 text-purple-400" />
                      <span>Wayback Historical Archive</span>
                    </span>
                    <span className="text-[10px] text-purple-400 bg-purple-500/10 px-1.5 py-0.2 rounded border border-purple-500/20">
                      Archive.org
                    </span>
                  </div>
                  {(!webcheck.archives.totalScans && !webcheck.archives.firstScan && !webcheck.archives.lastScan && !webcheck.archives.changeCount && !webcheck.archives.skipped) ? (
                    <p className="text-[10px] text-theme-muted pt-1">No historical snapshots found in the Wayback Machine archive.</p>
                  ) : (
                    <div className="space-y-1 pt-1 text-[11px]">
                      {(webcheck.archives.totalScans != null && Number(webcheck.archives.totalScans) > 0) ? (
                        <div className="flex justify-between items-center">
                          <span className="text-theme-secondary">Total Archival Snapshots:</span>
                          <span className="text-theme-primary font-bold">
                            {Number(webcheck.archives.totalScans).toLocaleString()}
                          </span>
                        </div>
                      ) : (webcheck.archives.changeCount != null && Number(webcheck.archives.changeCount) > 0) ? (
                        <div className="flex justify-between items-center">
                          <span className="text-theme-secondary">Archival Status:</span>
                          <span className="text-theme-primary font-bold">
                            Historical revisions detected ({webcheck.archives.changeCount})
                          </span>
                        </div>
                      ) : (webcheck.archives.firstScan || webcheck.archives.lastScan) ? (
                        <div className="flex justify-between items-center">
                          <span className="text-theme-secondary">Archival Status:</span>
                          <span className="text-theme-primary font-bold">
                            Snapshots recorded
                          </span>
                        </div>
                      ) : (
                        <div className="flex justify-between items-center">
                          <span className="text-theme-secondary">Total Archival Snapshots:</span>
                          <span className="text-theme-muted font-bold">
                            0
                          </span>
                        </div>
                      )}
                      {webcheck.archives.firstScan && (
                        <div className="flex justify-between items-center">
                          <span className="text-theme-secondary">First Recorded Archive:</span>
                          <span className="text-purple-300 font-medium">{formatTimestamp(webcheck.archives.firstScan)}</span>
                        </div>
                      )}
                      {webcheck.archives.lastScan && (
                        <div className="flex justify-between items-center">
                          <span className="text-theme-secondary">Latest Recorded Archive:</span>
                          <span className="text-purple-300 font-medium">{formatTimestamp(webcheck.archives.lastScan)}</span>
                        </div>
                      )}
                      {webcheck.archives.changeCount != null && (
                        <div className="flex justify-between items-center">
                          <span className="text-theme-secondary">Page Content Changes:</span>
                          <span className="text-theme-primary">{webcheck.archives.changeCount} revisions</span>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}

              {/* 11. DNSSEC & DNS Server Resolvers */}
              {(webcheck.dnssec || webcheck['dns-server'] || webcheck['txt-records']) && (
                <div className="bg-theme-inset border border-theme rounded-lg p-3 space-y-2 text-xs font-mono">
                  <div className="flex items-center justify-between">
                    <span className="text-theme-secondary font-bold uppercase text-[10px] flex items-center space-x-1">
                      <ShieldCheck className="w-3.5 h-3.5 text-blue-400" />
                      <span>DNSSEC & Resolver Infrastructure</span>
                    </span>
                  </div>
                  <div className="space-y-1.5 pt-1 text-[11px]">
                    {webcheck.dnssec && (
                      <div className="flex justify-between items-center bg-theme-surface/50 p-2 rounded border border-theme">
                        <span className="text-theme-secondary">DNSSEC Validation:</span>
                        <span className={`px-1.5 py-0.2 rounded text-[10px] font-bold ${
                          webcheck.dnssec.isDnssec || webcheck.dnssec.dnssec
                            ? 'bg-emerald-500/20 text-emerald-400'
                            : 'bg-theme-surface text-theme-muted'
                        }`}>
                          {webcheck.dnssec.isDnssec || webcheck.dnssec.dnssec ? 'DNSSEC ENABLED' : 'DNSSEC DISABLED / UNSIGNED'}
                        </span>
                      </div>
                    )}
                    {webcheck['dns-server']?.dns && Array.isArray(webcheck['dns-server'].dns) && webcheck['dns-server'].dns.length > 0 && (
                      <div className="space-y-0.5">
                        <span className="text-theme-secondary text-[10px] block">DNS Resolver Servers:</span>
                        <div className="flex flex-wrap gap-1">
                          {webcheck['dns-server'].dns.map((s: any, idx: number) => (
                            <span key={idx} className="px-1.5 py-0.5 rounded text-[10px] bg-theme-surface text-blue-300 border border-theme font-mono">
                              {typeof s === 'string' ? s : (s.address || s.ip || JSON.stringify(s))}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* 12. Crawl Directives & Policy Files */}
              {(webcheck['robots-txt'] || webcheck.sitemap || webcheck['security-txt']) && (
                <div className="bg-theme-inset border border-theme rounded-lg p-3 space-y-2 text-xs font-mono">
                  <div className="flex items-center justify-between">
                    <span className="text-theme-secondary font-bold uppercase text-[10px] flex items-center space-x-1">
                      <FileText className="w-3.5 h-3.5 text-amber-400" />
                      <span>Crawl Directives & Policies</span>
                    </span>
                  </div>
                  <div className="space-y-1.5 pt-1 text-[11px]">
                    <div className="flex justify-between items-center">
                      <span className="text-theme-secondary">robots.txt:</span>
                      <span className={webcheck['robots-txt']?.robots ? 'text-emerald-400 font-bold' : 'text-theme-muted'}>
                        {webcheck['robots-txt']?.robots ? 'PRESENT' : 'NOT FOUND'}
                      </span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-theme-secondary">sitemap.xml:</span>
                      <span className={webcheck.sitemap?.sitemap || webcheck.sitemap?.pages?.length ? 'text-emerald-400 font-bold' : 'text-theme-muted'}>
                        {webcheck.sitemap?.pages?.length ? `${webcheck.sitemap.pages.length} URLs indexed` : (webcheck.sitemap?.sitemap ? 'PRESENT' : 'NOT FOUND')}
                      </span>
                    </div>
                    {webcheck['security-txt'] && (
                      <div className="flex justify-between items-center">
                        <span className="text-theme-secondary">security.txt:</span>
                        <span className={webcheck['security-txt'].isFound || webcheck['security-txt'].isPresent ? 'text-emerald-400 font-bold' : 'text-theme-muted'}>
                          {webcheck['security-txt'].isFound || webcheck['security-txt'].isPresent ? 'PRESENT' : 'NOT FOUND'}
                        </span>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* 13. Network Route & Hop Trace */}
              {webcheck['trace-route']?.hops && Array.isArray(webcheck['trace-route'].hops) && webcheck['trace-route'].hops.length > 0 && (
                <div className="bg-theme-inset border border-theme rounded-lg p-3 space-y-2 text-xs font-mono md:col-span-2">
                  <div className="flex items-center justify-between">
                    <span className="text-theme-secondary font-bold uppercase text-[10px] flex items-center space-x-1">
                      <Network className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Traceroute Network Hops ({webcheck['trace-route'].hops.length})</span>
                    </span>
                  </div>
                  <div className="flex flex-wrap gap-1 max-h-24 overflow-y-auto pt-1">
                    {webcheck['trace-route'].hops.map((hop: any, idx: number) => (
                      <span key={idx} className="px-1.5 py-0.5 rounded text-[10px] bg-theme-surface text-theme-primary border border-theme font-mono">
                        #{hop.hop || idx + 1}: {hop.ip || '—'} {hop.rtt ? `(${hop.rtt})` : ''}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* 14. Cookies & Session Attributes */}
              {allCookies.length > 0 && (
                <div className="bg-theme-inset border border-theme rounded-lg p-3 space-y-2 text-xs font-mono">
                  <div className="flex items-center justify-between">
                    <span className="text-theme-secondary font-bold uppercase text-[10px] flex items-center space-x-1">
                      <Cookie className="w-3.5 h-3.5 text-amber-400" />
                      <span>Cookies ({allCookies.length})</span>
                    </span>
                  </div>
                  <div className="space-y-1 max-h-32 overflow-y-auto pt-1">
                    {allCookies.map((c: any, idx: number) => (
                      <div key={idx} className="flex justify-between items-center text-[10px] bg-theme-surface/40 p-1 rounded">
                        <span className="font-semibold text-theme-primary truncate max-w-[120px]" title={c.name || c.key || 'Cookie'}>
                          {c.name || c.key || 'Cookie'}
                        </span>
                        <div className="flex items-center space-x-1">
                          {c.secure && <span className="px-1 py-0.1 rounded text-[8px] bg-emerald-500/20 text-emerald-400">Secure</span>}
                          {c.httpOnly && <span className="px-1 py-0.1 rounded text-[8px] bg-cyan-500/20 text-cyan-400">HttpOnly</span>}
                          {c.sameSite && <span className="px-1 py-0.1 rounded text-[8px] bg-theme-surface text-theme-muted">{c.sameSite}</span>}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* 14b. Third-Party Trackers & Privacy */}
              {webcheck.trackers && (Array.isArray(webcheck.trackers) ? webcheck.trackers.length > 0 : (webcheck.trackers.trackers?.length > 0)) && (
                <div className="bg-theme-inset border border-theme rounded-lg p-3 space-y-2 text-xs font-mono">
                  <div className="flex items-center justify-between">
                    <span className="text-theme-secondary font-bold uppercase text-[10px] flex items-center space-x-1">
                      <Eye className="w-3.5 h-3.5 text-pink-400" />
                      <span>Third-Party Trackers ({(() => {
                        const trs = Array.isArray(webcheck.trackers) ? webcheck.trackers : (webcheck.trackers.trackers || []);
                        return trs.length;
                      })()})</span>
                    </span>
                    <span className="text-[10px] text-pink-400 bg-pink-500/10 px-1.5 py-0.2 rounded border border-pink-500/20">
                      Privacy
                    </span>
                  </div>
                  <div className="flex flex-wrap gap-1 max-h-24 overflow-y-auto pt-1">
                    {(() => {
                      const trs = Array.isArray(webcheck.trackers) ? webcheck.trackers : (webcheck.trackers.trackers || []);
                      return trs.map((t: any, idx: number) => {
                        const tName = typeof t === 'string' ? t : (t.name || t.tracker || JSON.stringify(t));
                        return (
                          <span key={idx} className="px-1.5 py-0.5 rounded text-[10px] bg-theme-surface text-pink-300 border border-theme font-mono">
                            {tName}
                          </span>
                        );
                      });
                    })()}
                  </div>
                </div>
              )}

              {/* 15. Social Metadata & Brand Presence */}
              {(webcheck['social-tags'] || webcheck['social-presence']) && (
                <div className="bg-theme-inset border border-theme rounded-lg p-3 space-y-2 text-xs font-mono md:col-span-2">
                  <div className="flex items-center justify-between">
                    <span className="text-theme-secondary font-bold uppercase text-[10px] flex items-center space-x-1">
                      <Share2 className="w-3.5 h-3.5 text-pink-400" />
                      <span>Social Metadata & Digital Footprint</span>
                    </span>
                  </div>
                  <div className="space-y-1 text-[11px] pt-1">
                    {(() => {
                      const hasSocialTags = Boolean(
                        webcheck['social-tags'] &&
                        (webcheck['social-tags'].ogTitle ||
                         webcheck['social-tags'].title ||
                         webcheck['social-tags'].ogDescription ||
                         webcheck['social-tags'].description)
                      );
                      const socialPresenceEntries = webcheck['social-presence'] && typeof webcheck['social-presence'] === 'object'
                        ? Object.entries(webcheck['social-presence']).filter(([_, v]: [string, any]) => v && (v.isFound || v.exists))
                        : [];

                      if (!hasSocialTags && socialPresenceEntries.length === 0) {
                        return <p className="text-[10px] text-theme-muted pt-1">No OpenGraph metadata or brand social profiles detected.</p>;
                      }

                      return (
                        <>
                          {webcheck['social-tags'] && (
                            <div className="space-y-0.5">
                              {(webcheck['social-tags'].ogTitle || webcheck['social-tags'].title) && (
                                <div className="text-theme-primary font-semibold truncate" title={webcheck['social-tags'].ogTitle || webcheck['social-tags'].title}>
                                  {webcheck['social-tags'].ogTitle || webcheck['social-tags'].title}
                                </div>
                              )}
                              {(webcheck['social-tags'].ogDescription || webcheck['social-tags'].description) && (
                                <div className="text-[10px] text-theme-muted line-clamp-2" title={webcheck['social-tags'].ogDescription || webcheck['social-tags'].description}>
                                  {webcheck['social-tags'].ogDescription || webcheck['social-tags'].description}
                                </div>
                              )}
                            </div>
                          )}
                          {socialPresenceEntries.length > 0 && (
                            <div className="flex flex-wrap gap-1 pt-1">
                              {socialPresenceEntries.map(([platform, _]) => (
                                <span key={platform} className="px-1.5 py-0.2 rounded text-[9px] bg-pink-500/10 text-pink-300 border border-pink-500/20 capitalize">
                                  {platform}
                                </span>
                              ))}
                            </div>
                          )}
                        </>
                      );
                    })()}
                  </div>
                </div>
              )}

              {/* 16. Linked Pages & Endpoints */}
              {webcheck['linked-pages'] && (
                <div className="bg-theme-inset border border-theme rounded-lg p-3 space-y-2 text-xs font-mono">
                  <div className="flex items-center justify-between">
                    <span className="text-theme-secondary font-bold uppercase text-[10px] flex items-center space-x-1">
                      <Link2 className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Linked Pages & Crawled Endpoints</span>
                    </span>
                  </div>
                  <div className="space-y-1 pt-1 text-[11px]">
                    <div className="flex justify-between items-center">
                      <span className="text-theme-secondary">Internal Links:</span>
                      <span className="text-theme-primary font-bold">
                        {Array.isArray(webcheck['linked-pages'].internal) ? webcheck['linked-pages'].internal.length : 0}
                      </span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-theme-secondary">External Outbound Links:</span>
                      <span className="text-cyan-400 font-bold">
                        {Array.isArray(webcheck['linked-pages'].external) ? webcheck['linked-pages'].external.length : 0}
                      </span>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* 7. Payload & File Intelligence Card (For Hashes) */}
        {hasFile && (
          <div className="bg-theme-card border border-theme rounded-xl p-4.5 space-y-3 shadow-sm md:col-span-2 lg:col-span-3">
            <div className="flex items-center justify-between pb-2 border-b border-theme">
              <div className="flex items-center space-x-2 text-emerald-500 text-xs font-bold uppercase tracking-wider">
                <Cpu className="w-4 h-4" />
                <span>Payload & File Technical Details</span>
              </div>
              <ProvenanceBadges sources={fileMeta?.sources || ['virustotal']} />
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 text-xs font-mono">
              {/* Basic File Properties */}
              <div className="space-y-2 bg-theme-surface/50 p-3 rounded-lg border border-theme">
                <span className="text-[11px] font-bold text-theme-secondary uppercase tracking-wider block border-b border-theme pb-1">
                  File Attributes
                </span>
                {(fileMeta?.file_type || infra.file_type) && (
                  <div className="flex justify-between items-center">
                    <span className="text-theme-secondary">Type:</span>
                    <span className="text-theme-primary font-bold">{fileMeta?.file_type || infra.file_type}</span>
                  </div>
                )}
                {fileMeta?.magika && (
                  <div className="flex justify-between items-center">
                    <span className="text-theme-secondary">Magika:</span>
                    <span className="text-emerald-400 font-bold">{fileMeta.magika}</span>
                  </div>
                )}
                {(fileMeta?.file_size != null || infra.file_size != null) && (
                  <div className="flex justify-between items-center">
                    <span className="text-theme-secondary">Size:</span>
                    <span className="text-theme-primary">
                      {(Number(fileMeta?.file_size ?? infra.file_size ?? 0) / 1024).toFixed(1)} KB (
                      {Number(fileMeta?.file_size ?? infra.file_size ?? 0).toLocaleString()} bytes)
                    </span>
                  </div>
                )}
                {fileMeta?.magic && (
                  <div className="space-y-1">
                    <span className="text-theme-secondary block">Magic Bytes:</span>
                    <div className="p-1.5 bg-theme-surface rounded text-[11px] text-theme-muted break-all">
                      {fileMeta.magic}
                    </div>
                  </div>
                )}
                {fileMeta?.compiler_info && (
                  <div className="flex justify-between items-center">
                    <span className="text-theme-secondary">Compiler:</span>
                    <span className="text-theme-primary">{fileMeta.compiler_info}</span>
                  </div>
                )}
              </div>

              {/* Cryptographic Hashes */}
              <div className="space-y-2 bg-theme-surface/50 p-3 rounded-lg border border-theme">
                <span className="text-[11px] font-bold text-theme-secondary uppercase tracking-wider block border-b border-theme pb-1">
                  Cryptographic & Analysis Hashes
                </span>
                {[
                  { label: 'MD5', val: fileMeta?.md5 || infra.extra?.md5 },
                  { label: 'SHA1', val: fileMeta?.sha1 || infra.extra?.sha1 },
                  { label: 'SHA256', val: fileMeta?.sha256 || infra.extra?.sha256 },
                  { label: 'Vhash', val: fileMeta?.vhash || infra.extra?.vhash },
                  { label: 'Authentihash', val: fileMeta?.authentihash },
                  { label: 'Imphash', val: fileMeta?.imphash },
                  { label: 'Rich PE Hash', val: fileMeta?.rich_pe_header_hash },
                  { label: 'SSDEEP', val: fileMeta?.ssdeep || infra.extra?.ssdeep },
                  { label: 'TLSH', val: fileMeta?.tlsh || infra.extra?.tlsh },
                ].filter((item) => item.val).map((h, idx) => (
                  <div key={idx} className="space-y-0.5">
                    <div className="flex justify-between items-center text-[11px]">
                      <span className="text-theme-secondary">{h.label}:</span>
                      <button
                        onClick={() => copyToClipboard(`hash-${h.label}`, h.val!)}
                        className="text-theme-muted hover:text-cyan-400 flex items-center space-x-1"
                        title="Copy hash"
                      >
                        {copiedKey === `hash-${h.label}` ? <Check className="w-3 h-3 text-green-400" /> : <Copy className="w-3 h-3" />}
                      </button>
                    </div>
                    <div className="p-1 bg-theme-surface rounded text-[10px] text-theme-primary truncate font-mono select-all">
                      {h.val}
                    </div>
                  </div>
                ))}
              </div>

              {/* Detections, Signatures & Filenames */}
              <div className="space-y-2 bg-theme-surface/50 p-3 rounded-lg border border-theme">
                <span className="text-[11px] font-bold text-theme-secondary uppercase tracking-wider block border-b border-theme pb-1">
                  Identification & Signatures
                </span>
                {fileMeta?.file_names && fileMeta.file_names.length > 0 && (
                  <div className="space-y-1">
                    <span className="text-theme-secondary block text-[11px]">Observed Filenames:</span>
                    <div className="flex flex-wrap gap-1 max-h-24 overflow-y-auto">
                      {fileMeta.file_names.map((name, i) => (
                        <span key={i} className="px-1.5 py-0.5 rounded text-[10px] bg-theme-surface text-cyan-400 border border-theme font-mono">
                          {name}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                {fileMeta?.trid && fileMeta.trid.length > 0 && (
                  <div className="space-y-1">
                    <span className="text-theme-secondary block text-[11px]">TrID Analysis:</span>
                    <div className="space-y-1 max-h-20 overflow-y-auto">
                      {fileMeta.trid.slice(0, 3).map((tr, i) => (
                        <div key={i} className="text-[10px] text-theme-muted flex justify-between">
                          <span className="truncate">{tr.file_type}</span>
                          {tr.probability !== undefined && <span className="text-theme-secondary ml-1">{tr.probability}%</span>}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                {fileMeta?.signature_info && (
                  <div className="space-y-1 pt-1 border-t border-theme text-[11px]">
                    <span className="text-theme-secondary block">Authenticode / Signature:</span>
                    <div className="p-1.5 bg-theme-surface rounded text-[10px] text-theme-primary space-y-0.5">
                      {fileMeta.signature_info['product'] && <div>Product: {String(fileMeta.signature_info['product'])}</div>}
                      {fileMeta.signature_info['copyright'] && <div>Copyright: {String(fileMeta.signature_info['copyright'])}</div>}
                      {fileMeta.signature_info['signers'] && <div>Signers: {String(fileMeta.signature_info['signers'])}</div>}
                    </div>
                  </div>
                )}
                {fileMeta?.timestamps && Object.keys(fileMeta.timestamps).length > 0 && (
                  <div className="space-y-1 pt-1 border-t border-theme text-[10px]">
                    {fileMeta.timestamps['first_submission'] && (
                      <div className="flex justify-between">
                        <span className="text-theme-secondary">First Submitted:</span>
                        <span className="text-theme-muted">{formatTimestamp(fileMeta.timestamps['first_submission'])}</span>
                      </div>
                    )}
                    {fileMeta.timestamps['last_submission'] && (
                      <div className="flex justify-between">
                        <span className="text-theme-secondary">Last Submitted:</span>
                        <span className="text-theme-muted">{formatTimestamp(fileMeta.timestamps['last_submission'])}</span>
                      </div>
                    )}
                    {fileMeta.timestamps['last_analysis'] && (
                      <div className="flex justify-between">
                        <span className="text-theme-secondary">Last Analyzed:</span>
                        <span className="text-theme-muted">{formatTimestamp(fileMeta.timestamps['last_analysis'])}</span>
                      </div>
                    )}
                    {fileMeta.timestamps['signature_date'] && (
                      <div className="flex justify-between">
                        <span className="text-theme-secondary">Signature Date:</span>
                        <span className="text-theme-muted">{formatTimestamp(fileMeta.timestamps['signature_date'])}</span>
                      </div>
                    )}
                    {fileMeta.timestamps['times_submitted'] && (
                      <div className="flex justify-between">
                        <span className="text-theme-secondary">Times Submitted:</span>
                        <span className="text-theme-muted">{fileMeta.timestamps['times_submitted']}</span>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* 8. AlienVault OTX Pulse Intelligence Card */}
        {hasPulses && (
          <div className="bg-theme-card border border-emerald-500/30 rounded-xl p-4.5 space-y-3 shadow-sm md:col-span-2 lg:col-span-3">
            <div className="flex items-center justify-between pb-2 border-b border-theme flex-wrap gap-2">
              <div className="flex items-center space-x-2 text-emerald-400 text-xs font-bold uppercase tracking-wider">
                <Activity className="w-4 h-4" />
                <span>AlienVault OTX Pulse Intelligence ({pulses.length})</span>
              </div>
              <ProvenanceBadges sources={['otx']} />
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {pulses.map((pulse, idx) => (
                <div key={idx} className="bg-theme-inset border border-theme rounded-lg p-3 space-y-2 text-xs font-mono">
                  <div className="flex items-center justify-between">
                    <a
                      href={`https://otx.alienvault.com/pulse/${pulse.pulse_id}`}
                      target="_blank"
                      rel="noreferrer"
                      className="text-emerald-400 hover:text-emerald-300 font-bold inline-flex items-center space-x-1 truncate max-w-[220px]"
                      title={pulse.pulse_name}
                    >
                      <span className="truncate">{pulse.pulse_name}</span>
                      <ExternalLink className="w-3 h-3 shrink-0" />
                    </a>
                    <span className="px-1.5 py-0.2 rounded text-[10px] bg-theme-surface text-theme-secondary border border-theme">
                      {pulse.indicator_count ?? 0} IOCs
                    </span>
                  </div>

                  {pulse.description && (
                    <p className="text-[11px] text-theme-muted line-clamp-2" title={pulse.description}>
                      {pulse.description}
                    </p>
                  )}

                  <div className="space-y-1 text-[10px]">
                    {pulse.author && (
                      <div className="flex justify-between items-center text-theme-secondary">
                        <span>Pulse Author:</span>
                        <span className="text-theme-primary truncate max-w-[150px]" title={pulse.author}>
                          {pulse.author}
                        </span>
                      </div>
                    )}
                    {pulse.adversary && (
                      <div className="flex justify-between items-center text-theme-secondary">
                        <span>Target Adversary:</span>
                        <span className="text-rose-400 font-semibold truncate max-w-[150px]" title={pulse.adversary}>
                          {pulse.adversary}
                        </span>
                      </div>
                    )}
                    {pulse.created && (
                      <div className="flex justify-between items-center text-theme-secondary">
                        <span>Created:</span>
                        <span className="text-theme-muted">{formatTimestamp(pulse.created)}</span>
                      </div>
                    )}
                    {pulse.modified && (
                      <div className="flex justify-between items-center text-theme-secondary">
                        <span>Modified:</span>
                        <span className="text-theme-muted">{formatTimestamp(pulse.modified)}</span>
                      </div>
                    )}
                  </div>

                  {pulse.malware_families && pulse.malware_families.length > 0 && (
                    <div className="space-y-0.5 pt-1">
                      <span className="text-theme-secondary text-[9px] block uppercase font-bold">Malware Families:</span>
                      <div className="flex flex-wrap gap-1">
                        {pulse.malware_families.map((fam, famIdx) => (
                          <span
                            key={famIdx}
                            className="px-1.5 py-0.2 rounded text-[9px] font-bold uppercase bg-red-500/10 text-red-400 border border-red-500/20"
                          >
                            {fam}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {pulse.tags && pulse.tags.length > 0 && (
                    <div className="space-y-0.5 pt-1">
                      <span className="text-theme-secondary text-[9px] block uppercase font-bold">Tags:</span>
                      <div className="flex flex-wrap gap-1 max-h-16 overflow-y-auto">
                        {pulse.tags.slice(0, 6).map((tag, tIdx) => (
                          <span
                            key={tIdx}
                            className="px-1.5 py-0.2 rounded text-[9px] bg-theme-surface text-theme-muted border border-theme"
                          >
                            #{tag}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* 9. Observation Timeline Card */}
        {hasTemporal && (
          <div className="bg-theme-card border border-theme rounded-xl p-4.5 space-y-3 shadow-sm">
            <div className="flex items-center justify-between pb-2 border-b border-theme">
              <div className="flex items-center space-x-2 text-indigo-400 text-xs font-bold uppercase tracking-wider">
                <Clock className="w-4 h-4" />
                <span>Observation Timeline</span>
              </div>
              <ProvenanceBadges sources={temporal?.sources} />
            </div>
            <div className="space-y-2 text-xs font-mono">
              {temporal?.first_seen && (
                <div className="flex justify-between items-center">
                  <span className="text-theme-secondary">First Observed:</span>
                  <span className="text-theme-primary">{formatTimestamp(temporal.first_seen)}</span>
                </div>
              )}
              {temporal?.last_seen && (
                <div className="flex justify-between items-center">
                  <span className="text-theme-secondary">Last Observed:</span>
                  <span className="text-theme-primary">{formatTimestamp(temporal.last_seen)}</span>
                </div>
              )}
              {temporal?.last_scan && (
                <div className="flex justify-between items-center">
                  <span className="text-theme-secondary">Last Active Scan:</span>
                  <span className="text-theme-primary">{formatTimestamp(temporal.last_scan)}</span>
                </div>
              )}
            </div>
          </div>
        )}
        {/* Hash Empty State Placeholder */}
        {isHash && !hasFile && !hasTTPs && !hasTemporal && (
          <div className="col-span-full bg-theme-card border border-theme rounded-xl p-8 text-center space-y-2">
            <Cpu className="w-8 h-8 text-theme-muted mx-auto" />
            <p className="text-xs font-mono text-theme-secondary">
              No static payload attributes or MITRE ATT&CK techniques reported by threat intelligence providers for this hash.
            </p>
          </div>
        )}
      </div>

      {/* PASSIVE DNS HISTORICAL TELEMETRY SECTION (Rendered for Domains & IPs with Passive DNS) */}
      {hasPassiveDns && (
        <div className="bg-theme-card border border-sky-500/30 rounded-xl p-4.5 space-y-3 shadow-sm">
          <div className="flex items-center justify-between pb-2 border-b border-theme flex-wrap gap-3">
            <div className="flex items-center space-x-2 text-sky-400 text-xs font-bold uppercase tracking-wider">
              <History className="w-4 h-4" />
              <span>Passive DNS Historical Resolutions ({passiveDns.length})</span>
            </div>

            <div className="flex items-center flex-wrap gap-2 text-xs">
              {/* RRType filter dropdown */}
              <select
                value={pdnsFilterType}
                onChange={(e) => setPdnsFilterType(e.target.value)}
                className="bg-theme-surface border border-theme text-theme-primary rounded px-2.5 py-1 text-xs focus:outline-none focus:border-sky-500"
              >
                <option value="ALL">All Types ({passiveDns.length})</option>
                {uniqueRrtypes.map((t) => (
                  <option key={t} value={t}>
                    {t} ({passiveDns.filter((r) => r.rrtype?.toUpperCase() === t).length})
                  </option>
                ))}
              </select>

              {/* Search filter input */}
              <input
                type="text"
                value={pdnsSearch}
                onChange={(e) => setPdnsSearch(e.target.value)}
                placeholder="Filter query, answer, source..."
                className="bg-theme-surface border border-theme text-theme-primary placeholder-theme-muted rounded px-2.5 py-1 text-xs focus:outline-none focus:border-sky-500 w-48 font-mono"
              />

              <span className="text-[10px] font-mono text-sky-400 bg-sky-500/10 px-2 py-0.5 rounded border border-sky-500/20">
                Resolution Telemetry
              </span>
            </div>
          </div>

          {filteredPassiveDns.length === 0 ? (
            <div className="text-center py-6 text-xs text-theme-muted font-mono">
              No passive DNS records match your filter criteria.
            </div>
          ) : (
            <div className="overflow-x-auto max-h-96 border border-theme rounded-lg">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-theme-surface/80 text-theme-secondary text-[11px] uppercase tracking-wider sticky top-0 z-10 border-b border-theme">
                  <tr>
                    <th className="py-2.5 px-3 font-semibold">Type</th>
                    <th className="py-2.5 px-3 font-semibold">Query</th>
                    <th className="py-2.5 px-3 font-semibold">Answer</th>
                    <th className="py-2.5 px-3 font-semibold">First Seen (UTC)</th>
                    <th className="py-2.5 px-3 font-semibold">Last Seen (UTC)</th>
                    <th className="py-2.5 px-3 font-semibold text-right">Count</th>
                    <th className="py-2.5 px-3 font-semibold">TTL Range</th>
                    <th className="py-2.5 px-3 font-semibold">TLP / Class</th>
                    <th className="py-2.5 px-3 font-semibold">Source</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-theme">
                  {filteredPassiveDns.map((rec, idx) => (
                    <tr key={idx} className="hover:bg-theme-surface/40 transition-colors">
                      <td className="py-2 px-3">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold border ${getRrtypeBadge(rec.rrtype)}`}>
                          {rec.rrtype || '—'}
                        </span>
                      </td>
                      <td className="py-2 px-3 text-theme-primary font-medium max-w-[220px] truncate" title={rec.query}>
                        {rec.query || '—'}
                      </td>
                      <td className="py-2 px-3 text-sky-400 font-medium max-w-[240px] truncate" title={rec.answer}>
                        {rec.answer || '—'}
                      </td>
                      <td className="py-2 px-3 text-theme-muted whitespace-nowrap">
                        {rec.first_seen || '—'}
                      </td>
                      <td className="py-2 px-3 text-theme-muted whitespace-nowrap">
                        {rec.last_seen || '—'}
                      </td>
                      <td className="py-2 px-3 text-right text-theme-primary font-bold">
                        {rec.observation_count ?? '—'}
                      </td>
                      <td className="py-2 px-3 text-theme-secondary whitespace-nowrap">
                        {rec.min_ttl != null && rec.max_ttl != null
                          ? rec.min_ttl === rec.max_ttl
                            ? `${rec.min_ttl}s`
                            : `${rec.min_ttl}–${rec.max_ttl}s`
                          : rec.min_ttl != null
                          ? `${rec.min_ttl}s`
                          : rec.max_ttl != null
                          ? `${rec.max_ttl}s`
                          : '—'}
                      </td>
                      <td className="py-2 px-3 text-theme-secondary text-[11px] whitespace-nowrap">
                        <span className="uppercase text-[10px] bg-theme-surface px-1.5 py-0.5 rounded border border-theme mr-1 font-semibold">
                          {rec.tlp || 'WHITE'}
                        </span>
                        <span className="text-[10px]">{rec.rrclass || 'IN'}</span>
                      </td>
                      <td className="py-2 px-3">
                        <ProvenanceBadges sources={rec.sources && rec.sources.length > 0 ? rec.sources : ['mnemonic']} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* HISTORICAL WHOIS SECTION (Rendered for Domains, URLs, & IPs with Historical WHOIS) */}
      {hasHistoricalWhois && (
        <div className="bg-theme-card border border-purple-500/30 rounded-xl p-4.5 space-y-3 shadow-sm">
          <div className="flex items-center justify-between pb-2 border-b border-theme flex-wrap gap-3">
            <div className="flex items-center space-x-2 text-purple-400 text-xs font-bold uppercase tracking-wider">
              <History className="w-4 h-4" />
              <span>Historical WHOIS Archives ({historicalWhois.length} {historicalWhois.length === 1 ? 'snapshot' : 'snapshots'})</span>
            </div>

            <div className="flex items-center flex-wrap gap-2 text-xs">
              <input
                type="text"
                value={whoisSearch}
                onChange={(e) => setWhoisSearch(e.target.value)}
                placeholder="Filter registrar, org, nameserver, date..."
                className="bg-theme-surface border border-theme text-theme-primary placeholder-theme-muted rounded px-2.5 py-1 text-xs focus:outline-none focus:border-purple-500 w-64 font-mono"
              />
              <span className="text-[10px] font-mono text-purple-400 bg-purple-500/10 px-2 py-0.5 rounded border border-purple-500/20">
                VirusTotal WHOIS Archive
              </span>
            </div>
          </div>

          {filteredHistoricalWhois.length === 0 ? (
            <div className="text-center py-6 text-xs text-theme-muted font-mono">
              No historical WHOIS records match your filter criteria.
            </div>
          ) : (
            <div className="space-y-3">
              {filteredHistoricalWhois.map((rec, idx) => {
                const recId = rec.id || `whois_${idx}`;
                const isExpanded = expandedWhois[recId] ?? (idx === 0);

                return (
                  <div key={recId} className="border border-theme rounded-lg overflow-hidden bg-theme-inset/40">
                    <button
                      type="button"
                      onClick={() => toggleWhois(recId)}
                      className="w-full px-3.5 py-2.5 flex items-center justify-between bg-theme-surface/60 hover:bg-theme-surface transition-colors text-left cursor-pointer"
                    >
                      <div className="flex items-center space-x-2.5 flex-wrap gap-y-1">
                        {isExpanded ? (
                          <ChevronDown className="w-4 h-4 text-purple-400 shrink-0" />
                        ) : (
                          <ChevronRight className="w-4 h-4 text-purple-400 shrink-0" />
                        )}
                        <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-purple-500/15 text-purple-400 border border-purple-500/30">
                          {rec.first_seen ? `First Seen: ${rec.first_seen}` : `Snapshot #${idx + 1}`}
                        </span>
                        {rec.last_updated && rec.last_updated !== rec.first_seen && (
                          <span className="text-[11px] font-mono text-theme-muted">
                            (Updated: {rec.last_updated})
                          </span>
                        )}
                        {rec.registrar && (
                          <span className="text-xs font-semibold text-theme-primary truncate max-w-[200px]" title={rec.registrar}>
                            {rec.registrar}
                          </span>
                        )}
                        {rec.registrant_country && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-mono uppercase bg-theme-surface text-theme-secondary border border-theme">
                            {rec.registrant_country}
                          </span>
                        )}
                        {rec.registrant_organization && (
                          <span className="text-[11px] font-mono text-theme-secondary truncate max-w-[180px]" title={rec.registrant_organization}>
                            {rec.registrant_organization}
                          </span>
                        )}
                      </div>

                      <div className="flex items-center space-x-2 text-[11px] font-mono text-theme-secondary">
                        <ProvenanceBadges sources={rec.sources && rec.sources.length > 0 ? rec.sources : ['virustotal']} />
                      </div>
                    </button>

                    {isExpanded && (
                      <div className="p-3.5 space-y-3 border-t border-theme/50 text-xs font-mono">
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                          {/* Domain Dates */}
                          <div className="space-y-1.5 bg-theme-card/60 p-2.5 rounded border border-theme">
                            <span className="text-[10px] text-theme-secondary uppercase font-semibold block border-b border-theme pb-1">
                              Record Dates (UTC)
                            </span>
                            <div className="space-y-1 text-[11px]">
                              {rec.creation_date && (
                                <div className="flex justify-between items-center">
                                  <span className="text-theme-secondary">Created:</span>
                                  <span className="text-theme-primary">{formatTimestamp(rec.creation_date)}</span>
                                </div>
                              )}
                              {rec.updated_date && (
                                <div className="flex justify-between items-center">
                                  <span className="text-theme-secondary">Updated:</span>
                                  <span className="text-theme-primary">{formatTimestamp(rec.updated_date)}</span>
                                </div>
                              )}
                              {rec.expiry_date && (
                                <div className="flex justify-between items-center">
                                  <span className="text-theme-secondary">Expires:</span>
                                  <span className="text-theme-primary">{formatTimestamp(rec.expiry_date)}</span>
                                </div>
                              )}
                              {rec.first_seen && (
                                <div className="flex justify-between items-center">
                                  <span className="text-theme-secondary">Archive Seen:</span>
                                  <span className="text-purple-400 font-medium">{rec.first_seen}</span>
                                </div>
                              )}
                            </div>
                          </div>

                          {/* Registrar & Server */}
                          <div className="space-y-1.5 bg-theme-card/60 p-2.5 rounded border border-theme">
                            <span className="text-[10px] text-theme-secondary uppercase font-semibold block border-b border-theme pb-1">
                              Registrar Info
                            </span>
                            <div className="space-y-1 text-[11px]">
                              {rec.registrar && (
                                <div className="flex justify-between items-center">
                                  <span className="text-theme-secondary">Registrar:</span>
                                  <span className="text-theme-primary font-semibold truncate max-w-[170px]" title={rec.registrar}>
                                    {rec.registrar}
                                  </span>
                                </div>
                              )}
                              {rec.registrar_whois_server && (
                                <div className="flex justify-between items-center">
                                  <span className="text-theme-secondary">WHOIS Server:</span>
                                  <span className="text-theme-primary truncate max-w-[170px]" title={rec.registrar_whois_server}>
                                    {rec.registrar_whois_server}
                                  </span>
                                </div>
                              )}
                              {rec.registrar_url && (
                                <div className="flex justify-between items-center">
                                  <span className="text-theme-secondary">URL:</span>
                                  <a
                                    href={rec.registrar_url.startsWith('http') ? rec.registrar_url : `http://${rec.registrar_url}`}
                                    target="_blank"
                                    rel="noreferrer"
                                    className="text-cyan-400 hover:underline truncate max-w-[170px] inline-flex items-center space-x-1"
                                    title={rec.registrar_url}
                                  >
                                    <span>{rec.registrar_url}</span>
                                    <ExternalLink className="w-2.5 h-2.5 shrink-0" />
                                  </a>
                                </div>
                              )}
                              {rec.origin_as && (
                                <div className="flex justify-between items-center">
                                  <span className="text-theme-secondary">Origin AS:</span>
                                  <span className="text-theme-primary font-bold">{rec.origin_as}</span>
                                </div>
                              )}
                            </div>
                          </div>

                          {/* Registrant Contact */}
                          <div className="space-y-1.5 bg-theme-card/60 p-2.5 rounded border border-theme">
                            <span className="text-[10px] text-theme-secondary uppercase font-semibold block border-b border-theme pb-1">
                              Registrant Details
                            </span>
                            <div className="space-y-1 text-[11px]">
                              {rec.registrant_organization && (
                                <div className="flex justify-between items-center">
                                  <span className="text-theme-secondary">Organization:</span>
                                  <span className="text-theme-primary font-semibold truncate max-w-[170px]" title={rec.registrant_organization}>
                                    {rec.registrant_organization}
                                  </span>
                                </div>
                              )}
                              {rec.registrant_name && (
                                <div className="flex justify-between items-center">
                                  <span className="text-theme-secondary">Name:</span>
                                  <span className="text-theme-primary truncate max-w-[170px]" title={rec.registrant_name}>
                                    {rec.registrant_name}
                                  </span>
                                </div>
                              )}
                              {rec.registrant_country && (
                                <div className="flex justify-between items-center">
                                  <span className="text-theme-secondary">Country:</span>
                                  <span className="text-theme-primary">{rec.registrant_country}</span>
                                </div>
                              )}
                              {rec.registrant_email && (
                                <div className="flex justify-between items-center">
                                  <span className="text-theme-secondary">Email:</span>
                                  <span className="text-theme-primary truncate max-w-[170px]" title={rec.registrant_email}>
                                    {rec.registrant_email}
                                  </span>
                                </div>
                              )}
                            </div>
                          </div>
                        </div>

                        {/* Nameservers */}
                        {rec.nameservers && rec.nameservers.length > 0 && (
                          <div className="space-y-1 pt-1">
                            <span className="text-theme-secondary text-[10px] uppercase font-semibold block">
                              Name Servers ({rec.nameservers.length}):
                            </span>
                            <div className="flex flex-wrap gap-1.5">
                              {rec.nameservers.map((ns, nsIdx) => (
                                <span
                                  key={nsIdx}
                                  className="px-2 py-0.5 rounded text-[11px] font-mono bg-purple-500/10 text-purple-300 border border-purple-500/30"
                                >
                                  {ns}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* Domain Status */}
                        {rec.domain_status && rec.domain_status.length > 0 && (
                          <div className="space-y-1 pt-1">
                            <span className="text-theme-secondary text-[10px] uppercase font-semibold block">
                              Domain Status Codes ({rec.domain_status.length}):
                            </span>
                            <div className="flex flex-wrap gap-1">
                              {rec.domain_status.map((st, stIdx) => (
                                <span
                                  key={stIdx}
                                  className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-theme-surface text-theme-muted border border-theme"
                                >
                                  {st}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* MITRE ATT&CK BEHAVIORAL HIERARCHY SECTION (Tactics -> Techniques -> Sub-Techniques) */}
      {hasTTPs && (
        <div className="bg-theme-card border border-amber-500/30 rounded-xl p-4.5 space-y-4 shadow-sm">
          <div className="flex items-center justify-between pb-2 border-b border-theme flex-wrap gap-2">
            <div className="flex items-center space-x-2 text-amber-500 text-xs font-bold uppercase tracking-wider">
              <Crosshair className="w-4 h-4" />
              <span>
                MITRE ATT&CK Matrix Hierarchy ({totalTechniquesCount || ttps.length} Techniques across {resolvedTtpTree.length} Tactics)
              </span>
            </div>
            <div className="flex items-center space-x-2">
              <button
                type="button"
                onClick={() => {
                  const allCollapsed = resolvedTtpTree.every((t) => collapsedTactics[t.id]);
                  const next: Record<string, boolean> = {};
                  resolvedTtpTree.forEach((t) => {
                    next[t.id] = !allCollapsed;
                  });
                  setCollapsedTactics(next);
                }}
                className="text-[11px] font-mono text-amber-400 hover:text-amber-300 underline px-2 py-0.5 cursor-pointer"
              >
                {resolvedTtpTree.every((t) => collapsedTactics[t.id]) ? 'Expand All Tactics' : 'Collapse All Tactics'}
              </button>
              <span className="text-[10px] font-mono text-amber-400 bg-amber-500/10 px-2 py-0.5 rounded border border-amber-500/20">
                Enterprise Matrix v14
              </span>
            </div>
          </div>

          <div className="space-y-3">
            {resolvedTtpTree.map((tactic) => {
              const isCollapsed = Boolean(collapsedTactics[tactic.id]);
              const subCount = tactic.techniques.reduce((acc, tech) => acc + (tech.sub_techniques?.length || 0), 0);

              return (
                <div key={tactic.id} className="border border-theme rounded-lg overflow-hidden bg-theme-inset/40">
                  {/* Tactic Collapsible Header */}
                  <button
                    type="button"
                    onClick={() => toggleTactic(tactic.id)}
                    className="w-full px-3.5 py-2.5 flex items-center justify-between bg-theme-surface/60 hover:bg-theme-surface transition-colors text-left cursor-pointer"
                  >
                    <div className="flex items-center space-x-2.5">
                      {isCollapsed ? (
                        <ChevronRight className="w-4 h-4 text-amber-400 shrink-0" />
                      ) : (
                        <ChevronDown className="w-4 h-4 text-amber-400 shrink-0" />
                      )}
                      <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-amber-500/15 text-amber-400 border border-amber-500/30">
                        {tactic.id.toUpperCase()}
                      </span>
                      <span className="text-xs font-bold text-theme-primary">
                        {tactic.name}
                      </span>
                    </div>

                    <div className="flex items-center space-x-2 text-[11px] font-mono text-theme-secondary">
                      <span className="bg-theme-card px-2 py-0.5 rounded border border-theme">
                        {tactic.techniques.length} {tactic.techniques.length === 1 ? 'Technique' : 'Techniques'}
                        {subCount > 0 && ` (${subCount} sub)`}
                      </span>
                    </div>
                  </button>

                  {/* Tactic Techniques Content */}
                  {!isCollapsed && (
                    <div className="p-3.5 space-y-3 border-t border-theme/50">
                      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                        {tactic.techniques.map((tech) => {
                          const hasSubs = tech.sub_techniques && tech.sub_techniques.length > 0;
                          const isTechExpanded = expandedTechniques[tech.id] !== false; // default expanded

                          return (
                            <div
                              key={tech.id}
                              className="bg-theme-card/90 border border-theme rounded-lg p-3 space-y-2 text-xs font-mono shadow-sm flex flex-col justify-between"
                            >
                              <div className="space-y-2">
                                {/* Technique Header */}
                                <div className="flex items-start justify-between gap-1">
                                  <a
                                    href={`https://attack.mitre.org/techniques/${tech.id.replace(/\./g, '/')}/`}
                                    target="_blank"
                                    rel="noreferrer"
                                    className="text-amber-400 hover:text-amber-300 font-bold inline-flex items-center space-x-1"
                                  >
                                    <span>{tech.id}</span>
                                    <ExternalLink className="w-3 h-3" />
                                  </a>

                                  {tech.severity && (
                                    <span
                                      className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase ${
                                        tech.severity.toUpperCase() === 'HIGH' || tech.severity.toUpperCase() === 'CRITICAL'
                                          ? 'bg-red-600/20 text-red-400 border border-red-500/40'
                                          : tech.severity.toUpperCase() === 'MEDIUM'
                                          ? 'bg-orange-500/20 text-orange-400 border border-orange-500/40'
                                          : 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/40'
                                      }`}
                                    >
                                      {tech.severity}
                                    </span>
                                  )}
                                </div>

                                <div className="text-[12px] font-semibold text-theme-primary">
                                  {tech.name}
                                </div>

                                {tech.description && (
                                  <p className="text-[11px] text-theme-muted line-clamp-3" title={tech.description}>
                                    {tech.description}
                                  </p>
                                )}

                                {/* Nested Sub-Techniques */}
                                {hasSubs && (
                                  <div className="pt-2 border-t border-theme/60 space-y-1.5">
                                    <div
                                      onClick={() => toggleTechnique(tech.id)}
                                      className="flex items-center justify-between text-[10px] uppercase font-bold text-amber-500/90 cursor-pointer hover:text-amber-400"
                                    >
                                      <span className="flex items-center space-x-1">
                                        <FolderGit2 className="w-3 h-3" />
                                        <span>Sub-Techniques ({tech.sub_techniques.length})</span>
                                      </span>
                                      <span className="text-[9px] text-theme-muted">
                                        {isTechExpanded ? 'Hide' : 'Show'}
                                      </span>
                                    </div>

                                    {isTechExpanded && (
                                      <div className="pl-2 border-l-2 border-amber-500/30 space-y-2 pt-1">
                                        {tech.sub_techniques.map((sub) => (
                                          <div
                                            key={sub.id}
                                            className="bg-theme-surface/50 border border-theme/40 rounded p-2 text-[11px] space-y-1"
                                          >
                                            <div className="flex items-center justify-between gap-1">
                                              <a
                                                href={`https://attack.mitre.org/techniques/${sub.id.replace(/\./g, '/')}/`}
                                                target="_blank"
                                                rel="noreferrer"
                                                className="text-amber-300 hover:text-amber-200 font-bold inline-flex items-center space-x-1"
                                              >
                                                <span>{sub.id}</span>
                                                <ExternalLink className="w-2.5 h-2.5" />
                                              </a>
                                              {sub.severity && (
                                                <span className="text-[9px] uppercase px-1 py-0.2 rounded font-semibold bg-amber-500/10 text-amber-300 border border-amber-500/20">
                                                  {sub.severity}
                                                </span>
                                              )}
                                            </div>

                                            <div className="font-semibold text-theme-primary text-[11px]">
                                              {sub.name}
                                            </div>

                                            {sub.description && (
                                              <p className="text-[10px] text-theme-muted line-clamp-2" title={sub.description}>
                                                {sub.description}
                                              </p>
                                            )}

                                            <div className="pt-1 flex items-center justify-between text-[9px]">
                                              <span className="text-theme-secondary">Sources:</span>
                                              <ProvenanceBadges sources={sub.sources} />
                                            </div>
                                          </div>
                                        ))}
                                      </div>
                                    )}
                                  </div>
                                )}
                              </div>

                              {/* Footer Sources */}
                              <div className="pt-2 mt-2 border-t border-theme flex justify-between items-center">
                                <span className="text-[10px] text-theme-secondary">Sources:</span>
                                <ProvenanceBadges sources={tech.sources} />
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}
      {hasVulns ? (
        <div className="bg-theme-card border border-red-500/30 rounded-xl p-4.5 space-y-3 shadow-sm">
          <div className="flex items-center justify-between pb-2 border-b border-theme">
            <div className="flex items-center space-x-2 text-red-500 text-xs font-bold uppercase tracking-wider">
              <ShieldAlert className="w-4 h-4" />
              <span>Detected Vulnerabilities & Exploits ({vulnsDetail.length})</span>
            </div>
            <span className="text-[10px] font-mono text-red-400 bg-red-500/10 px-2 py-0.5 rounded border border-red-500/20">
              Corroborated by Active Scanners
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {vulnsDetail.map((vuln, idx) => (
              <div key={idx} className="bg-theme-inset border border-theme rounded-lg p-3 space-y-2 text-xs font-mono">
                <div className="flex items-center justify-between flex-wrap gap-1">
                  <div className="flex items-center space-x-1.5">
                    <a
                      href={`https://nvd.nist.gov/vuln/detail/${vuln.cve_id}`}
                      target="_blank"
                      rel="noreferrer"
                      className="text-red-400 hover:text-red-300 font-bold inline-flex items-center space-x-1"
                    >
                      <span>{vuln.cve_id}</span>
                      <ExternalLink className="w-3 h-3" />
                    </a>
                    {vuln.cwe_id && (
                      <a
                        href={`https://cwe.mitre.org/data/definitions/${vuln.cwe_id.replace('CWE-', '')}.html`}
                        target="_blank"
                        rel="noreferrer"
                        className="px-1.5 py-0.2 rounded text-[10px] font-bold bg-amber-500/10 text-amber-400 border border-amber-500/30 hover:underline"
                        title={`Common Weakness Enumeration: ${vuln.cwe_id}`}
                      >
                        {vuln.cwe_id}
                      </a>
                    )}
                  </div>
                  <div className="flex items-center space-x-1">
                    {vuln.severity && (
                      <span className={`px-1.5 py-0.2 rounded text-[9px] font-bold uppercase ${
                        vuln.severity.toUpperCase() === 'CRITICAL'
                          ? 'bg-red-600/20 text-red-400 border border-red-500/40'
                          : vuln.severity.toUpperCase() === 'HIGH'
                          ? 'bg-orange-500/20 text-orange-400 border border-orange-500/40'
                          : 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/40'
                      }`}>
                        {vuln.severity}
                      </span>
                    )}
                    {vuln.cvss_v3 != null ? (
                      <span className="px-1.5 py-0.2 rounded text-[10px] font-bold bg-red-600/20 text-red-400 border border-red-500/40">
                        CVSSv3 {Number(vuln.cvss_v3).toFixed(1)}
                      </span>
                    ) : vuln.cvss != null && !isNaN(Number(vuln.cvss)) ? (
                      <span className="px-1.5 py-0.2 rounded text-[10px] font-bold bg-red-600/20 text-red-400 border border-red-500/40">
                        CVSS {Number(vuln.cvss).toFixed(1)}
                      </span>
                    ) : null}
                  </div>
                </div>

                <div className="space-y-1 text-[11px]">
                  {(vuln.affected_product || vuln.affected_vendor) && (
                    <div className="flex justify-between items-center text-theme-secondary">
                      <span>Affected Product:</span>
                      <span className="text-theme-primary font-semibold truncate max-w-[180px]">
                        {[vuln.affected_vendor, vuln.affected_product].filter(Boolean).join(' ')}
                      </span>
                    </div>
                  )}

                  {vuln.attack_vector && (
                    <div className="flex justify-between items-center text-theme-secondary">
                      <span>Attack Vector:</span>
                      <span className="text-cyan-400 font-semibold">{vuln.attack_vector}</span>
                    </div>
                  )}

                  {vuln.port && (
                    <div className="flex justify-between items-center text-theme-secondary">
                      <span>Service Port:</span>
                      <span className="text-theme-primary font-semibold">{vuln.port}</span>
                    </div>
                  )}

                  {vuln.exploit && (
                    <div className="bg-red-500/10 border border-red-500/30 text-red-400 px-2 py-1 rounded text-[10px] font-bold flex items-center justify-between">
                      <span>EXPLOIT AVAILABLE</span>
                      {vuln.exploit_details && <span className="font-mono text-[9px] truncate max-w-[150px]">{vuln.exploit_details}</span>}
                    </div>
                  )}
                </div>

                {vuln.summary && (
                  <p className="text-[11px] text-theme-muted line-clamp-3" title={vuln.summary}>
                    {vuln.summary}
                  </p>
                )}

                {vuln.related_products && vuln.related_products.length > 0 && (
                  <div className="space-y-0.5 pt-1">
                    <span className="text-theme-secondary text-[10px] block">Related Products:</span>
                    <div className="flex flex-wrap gap-1 max-h-16 overflow-y-auto">
                      {vuln.related_products.map((rp, rIdx) => (
                        <span key={rIdx} className="px-1.5 py-0.2 rounded text-[9px] bg-theme-surface text-theme-muted border border-theme">
                          {rp}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                <div className="pt-1 border-t border-theme flex justify-between items-center">
                  <span className="text-[10px] text-theme-secondary">Source:</span>
                  <ProvenanceBadges sources={vuln.sources} />
                </div>
              </div>
            ))}
          </div>
        </div>
      ) : (!isHash && (hasShodanDetails || hasCensysDetails) ? (
        <div className="bg-theme-card border border-theme rounded-xl p-4.5 space-y-3 shadow-sm">
          <div className="flex items-center justify-between pb-2 border-b border-theme">
            <div className="flex items-center space-x-2 text-emerald-500 text-xs font-bold uppercase tracking-wider">
              <ShieldCheck className="w-4 h-4" />
              <span>Vulnerabilities & Exploits (0)</span>
            </div>
            <span className="text-[10px] font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
              Active Scanners
            </span>
          </div>
          <div className="p-3 bg-theme-inset border border-theme rounded-lg text-xs font-mono text-theme-muted">
            No known CVE vulnerabilities reported by active scanner telemetry (Shodan & Censys).
          </div>
        </div>
      ) : null)}

      {/* 10. OPEN PORTS & EXPOSED SERVICES SECTION */}
      {hasServices && (
        <div className="bg-theme-card border border-theme rounded-xl p-4.5 space-y-4 shadow-sm">
          <div className="flex items-center justify-between pb-2 border-b border-theme flex-wrap gap-2">
            <div className="flex items-center space-x-2 text-rose-500 text-xs font-bold uppercase tracking-wider">
              <Radio className="w-4 h-4" />
              <span>Open Ports & Exposed Services ({servicesDetail.length})</span>
            </div>

            {/* Quick Port Badges */}
            <div className="flex flex-wrap gap-1.5">
              {servicesDetail.map((s, idx) => (
                <span
                  key={idx}
                  className="px-2 py-0.5 text-xs font-mono font-bold rounded bg-rose-500/10 text-rose-400 border border-rose-500/30"
                >
                  {s.port}/{s.transport}
                </span>
              ))}
            </div>
          </div>

          {/* Detailed Services Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {servicesDetail.map((svc, idx) => {
              const bannerKey = `banner_${svc.port}_${idx}`;
              const isExpanded = expandedBanners[bannerKey];

              return (
                <div key={idx} className="bg-theme-inset border border-theme rounded-lg p-3 space-y-2 text-xs font-mono">
                  <div className="flex items-center justify-between flex-wrap gap-1">
                    <div className="flex items-center space-x-2">
                      <span className="font-bold text-sm text-theme-primary">
                        Port {svc.port}
                      </span>
                      <span className="px-1.5 py-0.2 rounded text-[10px] uppercase font-semibold bg-theme-surface text-theme-secondary border border-theme">
                        {svc.transport}
                      </span>
                      {svc.protocol && (
                        <span className="text-cyan-400 font-semibold">{svc.protocol}</span>
                      )}
                    </div>
                    <ProvenanceBadges sources={svc.sources} />
                  </div>

                  <div className="space-y-1 pt-1">
                    {(svc.service_name || svc.product || svc.vendor) && (
                      <div className="flex justify-between items-center text-[11px]">
                        <span className="text-theme-secondary">Product / Service:</span>
                        <span className="text-theme-primary font-semibold">
                          {[svc.vendor, svc.product || svc.service_name].filter(Boolean).join(' ')} {svc.version || ''}
                        </span>
                      </div>
                    )}
                    {svc.devicetype && (
                      <div className="flex justify-between items-center text-[11px]">
                        <span className="text-theme-secondary">Device Type:</span>
                        <span className="text-theme-primary font-medium capitalize">{svc.devicetype}</span>
                      </div>
                    )}
                    {svc.http_status != null && (
                      <div className="flex justify-between items-center text-[11px]">
                        <span className="text-theme-secondary">HTTP Status:</span>
                        <span className={`px-1.5 py-0.2 rounded text-[10px] font-bold ${
                          svc.http_status >= 200 && svc.http_status < 300
                            ? 'bg-emerald-500/20 text-emerald-400'
                            : svc.http_status >= 300 && svc.http_status < 400
                            ? 'bg-amber-500/20 text-amber-400'
                            : 'bg-red-500/20 text-red-400'
                        }`}>
                          {svc.http_status}
                        </span>
                      </div>
                    )}
                    {svc.http_title && (
                      <div className="text-[11px] text-yellow-400 italic truncate" title={svc.http_title}>
                        Title: "{svc.http_title}"
                      </div>
                    )}
                    {svc.http_server && (
                      <div className="flex justify-between items-center text-[11px]">
                        <span className="text-theme-secondary">HTTP Server:</span>
                        <span className="text-theme-primary">{svc.http_server}</span>
                      </div>
                    )}
                    {(svc.tls_version || svc.cipher) && (
                      <div className="flex justify-between items-center text-[11px]">
                        <span className="text-theme-secondary">SSL/TLS:</span>
                        <span className="text-cyan-400 font-mono text-[10px] truncate max-w-[200px]" title={[svc.tls_version, svc.cipher].filter(Boolean).join(' / ')}>
                          {[svc.tls_version, svc.cipher].filter(Boolean).join(' / ')}
                        </span>
                      </div>
                    )}
                    {(svc.jarm || svc.ja3s) && (
                      <div className="space-y-0.5 pt-0.5 text-[10px]">
                        {svc.jarm && (
                          <div className="flex justify-between items-center">
                            <span className="text-theme-secondary">JARM:</span>
                            <span className="font-mono text-cyan-300 truncate max-w-[180px]" title={svc.jarm}>{svc.jarm}</span>
                          </div>
                        )}
                        {svc.ja3s && (
                          <div className="flex justify-between items-center">
                            <span className="text-theme-secondary">JA3S:</span>
                            <span className="font-mono text-cyan-300 truncate max-w-[180px]" title={svc.ja3s}>{svc.ja3s}</span>
                          </div>
                        )}
                      </div>
                    )}
                    {svc.alpn && svc.alpn.length > 0 && (
                      <div className="flex justify-between items-center text-[10px]">
                        <span className="text-theme-secondary">ALPN:</span>
                        <span className="text-theme-muted font-mono">{svc.alpn.join(', ')}</span>
                      </div>
                    )}
                    {svc.scan_time && (
                      <div className="flex justify-between items-center text-[10px] text-theme-secondary">
                        <span>Observed Scan Time:</span>
                        <span className="text-theme-muted">{formatTimestamp(svc.scan_time)}</span>
                      </div>
                    )}
                    {svc.vulnerabilities && svc.vulnerabilities.length > 0 && (
                      <div className="space-y-0.5 pt-1">
                        <span className="text-theme-secondary text-[10px] block font-semibold text-red-400">
                          Associated Vulnerabilities ({svc.vulnerabilities.length}):
                        </span>
                        <div className="flex flex-wrap gap-1">
                          {svc.vulnerabilities.map((cveId, cveIdx) => (
                            <span
                              key={cveIdx}
                              className="px-1.5 py-0.2 rounded text-[9px] font-bold bg-red-500/20 text-red-400 border border-red-500/30"
                            >
                              {cveId}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                    {svc.cpe && svc.cpe.length > 0 && (
                      <div className="space-y-0.5 pt-1">
                        <span className="text-theme-secondary text-[10px] block">CPE Software Identifiers:</span>
                        <div className="flex flex-wrap gap-1">
                          {svc.cpe.map((cpeItem, cpeIdx) => (
                            <span
                              key={cpeIdx}
                              className="px-1.5 py-0.5 rounded text-[9px] bg-theme-surface text-theme-muted border border-theme truncate max-w-[280px]"
                              title={cpeItem}
                            >
                              {cpeItem}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Service Banner Viewer */}
                  {svc.banner && (
                    <div className="pt-2 border-t border-theme">
                      <div className="flex items-center justify-between pb-1 text-[10px] text-theme-secondary">
                        <span className="flex items-center space-x-1">
                          <Terminal className="w-3 h-3" />
                          <span>Service Banner</span>
                        </span>
                        <div className="flex items-center space-x-2">
                          <button
                            onClick={() => copyToClipboard(bannerKey, svc.banner || '')}
                            className="hover:text-theme-primary transition-colors inline-flex items-center space-x-0.5"
                            title="Copy Banner"
                          >
                            {copiedKey === bannerKey ? <Check className="w-3 h-3 text-green-400" /> : <Copy className="w-3 h-3" />}
                            <span>{copiedKey === bannerKey ? 'Copied' : 'Copy'}</span>
                          </button>
                          {svc.banner.length > 100 && (
                            <button
                              onClick={() => toggleBanner(bannerKey)}
                              className="hover:text-theme-primary transition-colors inline-flex items-center space-x-0.5"
                            >
                              {isExpanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                              <span>{isExpanded ? 'Less' : 'More'}</span>
                            </button>
                          )}
                        </div>
                      </div>
                      <pre
                        className={`bg-theme-surface p-2 rounded text-[10px] font-mono text-theme-muted overflow-x-auto whitespace-pre-wrap break-all ${
                          isExpanded ? 'max-h-64' : 'max-h-16'
                        }`}
                      >
                        {svc.banner}
                      </pre>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* 11. SSL / TLS CERTIFICATES SECTION */}
      {hasCerts && (
        <div className="bg-theme-card border border-theme rounded-xl p-4.5 space-y-4 shadow-sm">
          <div className="flex items-center justify-between pb-2 border-b border-theme">
            <div className="flex items-center space-x-2 text-emerald-500 text-xs font-bold uppercase tracking-wider">
              <Lock className="w-4 h-4" />
              <span>TLS / SSL Certificates ({certsDetail.length})</span>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {certsDetail.map((cert, idx) => {
              const isTestCert = Boolean(
                (cert.subject_cn && /localhost|example\.com|my\s*company|test/i.test(cert.subject_cn)) ||
                (cert.issuer_cn && /localhost|example\.com|my\s*company|test/i.test(cert.issuer_cn)) ||
                (cert.subject_org && /my\s*company|test|example/i.test(cert.subject_org))
              );

              return (
              <div key={idx} className="bg-theme-inset border border-theme rounded-lg p-3 space-y-2 text-xs font-mono">
                <div className="flex items-center justify-between flex-wrap gap-1">
                  <div className="flex items-center gap-1.5 truncate max-w-[240px]">
                    <span className="font-bold text-emerald-400 truncate" title={cert.subject_cn || cert.sans[0] || 'X.509 Certificate'}>
                      {cert.subject_cn || cert.sans[0] || 'X.509 Certificate'}
                    </span>
                    {cert.port && (
                      <span className="px-1.5 py-0.2 rounded text-[9px] bg-theme-surface text-cyan-400 border border-theme font-mono">
                        Port {cert.port}{cert.protocol ? `/${cert.protocol}` : ''}
                      </span>
                    )}
                  </div>
                  <ProvenanceBadges sources={cert.sources} />
                </div>

                {isTestCert && (
                  <div className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase bg-amber-500/15 text-amber-400 border border-amber-500/30">
                    Self-Signed / Test Certificate (Non-Authoritative)
                  </div>
                )}

                <div className="space-y-1 text-[11px]">
                  {cert.service_name && (
                    <div className="flex justify-between items-center">
                      <span className="text-theme-secondary">Service:</span>
                      <span className="text-theme-primary">{cert.service_name}</span>
                    </div>
                  )}
                  {cert.observation_time && (
                    <div className="flex justify-between items-center text-[10px]">
                      <span className="text-theme-secondary">Observed:</span>
                      <span className="text-theme-muted">{formatTimestamp(cert.observation_time)}</span>
                    </div>
                  )}
                  {cert.subject_org && (
                    <div className="flex justify-between items-center">
                      <span className="text-theme-secondary">Subject Org:</span>
                      <span className="text-theme-primary">{cert.subject_org}</span>
                    </div>
                  )}
                  {cert.issuer_cn && (
                    <div className="flex justify-between items-center">
                      <span className="text-theme-secondary">Issuer CN:</span>
                      <span className="text-theme-primary">{cert.issuer_cn}</span>
                    </div>
                  )}
                  {cert.issuer_org && (
                    <div className="flex justify-between items-center">
                      <span className="text-theme-secondary">Issuer Org:</span>
                      <span className="text-theme-primary">{cert.issuer_org}</span>
                    </div>
                  )}
                  {cert.valid_from && cert.valid_to && (
                    <div className="flex justify-between items-center">
                      <span className="text-theme-secondary">Validity:</span>
                      <span className="text-theme-primary">
                        {formatTimestamp(cert.valid_from)} &rarr; {formatTimestamp(cert.valid_to)}
                      </span>
                    </div>
                  )}
                  {cert.serial_number && (
                    <div className="flex justify-between items-center text-[10px]">
                      <span className="text-theme-secondary">Serial Number:</span>
                      <span className="text-theme-muted font-mono truncate max-w-[170px]" title={cert.serial_number}>{cert.serial_number}</span>
                    </div>
                  )}
                  {cert.sig_alg && (
                    <div className="flex justify-between items-center text-[10px]">
                      <span className="text-theme-secondary">Signature Alg:</span>
                      <span className="text-theme-primary">{cert.sig_alg}</span>
                    </div>
                  )}
                  {cert.tls_versions && cert.tls_versions.length > 0 && (
                    <div className="flex justify-between items-center text-[10px]">
                      <span className="text-theme-secondary">Supported TLS:</span>
                      <span className="text-cyan-400 font-mono">{cert.tls_versions.join(', ')}</span>
                    </div>
                  )}
                  {cert.sans && cert.sans.length > 0 && (
                    <div className="space-y-1 pt-1">
                      <span className="text-theme-secondary text-[10px] block">Subject Alternative Names (SANs):</span>
                      <div className="flex flex-wrap gap-1 max-h-24 overflow-y-auto">
                        {cert.sans.map((san, sanIdx) => (
                          <span
                            key={sanIdx}
                            className="px-1.5 py-0.5 rounded text-[9px] bg-theme-surface text-emerald-400 border border-theme"
                          >
                            {san}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                {cert.fingerprint_sha256 && (
                  <div className="pt-2 border-t border-theme">
                    <span className="text-[10px] text-theme-secondary block mb-0.5">SHA256 Fingerprint:</span>
                    <span className="text-[10px] text-theme-muted truncate block" title={cert.fingerprint_sha256}>
                      {cert.fingerprint_sha256}
                    </span>
                  </div>
                )}
              </div>
              );
            })}
          </div>
        </div>
      )}
    </section>
  );
};
