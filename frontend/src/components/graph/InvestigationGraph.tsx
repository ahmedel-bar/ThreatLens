import React, { useMemo, useState, useCallback, useEffect } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  Node,
  Edge,
  MarkerType,
  useNodesState,
  useEdgesState,
  Panel,
  Handle,
  Position,
  NodeProps,
  ReactFlowProvider,
  useReactFlow,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { GraphResponse, IOCType, GraphNode } from '../../types';
import {
  GitFork,
  X,
  ShieldAlert,
  Globe,
  Link2,
  Hash,
  Lock,
  Network,
  Copy,
  Check,
  Maximize2,
  Layers,
} from 'lucide-react';
import { calculateForceRadialLayout } from './layout';

interface InvestigationGraphProps {
  graphData: GraphResponse;
  onPivot: (ioc: string, type: IOCType) => void;
  isPivoting?: boolean;
  theme?: 'dark' | 'light';
}

interface IOCNodeData extends GraphNode {
  canonical_ioc?: string;
  display_label?: string;
}

/**
 * Truncate long IOCs for visually contained graph node labels.
 * Hashes use balanced truncation (prefix + "..." + suffix).
 * Short values (e.g. 8.8.8.8, example.com) remain completely untouched.
 */
const truncateIocForDisplay = (ioc: string, type?: string): string => {
  if (!ioc || typeof ioc !== 'string') return '';

  const cleanIoc = ioc.trim();
  const lowerType = (type || '').toLowerCase();

  // 1. Hashes (SHA256, SHA1, MD5, or hex hashes)
  const isHexHash = /^[a-fA-F0-9]{32,}$/.test(cleanIoc);
  const isHashType = ['sha256', 'sha1', 'md5', 'hash'].includes(lowerType);

  if (isHashType || isHexHash) {
    if (cleanIoc.length >= 64 || lowerType === 'sha256') {
      if (cleanIoc.length <= 19) return cleanIoc;
      return `${cleanIoc.slice(0, 12)}...${cleanIoc.slice(-4)}`;
    }
    if (cleanIoc.length >= 40 || lowerType === 'sha1') {
      if (cleanIoc.length <= 17) return cleanIoc;
      return `${cleanIoc.slice(0, 10)}...${cleanIoc.slice(-4)}`;
    }
    if (cleanIoc.length >= 32 || lowerType === 'md5') {
      if (cleanIoc.length <= 15) return cleanIoc;
      return `${cleanIoc.slice(0, 8)}...${cleanIoc.slice(-4)}`;
    }
    if (cleanIoc.length > 16) {
      return `${cleanIoc.slice(0, 8)}...${cleanIoc.slice(-4)}`;
    }
    return cleanIoc;
  }

  // 2. URLs
  if (lowerType === 'url' || cleanIoc.startsWith('http://') || cleanIoc.startsWith('https://')) {
    if (cleanIoc.length <= 28) return cleanIoc;

    try {
      const url = new URL(cleanIoc);
      const host = url.hostname;
      const path = url.pathname;
      const pathSegments = path.split('/').filter(Boolean);
      if (pathSegments.length > 0) {
        const lastSegment = pathSegments[pathSegments.length - 1];
        const candidate = `${host}/.../${lastSegment}`;
        if (candidate.length <= 30) {
          return candidate;
        }
        return `${candidate.slice(0, 16)}...${candidate.slice(-8)}`;
      }
    } catch {
      // invalid URL format, fallback to string truncation
    }
    return `${cleanIoc.slice(0, 18)}...${cleanIoc.slice(-8)}`;
  }

  // 3. Domains
  if (lowerType === 'domain') {
    if (cleanIoc.length <= 28) return cleanIoc;
    return `${cleanIoc.slice(0, 14)}...${cleanIoc.slice(-10)}`;
  }

  // 4. IP Addresses
  if (lowerType === 'ipv4') {
    return cleanIoc;
  }
  if (lowerType === 'ipv6') {
    if (cleanIoc.length <= 24) return cleanIoc;
    return `${cleanIoc.slice(0, 12)}...${cleanIoc.slice(-6)}`;
  }

  // 5. Fallback
  if (cleanIoc.length <= 28) return cleanIoc;
  return `${cleanIoc.slice(0, 14)}...${cleanIoc.slice(-8)}`;
};

/**
 * Visual icon indicator for node types.
 */
const getIocIcon = (type?: string, isRoot?: boolean) => {
  if (isRoot) {
    return <ShieldAlert className="w-3.5 h-3.5 shrink-0 text-white" />;
  }
  const t = (type || '').toLowerCase();
  if (t === 'ipv4' || t === 'ipv6') {
    return <Network className="w-3.5 h-3.5 shrink-0 text-blue-300" />;
  }
  if (t === 'domain') {
    return <Globe className="w-3.5 h-3.5 shrink-0 text-purple-300" />;
  }
  if (t === 'url') {
    return <Link2 className="w-3.5 h-3.5 shrink-0 text-cyan-300" />;
  }
  if (t === 'md5' || t === 'sha1' || t === 'sha256' || t === 'hash') {
    return <Hash className="w-3.5 h-3.5 shrink-0 text-amber-300" />;
  }
  return <Lock className="w-3.5 h-3.5 shrink-0 text-slate-300" />;
};

/**
 * Custom node component ensuring visual containment, tooltip on hover,
 * and 4-way handles for clean direct edge routing.
 */
const IOCNode: React.FC<NodeProps> = ({ data, id }) => {
  const nodeData = data as unknown as IOCNodeData;
  const fullIoc = nodeData.canonical_ioc || nodeData.id || nodeData.label || id;
  const displayLabel = nodeData.display_label || truncateIocForDisplay(fullIoc, nodeData.type);
  const typeStr = (nodeData.type || 'ioc').toUpperCase();

  const handleStyle = {
    background: '#94a3b8',
    width: 6,
    height: 6,
    border: 'none',
  };

  return (
    <div
      title={`Full ${typeStr}: ${fullIoc}`}
      className="flex items-center space-x-1.5 w-full min-w-0 overflow-hidden select-none relative"
      style={{
        maxWidth: '100%',
        overflow: 'hidden',
        textOverflow: 'ellipsis',
        whiteSpace: 'nowrap',
      }}
    >
      {/* 4-Way Dynamic Connection Handles */}
      <Handle type="target" position={Position.Top} id="top-target" style={handleStyle} />
      <Handle type="source" position={Position.Top} id="top-source" style={handleStyle} />

      <Handle type="target" position={Position.Bottom} id="bottom-target" style={handleStyle} />
      <Handle type="source" position={Position.Bottom} id="bottom-source" style={handleStyle} />

      <Handle type="target" position={Position.Left} id="left-target" style={handleStyle} />
      <Handle type="source" position={Position.Left} id="left-source" style={handleStyle} />

      <Handle type="target" position={Position.Right} id="right-target" style={handleStyle} />
      <Handle type="source" position={Position.Right} id="right-source" style={handleStyle} />

      {getIocIcon(nodeData.type, nodeData.is_root)}
      <span
        className="truncate font-mono font-medium"
        style={{
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          whiteSpace: 'nowrap',
          maxWidth: '180px',
        }}
      >
        {displayLabel}
      </span>
    </div>
  );
};

// Memoized node types object for React Flow
const nodeTypes = {
  iocNode: IOCNode,
  default: IOCNode,
};

/**
 * Helper component inside ReactFlowProvider that manages automatic fitView on data changes.
 */
const GraphAutoFitter: React.FC<{ dataTrigger: any }> = ({ dataTrigger }) => {
  const { fitView } = useReactFlow();

  useEffect(() => {
    const timer = setTimeout(() => {
      fitView({ duration: 500, padding: 0.10 });
    }, 60);
    return () => clearTimeout(timer);
  }, [dataTrigger, fitView]);

  return null;
};

/**
 * Inner component using React Flow context for graph visualization.
 */
const InvestigationGraphContent: React.FC<InvestigationGraphProps> = ({
  graphData,
  onPivot,
  isPivoting,
  theme = 'dark',
}) => {
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [copied, setCopied] = useState(false);
  const { fitView } = useReactFlow();

  // Compute Layout using the scalable force-directed radial engine
  const { initialNodes, initialEdges, nodeCount, edgeCount } = useMemo(() => {
    const nodes: Node[] = [];
    const edges: Edge[] = [];

    const rawNodes = graphData?.nodes || [];
    const rawEdges = graphData?.edges || [];

    if (rawNodes.length === 0) {
      return { initialNodes: [], initialEdges: [], nodeCount: 0, edgeCount: 0 };
    }

    // Run scalable force-directed radial layout
    const layout = calculateForceRadialLayout(
      rawNodes,
      rawEdges,
      graphData?.root_ioc
    );

    const rootNode =
      (graphData?.root_ioc ? rawNodes.find((n) => n.id === graphData.root_ioc) : null) ||
      rawNodes.find((n) => n.is_root) ||
      rawNodes[0];

    rawNodes.forEach((node) => {
      const isRoot = node.id === rootNode?.id || node.is_root;
      const fullIoc = node.id || node.label;
      const displayLabel = truncateIocForDisplay(fullIoc, node.type);
      const pos = layout.positions.get(node.id) || { x: 0, y: 0 };

      let bg = '#1e293b';
      let border = '#334155';
      let text = '#f8fafc';
      let boxShadow = '0 2px 8px rgba(0, 0, 0, 0.2)';

      if (isRoot) {
        bg = '#ef4444';
        border = '#b91c1c';
        text = '#ffffff';
        boxShadow = '0 0 24px rgba(239, 68, 68, 0.45)';
      } else if (node.type === 'ipv4' || node.type === 'ipv6') {
        bg = '#1e3a8a';
        border = '#3b82f6';
      } else if (node.type === 'domain') {
        bg = '#581c87';
        border = '#a855f7';
      } else if (node.type === 'url') {
        bg = '#164e63';
        border = '#06b6d4';
      } else if (node.type === 'md5' || node.type === 'sha1' || node.type === 'sha256' || node.type === 'hash') {
        bg = '#78350f';
        border = '#f59e0b';
      }

      nodes.push({
        id: node.id,
        type: 'iocNode',
        position: pos,
        data: {
          ...node,
          canonical_ioc: fullIoc,
          display_label: displayLabel,
        },
        style: {
          background: bg,
          color: text,
          border: `${isRoot ? '2px' : '1.5px'} solid ${border}`,
          borderRadius: isRoot ? '10px' : '8px',
          padding: isRoot ? '7px 12px' : '5px 10px',
          fontWeight: isRoot ? 'bold' : 'normal',
          fontSize: '11px',
          fontFamily: 'monospace',
          boxShadow,
          cursor: 'pointer',
          maxWidth: '200px',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          whiteSpace: 'nowrap',
          boxSizing: 'border-box',
        },
      });
    });

    const edgeStroke = theme === 'light' ? '#94a3b8' : '#64748b';
    const labelFill = theme === 'light' ? '#475569' : '#94a3b8';
    const labelBg = theme === 'light' ? '#ffffff' : '#090d16';

    rawEdges.forEach((edge) => {
      const handles = layout.edgeHandles.get(edge.id) || {
        sourceHandle: 'bottom-source',
        targetHandle: 'top-target',
      };

      edges.push({
        id: edge.id,
        source: edge.source,
        target: edge.target,
        sourceHandle: handles.sourceHandle,
        targetHandle: handles.targetHandle,
        label: edge.label,
        animated: true,
        style: { stroke: edgeStroke, strokeWidth: 1.5 },
        labelStyle: { fill: labelFill, fontSize: 10, fontFamily: 'monospace' },
        labelBgStyle: { fill: labelBg, fillOpacity: 0.85 },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: edgeStroke,
        },
      });
    });

    return {
      initialNodes: nodes,
      initialEdges: edges,
      nodeCount: nodes.length,
      edgeCount: edges.length,
    };
  }, [graphData, theme]);

  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  // Synchronize graph nodes and edges when investigation or theme updates
  useEffect(() => {
    setNodes(initialNodes);
    setEdges(initialEdges);
    setSelectedNode(null);
    setCopied(false);
  }, [initialNodes, initialEdges, setNodes, setEdges]);

  const onNodeClick = useCallback((_: any, node: Node) => {
    setSelectedNode(node.data as unknown as GraphNode);
    setCopied(false);
  }, []);

  const handleCopyIoc = useCallback((iocToCopy: string) => {
    if (!iocToCopy) return;
    navigator.clipboard.writeText(iocToCopy).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }).catch((err) => {
      console.error('Failed to copy IOC:', err);
    });
  }, []);

  const selectedFullIoc = selectedNode
    ? (selectedNode.metadata?.canonical_ioc as string) ||
      (selectedNode.metadata?.raw_ioc as string) ||
      selectedNode.id ||
      selectedNode.label
    : '';

  return (
    <section className="space-y-4">
      <div className="flex items-center justify-between border-b border-theme pb-3">
        <div>
          <div className="flex items-center space-x-2">
            <span className="text-xs font-mono font-bold tracking-widest text-emerald-500 uppercase">Interactive Graph</span>
            <span className="text-theme-muted">/</span>
            <h2 className="text-lg font-bold text-theme-primary tracking-wide">Threat Relationship Topology</h2>
          </div>
          <p className="text-xs text-theme-secondary">
            Visual provenance map connecting root IOC to discovered nodes and edges. Click any node to inspect and pivot.
          </p>
        </div>

        {/* Graph metrics badge */}
        <div className="flex items-center space-x-2 text-xs font-mono">
          <span className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg border border-theme bg-theme-surface text-theme-secondary">
            <Layers className="w-3.5 h-3.5 text-emerald-400" />
            <span className="font-bold text-theme-primary">{nodeCount}</span>
            <span>nodes</span>
            <span className="text-theme-muted">|</span>
            <span className="font-bold text-theme-primary">{edgeCount}</span>
            <span>relationships</span>
          </span>
        </div>
      </div>

      <div className="relative h-[620px] bg-theme-card border border-theme rounded-xl overflow-hidden shadow-inner">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onNodeClick={onNodeClick}
          fitView
          fitViewOptions={{ padding: 0.10, duration: 500 }}
          minZoom={0.05}
          maxZoom={2.0}
        >
          <GraphAutoFitter dataTrigger={graphData?.nodes?.length} />
          <Background color={theme === 'light' ? '#cbd5e1' : '#1e293b'} gap={18} size={1} />
          <Controls className="!bg-theme-surface !border-theme !text-theme-primary shadow-md" />
          <MiniMap
            nodeColor={(n) => {
              if (n.data?.is_root) return '#ef4444';
              if (n.data?.type === 'domain') return '#a855f7';
              if (n.data?.type === 'url') return '#06b6d4';
              if (n.data?.type === 'ipv4' || n.data?.type === 'ipv6') return '#3b82f6';
              return '#f59e0b';
            }}
            className="!bg-theme-surface !border-theme shadow-md"
          />

          <Panel position="top-left" className="bg-theme-panel border border-theme p-3 rounded-lg text-[11px] font-mono space-y-1.5 shadow-md">
            <div className="text-theme-primary font-bold mb-1 flex items-center justify-between">
              <span>Graph Legend</span>
            </div>
            <div className="flex items-center space-x-2">
              <span className="w-2.5 h-2.5 rounded-full bg-red-500 inline-block" />
              <span className="text-theme-secondary">Root IOC</span>
            </div>
            <div className="flex items-center space-x-2">
              <span className="w-2.5 h-2.5 rounded-full bg-blue-500 inline-block" />
              <span className="text-theme-secondary">IP Address</span>
            </div>
            <div className="flex items-center space-x-2">
              <span className="w-2.5 h-2.5 rounded-full bg-purple-500 inline-block" />
              <span className="text-theme-secondary">Domain</span>
            </div>
            <div className="flex items-center space-x-2">
              <span className="w-2.5 h-2.5 rounded-full bg-cyan-500 inline-block" />
              <span className="text-theme-secondary">URL</span>
            </div>
            <div className="flex items-center space-x-2">
              <span className="w-2.5 h-2.5 rounded-full bg-amber-500 inline-block" />
              <span className="text-theme-secondary">Hash</span>
            </div>

            <button
              onClick={() => fitView({ duration: 500, padding: 0.10 })}
              className="mt-2.5 w-full text-[10px] py-1 px-2 rounded bg-theme-surface hover:bg-theme-hover border border-theme text-theme-primary transition cursor-pointer flex items-center justify-center space-x-1.5 font-bold"
              title="Fit and center entire network layout in view"
            >
              <Maximize2 className="w-3 h-3 text-emerald-400" />
              <span>Recenter Network</span>
            </button>
          </Panel>
        </ReactFlow>

        {/* Selected Node Inspection Drawer */}
        {selectedNode && (
          <div className="absolute right-4 top-4 bottom-4 w-80 bg-theme-panel border border-theme rounded-xl p-4 shadow-2xl backdrop-blur flex flex-col justify-between z-30 font-mono text-xs">
            <div>
              <div className="flex items-center justify-between pb-2 border-b border-theme">
                <span className="font-bold text-theme-primary">Node Inspector</span>
                <button
                  onClick={() => {
                    setSelectedNode(null);
                    setCopied(false);
                  }}
                  className="text-theme-muted hover:text-theme-primary cursor-pointer p-1"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="py-3 space-y-3">
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-theme-muted text-[10px] font-bold uppercase tracking-wider">FULL IOC:</span>
                    <button
                      onClick={() => handleCopyIoc(selectedFullIoc)}
                      className="text-[10px] px-2 py-0.5 rounded border border-theme bg-theme-surface hover:bg-theme-hover text-theme-secondary hover:text-theme-primary transition flex items-center space-x-1 cursor-pointer"
                      title="Copy full IOC to clipboard"
                    >
                      {copied ? (
                        <>
                          <Check className="w-3 h-3 text-emerald-500" />
                          <span className="text-emerald-500 font-bold">Copied!</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3 h-3" />
                          <span>Copy IOC</span>
                        </>
                      )}
                    </button>
                  </div>
                  <div className="p-2 rounded bg-theme-inset border border-theme max-h-24 overflow-y-auto">
                    <span className="text-theme-primary font-bold break-all select-all font-mono text-xs block leading-relaxed">
                      {selectedFullIoc}
                    </span>
                  </div>
                </div>

                <div className="flex justify-between">
                  <span className="text-theme-muted">TYPE:</span>
                  <span className="text-cyan-500 font-bold uppercase">{selectedNode.type}</span>
                </div>

                <div className="flex justify-between">
                  <span className="text-theme-muted">CONFIDENCE:</span>
                  <span className="text-amber-500 font-bold">{selectedNode.confidence}%</span>
                </div>

                <div className="flex justify-between">
                  <span className="text-theme-muted">DEPTH:</span>
                  <span className="text-theme-secondary">{selectedNode.depth}</span>
                </div>

                {selectedNode.metadata?.providers && (
                  <div>
                    <span className="text-theme-muted block text-[10px]">PROVIDERS:</span>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {selectedNode.metadata.providers.map((p: string) => (
                        <span key={p} className="px-1.5 py-0.5 rounded bg-theme-inset text-theme-secondary border border-theme text-[10px]">
                          {p}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>

            <button
              onClick={() => {
                onPivot(selectedFullIoc, selectedNode.type as IOCType);
                setSelectedNode(null);
              }}
              disabled={isPivoting}
              className="w-full py-2 bg-red-600 hover:bg-red-500 text-white font-bold rounded-lg flex items-center justify-center space-x-2 transition disabled:opacity-50 cursor-pointer shadow-lg shadow-red-900/30"
            >
              <GitFork className="w-4 h-4" />
              <span>PIVOT FROM THIS IOC</span>
            </button>
          </div>
        )}
      </div>
    </section>
  );
};

export const InvestigationGraph: React.FC<InvestigationGraphProps> = (props) => {
  return (
    <ReactFlowProvider>
      <InvestigationGraphContent {...props} />
    </ReactFlowProvider>
  );
};
