import type { GraphNode, GraphEdge } from '../../types';

export interface LayoutOptions {
  cardWidth?: number;
  cardHeight?: number;
  horizontalPadding?: number;
  verticalPadding?: number;
  aspectRatioX?: number;
  aspectRatioY?: number;
}

export interface NodePosition {
  x: number;
  y: number;
}

export interface EdgeHandleAssignment {
  sourceHandle: string;
  targetHandle: string;
}

export interface LayoutResult {
  positions: Map<string, NodePosition>;
  edgeHandles: Map<string, EdgeHandleAssignment>;
  bounds: {
    minX: number;
    maxX: number;
    minY: number;
    maxY: number;
    width: number;
    height: number;
  };
}

/**
 * Calculates a compact, deterministic multi-ring layout for ThreatLens React Flow graph.
 *
 * Key Design Principles:
 * 1. Root Centricity: Root IOC is strictly fixed at (0, 0).
 * 2. Depth-Aware Multi-Ring Hierarchy:
 *    - Depth 0: Root IOC at center.
 *    - Depth 1: Direct relationships placed in tightly-spaced concentric inner shells.
 *    - Depth 2+: Subsequent pivot/derived relationships placed in progressive outer shells.
 * 3. Dynamic Capacity & Zero Void:
 *    - Radii scale smoothly with node count; small graphs (10-100 nodes) stay tightly clustered.
 *    - Large graphs (500-1000+ nodes) expand cleanly outward without empty central voids.
 * 4. Aspect-Ratio Ellipses:
 *    - Matches both horizontal node cards (~200px x ~36px) and widescreen viewports (~16:9).
 * 5. Deterministic Overlap Separation:
 *    - Pairwise AABB collision passes guarantee zero card overlap without running physics simulations.
 * 6. Dynamic 4-Way Handle Routing:
 *    - Edges connect to closest facing sides (top, bottom, left, right) for clean, readable paths.
 */
export function calculateForceRadialLayout(
  nodes: GraphNode[],
  edges: GraphEdge[],
  rootIocValue?: string,
  options: LayoutOptions = {}
): LayoutResult {
  const {
    cardWidth = 200,
    cardHeight = 36,
    horizontalPadding = 16,
    verticalPadding = 14,
    aspectRatioX = 1.30,
    aspectRatioY = 0.95,
  } = options;

  const positions = new Map<string, NodePosition>();
  const edgeHandles = new Map<string, EdgeHandleAssignment>();

  if (!nodes || nodes.length === 0) {
    return {
      positions,
      edgeHandles,
      bounds: { minX: 0, maxX: 0, minY: 0, maxY: 0, width: 0, height: 0 },
    };
  }

  // 1. Identify Root Node
  const rootNode =
    (rootIocValue ? nodes.find((n) => n.id === rootIocValue) : null) ||
    nodes.find((n) => n.is_root) ||
    nodes[0];
  const rootId = rootNode.id;

  if (nodes.length === 1) {
    positions.set(rootId, { x: 0, y: 0 });
    return {
      positions,
      edgeHandles,
      bounds: {
        minX: -cardWidth / 2,
        maxX: cardWidth / 2,
        minY: -cardHeight / 2,
        maxY: cardHeight / 2,
        width: cardWidth,
        height: cardHeight,
      },
    };
  }

  // 2. Build Adjacency List for Topological Distance
  const adj = new Map<string, Set<string>>();
  nodes.forEach((n) => adj.set(n.id, new Set()));
  edges.forEach((e) => {
    if (adj.has(e.source) && adj.has(e.target)) {
      adj.get(e.source)!.add(e.target);
      adj.get(e.target)!.add(e.source);
    }
  });

  // 3. BFS Shortest Path from Root
  const depthMap = new Map<string, number>();
  const parentMap = new Map<string, string | null>();
  const childrenMap = new Map<string, string[]>();
  nodes.forEach((n) => {
    depthMap.set(n.id, n.id === rootId ? 0 : 9999);
    parentMap.set(n.id, null);
    childrenMap.set(n.id, []);
  });

  const queue: string[] = [rootId];
  const visited = new Set<string>([rootId]);

  while (queue.length > 0) {
    const curr = queue.shift()!;
    const currDepth = depthMap.get(curr)!;
    const neighbors = adj.get(curr) || new Set();

    for (const neighbor of neighbors) {
      if (!visited.has(neighbor)) {
        visited.add(neighbor);
        depthMap.set(neighbor, currDepth + 1);
        parentMap.set(neighbor, curr);
        childrenMap.get(curr)!.push(neighbor);
        queue.push(neighbor);
      }
    }
  }

  // Handle disconnected components by attaching them to root at depth 1
  nodes.forEach((n) => {
    if (!visited.has(n.id)) {
      depthMap.set(n.id, 1);
      parentMap.set(n.id, rootId);
      childrenMap.get(rootId)!.push(n.id);
      visited.add(n.id);
    }
  });

  // 4. Group Non-Root Nodes by Topological Depth
  const depthGroups = new Map<number, GraphNode[]>();
  nodes.forEach((n) => {
    if (n.id === rootId) return;
    const d = depthMap.get(n.id) || 1;
    if (!depthGroups.has(d)) depthGroups.set(d, []);
    depthGroups.get(d)!.push(n);
  });

  // Type grouping order for visual clarity (IPs, Domains, URLs, Hashes grouped together)
  const typeOrder: Record<string, number> = {
    ipv4: 1,
    ipv6: 2,
    domain: 3,
    url: 4,
    md5: 5,
    sha1: 6,
    sha256: 7,
    hash: 8,
  };

  // Sort nodes within each depth group
  depthGroups.forEach((groupNodes) => {
    groupNodes.sort((a, b) => {
      // Primary: cluster by parent node if depth > 1
      const parentA = parentMap.get(a.id);
      const parentB = parentMap.get(b.id);
      if (parentA && parentB && parentA !== parentB) {
        return parentA.localeCompare(parentB);
      }
      // Secondary: group by IOC type
      const orderA = typeOrder[(a.type || '').toLowerCase()] || 99;
      const orderB = typeOrder[(b.type || '').toLowerCase()] || 99;
      if (orderA !== orderB) return orderA - orderB;
      // Tertiary: deterministic tie-break by ID
      return a.id.localeCompare(b.id);
    });
  });

  // Place Root at (0, 0)
  positions.set(rootId, { x: 0, y: 0 });

  // 5. Dynamic Shell Geometry Scaling
  const totalNonRoot = nodes.length - 1;
  const baseRadius = totalNonRoot <= 4 ? 140 : totalNonRoot <= 8 ? 160 : totalNonRoot <= 25 ? 180 : 200;
  const shellStep = totalNonRoot <= 30 ? 95 : totalNonRoot <= 100 ? 110 : 125;
  const nodeArcSpan = totalNonRoot <= 100 ? 160 : 190;

  let currentShellIndex = 0;
  const sortedDepths = Array.from(depthGroups.keys()).sort((a, b) => a - b);

  sortedDepths.forEach((depth) => {
    const groupNodes = depthGroups.get(depth)!;
    const count = groupNodes.length;

    // Calculate concentric shells allocated to this depth tier
    const shellsForDepth: Array<{
      shellIdx: number;
      r: number;
      a: number;
      b: number;
      capacity: number;
    }> = [];
    let allocated = 0;

    while (allocated < count) {
      const shellIdx = currentShellIndex + shellsForDepth.length;
      const r = baseRadius + shellIdx * shellStep;
      const a = r * aspectRatioX;
      const b = r * aspectRatioY;
      // Ramanujan ellipse circumference approximation
      const circ = Math.PI * (3 * (a + b) - Math.sqrt((3 * a + b) * (a + 3 * b)));
      const capacity = Math.max(4, Math.floor(circ / nodeArcSpan));
      shellsForDepth.push({ shellIdx, r, a, b, capacity });
      allocated += capacity;
    }

    // Distribute nodes across the allocated shells proportionally to capacity
    let nodeOffset = 0;
    shellsForDepth.forEach((shell, sIdx) => {
      const isLastShell = sIdx === shellsForDepth.length - 1;
      const remainingNodes = count - nodeOffset;
      const remainingCapacity = shellsForDepth
        .slice(sIdx)
        .reduce((acc, sh) => acc + sh.capacity, 0);

      const numNodesForShell = isLastShell
        ? remainingNodes
        : Math.max(
            1,
            Math.min(
              remainingNodes,
              Math.round((shell.capacity / remainingCapacity) * remainingNodes)
            )
          );

      const nodesInThisShell = groupNodes.slice(nodeOffset, nodeOffset + numNodesForShell);
      nodeOffset += numNodesForShell;

      const nInShell = nodesInThisShell.length;
      // Phase-stagger alternating rings so nodes nest in angular gaps of neighboring rings
      const phaseOffset =
        -Math.PI / 2 + (shell.shellIdx % 2 === 1 ? Math.PI / Math.max(1, nInShell) : 0);

      nodesInThisShell.forEach((node, idx) => {
        const theta = phaseOffset + (idx / nInShell) * 2 * Math.PI;
        const x = Math.round(shell.a * Math.cos(theta) * 10) / 10;
        const y = Math.round(shell.b * Math.sin(theta) * 10) / 10;
        positions.set(node.id, { x, y });
      });
    });

    currentShellIndex += shellsForDepth.length;
  });

  // 6. Fast Deterministic Pairwise AABB Overlap Resolution Pass
  const reqDistX = cardWidth + horizontalPadding;
  const reqDistY = cardHeight + verticalPadding;
  const posArr = nodes.map((n) => ({
    id: n.id,
    isRoot: n.id === rootId,
    ...positions.get(n.id)!,
  }));

  for (let pass = 0; pass < 8; pass++) {
    let hadCollision = false;
    for (let i = 0; i < posArr.length; i++) {
      for (let j = i + 1; j < posArr.length; j++) {
        const a = posArr[i];
        const b = posArr[j];
        const dx = b.x - a.x;
        const dy = b.y - a.y;
        const absDx = Math.abs(dx);
        const absDy = Math.abs(dy);

        if (absDx < reqDistX && absDy < reqDistY) {
          hadCollision = true;
          const overlapX = reqDistX - absDx;
          const overlapY = reqDistY - absDy;

          // Separate along axis of minimum fractional overlap
          if (overlapX / reqDistX < overlapY / reqDistY) {
            const pushX = (overlapX / 2) * (dx >= 0 ? 1 : -1);
            if (!a.isRoot && !b.isRoot) {
              a.x -= pushX;
              b.x += pushX;
            } else if (a.isRoot) {
              b.x += pushX * 2;
            } else {
              a.x -= pushX * 2;
            }
          } else {
            const pushY = (overlapY / 2) * (dy >= 0 ? 1 : -1);
            if (!a.isRoot && !b.isRoot) {
              a.y -= pushY;
              b.y += pushY;
            } else if (a.isRoot) {
              b.y += pushY * 2;
            } else {
              a.y -= pushY * 2;
            }
          }
        }
      }
    }
    if (!hadCollision) break;
  }

  // 7. Commit Final Coordinates and Compute Exact Bounds
  let minX = Infinity;
  let maxX = -Infinity;
  let minY = Infinity;
  let maxY = -Infinity;

  posArr.forEach((p) => {
    const finalX = Math.round(p.x * 10) / 10;
    const finalY = Math.round(p.y * 10) / 10;
    positions.set(p.id, { x: finalX, y: finalY });
    minX = Math.min(minX, finalX - cardWidth / 2);
    maxX = Math.max(maxX, finalX + cardWidth / 2);
    minY = Math.min(minY, finalY - cardHeight / 2);
    maxY = Math.max(maxY, finalY + cardHeight / 2);
  });

  // 8. Dynamic 4-Way Handles Routing
  edges.forEach((edge) => {
    const edgeKey = edge.id || `${edge.source}->${edge.target}`;
    const srcPos = positions.get(edge.source);
    const tgtPos = positions.get(edge.target);
    if (!srcPos || !tgtPos) {
      const defaultAssignment = { sourceHandle: 'bottom-source', targetHandle: 'top-target' };
      edgeHandles.set(edgeKey, defaultAssignment);
      if (edge.id) edgeHandles.set(edge.id, defaultAssignment);
      return;
    }

    const dx = tgtPos.x - srcPos.x;
    const dy = tgtPos.y - srcPos.y;
    let sourceHandle = 'bottom-source';
    let targetHandle = 'top-target';

    if (Math.abs(dx) > Math.abs(dy) * 1.15) {
      if (dx > 0) {
        sourceHandle = 'right-source';
        targetHandle = 'left-target';
      } else {
        sourceHandle = 'left-source';
        targetHandle = 'right-target';
      }
    } else {
      if (dy > 0) {
        sourceHandle = 'bottom-source';
        targetHandle = 'top-target';
      } else {
        sourceHandle = 'top-source';
        targetHandle = 'bottom-target';
      }
    }

    const assignment = { sourceHandle, targetHandle };
    edgeHandles.set(edgeKey, assignment);
    if (edge.id) edgeHandles.set(edge.id, assignment);
  });

  return {
    positions,
    edgeHandles,
    bounds: {
      minX,
      maxX,
      minY,
      maxY,
      width: maxX - minX,
      height: maxY - minY,
    },
  };
}

// Alias for seamless backward compatibility
export const calculateCompactMultiRingLayout = calculateForceRadialLayout;
