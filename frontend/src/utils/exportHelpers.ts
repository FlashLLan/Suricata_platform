/**
 * exportHelpers.ts
 *
 * Pure topology-inspection helpers used by ExportModal. Extracted so they can
 * be unit-tested without a DOM. The node shape is kept generic (data: unknown)
 * so the functions accept both ReactFlow Node objects and plain test fixtures.
 */

interface NodeLike {
  data: unknown
}

interface DeviceLike {
  ip?: string
  zone?: string
}

function getDeviceData(n: NodeLike): DeviceLike {
  return n.data as DeviceLike
}

export function getHomeIPs(nodes: NodeLike[]): string[] {
  return nodes
    .map(getDeviceData)
    .filter(d => d.ip && ['internal', 'dmz', 'management'].includes(d.zone ?? ''))
    .map(d => d.ip!)
}

/**
 * Resolve the Suricata HOME_NET value.
 *  - If override is provided, use it as-is.
 *  - Otherwise derive from internal/dmz/management node IPs.
 *  - Falls back to "192.168.0.0/16" when the canvas has no qualifying nodes.
 */
export function resolveHomeNet(nodes: NodeLike[], override: string): string {
  if (override.trim()) return override.trim()
  const ips = getHomeIPs(nodes)
  if (ips.length === 0) return '192.168.0.0/16'
  if (ips.length === 1) return ips[0]
  return `[${ips.join(',')}]`
}
