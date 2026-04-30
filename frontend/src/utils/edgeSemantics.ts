/**
 * edgeSemantics.ts
 *
 * Pure functions that decide the visual and semantic type of a ReactFlow edge
 * based on the two connected devices' data. Extracted from LabPage.tsx so they
 * can be unit-tested without a DOM or React context.
 */
import type { DeviceData } from '../types/lab'

export type EdgeKind =
  | 'same-zone'
  | 'cross-zone'
  | 'attack'
  | 'monitoring'
  | 'blocked'
  | 'no-route'

export interface EdgeSemantics {
  kind: EdgeKind
  label?: string
  warning?: string
  /** True for IDS taps — does NOT create a routable communication path */
  monitoringOnly: boolean
  /** False for monitoring, blocked, and no-route edges */
  communicationAllowed: boolean
  /** True when source and target are in different zones */
  crossZone: boolean
}

const GATEWAY_TYPES = ['router', 'firewall'] as const

function isPrivateIP(ip: string): boolean {
  const parts = ip.split('.').map(Number)
  if (parts.length !== 4 || parts.some(isNaN)) return false
  if (parts[0] === 10) return true
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true
  if (parts[0] === 192 && parts[1] === 168) return true
  return false
}

/**
 * Returns the network prefix of an IP based on its class:
 *   Class A  → first octet        (e.g. 10.x.x.x → "10")
 *   Class B  → first two octets   (e.g. 172.16.x.x → "172.16")
 *   Class C  → first three octets (e.g. 192.168.1.x → "192.168.1")
 *   Class D  → multicast, no prefix comparison
 */
export function ipNetworkPrefix(ip: string, ipClass: DeviceData['ipClass']): string | null {
  const parts = ip.split('.')
  if (parts.length !== 4) return null
  if (ipClass === 'A') return parts[0]
  if (ipClass === 'B') return `${parts[0]}.${parts[1]}`
  if (ipClass === 'C') return `${parts[0]}.${parts[1]}.${parts[2]}`
  return null  // Class D multicast — skip prefix check
}

export function getEdgeKind(srcData: DeviceData, tgtData: DeviceData): EdgeSemantics {
  const crossZone = srcData.zone !== tgtData.zone

  // Attacker involved — always an attack path
  if (srcData.deviceType === 'attacker' || tgtData.deviceType === 'attacker') {
    return { kind: 'attack', label: 'attack path', monitoringOnly: false, communicationAllowed: true, crossZone }
  }

  // IDS monitors everything — passive tap, not a routable link
  if (srcData.deviceType === 'ids' || tgtData.deviceType === 'ids') {
    return { kind: 'monitoring', monitoringOnly: true, communicationAllowed: false, crossZone }
  }

  // Database should never be directly reachable from external
  if (
    (srcData.deviceType === 'database' && tgtData.zone === 'external') ||
    (tgtData.deviceType === 'database' && srcData.zone === 'external')
  ) {
    return {
      kind: 'blocked',
      label: 'blocked',
      warning: 'Database should not be directly reachable from the external zone. Route through a firewall.',
      monitoringOnly: false,
      communicationAllowed: false,
      crossZone,
    }
  }

  // Subnet mismatch — devices in different networks without a gateway between them
  const isGateway = (GATEWAY_TYPES as readonly string[]).includes(srcData.deviceType) ||
                    (GATEWAY_TYPES as readonly string[]).includes(tgtData.deviceType)

  if (!isGateway && srcData.ip && tgtData.ip) {
    const srcPrefix = ipNetworkPrefix(srcData.ip, srcData.ipClass)
    const tgtPrefix = ipNetworkPrefix(tgtData.ip, tgtData.ipClass)
    if (srcPrefix && tgtPrefix && srcPrefix !== tgtPrefix) {
      return {
        kind: 'no-route',
        label: 'no route',
        warning: `Subnet mismatch: ${srcData.ip} (${srcPrefix}.0) and ${tgtData.ip} (${tgtPrefix}.0) are on different networks. Direct L2 communication is impossible — route through a router or firewall.`,
        monitoringOnly: false,
        communicationAllowed: false,
        crossZone,
      }
    }
  }

  // Public ↔ private IP mismatch — always a zone boundary regardless of zone label
  if (srcData.ip && tgtData.ip) {
    const srcPrivate = isPrivateIP(srcData.ip)
    const tgtPrivate = isPrivateIP(tgtData.ip)
    if (srcPrivate !== tgtPrivate) {
      return {
        kind: 'cross-zone',
        label: `${srcData.zone} → ${tgtData.zone}`,
        warning: !isGateway
          ? `Cross-zone link between private and public address space without a router or firewall.`
          : undefined,
        monitoringOnly: false,
        communicationAllowed: true,
        crossZone: true,
      }
    }
  }

  // Same zone — normal internal traffic
  if (srcData.zone === tgtData.zone) {
    return { kind: 'same-zone', monitoringOnly: false, communicationAllowed: true, crossZone: false }
  }

  // Cross-zone — flag it, suggest a gateway device
  const needsGateway = !isGateway
  return {
    kind: 'cross-zone',
    label: `${srcData.zone} → ${tgtData.zone}`,
    warning: needsGateway
      ? `Cross-zone link between ${srcData.zone} and ${tgtData.zone} without a router or firewall. In a real network this traffic would be blocked.`
      : undefined,
    monitoringOnly: false,
    communicationAllowed: true,
    crossZone: true,
  }
}
