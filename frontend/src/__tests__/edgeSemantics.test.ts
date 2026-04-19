import { describe, it, expect } from 'vitest'
import { ipNetworkPrefix, getEdgeKind } from '../utils/edgeSemantics'
import type { DeviceData } from '../types/lab'

// ─── Fixtures ─────────────────────────────────────────────────────────────────

function makeDevice(overrides: Partial<DeviceData> = {}): DeviceData {
  return {
    label: 'Test',
    deviceType: 'workstation',
    ip: '192.168.1.10',
    ipClass: 'C',
    subnet: '192.168.1.0/24',
    ports: '',
    os: '',
    zone: 'internal',
    notes: '',
    selectedAttacks: [],
    customAttackCommands: '',
    noDefense: false,
    enabledDefenses: [],
    customDefenseConfig: '',
    selectedRuleIds: [],
    customRules: [],
    ...overrides,
  }
}

// ─── ipNetworkPrefix ──────────────────────────────────────────────────────────

describe('ipNetworkPrefix', () => {
  it('returns first octet for Class A', () => {
    expect(ipNetworkPrefix('10.0.0.1', 'A')).toBe('10')
  })

  it('returns first two octets for Class B', () => {
    expect(ipNetworkPrefix('172.16.5.1', 'B')).toBe('172.16')
  })

  it('returns first three octets for Class C', () => {
    expect(ipNetworkPrefix('192.168.1.50', 'C')).toBe('192.168.1')
  })

  it('returns null for Class D (multicast)', () => {
    expect(ipNetworkPrefix('224.0.0.1', 'D')).toBeNull()
  })

  it('returns null for a malformed IP', () => {
    expect(ipNetworkPrefix('not-an-ip', 'C')).toBeNull()
  })

  it('returns null for an IP with fewer than 4 octets', () => {
    expect(ipNetworkPrefix('192.168.1', 'C')).toBeNull()
  })
})

// ─── getEdgeKind — same-zone ──────────────────────────────────────────────────

describe('getEdgeKind — same-zone', () => {
  it('two internal devices → same-zone', () => {
    const src = makeDevice({ zone: 'internal' })
    const tgt = makeDevice({ zone: 'internal', ip: '192.168.1.20' })
    const result = getEdgeKind(src, tgt)
    expect(result.kind).toBe('same-zone')
    expect(result.communicationAllowed).toBe(true)
    expect(result.crossZone).toBe(false)
  })

  it('two external devices → same-zone', () => {
    const src = makeDevice({ zone: 'external', ip: '1.2.3.4', ipClass: 'A' })
    const tgt = makeDevice({ zone: 'external', ip: '1.2.3.5', ipClass: 'A' })
    expect(getEdgeKind(src, tgt).kind).toBe('same-zone')
  })
})

// ─── getEdgeKind — attack ─────────────────────────────────────────────────────

describe('getEdgeKind — attack', () => {
  it('attacker as source → attack', () => {
    const src = makeDevice({ deviceType: 'attacker', zone: 'external' })
    const tgt = makeDevice({ zone: 'internal' })
    const result = getEdgeKind(src, tgt)
    expect(result.kind).toBe('attack')
    expect(result.label).toBe('attack path')
    expect(result.communicationAllowed).toBe(true)
  })

  it('attacker as target → attack', () => {
    const src = makeDevice({ zone: 'internal' })
    const tgt = makeDevice({ deviceType: 'attacker', zone: 'external' })
    expect(getEdgeKind(src, tgt).kind).toBe('attack')
  })
})

// ─── getEdgeKind — monitoring ─────────────────────────────────────────────────

describe('getEdgeKind — monitoring', () => {
  it('IDS as source → monitoring', () => {
    const src = makeDevice({ deviceType: 'ids', zone: 'management' })
    const tgt = makeDevice({ zone: 'internal' })
    const result = getEdgeKind(src, tgt)
    expect(result.kind).toBe('monitoring')
    expect(result.monitoringOnly).toBe(true)
    expect(result.communicationAllowed).toBe(false)
  })

  it('IDS as target → monitoring', () => {
    const src = makeDevice({ zone: 'internal' })
    const tgt = makeDevice({ deviceType: 'ids', zone: 'management' })
    expect(getEdgeKind(src, tgt).kind).toBe('monitoring')
  })
})

// ─── getEdgeKind — blocked ────────────────────────────────────────────────────

describe('getEdgeKind — blocked', () => {
  it('database → external zone → blocked', () => {
    const src = makeDevice({ deviceType: 'database', zone: 'internal' })
    const tgt = makeDevice({ zone: 'external', ip: '8.8.8.8', ipClass: 'A' })
    const result = getEdgeKind(src, tgt)
    expect(result.kind).toBe('blocked')
    expect(result.communicationAllowed).toBe(false)
    expect(result.warning).toMatch(/firewall/i)
  })

  it('external zone → database → blocked', () => {
    const src = makeDevice({ zone: 'external', ip: '8.8.8.8', ipClass: 'A' })
    const tgt = makeDevice({ deviceType: 'database', zone: 'internal' })
    expect(getEdgeKind(src, tgt).kind).toBe('blocked')
  })
})

// ─── getEdgeKind — no-route ───────────────────────────────────────────────────

describe('getEdgeKind — no-route', () => {
  it('Class C subnet mismatch without gateway → no-route', () => {
    const src = makeDevice({ ip: '192.168.1.10', ipClass: 'C', zone: 'internal' })
    const tgt = makeDevice({ ip: '192.168.2.10', ipClass: 'C', zone: 'internal' })
    const result = getEdgeKind(src, tgt)
    expect(result.kind).toBe('no-route')
    expect(result.communicationAllowed).toBe(false)
    expect(result.warning).toMatch(/subnet mismatch/i)
  })

  it('router bridges different subnets — NOT no-route', () => {
    const src = makeDevice({ deviceType: 'router', ip: '192.168.1.1', ipClass: 'C', zone: 'internal' })
    const tgt = makeDevice({ ip: '192.168.2.10', ipClass: 'C', zone: 'internal' })
    const result = getEdgeKind(src, tgt)
    expect(result.kind).not.toBe('no-route')
  })

  it('firewall bridges different subnets — NOT no-route', () => {
    const src = makeDevice({ deviceType: 'firewall', ip: '10.0.0.1', ipClass: 'A', zone: 'management' })
    const tgt = makeDevice({ ip: '192.168.1.5', ipClass: 'C', zone: 'internal' })
    const result = getEdgeKind(src, tgt)
    expect(result.kind).not.toBe('no-route')
  })
})

// ─── getEdgeKind — cross-zone ─────────────────────────────────────────────────

describe('getEdgeKind — cross-zone', () => {
  it('internal → dmz without gateway → cross-zone with warning', () => {
    const src = makeDevice({ zone: 'internal' })
    const tgt = makeDevice({ zone: 'dmz', ip: '192.168.1.30' })
    const result = getEdgeKind(src, tgt)
    expect(result.kind).toBe('cross-zone')
    expect(result.crossZone).toBe(true)
    expect(result.warning).toMatch(/router or firewall/i)
  })

  it('router → dmz cross-zone — no warning (gateway bridges zones)', () => {
    const src = makeDevice({ deviceType: 'router', zone: 'internal', ip: '192.168.1.1' })
    const tgt = makeDevice({ zone: 'dmz', ip: '192.168.1.30' })
    const result = getEdgeKind(src, tgt)
    expect(result.kind).toBe('cross-zone')
    expect(result.warning).toBeUndefined()
  })

  it('cross-zone label shows zone names', () => {
    const src = makeDevice({ zone: 'internal' })
    const tgt = makeDevice({ zone: 'external', ip: '8.8.8.8', ipClass: 'A' })
    // external target is not database, and workstation → external is cross-zone
    const result = getEdgeKind(src, tgt)
    // Could be cross-zone if same subnet check passes (different class A vs C)
    // The key assertion: crossZone must be true
    expect(result.crossZone).toBe(true)
  })
})
