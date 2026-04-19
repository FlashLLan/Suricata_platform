import { describe, it, expect } from 'vitest'
import { getHomeIPs, resolveHomeNet } from '../utils/exportHelpers'

/** Minimal node-like fixture — only the fields our helpers inspect. */
function node(ip: string, zone: string) {
  return { data: { ip, zone } }
}

// ─── getHomeIPs ───────────────────────────────────────────────────────────────

describe('getHomeIPs', () => {
  it('includes internal zone IPs', () => {
    expect(getHomeIPs([node('192.168.1.10', 'internal')])).toEqual(['192.168.1.10'])
  })

  it('includes dmz zone IPs', () => {
    expect(getHomeIPs([node('192.168.1.30', 'dmz')])).toEqual(['192.168.1.30'])
  })

  it('includes management zone IPs', () => {
    expect(getHomeIPs([node('192.168.1.5', 'management')])).toEqual(['192.168.1.5'])
  })

  it('excludes external zone IPs', () => {
    expect(getHomeIPs([node('8.8.8.8', 'external')])).toEqual([])
  })

  it('excludes nodes with no IP', () => {
    expect(getHomeIPs([{ data: { ip: '', zone: 'internal' } }])).toEqual([])
  })

  it('returns multiple IPs from mixed topology', () => {
    const nodes = [
      node('192.168.1.10', 'internal'),
      node('192.168.1.30', 'dmz'),
      node('8.8.8.8', 'external'),
      node('192.168.1.5', 'management'),
    ]
    expect(getHomeIPs(nodes)).toEqual(['192.168.1.10', '192.168.1.30', '192.168.1.5'])
  })
})

// ─── resolveHomeNet ───────────────────────────────────────────────────────────

describe('resolveHomeNet', () => {
  it('uses the override when provided', () => {
    const nodes = [node('192.168.1.10', 'internal')]
    expect(resolveHomeNet(nodes, '10.0.0.0/8')).toBe('10.0.0.0/8')
  })

  it('trims whitespace from override', () => {
    expect(resolveHomeNet([], '  10.0.0.0/8  ')).toBe('10.0.0.0/8')
  })

  it('falls back to 192.168.0.0/16 when canvas has no qualifying nodes', () => {
    expect(resolveHomeNet([], '')).toBe('192.168.0.0/16')
    expect(resolveHomeNet([node('8.8.8.8', 'external')], '')).toBe('192.168.0.0/16')
  })

  it('returns the single IP when there is exactly one qualifying node', () => {
    expect(resolveHomeNet([node('192.168.1.10', 'internal')], '')).toBe('192.168.1.10')
  })

  it('wraps multiple IPs in square brackets', () => {
    const nodes = [node('192.168.1.10', 'internal'), node('192.168.1.30', 'dmz')]
    expect(resolveHomeNet(nodes, '')).toBe('[192.168.1.10,192.168.1.30]')
  })

  it('empty override string (whitespace only) still auto-derives', () => {
    expect(resolveHomeNet([node('10.0.0.1', 'internal')], '   ')).toBe('10.0.0.1')
  })
})
