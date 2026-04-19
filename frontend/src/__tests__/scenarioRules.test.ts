import { describe, it, expect } from 'vitest'
import { SCENARIO_RULES } from '../data/scenarioRules'
import { PREDEFINED_RULES } from '../data/rules'

const ALL_SIDS = new Set(PREDEFINED_RULES.map(r => r.sid))

describe('SCENARIO_RULES', () => {
  it('covers all expected scenario IDs', () => {
    const expected = [
      'nmap-syn-scan',
      'ping-sweep',
      'ssh-brute-force',
      'http-brute-force',
      'sql-injection',
      'dns-tunneling',
      'http-c2-beacon',
      'normal-browsing',
    ]
    for (const id of expected) {
      expect(SCENARIO_RULES).toHaveProperty(id)
    }
  })

  it('every referenced SID exists in PREDEFINED_RULES', () => {
    for (const [scenarioId, sids] of Object.entries(SCENARIO_RULES)) {
      for (const sid of sids) {
        expect(ALL_SIDS, `SID ${sid} in scenario '${scenarioId}' not found in PREDEFINED_RULES`).toContain(sid)
      }
    }
  })

  it('normal-browsing has no rules (expected empty)', () => {
    expect(SCENARIO_RULES['normal-browsing']).toEqual([])
  })

  it('nmap-syn-scan references at least one rule', () => {
    expect(SCENARIO_RULES['nmap-syn-scan'].length).toBeGreaterThan(0)
  })

  it('all values are arrays (never undefined or null)', () => {
    for (const [id, sids] of Object.entries(SCENARIO_RULES)) {
      expect(Array.isArray(sids), `${id} should be an array`).toBe(true)
    }
  })

  it('no duplicate SIDs within a single scenario', () => {
    for (const [id, sids] of Object.entries(SCENARIO_RULES)) {
      const unique = new Set(sids)
      expect(unique.size, `Duplicate SIDs in scenario '${id}'`).toBe(sids.length)
    }
  })
})
