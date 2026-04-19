import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { timeAgo } from '../utils/timeAgo'

/**
 * Pin Date.now() to a fixed point so tests are deterministic regardless of
 * when they run.  We treat "now" as 2026-04-19T12:00:00Z.
 */
const NOW = new Date('2026-04-19T12:00:00Z').getTime()

beforeEach(() => { vi.spyOn(Date, 'now').mockReturnValue(NOW) })
afterEach(() => { vi.restoreAllMocks() })

function isoAt(offsetMs: number): string {
  return new Date(NOW - offsetMs).toISOString()
}

describe('timeAgo', () => {
  it('returns "just now" for timestamps < 1 minute ago', () => {
    expect(timeAgo(isoAt(30_000))).toBe('just now')
    expect(timeAgo(isoAt(0))).toBe('just now')
  })

  it('returns minutes for timestamps 1–59 minutes ago', () => {
    expect(timeAgo(isoAt(60_000))).toBe('1m ago')
    expect(timeAgo(isoAt(5 * 60_000))).toBe('5m ago')
    expect(timeAgo(isoAt(59 * 60_000))).toBe('59m ago')
  })

  it('returns hours for timestamps 1–23 hours ago', () => {
    expect(timeAgo(isoAt(60 * 60_000))).toBe('1h ago')
    expect(timeAgo(isoAt(3 * 60 * 60_000))).toBe('3h ago')
    expect(timeAgo(isoAt(23 * 60 * 60_000))).toBe('23h ago')
  })

  it('returns days for timestamps ≥ 24 hours ago', () => {
    expect(timeAgo(isoAt(24 * 60 * 60_000))).toBe('1d ago')
    expect(timeAgo(isoAt(7 * 24 * 60 * 60_000))).toBe('7d ago')
  })

  it('handles timestamps without Z suffix (backend format)', () => {
    // Backend returns "2026-04-19T11:59:00" — no trailing Z
    const withoutZ = new Date(NOW - 60_000).toISOString().replace('Z', '')
    expect(timeAgo(withoutZ)).toBe('1m ago')
  })

  it('handles timestamps that already have Z suffix', () => {
    const withZ = isoAt(2 * 60_000)   // 2 minutes ago, already has Z
    expect(timeAgo(withZ)).toBe('2m ago')
  })

  it('handles timestamps with explicit UTC offset (+00:00)', () => {
    const withOffset = new Date(NOW - 5 * 60_000).toISOString().replace('Z', '+00:00')
    expect(timeAgo(withOffset)).toBe('5m ago')
  })
})
