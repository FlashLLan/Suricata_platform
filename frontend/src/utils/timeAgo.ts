/**
 * timeAgo — convert a UTC date string to a human-readable relative label.
 *
 * The backend returns timestamps without a 'Z' suffix; we append it so the
 * browser parses them as UTC rather than local time.
 */
export function timeAgo(dateStr: string): string {
  const normalized = dateStr.endsWith('Z') || dateStr.includes('+') ? dateStr : dateStr + 'Z'
  const diff = Date.now() - new Date(normalized).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  const days = Math.floor(hrs / 24)
  return `${days}d ago`
}
