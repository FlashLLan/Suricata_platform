import type { Node, Edge } from '@xyflow/react'
import type { DeviceData } from '../types/lab'

export type TemplateDifficulty = 'beginner' | 'intermediate' | 'advanced'

export interface LabTemplate {
  id: string
  name: string
  description: string
  difficulty: TemplateDifficulty
  /** null means blank canvas — no topology pre-loaded */
  topology: { nodes: Node[]; edges: Edge[] } | null
  /** SIDs of predefined rules to pre-load in the rule library panel */
  ruleSids: string[]
  tags: string[]
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const DEVICE_DEFAULTS: Record<DeviceData['deviceType'], Partial<DeviceData>> = {
  workstation:   { label: 'Workstation',  ip: '192.168.1.10', zone: 'internal',   ports: '22,3389' },
  server:        { label: 'Server',       ip: '192.168.1.20', zone: 'internal',   ports: '22,80' },
  'web-server':  { label: 'Web Server',   ip: '192.168.1.30', zone: 'dmz',        ports: '80,443' },
  database:      { label: 'Database',     ip: '192.168.1.40', zone: 'internal',   ports: '3306,5432' },
  router:        { label: 'Router',       ip: '192.168.1.1',  zone: 'internal',   ports: '' },
  firewall:      { label: 'Firewall',     ip: '192.168.1.2',  zone: 'management', ports: '' },
  attacker:      { label: 'Attacker',     ip: '203.0.113.10', zone: 'external',   ports: '' },
  'dns-server':  { label: 'DNS Server',   ip: '192.168.1.53', zone: 'internal',   ports: '53' },
  'mail-server': { label: 'Mail Server',  ip: '192.168.1.25', zone: 'dmz',        ports: '25,465,993' },
  ids:           { label: 'Suricata IDS', ip: '192.168.1.5',  zone: 'management', ports: '' },
}

function n(
  id: string,
  deviceType: DeviceData['deviceType'],
  position: { x: number; y: number },
  overrides?: Partial<DeviceData>,
): Node {
  const data: DeviceData = {
    label: '', deviceType, ip: '', ipClass: 'C', subnet: '192.168.1.0/24',
    ports: '', os: '', zone: 'internal', notes: '',
    selectedAttacks: [], customAttackCommands: '',
    noDefense: false, enabledDefenses: [], customDefenseConfig: '',
    selectedRuleIds: [], customRules: [],
    ...DEVICE_DEFAULTS[deviceType],
    ...overrides,
  }
  return { id, type: 'device', position, data: data as unknown as Record<string, unknown> }
}

function e(id: string, source: string, target: string): Edge {
  // Minimal edge — styles are re-derived by getEdgeKind() when the project loads.
  return { id, source, target }
}

// ─── Templates ────────────────────────────────────────────────────────────────

export const LAB_TEMPLATES: LabTemplate[] = [
  // ── 1. Blank Canvas ─────────────────────────────────────────────────────────
  {
    id: 'blank',
    name: 'Blank Canvas',
    description: 'Start from scratch. Add devices, draw connections, and load rules manually.',
    difficulty: 'beginner',
    topology: null,
    ruleSids: [],
    tags: [],
  },

  // ── 2. Home Network Basics ───────────────────────────────────────────────────
  {
    id: 'home-network',
    name: 'Home Network Basics',
    description: 'Workstation behind a router with an IDS sensor. Attacker probing the perimeter.',
    difficulty: 'beginner',
    topology: {
      nodes: [
        n('node-1', 'workstation', { x: 100, y: 200 }),
        n('node-2', 'router',      { x: 440, y: 200 }),
        n('node-3', 'ids',         { x: 440, y: 370 }),
        n('node-4', 'attacker',    { x: 740, y: 200 }),
      ],
      edges: [
        e('e1-2', 'node-1', 'node-2'),
        e('e4-2', 'node-4', 'node-2'),
        e('e3-1', 'node-3', 'node-1'),
        e('e3-2', 'node-3', 'node-2'),
      ],
    },
    ruleSids: ['1000001', '1000002'],
    tags: ['scanning', 'perimeter'],
  },

  // ── 3. SSH Brute Force Lab ───────────────────────────────────────────────────
  {
    id: 'ssh-brute-force',
    name: 'SSH Brute Force Lab',
    description: 'Attacker targeting an internal server over SSH — detect automated password guessing.',
    difficulty: 'beginner',
    topology: {
      nodes: [
        n('node-1', 'attacker', { x: 100, y: 210 }),
        n('node-2', 'server',   { x: 480, y: 210 }),
        n('node-3', 'ids',      { x: 300, y: 390 }),
      ],
      edges: [
        e('e1-2', 'node-1', 'node-2'),
        e('e3-1', 'node-3', 'node-1'),
        e('e3-2', 'node-3', 'node-2'),
      ],
    },
    ruleSids: ['1000010'],
    tags: ['brute-force', 'ssh'],
  },

  // ── 4. Small Office with DMZ ─────────────────────────────────────────────────
  {
    id: 'dmz-office',
    name: 'Small Office with DMZ',
    description: 'Firewall-protected network with a web server in the DMZ and database in the internal zone.',
    difficulty: 'beginner',
    topology: {
      nodes: [
        n('node-1', 'attacker',   { x: 50,  y: 220 }),
        n('node-2', 'firewall',   { x: 280, y: 220 }),
        n('node-3', 'web-server', { x: 510, y: 100 }),
        n('node-4', 'database',   { x: 740, y: 220 }),
        n('node-5', 'ids',        { x: 510, y: 360 }),
      ],
      edges: [
        e('e1-2', 'node-1', 'node-2'),
        e('e2-3', 'node-2', 'node-3'),
        e('e3-4', 'node-3', 'node-4'),
        e('e5-2', 'node-5', 'node-2'),
        e('e5-3', 'node-5', 'node-3'),
      ],
    },
    ruleSids: ['1000020', '1000022', '1000023'],
    tags: ['web-attacks', 'dmz', 'sql-injection'],
  },

  // ── 5. Web Application Attack Lab ────────────────────────────────────────────
  {
    id: 'web-attack-lab',
    name: 'Web Application Attack Lab',
    description: 'Attacker hitting a web app to extract data from a backend database. SQL injection + login brute force.',
    difficulty: 'beginner',
    topology: {
      nodes: [
        n('node-1', 'attacker',   { x: 80,  y: 210 }),
        n('node-2', 'web-server', { x: 390, y: 120 }),
        n('node-3', 'database',   { x: 650, y: 120 }),
        n('node-4', 'ids',        { x: 250, y: 360 }),
      ],
      edges: [
        e('e1-2', 'node-1', 'node-2'),
        e('e2-3', 'node-2', 'node-3'),
        e('e4-1', 'node-4', 'node-1'),
        e('e4-2', 'node-4', 'node-2'),
      ],
    },
    ruleSids: ['1000020', '1000011'],
    tags: ['web-attacks', 'sql-injection', 'brute-force'],
  },

  // ── 6. DNS Tunneling Detection ───────────────────────────────────────────────
  {
    id: 'dns-tunneling',
    name: 'DNS Tunneling Detection',
    description: 'Internal workstation making suspiciously long DNS queries — classic data exfiltration via DNS.',
    difficulty: 'intermediate',
    topology: {
      nodes: [
        n('node-1', 'workstation', { x: 80,  y: 210 }),
        n('node-2', 'dns-server',  { x: 380, y: 210 }),
        n('node-3', 'router',      { x: 640, y: 210 }),
        n('node-4', 'ids',         { x: 230, y: 380 }),
      ],
      edges: [
        e('e1-2', 'node-1', 'node-2'),
        e('e2-3', 'node-2', 'node-3'),
        e('e4-1', 'node-4', 'node-1'),
        e('e4-2', 'node-4', 'node-2'),
      ],
    },
    ruleSids: ['1000030', '1000031'],
    tags: ['dns', 'exfiltration'],
  },

  // ── 7. C2 Beacon Lab ─────────────────────────────────────────────────────────
  {
    id: 'c2-beacon',
    name: 'C2 Beacon Lab',
    description: 'Compromised host periodically beaconing to an external C2 server using suspicious HTTP patterns.',
    difficulty: 'intermediate',
    topology: {
      nodes: [
        n('node-1', 'workstation', { x: 130, y: 210 }, {
          label: 'Compromised Host',
          notes: 'Simulates an infected workstation sending C2 beacons',
        }),
        n('node-2', 'router',   { x: 440, y: 210 }),
        n('node-3', 'ids',      { x: 290, y: 390 }),
        n('node-4', 'attacker', { x: 720, y: 210 }, {
          label: 'C2 Server',
          notes: 'Attacker-controlled command & control server',
        }),
      ],
      edges: [
        e('e4-1', 'node-4', 'node-1'),
        e('e1-2', 'node-1', 'node-2'),
        e('e3-1', 'node-3', 'node-1'),
        e('e3-2', 'node-3', 'node-2'),
      ],
    },
    ruleSids: ['1000040', '1000041'],
    tags: ['malware', 'c2', 'beacon'],
  },
]
