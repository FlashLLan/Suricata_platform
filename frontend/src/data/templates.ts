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

  // ── 8. Enterprise Network ────────────────────────────────────────────────────
  {
    id: 'enterprise-network',
    name: 'Enterprise Network',
    description: 'Full corporate topology: firewall, DMZ with web and mail servers, internal LAN with file server and DNS. IDS covers the perimeter — but not the internal segment.',
    difficulty: 'advanced',
    topology: {
      nodes: [
        n('node-1', 'attacker',      { x: 40,  y: 290 }),
        n('node-2', 'firewall',      { x: 230, y: 290 }),
        n('node-3', 'web-server',    { x: 430, y: 150 }),
        n('node-4', 'mail-server',   { x: 430, y: 300 }),
        n('node-5', 'ids',           { x: 430, y: 460 }),
        n('node-6', 'router',        { x: 640, y: 290 }),
        n('node-7', 'workstation',   { x: 850, y: 160 }),
        n('node-8', 'server',        { x: 850, y: 290 }, {
          label: 'File Server',
          notes: 'Internal file share — not directly reachable from the DMZ',
        }),
        n('node-9', 'dns-server',    { x: 850, y: 420 }),
      ],
      edges: [
        // Perimeter
        e('e1-2',  'node-1', 'node-2'),   // Attacker → Firewall
        e('e2-3',  'node-2', 'node-3'),   // Firewall → Web Server (DMZ)
        e('e2-4',  'node-2', 'node-4'),   // Firewall → Mail Server (DMZ)
        // DMZ → Internal
        e('e3-6',  'node-3', 'node-6'),   // Web Server → Router
        e('e4-6',  'node-4', 'node-6'),   // Mail Server → Router
        // Internal LAN
        e('e6-7',  'node-6', 'node-7'),   // Router → Workstation
        e('e6-8',  'node-6', 'node-8'),   // Router → File Server
        e('e6-9',  'node-6', 'node-9'),   // Router → DNS Server
        // IDS monitors the perimeter and DMZ — blind to internal LAN
        e('e5-2',  'node-5', 'node-2'),
        e('e5-3',  'node-5', 'node-3'),
        e('e5-4',  'node-5', 'node-4'),
      ],
    },
    ruleSids: ['1000001', '1000002', '1000010', '1000011', '1000020', '1000030', '1000040'],
    tags: ['enterprise', 'dmz', 'perimeter', 'advanced'],
  },

  // ── 9. Full Kill Chain ───────────────────────────────────────────────────────
  {
    id: 'kill-chain',
    name: 'Full Kill Chain',
    description: 'Follows all MITRE ATT&CK stages: recon → initial access → exploitation → lateral movement → exfiltration. The IDS only covers the DMZ — discover which stages go undetected.',
    difficulty: 'advanced',
    topology: {
      nodes: [
        n('node-1', 'attacker',   { x: 50,  y: 260 }),
        n('node-2', 'firewall',   { x: 240, y: 260 }),
        n('node-3', 'web-server', { x: 450, y: 130 }, {
          label: 'Web Server (Pivot)',
          notes: 'Initial foothold — attacker exploits a web vulnerability and uses this host to pivot into the internal network',
        }),
        n('node-4', 'ids',        { x: 450, y: 410 }),
        n('node-5', 'server',     { x: 660, y: 260 }, {
          label: 'App Server',
          notes: 'Lateral movement target — attacker moves here after compromising the web server',
        }),
        n('node-6', 'database',   { x: 870, y: 130 }, {
          notes: 'Final target — sensitive data to be exfiltrated',
        }),
        n('node-7', 'router',     { x: 870, y: 390 }, {
          notes: 'Used as exfiltration gateway — traffic here is outside IDS visibility',
        }),
      ],
      edges: [
        // Stage 1 — Recon & Initial Access
        e('e1-2', 'node-1', 'node-2'),   // Attacker → Firewall
        e('e2-3', 'node-2', 'node-3'),   // Firewall → Web Server
        // Stage 2 — Lateral Movement (pivot through web server)
        e('e3-5', 'node-3', 'node-5'),   // Web Server → App Server
        // Stage 3 — Privilege Escalation & Collection
        e('e5-6', 'node-5', 'node-6'),   // App Server → Database
        // Stage 4 — Exfiltration (routes outside IDS coverage)
        e('e5-7', 'node-5', 'node-7'),   // App Server → Router (exfil path)
        // IDS — covers only perimeter and DMZ
        e('e4-2', 'node-4', 'node-2'),
        e('e4-3', 'node-4', 'node-3'),
      ],
    },
    ruleSids: ['1000001', '1000020', '1000022', '1000010', '1000040', '1000041', '1000050'],
    tags: ['kill-chain', 'lateral-movement', 'advanced'],
  },

  // ── 10. Lateral Movement & Pivoting ──────────────────────────────────────────
  {
    id: 'lateral-movement',
    name: 'Lateral Movement & Pivoting',
    description: 'The perimeter has already been breached. A compromised internal host scans the LAN, moves laterally to a file server and database, and exfiltrates data through the router.',
    difficulty: 'advanced',
    topology: {
      nodes: [
        n('node-1', 'attacker',    { x: 50,  y: 240 }, {
          label: 'C2 Server',
          notes: 'External command & control — the perimeter was breached before this scenario starts',
        }),
        n('node-2', 'workstation', { x: 280, y: 240 }, {
          label: 'Compromised Host',
          notes: 'Infected workstation — executes attacker commands and pivots laterally inside the network',
        }),
        n('node-3', 'server',      { x: 520, y: 110 }, {
          label: 'File Server',
          notes: 'Contains sensitive documents — lateral movement target',
        }),
        n('node-4', 'database',    { x: 760, y: 110 }, {
          notes: 'Final data target for exfiltration',
        }),
        n('node-5', 'router',      { x: 760, y: 370 }, {
          notes: 'Exfiltration gateway to the internet',
        }),
        n('node-6', 'ids',         { x: 520, y: 390 }),
      ],
      edges: [
        // C2 channel — ongoing communication from outside
        e('e1-2', 'node-1', 'node-2'),   // C2 Server → Compromised Host
        // Lateral movement inside the LAN
        e('e2-3', 'node-2', 'node-3'),   // Compromised Host → File Server
        e('e3-4', 'node-3', 'node-4'),   // File Server → Database
        // Exfiltration path
        e('e2-5', 'node-2', 'node-5'),   // Compromised Host → Router
        // IDS monitors east-west traffic
        e('e6-2', 'node-6', 'node-2'),
        e('e6-3', 'node-6', 'node-3'),
        e('e6-5', 'node-6', 'node-5'),
      ],
    },
    ruleSids: ['1000001', '1000040', '1000041', '1000050', '1000030'],
    tags: ['lateral-movement', 'east-west', 'exfiltration', 'advanced'],
  },
]
