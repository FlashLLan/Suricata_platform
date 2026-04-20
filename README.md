# Suricata Learning Platform

A full-stack interactive web application for learning network intrusion detection. Build visual network topologies, attach Suricata IDS rules, run simulated or real traffic scenarios, import real PCAP files, and export production-ready configurations - all without needing a physical network or a live Suricata instance.

---

## What it does

The platform walks you through the core detection-engineering workflow:

1. **Design a network** - drag and drop routers, servers, workstations, firewalls, and IDS sensors onto an interactive canvas. Configure each device's IP, zone (internal / DMZ / external / management), and role.
2. **Attach rules** - pick rules from a built-in library of 400+ Suricata signatures, or write your own with the custom-rule editor.
3. **Run a simulation** - choose an attack scenario (Nmap scan, SSH brute-force, SQL injection, DNS tunnelling, HTTP C2 beacon, and more). The backend simulates packet flows across your topology, evaluates which rules fire, and produces a detailed timeline with attack paths and IDS visibility scores.
4. **Import a PCAP** - upload a real `.pcap` / `.pcapng` capture. Scapy parses it, reconstructs the network topology, infers device zones and roles, detects the attack scenario from traffic patterns, and evaluates your rule set against the actual packets.
5. **Export configs** - download a ready-to-use `suricata.yaml` + rule file for your real environment.

---

## Architecture

```
suricata-platform/
├── backend/          # FastAPI (Python 3.13)
│   ├── app/
│   │   ├── main.py            # App entry point, CORS, router registration
│   │   ├── auth.py            # JWT creation + bcrypt password hashing
│   │   ├── config.py          # Pydantic settings (loaded from .env)
│   │   ├── database.py        # SQLAlchemy engine + session factory
│   │   ├── models.py          # ORM models: User, Project
│   │   ├── schemas.py         # Pydantic request/response schemas
│   │   └── routers/
│   │       ├── auth.py        # POST /register, POST /login, GET /me
│   │       ├── projects.py    # Full CRUD for user projects
│   │       ├── simulation.py  # POST /simulate, GET /simulate/status
│   │       └── pcap.py        # POST /pcap/analyze
│   └── simulation/
│       ├── engine.py          # Core simulation: packet generation, rule matching, defense scoring
│       ├── pcap_analyzer.py   # Scapy-based PCAP parsing and topology inference
│       ├── rule_parser.py     # Suricata rule tokeniser and field extractor
│       ├── scenarios.py       # Predefined attack scenario definitions
│       ├── pcap_builder.py    # Programmatic PCAP generation for simulation
│       ├── suricata_runner.py # Docker API integration for real Suricata execution
│       ├── suricata_mapper.py # Maps Suricata alert logs back to rule results
│       └── defenses.py        # Defense mechanism impact modelling
├── frontend/         # React 19 + TypeScript + Vite
│   └── src/
│       ├── pages/             # LoginPage, RegisterPage, DashboardPage, LabPage
│       ├── components/lab/    # DeviceNode, RuleLibraryPanel, SimulationModal,
│       │                      #   PcapImportModal, ExportModal, AnimatedPacketEdge…
│       ├── api/               # Axios clients for auth, projects, simulation, pcap
│       ├── store/             # Zustand auth store (token + user, localStorage)
│       ├── utils/             # edgeSemantics, exportHelpers, timeAgo
│       └── data/              # rules.ts, attacks.ts, defenses.ts, templates.ts
└── tests/            # pytest (backend) + Vitest (frontend) + Playwright (E2E)
```

### Tech stack

| Layer | Technology |
|---|---|
| Backend API | FastAPI 0.115, Uvicorn |
| ORM / DB | SQLAlchemy 2.0, SQLite |
| Auth | JWT (python-jose), bcrypt (passlib) |
| Packet analysis | Scapy 2.6 |
| Real Suricata | Docker SDK (optional) |
| Frontend | React 19, TypeScript, Vite 8 |
| Canvas | @xyflow/react (React Flow) |
| State | Zustand 5 |
| Styling | Tailwind CSS 4 |
| Testing | pytest, Vitest, Playwright |

---

## Simulation modes

The backend supports two simulation modes selectable per-request:

### Python mode (default, no dependencies)
A pure-Python engine generates synthetic packet flows for the chosen scenario, evaluates each active rule against every packet using the parsed rule fields (protocol, ports, direction, content patterns, flags), and returns a structured result with a timeline, attack-path graph, and IDS visibility score.

### Suricata mode (requires Docker)
When Docker is available and the `jasonish/suricata` image is pulled, the backend uses `pcap_builder.py` to produce a real `.pcap` file for the scenario, mounts it into a Suricata container, runs `suricata -r`, and parses `eve.json` alert output. `suricata_mapper.py` correlates alerts back to your rule list and merges them with the simulation result structure. If Docker is unavailable the backend automatically falls back to Python mode.

Check Docker availability at any time:
```
GET /api/simulate/status
# → { "status": "ready" | "image_not_pulled" | "docker_unavailable" }
```

---

## REST API reference

All endpoints under `/api/`. Protected endpoints require `Authorization: Bearer <token>`.

### Auth
| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/api/auth/register` | — | Create account `{ email, password }` |
| POST | `/api/auth/login` | — | Get JWT token (form data: `username`, `password`) |
| GET | `/api/auth/me` | ✓ | Current user profile |

### Projects
| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/projects` | ✓ | List user's projects (sorted by `updated_at`) |
| POST | `/api/projects` | ✓ | Create project `{ name, description? }` |
| GET | `/api/projects/{id}` | ✓ | Get project (updates `last_opened_at`) |
| PATCH | `/api/projects/{id}` | ✓ | Update `topology_json`, `rules_json`, `name`, etc. |
| DELETE | `/api/projects/{id}` | ✓ | Delete project |

### Simulation
| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/api/simulate` | ✓ | Run simulation `{ scenario_id, rule_texts, topology?, mode? }` |
| GET | `/api/simulate/status` | ✓ | Check Docker / Suricata availability |

### PCAP
| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/api/pcap/analyze` | ✓ | Upload `.pcap` (≤20 MB), returns topology + rule matches |

### Health
| Method | Path | Description |
|---|---|---|
| GET | `/api/health` | `{ "status": "ok" }` |

---

## Local development (no Docker)

### Prerequisites
- Python 3.11+ (3.13 recommended)
- Node.js 20+

### 1. Backend

```bash
cd backend

# Create and activate a virtual environment
python -m venv venv
# Windows
venv\Scripts\activate
# macOS / Linux
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env - at minimum set a SECRET_KEY value

# Start the API server
uvicorn app.main:app --reload
# Listening on http://localhost:8000
```

The SQLite database (`suricata_platform.db`) is created automatically on first run.

### 2. Frontend

```bash
cd frontend
npm install
npm run dev
# Listening on http://localhost:5173
```

Vite proxies all `/api/*` requests to `http://localhost:8000`, so no CORS issues in development.

Open `http://localhost:5173` in your browser, register an account, and start building.

---

## Docker deployment

> Docker support is provided for running real Suricata simulations. A full Compose setup for self-hosted deployment is planned; the steps below cover the Suricata integration feature.

### Enable real Suricata simulations

1. Install Docker Desktop (Windows/Mac) or Docker Engine (Linux).
2. Pull the Suricata image:
   ```bash
   docker pull jasonish/suricata:latest
   ```
3. Start the backend as normal (`uvicorn app.main:app --reload`).
4. In the Lab UI, the simulation mode selector will show **Suricata** as available once `GET /api/simulate/status` returns `"ready"`.

The backend mounts a temporary directory into the container, runs Suricata against the generated PCAP, and cleans up the container after each run. No persistent containers are left running.

### Full stack Docker Compose (coming soon)

A `docker-compose.yml` that starts the FastAPI backend, serves the built React frontend via Nginx, and exposes a single port is on the roadmap. For now use the local development setup above.

---

## Running tests

### Backend (pytest)

```bash
cd backend
pip install -r requirements-dev.txt

# Run all tests
python -m pytest tests/ -v

# With coverage report
python -m pytest tests/ --cov=app --cov-report=term-missing
```

The test suite uses an in-memory SQLite database (`StaticPool`) so no database file is created or modified. Tests cover:
- Auth: register, duplicate email, invalid email, login success/failure, JWT guard
- Projects: CRUD, ownership isolation, duplicate name (same user → 409, different user → 201), ordering
- PCAP analyzer: topology reconstruction, zone inference, device type detection

### Frontend unit tests (Vitest)

```bash
cd frontend
npm test
```

Pure TypeScript unit tests - no browser, no DOM. Covers:
- `edgeSemantics`: zone-crossing logic, attack/monitoring edge classification
- `exportHelpers`: `getHomeIPs`, `resolveHomeNet` HOME_NET derivation
- `timeAgo`: relative timestamp formatting
- `scenarioRules`: all referenced SIDs exist in the rule library

### E2E tests (Playwright)

Both servers must be running first:
```bash
# Terminal 1
cd backend && uvicorn app.main:app --reload

# Terminal 2
cd frontend && npm run dev

# Terminal 3
cd frontend
npx playwright install chromium   # first time only
npm run test:e2e
```

E2E smoke tests cover:
- Register → dashboard → create project → lab loads → back to dashboard
- Duplicate project name shows inline validation error
- Lab topology persists across a full page reload (autosave verification)

---

## Environment variables

Create `backend/.env` from `backend/.env.example`:

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | *(required)* | Random string used to sign JWT tokens |
| `ALGORITHM` | `HS256` | JWT signing algorithm |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `10080` | Token lifetime (7 days) |
| `DATABASE_URL` | `sqlite:///./suricata_platform.db` | SQLAlchemy database URL |

For production, generate a strong secret key:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

---

## Data model

```
users
  id            INTEGER PRIMARY KEY
  email         TEXT UNIQUE NOT NULL
  password_hash TEXT NOT NULL
  created_at    DATETIME

projects
  id              INTEGER PRIMARY KEY
  user_id         INTEGER FK → users.id (cascade delete)
  name            TEXT NOT NULL
  description     TEXT
  topology_json   TEXT    ← React Flow nodes + edges
  rules_json      TEXT    ← active Suricata rule list
  simulation_json TEXT    ← last simulation result
  export_json     TEXT    ← last export configuration
  created_at      DATETIME
  updated_at      DATETIME
  last_opened_at  DATETIME
```

Project names are unique per user (enforced at the API layer with a 409 conflict response).

---

## PCAP analysis pipeline

When you upload a `.pcap` file the backend runs it through a multi-stage pipeline:

1. **Parse** - Scapy reads all packets and extracts IP/TCP/UDP/ICMP/DNS/HTTP fields.
2. **Host inventory** - unique IPs are collected; each gets a `HostInfo` record with observed ports, protocols, and role signals.
3. **Zone inference** - RFC 1918 ranges → internal; observed public IPs with no inbound connections → external; IPs proxying between zones → DMZ; IPs with management protocols → management.
4. **Device type inference** - port 80/443 → web server; port 22 → SSH server; port 53 → DNS; gateway traffic patterns → router; etc.
5. **Scenario detection** - traffic fingerprints (SYN flood with no ACK → Nmap SYN scan; repeated auth failures → brute-force; periodic beacon intervals → C2; high-entropy DNS payloads → DNS tunnelling) produce a confidence-scored scenario ID.
6. **Rule evaluation** - each active rule is matched against the parsed packets using the Python rule engine.
7. **Topology output** - the result includes React Flow-compatible node and edge objects ready to load directly into the canvas.

---

## Project status

The MVP feature set is complete:

- [x] JWT authentication (register / login / session)
- [x] Multi-user project management with autosave
- [x] Interactive React Flow network canvas
- [x] Device configuration panel (IP, zone, role, ports)
- [x] Rule library (400+ signatures) + custom rule editor
- [x] Python simulation engine with 8 attack scenarios
- [x] Real Suricata execution via Docker
- [x] PCAP import with Scapy-based topology inference
- [x] Config export (Suricata rule set + HOME_NET derivation)
- [x] Full test suite (pytest + Vitest + Playwright)

**Planned:**
- [ ] Docker Compose for one-command self-hosted deployment
- [ ] nftables firewall rule generation from topology
- [ ] Additional attack scenarios and rule categories
- [ ] Collaborative projects (shared lab sessions)
