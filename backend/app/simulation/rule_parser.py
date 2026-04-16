"""
Suricata rule parser — educational fidelity edition.

Supports:
  - Header: action, protocol, src/dst IP (groups, negation, CIDR, variables), ports (groups, ranges, variables)
  - Options (sequential, order-aware): msg, sid, rev, classtype, flow, flags, itype
  - Content keywords: content + nocase, http.uri / http.method / http.header sticky buffers,
    legacy http_uri / http_method / http_header modifiers
  - pcre:"/.../flags"
  - dsize:>N
  - threshold and detection_filter (count N, seconds N)
"""
import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ParsedRule:
    action: str = "alert"
    protocol: str = "tcp"
    src_ip: str = "any"
    src_port: str = "any"
    direction: str = "->"
    dst_ip: str = "any"
    dst_port: str = "any"

    # Basic options
    msg: str = ""
    sid: str = ""
    rev: str = "1"
    classtype: str = ""
    flow: str = ""
    flags: str = ""
    itype: Optional[int] = None

    # Content matching — order-aware buckets
    content: list[str] = field(default_factory=list)              # plain content (case-sensitive)
    nocase_content: list[str] = field(default_factory=list)       # content + nocase (stored lower)
    http_uri_content: list[str] = field(default_factory=list)     # content + http.uri sticky
    http_method_content: list[str] = field(default_factory=list)  # content + http.method sticky
    http_header_content: list[str] = field(default_factory=list)  # content + http.header sticky

    # PCRE patterns (stored as raw /pattern/flags strings)
    pcre: list[str] = field(default_factory=list)

    # Legacy boolean flags (kept for backward compat)
    http_uri: bool = False
    http_method: bool = False
    http_header: bool = False

    # Size / threshold
    dsize_gt: Optional[int] = None
    threshold_count: Optional[int] = None
    threshold_seconds: Optional[int] = None

    raw: str = ""


# ─── Public API ───────────────────────────────────────────────────────────────

def parse_rule(rule_text: str) -> Optional[ParsedRule]:
    """Parse a Suricata rule string. Returns None for blank lines and comments."""
    rule_text = rule_text.strip()
    if not rule_text or rule_text.startswith("#"):
        return None

    m = re.match(
        r'^(alert|drop|pass|reject)\s+'
        r'(\w+)\s+'          # protocol
        r'(\S+)\s+'          # src_ip  (may include brackets — handled by matching non-space)
        r'(\S+)\s+'          # src_port
        r'(<>|->|<-)\s+'     # direction
        r'(\S+)\s+'          # dst_ip
        r'(\S+)\s+'          # dst_port
        r'\((.+)\)\s*$',     # options block
        rule_text,
        re.DOTALL,
    )
    if not m:
        return None

    r = ParsedRule(raw=rule_text)
    r.action    = m.group(1)
    r.protocol  = m.group(2).lower()
    r.src_ip    = m.group(3)
    r.src_port  = m.group(4)
    r.direction = m.group(5)
    r.dst_ip    = m.group(6)
    r.dst_port  = m.group(7)

    _parse_options(r, m.group(8))
    return r


# ─── Options parser ───────────────────────────────────────────────────────────

def _tokenize_options(options_str: str) -> list[str]:
    """
    Split the options block on semicolons, respecting quoted strings.
    Returns a list of non-empty stripped tokens.
    """
    tokens: list[str] = []
    current: list[str] = []
    in_quote = False
    for ch in options_str:
        if ch == '"':
            in_quote = not in_quote
            current.append(ch)
        elif ch == ';' and not in_quote:
            t = ''.join(current).strip()
            if t:
                tokens.append(t)
            current = []
        else:
            current.append(ch)
    tail = ''.join(current).strip()
    if tail:
        tokens.append(tail)
    return tokens


def _parse_options(r: ParsedRule, options_str: str) -> None:
    """
    Process options sequentially so sticky buffer keywords (http.uri, http.method,
    http.header) are associated with the immediately preceding content keyword.
    """
    tokens = _tokenize_options(options_str)

    # Pending content state — the last parsed content:"..." waiting for a modifier
    pending_kw: Optional[str] = None
    pending_nocase: bool = False

    def commit(sticky: Optional[str] = None) -> None:
        nonlocal pending_kw, pending_nocase
        if pending_kw is None:
            return
        kw = pending_kw.lower() if pending_nocase else pending_kw
        if sticky == 'uri':
            r.http_uri_content.append(kw)
        elif sticky == 'method':
            r.http_method_content.append(kw)
        elif sticky == 'header':
            r.http_header_content.append(kw)
        elif pending_nocase:
            r.nocase_content.append(kw)
        else:
            r.content.append(kw)
        pending_kw = None
        pending_nocase = False

    for token in tokens:
        key = token.split(':')[0].strip().lower()

        # ── content:"..." ─────────────────────────────────────────────────────
        if key == 'content':
            commit()  # flush previous
            cm = re.match(r'^content\s*:\s*"([^"]*)"', token)
            if cm:
                pending_kw = cm.group(1)
                # Inline nocase on same token: content:"foo"; nocase  vs  content:"foo" nocase
                rest = token[cm.end():]
                if re.search(r'\bnocase\b', rest):
                    pending_nocase = True
            continue

        # ── Standalone nocase ─────────────────────────────────────────────────
        if key == 'nocase':
            pending_nocase = True
            continue

        # ── Sticky buffer keywords ─────────────────────────────────────────────
        if key in ('http.uri', 'http_uri', 'http.uri;'):
            r.http_uri = True
            commit('uri')
            continue
        if key in ('http.method', 'http_method'):
            r.http_method = True
            commit('method')
            continue
        if key in ('http.header', 'http_header', 'http.header_names',
                   'http.response_header', 'http.request_header'):
            r.http_header = True
            commit('header')
            continue

        # Any other keyword flushes pending content to plain/nocase bucket
        commit()

        # ── pcre ──────────────────────────────────────────────────────────────
        if key == 'pcre':
            pm = re.match(r'^pcre\s*:\s*"([^"]*)"', token)
            if pm:
                r.pcre.append(pm.group(1))
            continue

        # ── msg ───────────────────────────────────────────────────────────────
        if key == 'msg':
            mm = re.match(r'^msg\s*:\s*"([^"]*)"', token)
            if mm:
                r.msg = mm.group(1)
            continue

        # ── sid ───────────────────────────────────────────────────────────────
        if key == 'sid':
            mm = re.match(r'^sid\s*:\s*(\d+)', token)
            if mm:
                r.sid = mm.group(1)
            continue

        # ── rev ───────────────────────────────────────────────────────────────
        if key == 'rev':
            mm = re.match(r'^rev\s*:\s*(\d+)', token)
            if mm:
                r.rev = mm.group(1)
            continue

        # ── classtype ─────────────────────────────────────────────────────────
        if key == 'classtype':
            mm = re.match(r'^classtype\s*:\s*([\w-]+)', token)
            if mm:
                r.classtype = mm.group(1)
            continue

        # ── flow ─────────────────────────────────────────────────────────────
        if key == 'flow':
            mm = re.match(r'^flow\s*:\s*(.+)', token)
            if mm:
                r.flow = mm.group(1).strip()
            continue

        # ── flags ─────────────────────────────────────────────────────────────
        if key == 'flags':
            mm = re.match(r'^flags\s*:\s*(.+)', token)
            if mm:
                r.flags = mm.group(1).strip()
            continue

        # ── itype (ICMP) ──────────────────────────────────────────────────────
        if key == 'itype':
            mm = re.match(r'^itype\s*:\s*(\d+)', token)
            if mm:
                r.itype = int(mm.group(1))
            continue

        # ── dsize ─────────────────────────────────────────────────────────────
        if key == 'dsize':
            mm = re.match(r'^dsize\s*:\s*>\s*(\d+)', token)
            if mm:
                r.dsize_gt = int(mm.group(1))
            continue

        # ── threshold (classic syntax) ────────────────────────────────────────
        if key == 'threshold':
            mm = re.search(r'count\s+(\d+)\s*,\s*seconds\s+(\d+)', token)
            if mm:
                r.threshold_count  = int(mm.group(1))
                r.threshold_seconds = int(mm.group(2))
            continue

        # ── detection_filter (Suricata 5+ replacement for threshold) ─────────
        if key == 'detection_filter':
            mm = re.search(r'count\s+(\d+)\s*,\s*seconds\s+(\d+)', token)
            if mm:
                r.threshold_count  = int(mm.group(1))
                r.threshold_seconds = int(mm.group(2))
            continue

        # All other keywords (metadata, reference, priority, …) are silently ignored.

    # Flush any trailing pending content
    commit()
